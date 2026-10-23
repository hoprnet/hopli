//! This module migrates HOPR nodes from a v3 network (e.g. dufour) to a network of the current contracts
//! (e.g. jura-prod), in one go:
//!
//! 1. A new Safe and module pair is created on the new network, with the nodes included in the module. An existing new
//!    Safe can be used instead.
//! 2. The old Safe of each node (as registered in the v3 Node-Safe registry) closes all the channels between the node
//!    and the given counterparties, as well as the channels between the migrated nodes (see [`channel_candidates`]). v3
//!    networks are not indexed by Blokli, so the counterparties are provided by the user and the status of each channel
//!    is read on-chain.
//! 3. Nodes whose key is available transfer their xDAI to their old Safe, keeping only the fee of this transfer.
//! 4. Each old Safe transfers all its wxHOPR to the new Safe, and splits all its xDAI evenly between the nodes.
//!
//! Old Safes and the new Safe may have different owners. The old Safes are not changed otherwise: the nodes stay in
//! the old module and registered with the old Safe in the v3 Node-Safe registry, which the new network does not use.
use std::{collections::BTreeSet, sync::Arc, time::Duration};

use hopr_bindings::{
    exports::alloy::{
        primitives::{Address, U256},
        providers::{Provider, WalletProvider},
    },
    hopr_channels::HoprChannels,
    hopr_node_safe_registry::HoprNodeSafeRegistry,
    hopr_node_stake_factory::HoprNodeStakeFactory::HoprNodeStakeFactoryInstance,
    hopr_token::HoprToken,
};
use hopr_types::crypto::keypairs::{ChainKeypair, Keypair};
use tracing::{info, warn};

use crate::{
    channels::{ChannelClosureSummary, NodeChannelCandidates, NodeWithSafe, close_channels_of_nodes},
    environment_config::V3NetworkAddresses,
    methods::{
        SafeSingleton, deploy_safe_module_with_targets_and_nodes, ensure_safe_executable_by_signer,
        transfer_all_native_tokens, transfer_safe_funds,
    },
    utils::{HelperErrors, a2h},
};

/// The new Safe that receives the nodes and the wxHOPR
#[derive(Debug, Clone, PartialEq)]
pub enum NewSafe {
    /// Use a Safe that already exists on the new network, e.g. created by a previous run
    Existing(Address),
    /// Create a new Safe and module pair, owned by `admins`, with the nodes included in the module
    Create {
        /// Owners of the new Safe
        admins: Vec<Address>,
        /// Threshold of the new Safe
        threshold: u32,
        /// Allowance of the channels contract on the tokens of the new Safe, in whole tokens. `None` keeps the
        /// default allowance of the stake factory
        allowance: Option<f64>,
    },
}

/// Everything needed to migrate nodes from a v3 network
pub struct V3Migration<P> {
    /// Contracts of the v3 network
    pub old_network: V3NetworkAddresses,
    /// Provider whose default signer is an owner of the old Safes
    pub old_owner_provider: Arc<P>,
    /// Key of an owner of the old Safes, which signs the old Safe transactions
    pub old_owner_key: ChainKeypair,
    /// Node stake factory of the new network, with a provider whose default signer pays for the new Safe
    pub new_stake_factory: HoprNodeStakeFactoryInstance<Arc<P>>,
    /// HoprChannels contract of the new network, the default target of the new module
    pub new_channels: Address,
    /// wxHOPR token contract of the new network
    pub new_token: Address,
    /// The new Safe
    pub new_safe: NewSafe,
    /// Nodes to migrate
    pub nodes: Vec<Address>,
    /// Providers whose default signer is one of the nodes, used to return the xDAI of these nodes
    pub node_providers: Vec<Arc<P>>,
    /// Possible counterparties of the channels of the nodes on the v3 network
    pub counterparties: Vec<Address>,
    /// Maximum number of channels closed in one Safe transaction
    pub batch_size: usize,
    /// Maximum interval between two checks of the chain time while waiting for channel closures
    pub poll_interval: Duration,
}

/// Outcome of [`migrate_nodes_from_v3`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3MigrationSummary {
    /// Address of the new Safe
    pub new_safe: Address,
    /// Address of the new module, when it was created by this migration
    pub new_module: Option<Address>,
    /// Nodes registered with an old Safe, with that Safe
    pub old_safes: Vec<NodeWithSafe>,
    /// Channels closed on the v3 network
    pub channels: ChannelClosureSummary,
    /// wxHOPR transferred from the old Safes to the new Safe
    pub tokens_to_new_safe: U256,
    /// xDAI received by each node from the old Safes
    pub xdai_per_node: U256,
}

/// Candidate counterparties of the channels of each node, without duplicates. Their on-chain status decides which
/// channels exist.
///
/// - Outgoing channels: to the given counterparties and to the other nodes.
/// - Incoming channels: from the given counterparties and the other nodes, except nodes that have an old Safe.
///
/// Closing an incoming channel returns its balance to the source node itself, whereas finalizing an outgoing channel
/// returns it to the Safe of the source node. So a channel between two nodes that both have an old Safe is closed by
/// its source, as an outgoing channel, which keeps its balance in the old Safe and thus moves it to the new Safe.
pub fn channel_candidates(
    nodes: &[NodeWithSafe],
    all_nodes: &[Address],
    counterparties: &[Address],
) -> Vec<NodeChannelCandidates> {
    let with_old_safe: BTreeSet<Address> = nodes.iter().map(|n| n.node).collect();
    nodes
        .iter()
        .map(|node| {
            let peers: BTreeSet<Address> = counterparties
                .iter()
                .chain(all_nodes.iter())
                .copied()
                .filter(|peer| *peer != node.node)
                .collect();
            NodeChannelCandidates {
                node: *node,
                incoming_sources: peers
                    .iter()
                    .copied()
                    .filter(|peer| !with_old_safe.contains(peer))
                    .collect(),
                outgoing_destinations: peers.into_iter().collect(),
            }
        })
        .collect()
}

/// Migrate nodes from a v3 network, see the module documentation.
pub async fn migrate_nodes_from_v3<P>(migration: V3Migration<P>) -> Result<V3MigrationSummary, HelperErrors>
where
    P: Provider + WalletProvider,
{
    let V3Migration {
        old_network,
        old_owner_provider,
        old_owner_key,
        new_stake_factory,
        new_channels,
        new_token,
        new_safe,
        nodes,
        node_providers,
        counterparties,
        batch_size,
        poll_interval,
    } = migration;
    if nodes.is_empty() {
        return Err(HelperErrors::MissingParameter("no node to migrate".into()));
    }

    // find the old Safe of each node, and check that the old owner can execute its transactions,
    // before changing anything
    let old_registry = HoprNodeSafeRegistry::new(old_network.node_safe_registry, old_owner_provider.clone());
    let old_owner = a2h(old_owner_key.public().to_address());
    let mut old_safes: Vec<NodeWithSafe> = Vec::new();
    let mut checked_safes: BTreeSet<Address> = BTreeSet::new();
    for node in &nodes {
        let safe = old_registry.nodeToSafe(*node).call().await?;
        if safe.is_zero() {
            warn!(
                "node {:?} is not registered with any safe on the v3 network, nothing to clean up",
                node
            );
            continue;
        }
        if checked_safes.insert(safe) {
            ensure_safe_executable_by_signer(SafeSingleton::new(safe, old_owner_provider.clone()), old_owner).await?;
        }
        info!("node {:?} is registered with safe {:?} on the v3 network", node, safe);
        old_safes.push(NodeWithSafe { node: *node, safe });
    }

    // 1. the new Safe, with the nodes included in its module
    let (new_safe, new_module) = match new_safe {
        NewSafe::Existing(safe) => {
            info!("using the existing new safe {:?}", safe);
            (safe, None)
        }
        NewSafe::Create {
            admins,
            threshold,
            allowance,
        } => {
            let (safe, module) = deploy_safe_module_with_targets_and_nodes(
                new_stake_factory,
                new_channels,
                new_token,
                nodes.clone(),
                admins,
                U256::from(threshold),
                allowance,
            )
            .await?;
            info!(
                "created the new safe {:?} and module {:?}, with nodes {:?}",
                safe.address(),
                module.address(),
                nodes
            );
            (*safe.address(), Some(*module.address()))
        }
    };

    // 2. close the channels of the nodes on the v3 network
    let candidates = channel_candidates(&old_safes, &nodes, &counterparties);
    let channels = close_channels_of_nodes(
        &old_owner_key,
        HoprChannels::new(old_network.channels, old_owner_provider.clone()),
        &candidates,
        batch_size,
        poll_interval,
    )
    .await?;
    info!(
        "channels on the v3 network: {} incoming closed, {} outgoing finalized",
        channels.incoming_closed, channels.outgoing_finalized
    );

    // 3. the nodes return their xDAI to their old Safe
    for node_provider in node_providers {
        let node = node_provider.default_signer_address();
        match old_safes.iter().find(|n| n.node == node) {
            Some(NodeWithSafe { safe, .. }) => {
                transfer_all_native_tokens(node_provider, *safe).await?;
            }
            None => info!("node {:?} has no old safe, it keeps its xDAI", node),
        }
    }

    // 4. each old Safe transfers its wxHOPR to the new Safe, and splits its xDAI between the nodes
    let mut tokens_to_new_safe = U256::ZERO;
    let mut xdai_per_node = U256::ZERO;
    for old_safe in checked_safes {
        let (tokens, xdai) = transfer_safe_funds(
            SafeSingleton::new(old_safe, old_owner_provider.clone()),
            old_owner_key.clone(),
            HoprToken::new(old_network.token, old_owner_provider.clone()),
            new_safe,
            &nodes,
        )
        .await?;
        tokens_to_new_safe += tokens;
        xdai_per_node += xdai;
    }

    Ok(V3MigrationSummary {
        new_safe,
        new_module,
        old_safes,
        channels,
        tokens_to_new_safe,
        xdai_per_node,
    })
}

#[cfg(test)]
mod tests {
    use hopr_bindings::{
        config::ContractInstances,
        constants::SAFE_MULTISEND_ADDRESS,
        exports::alloy::{
            primitives::{Bytes, address, aliases::U96},
            sol_types::SolCall,
        },
        hopr_channels::HoprChannels::fundChannelSafeCall,
        hopr_node_management_module::HoprNodeManagementModule,
        hopr_node_stake_factory::HoprNodeStakeFactory,
    };

    use super::*;
    use crate::{
        channels::{ONCHAIN_CHANNEL_STATUS_CLOSED, get_channel_id},
        methods::{
            MultisendTransaction, SafeTxOperation, create_rpc_client_to_anvil, get_chain_id_and_safe_nonce,
            send_multisend_safe_transaction_with_threshold_one, transfer_native_tokens, transfer_or_mint_tokens,
        },
        utils::create_anvil,
    };

    const NODE_1: Address = address!("1111111111111111111111111111111111111111");
    const NODE_2: Address = address!("2222222222222222222222222222222222222222");
    const NODE_3: Address = address!("3333333333333333333333333333333333333333");
    const PEER: Address = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const SAFE: Address = address!("5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe");

    #[test]
    fn test_channel_candidates_include_counterparties_and_other_nodes() {
        let registered = [
            NodeWithSafe {
                node: NODE_1,
                safe: SAFE,
            },
            NodeWithSafe {
                node: NODE_2,
                safe: SAFE,
            },
        ];
        // NODE_3 has no old safe, so its channels to the other nodes are closed as their incoming channels
        let candidates = channel_candidates(&registered, &[NODE_1, NODE_2, NODE_3], &[PEER, PEER]);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].node, registered[0]);
        assert_eq!(candidates[0].incoming_sources, vec![NODE_3, PEER]);
        assert_eq!(candidates[0].outgoing_destinations, vec![NODE_2, NODE_3, PEER]);
        assert_eq!(candidates[1].node, registered[1]);
        assert_eq!(candidates[1].incoming_sources, vec![NODE_3, PEER]);
        assert_eq!(candidates[1].outgoing_destinations, vec![NODE_1, NODE_3, PEER]);

        // a node with an old safe is never a candidate source of incoming channels, even if given as counterparty
        let candidates = channel_candidates(&registered, &[NODE_1, NODE_2], &[NODE_2]);
        assert!(candidates[0].incoming_sources.is_empty());
        assert_eq!(candidates[0].outgoing_destinations, vec![NODE_2]);
        assert!(candidates[1].incoming_sources.is_empty());
    }

    #[test]
    fn test_channel_candidates_without_counterparties() {
        let registered = [NodeWithSafe {
            node: NODE_1,
            safe: SAFE,
        }];
        let candidates = channel_candidates(&registered, &[NODE_1], &[]);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].incoming_sources.is_empty());
        assert!(candidates[0].outgoing_destinations.is_empty());
    }

    /// Migrate two nodes from a v3-like network (a HoprChannels contract with a short notice period, and a
    /// Node-Safe registry) to a new network, on Anvil. The old Safe and the new Safe have different owners.
    /// - PEER -> NODE_1: open, closed as incoming channel; its balance returns to PEER
    /// - NODE_1 -> PEER: open, closed as outgoing channel; its balance returns to the old Safe
    /// - NODE_2 -> NODE_1: open, closed by NODE_2 as outgoing channel; its balance returns to the old Safe
    #[tokio::test]
    async fn test_migrate_nodes_from_v3_on_anvil() -> anyhow::Result<()> {
        const NOTICE_PERIOD: u32 = 5;
        let one_token = U256::from(1_000_000_000_000_000_000_u128);
        let channel_balance = U96::from(1_000_000_000_000_000_000_u128);

        let anvil = create_anvil(None);
        // the deployer owns the new safe
        let deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let deployer_address = a2h(deployer.public().to_address());
        let client = create_rpc_client_to_anvil(&anvil, &deployer);
        let instances =
            ContractInstances::deploy_for_testing(client.clone(), deployer_address, anvil.addresses()[1]).await?;
        ContractInstances::deploy_multicall3(client.clone(), anvil.addresses()[1]).await?;
        ContractInstances::deploy_safe_suites(client.clone(), anvil.addresses()[1]).await?;

        // old (v3-like) network, and new network, sharing the token and the stake factory
        let old_channels = HoprChannels::deploy(
            client.clone(),
            *instances.token.address(),
            NOTICE_PERIOD,
            *instances.safe_registry.address(),
        )
        .await?;
        let old_network = V3NetworkAddresses {
            channels: *old_channels.address(),
            node_safe_registry: *instances.safe_registry.address(),
            token: *instances.token.address(),
        };
        let new_registry = HoprNodeSafeRegistry::deploy(client.clone()).await?;
        let new_channels = HoprChannels::deploy(
            client.clone(),
            *instances.token.address(),
            NOTICE_PERIOD,
            *new_registry.address(),
        )
        .await?;

        // keys: owner of the old safe, nodes, and a peer without safe
        let old_owner = ChainKeypair::random();
        let old_owner_address = a2h(old_owner.public().to_address());
        let node_keys = [ChainKeypair::random(), ChainKeypair::random()];
        let nodes: Vec<Address> = node_keys.iter().map(|k| a2h(k.public().to_address())).collect();
        let peer_key = ChainKeypair::random();
        let peer = a2h(peer_key.public().to_address());
        transfer_native_tokens(
            client.clone(),
            vec![old_owner_address, nodes[0], nodes[1], peer],
            vec![U256::from(10) * one_token, one_token, one_token, one_token],
        )
        .await?;

        // the old safe, created and owned by the old owner, with the nodes registered
        let old_owner_client = create_rpc_client_to_anvil(&anvil, &old_owner);
        let (old_safe, _) = deploy_safe_module_with_targets_and_nodes(
            HoprNodeStakeFactory::new(*instances.stake_factory.address(), old_owner_client.clone()),
            *old_channels.address(),
            *instances.token.address(),
            nodes.clone(),
            vec![old_owner_address],
            U256::ONE,
            None,
        )
        .await?;
        let node_clients: Vec<_> = node_keys
            .iter()
            .map(|k| create_rpc_client_to_anvil(&anvil, k))
            .collect();
        for node_client in &node_clients {
            HoprNodeSafeRegistry::new(*instances.safe_registry.address(), node_client.clone())
                .registerSafeByNode(*old_safe.address())
                .send()
                .await?
                .watch()
                .await?;
        }
        let old_safe_tokens = U256::from(10) * one_token;
        let old_safe_xdai = U256::from(2) * one_token;
        transfer_or_mint_tokens(
            instances.token.clone(),
            vec![*old_safe.address(), peer],
            vec![old_safe_tokens, one_token],
        )
        .await?;
        transfer_native_tokens(client.clone(), vec![*old_safe.address()], vec![old_safe_xdai]).await?;

        // channels: the old safe opens NODE_1 -> PEER and NODE_2 -> NODE_1, PEER opens PEER -> NODE_1
        let fund = |node: Address, destination: Address| MultisendTransaction {
            encoded_data: Bytes::from(
                fundChannelSafeCall {
                    selfAddress: node,
                    account: destination,
                    amount: channel_balance,
                }
                .abi_encode(),
            ),
            tx_operation: SafeTxOperation::Call,
            to: *old_channels.address(),
            value: U256::ZERO,
        };
        let (chain_id, nonce) = get_chain_id_and_safe_nonce(old_safe.clone()).await?;
        send_multisend_safe_transaction_with_threshold_one(
            old_safe.clone(),
            old_owner.clone(),
            SAFE_MULTISEND_ADDRESS,
            vec![fund(nodes[0], peer), fund(nodes[1], nodes[0])],
            chain_id,
            nonce,
        )
        .await?;
        let peer_client = create_rpc_client_to_anvil(&anvil, &peer_key);
        HoprToken::new(*instances.token.address(), peer_client.clone())
            .approve(*old_channels.address(), one_token)
            .send()
            .await?
            .watch()
            .await?;
        HoprChannels::new(*old_channels.address(), peer_client)
            .fundChannel(nodes[0], channel_balance)
            .send()
            .await?
            .watch()
            .await?;
        // tokens of the old safe, minus the two channels it funded
        let old_safe_tokens = old_safe_tokens - U256::from(2) * one_token;

        // from now on, Anvil mines a block every second, so that the chain time moves on while waiting for the
        // notice period
        client
            .raw_request::<_, serde_json::Value>("evm_setIntervalMining".into(), [1])
            .await?;

        let summary = migrate_nodes_from_v3(V3Migration {
            old_network,
            old_owner_provider: old_owner_client.clone(),
            old_owner_key: old_owner.clone(),
            new_stake_factory: HoprNodeStakeFactory::new(*instances.stake_factory.address(), client.clone()),
            new_channels: *new_channels.address(),
            new_token: *instances.token.address(),
            new_safe: NewSafe::Create {
                admins: vec![deployer_address],
                threshold: 1,
                allowance: Some(100.0),
            },
            nodes: nodes.clone(),
            node_providers: node_clients,
            counterparties: vec![peer],
            batch_size: 2,
            poll_interval: Duration::from_secs(1),
        })
        .await?;

        // the new safe is owned by the deployer, and its module includes the nodes
        let new_safe = SafeSingleton::new(summary.new_safe, client.clone());
        assert_eq!(new_safe.getOwners().call().await?, vec![deployer_address]);
        let new_module = HoprNodeManagementModule::new(
            summary.new_module.expect("the new module must be created"),
            client.clone(),
        );
        for node in &nodes {
            assert!(new_module.isNode(*node).call().await?, "node must be in the new module");
        }
        assert_eq!(
            instances
                .token
                .allowance(summary.new_safe, *new_channels.address())
                .call()
                .await?,
            U256::from(100) * one_token,
            "the new channels contract must have the requested allowance"
        );

        // all the channels are closed on the old network
        assert_eq!(
            summary.channels,
            ChannelClosureSummary {
                incoming_closed: 1,
                outgoing_initiated: 2,
                outgoing_finalized: 2,
            }
        );
        for (source, destination) in [(peer, nodes[0]), (nodes[0], peer), (nodes[1], nodes[0])] {
            let channel = old_channels
                .channels(get_channel_id(source, destination))
                .call()
                .await?;
            assert_eq!(channel.status, ONCHAIN_CHANNEL_STATUS_CLOSED);
        }

        // the tokens of the old safe, including the balances of its outgoing channels, are in the new safe
        let expected_tokens = old_safe_tokens + U256::from(2) * one_token;
        assert_eq!(summary.tokens_to_new_safe, expected_tokens);
        assert_eq!(
            instances.token.balanceOf(summary.new_safe).call().await?,
            expected_tokens
        );
        assert_eq!(instances.token.balanceOf(*old_safe.address()).call().await?, U256::ZERO);
        assert_eq!(instances.token.balanceOf(peer).call().await?, one_token);

        // the xDAI of the nodes and of the old safe is split evenly between the nodes
        assert!(summary.xdai_per_node > old_safe_xdai / U256::from(2));
        for node in &nodes {
            assert_eq!(client.get_balance(*node).await?, summary.xdai_per_node);
        }
        assert!(client.get_balance(*old_safe.address()).await? < U256::from(nodes.len()));

        // the old safe is otherwise unchanged
        assert_eq!(old_safe.getOwners().call().await?, vec![old_owner_address]);
        assert_eq!(
            instances.safe_registry.nodeToSafe(nodes[0]).call().await?,
            *old_safe.address()
        );
        Ok(())
    }
}
