//! This module migrates HOPR nodes from a v3 network (e.g. dufour) to a network of the current contracts
//! (e.g. jura-prod), in one go:
//!
//! 1. A new Safe and module pair is created on the new network, with the nodes included in the module. An existing
//!    new Safe can be used instead.
//! 2. The old Safe of each node (as registered in the v3 Node-Safe registry) closes all the channels between the node
//!    and the given counterparties, as well as the channels between the migrated nodes (see [`channel_candidates`]).
//!    v3 networks are not indexed by Blokli, so the counterparties are provided by the user and the status of each
//!    channel is read on-chain.
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
    use hopr_bindings::exports::alloy::primitives::address;

    use super::*;

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
}
