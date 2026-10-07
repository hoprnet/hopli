//! This module contains helpers to close payment channels of HOPR nodes on behalf of their Safe.
//!
//! Channel information (status, source and destination of every channel) is read from a Blokli
//! indexer via [`blokli_client`]. Closing channels is done on-chain, by the Safe that the node is
//! registered with in the Node-Safe registry: the Safe owner signs one Safe transaction per batch,
//! which bundles many `*Safe` calls to the HoprChannels contract via the Safe MultiSend contract.
//!
//! [`ChannelClosureAction`] maps each closure step to the HoprChannels function to call:
//! - [`ChannelClosureAction::CloseIncoming`] -> `closeIncomingChannelSafe(selfAddress, source)`
//! - [`ChannelClosureAction::InitiateOutgoingClosure`] -> `initiateOutgoingChannelClosureSafe(selfAddress,
//!   destination)`
//! - [`ChannelClosureAction::FinalizeOutgoingClosure`] -> `finalizeOutgoingChannelClosureSafe(selfAddress,
//!   destination)`
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use blokli_client::{
    AccountSelector, BlokliClient, BlokliClientConfig, BlokliQueryClient, ChannelFilter, ChannelSelector, KeyId,
    types::ChannelStatus,
};
use hopr_bindings::{
    exports::alloy::{
        primitives::{Address, B256, Bytes, keccak256},
        providers::{Provider, WalletProvider},
        sol_types::{SolCall, SolValue},
    },
    hopr_channels::HoprChannels::{
        HoprChannelsInstance, closeIncomingChannelSafeCall, finalizeOutgoingChannelClosureSafeCall,
        initiateOutgoingChannelClosureSafeCall,
    },
};
use hopr_types::crypto::keypairs::ChainKeypair;
use tracing::{debug, info};

use crate::{
    methods::{
        SafeSingleton, execute_channel_closure_through_safe, get_latest_block_timestamp, get_pending_outgoing_closures,
        wait_until_block_timestamp_passed,
    },
    utils::HelperErrors,
};

/// Default number of channel operations bundled into a single Safe transaction.
///
/// Each operation costs roughly 50k-100k gas, so a batch of 30 stays well below the
/// block gas limit of Gnosis chain.
pub const DEFAULT_CHANNEL_BATCH_SIZE: usize = 30;

/// On-chain value of `HoprChannelsType.ChannelStatus.CLOSED`
pub const ONCHAIN_CHANNEL_STATUS_CLOSED: u8 = 0;
/// On-chain value of `HoprChannelsType.ChannelStatus.OPEN`
pub const ONCHAIN_CHANNEL_STATUS_OPEN: u8 = 1;
/// On-chain value of `HoprChannelsType.ChannelStatus.PENDING_TO_CLOSE`
pub const ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE: u8 = 2;

/// Compute the id of the channel from `source` to `destination`, as `HoprChannels._getChannelId` does
pub fn get_channel_id(source: Address, destination: Address) -> B256 {
    keccak256((source, destination).abi_encode_packed())
}

/// Direction of a channel, seen from the node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDirection {
    /// The node is the destination of the channel; the counterparty is the source
    Incoming,
    /// The node is the source of the channel; the counterparty is the destination
    Outgoing,
}

/// One step of closing channels, executed by the Safe on behalf of the node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelClosureAction {
    /// Close an incoming channel immediately
    CloseIncoming,
    /// Start the notice period of an outgoing channel
    InitiateOutgoingClosure,
    /// Close an outgoing channel once the notice period has elapsed
    FinalizeOutgoingClosure,
}

impl ChannelClosureAction {
    /// Encode the HoprChannels call for the given node (`selfAddress`) and channel counterparty
    pub fn encode(&self, node: Address, counterparty: Address) -> Bytes {
        match self {
            ChannelClosureAction::CloseIncoming => closeIncomingChannelSafeCall {
                selfAddress: node,
                source: counterparty,
            }
            .abi_encode(),
            ChannelClosureAction::InitiateOutgoingClosure => initiateOutgoingChannelClosureSafeCall {
                selfAddress: node,
                destination: counterparty,
            }
            .abi_encode(),
            ChannelClosureAction::FinalizeOutgoingClosure => finalizeOutgoingChannelClosureSafeCall {
                selfAddress: node,
                destination: counterparty,
            }
            .abi_encode(),
        }
        .into()
    }

    /// Source and destination of the channel affected by this action
    pub fn channel_endpoints(&self, node: Address, counterparty: Address) -> (Address, Address) {
        match self {
            ChannelClosureAction::CloseIncoming => (counterparty, node),
            ChannelClosureAction::InitiateOutgoingClosure | ChannelClosureAction::FinalizeOutgoingClosure => {
                (node, counterparty)
            }
        }
    }

    /// Whether the action can be applied to a channel with the given on-chain status.
    ///
    /// Used to drop channels whose state indexed by Blokli is outdated, which would otherwise make
    /// the whole batch revert.
    pub fn accepts_onchain_status(&self, status: u8) -> bool {
        match self {
            ChannelClosureAction::CloseIncoming => {
                status == ONCHAIN_CHANNEL_STATUS_OPEN || status == ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE
            }
            // initiating again on a PENDING_TO_CLOSE channel would push its closure time further out
            ChannelClosureAction::InitiateOutgoingClosure => status == ONCHAIN_CHANNEL_STATUS_OPEN,
            ChannelClosureAction::FinalizeOutgoingClosure => status == ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE,
        }
    }

    /// Human-readable description, used in logs
    pub fn describe(&self) -> &'static str {
        match self {
            ChannelClosureAction::CloseIncoming => "close incoming channels",
            ChannelClosureAction::InitiateOutgoingClosure => "initiate closure of outgoing channels",
            ChannelClosureAction::FinalizeOutgoingClosure => "finalize closure of outgoing channels",
        }
    }
}

/// Outgoing channel of a node whose closure has been initiated, with its on-chain closure time
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingOutgoingClosure {
    /// Source of the channel
    pub node: Address,
    /// Destination of the channel
    pub destination: Address,
    /// `closureTime` of the channel: the block timestamp at which its closure was initiated, plus
    /// `NOTICE_PERIOD_CHANNEL_CLOSURE`
    pub closure_time: u64,
}

/// Whether the closure of an outgoing channel can be finalized in a block with the given timestamp.
///
/// `finalizeOutgoingChannelClosure` reverts with `NoticePeriodNotDue` while
/// `closureTime >= block.timestamp`, so the closure is due only once `block.timestamp > closureTime`.
/// Since `closureTime` depends on when the closure of each channel was initiated, this is checked per channel.
pub fn is_closure_due(closure_time: u64, block_timestamp: u64) -> bool {
    block_timestamp > closure_time
}

/// Split pending closures into those which are due at the given block timestamp, and those which are not yet
pub fn split_due_closures(
    pending: Vec<PendingOutgoingClosure>,
    block_timestamp: u64,
) -> (Vec<PendingOutgoingClosure>, Vec<PendingOutgoingClosure>) {
    pending
        .into_iter()
        .partition(|p| is_closure_due(p.closure_time, block_timestamp))
}

/// Group the destinations of pending closures by node, keeping the order of nodes and destinations
pub fn group_destinations_by_node(pending: &[PendingOutgoingClosure]) -> Vec<(Address, Vec<Address>)> {
    let mut grouped: Vec<(Address, Vec<Address>)> = Vec::new();
    for p in pending {
        match grouped.iter_mut().find(|(node, _)| *node == p.node) {
            Some((_, destinations)) => destinations.push(p.destination),
            None => grouped.push((p.node, vec![p.destination])),
        }
    }
    grouped
}

/// Create a Blokli client from its base URL, e.g. `https://blokli.jura.hoprnet.link`
pub fn new_blokli_client(blokli_url: &str) -> Result<BlokliClient, HelperErrors> {
    let url = blokli_url
        .parse()
        .map_err(|e| HelperErrors::ParseError(format!("invalid Blokli url {blokli_url:?}: {e}")))?;
    Ok(BlokliClient::new(url, BlokliClientConfig::default()))
}

/// Parse an address returned by Blokli, with or without the `0x` prefix
pub fn parse_blokli_address(value: &str) -> Result<Address, HelperErrors> {
    let trimmed = value.trim();
    let prefixed = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        trimmed.to_string()
    } else {
        format!("0x{trimmed}")
    };
    Address::from_str(&prefixed)
        .map_err(|e| HelperErrors::InvalidAddress(format!("Cannot parse address {value:?} from Blokli: {e}")))
}

/// Get the Blokli key id of a node. Returns `None` when Blokli does not know the node,
/// which means the node has never been announced and cannot have any channel.
pub async fn get_node_key_id<C: BlokliQueryClient + Sync>(
    client: &C,
    node: Address,
) -> Result<Option<KeyId>, HelperErrors> {
    let accounts = client
        .query_accounts(AccountSelector::Address(node.into_array()))
        .await?;
    match accounts.as_slice() {
        [] => Ok(None),
        [account] => Ok(Some(KeyId::try_from(account.keyid).map_err(|_| {
            HelperErrors::ParseError(format!("invalid key id {} for node {node:?}", account.keyid))
        })?)),
        _ => Err(HelperErrors::ParseError(format!(
            "Blokli returned {} accounts for node {node:?}",
            accounts.len()
        ))),
    }
}

/// Resolve the chain address of a Blokli key id, using (and filling) a cache
async fn resolve_key_id<C: BlokliQueryClient + Sync>(
    client: &C,
    key_id: i32,
    cache: &mut HashMap<i32, Address>,
) -> Result<Address, HelperErrors> {
    if let Some(address) = cache.get(&key_id) {
        return Ok(*address);
    }
    let selector_key_id =
        KeyId::try_from(key_id).map_err(|_| HelperErrors::ParseError(format!("invalid key id {key_id}")))?;
    let accounts = client.query_accounts(AccountSelector::KeyId(selector_key_id)).await?;
    let [account] = accounts.as_slice() else {
        return Err(HelperErrors::ParseError(format!(
            "expected exactly one account for key id {key_id}, got {}",
            accounts.len()
        )));
    };
    let address = parse_blokli_address(&account.chain_key)?;
    cache.insert(key_id, address);
    Ok(address)
}

/// Get the counterparties of all the channels of a node, in a given direction and with one of the given statuses.
///
/// For incoming channels, the counterparty is the source of the channel; for outgoing channels it is the
/// destination. The returned addresses are unique and sorted.
pub async fn get_channel_counterparties<C: BlokliQueryClient + Sync>(
    client: &C,
    node_key_id: KeyId,
    direction: ChannelDirection,
    statuses: &[ChannelStatus],
    cache: &mut HashMap<i32, Address>,
) -> Result<Vec<Address>, HelperErrors> {
    if statuses.is_empty() {
        return Ok(vec![]);
    }

    let filter = match direction {
        ChannelDirection::Incoming => ChannelFilter::DestinationKeyId(node_key_id),
        ChannelDirection::Outgoing => ChannelFilter::SourceKeyId(node_key_id),
    };
    // let Blokli filter on status when only one is requested; otherwise filter locally
    let status = match statuses {
        [single] => Some(*single),
        _ => None,
    };
    let channels = client
        .query_channels(ChannelSelector {
            filter: Some(filter),
            status,
            safe_address: None,
        })
        .await?
        .channels;
    debug!(
        "Blokli returned {} {:?} channels for key id {}",
        channels.len(),
        direction,
        node_key_id
    );

    let mut counterparties = BTreeSet::new();
    for channel in channels.iter().filter(|c| statuses.contains(&c.status)) {
        let counterparty_key_id = match direction {
            ChannelDirection::Incoming => channel.source,
            ChannelDirection::Outgoing => channel.destination,
        };
        counterparties.insert(resolve_key_id(client, counterparty_key_id, cache).await?);
    }
    Ok(counterparties.into_iter().collect())
}

/// Merge several lists of addresses into one sorted list without duplicates
pub fn merge_unique_addresses<'a, I: IntoIterator<Item = &'a [Address]>>(lists: I) -> Vec<Address> {
    lists
        .into_iter()
        .flat_map(|l| l.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// A node, and the Safe it is registered with in the Node-Safe registry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeWithSafe {
    /// Address of the node
    pub node: Address,
    /// Address of the Safe the node is registered with
    pub safe: Address,
}

/// Number of channels on which each closure action has been executed by [`close_channels_of_nodes`]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChannelClosureSummary {
    /// Incoming channels closed
    pub incoming_closed: usize,
    /// Outgoing channels whose closure has been initiated
    pub outgoing_initiated: usize,
    /// Outgoing channels whose closure has been finalized
    pub outgoing_finalized: usize,
}

/// Counterparties that may have a channel with a node. Their channels are not assumed to exist: the on-chain
/// status of each channel decides which closure action, if any, applies to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeChannelCandidates {
    /// The node, and the Safe that closes its channels
    pub node: NodeWithSafe,
    /// Possible sources of incoming channels of the node
    pub incoming_sources: Vec<Address>,
    /// Possible destinations of outgoing channels of the node
    pub outgoing_destinations: Vec<Address>,
}

/// Close the channels between nodes and candidate counterparties, on behalf of the Safe of each node, which must be
/// executable by the `safe_owner_key` alone.
///
/// 1. Close the incoming channels that are Open or PendingToClose on-chain
/// 2. Initiate the closure of the outgoing channels that are Open on-chain
/// 3. Read the closure time of the outgoing channels that are PendingToClose on-chain, i.e. those initiated in step 2
///    and those initiated before
/// 4. Finalize the closure of each outgoing channel once its own closure time has passed, i.e. once `block.timestamp >
///    closureTime`, where `closureTime` is the timestamp of the block that included its
///    `initiateOutgoingChannelClosureSafe` plus `NOTICE_PERIOD_CHANNEL_CLOSURE`. Channels of all the nodes are handled
///    together, so the notice period is not waited once per node. The chain time is checked at most every
///    `poll_interval` while waiting.
///
/// Candidates whose channel does not exist, or is not in a state the action applies to, are skipped.
pub async fn close_channels_of_nodes<P>(
    safe_owner_key: &ChainKeypair,
    channels: HoprChannelsInstance<Arc<P>>,
    candidates: &[NodeChannelCandidates],
    batch_size: usize,
    poll_interval: Duration,
) -> Result<ChannelClosureSummary, HelperErrors>
where
    P: Provider + WalletProvider,
{
    let provider = channels.provider().clone();
    let mut summary = ChannelClosureSummary::default();
    let safes: HashMap<Address, Address> = candidates.iter().map(|c| (c.node.node, c.node.safe)).collect();

    // 1. close incoming channels
    for candidate in candidates {
        let node = candidate.node;
        let closed = execute_channel_closure_through_safe(
            SafeSingleton::new(node.safe, provider.clone()),
            safe_owner_key.clone(),
            channels.clone(),
            ChannelClosureAction::CloseIncoming,
            node.node,
            &candidate.incoming_sources,
            batch_size,
        )
        .await?;
        info!("node {:?}: {} incoming channels are closed", node.node, closed);
        summary.incoming_closed += closed;
    }

    // 2. initiate the closure of open outgoing channels
    for candidate in candidates {
        let node = candidate.node;
        let count = execute_channel_closure_through_safe(
            SafeSingleton::new(node.safe, provider.clone()),
            safe_owner_key.clone(),
            channels.clone(),
            ChannelClosureAction::InitiateOutgoingClosure,
            node.node,
            &candidate.outgoing_destinations,
            batch_size,
        )
        .await?;
        info!(
            "node {:?}: closure of {} outgoing channels is initiated",
            node.node, count
        );
        summary.outgoing_initiated += count;
    }

    // 3. read the closure time of the outgoing channels pending to close, which depends on when the closure of each
    //    channel was initiated
    let mut pending: Vec<PendingOutgoingClosure> = Vec::new();
    for candidate in candidates {
        pending.extend(
            get_pending_outgoing_closures(&channels, candidate.node.node, &candidate.outgoing_destinations).await?,
        );
    }

    // 4. finalize the closure of each outgoing channel once its own notice period is due, waiting for the next due
    //    channel in between
    while !pending.is_empty() {
        let now = get_latest_block_timestamp(provider.as_ref()).await?;
        let (due, not_due) = split_due_closures(pending, now);
        for (node, destinations) in group_destinations_by_node(&due) {
            let Some(safe) = safes.get(&node) else {
                continue;
            };
            let finalized = execute_channel_closure_through_safe(
                SafeSingleton::new(*safe, provider.clone()),
                safe_owner_key.clone(),
                channels.clone(),
                ChannelClosureAction::FinalizeOutgoingClosure,
                node,
                &destinations,
                batch_size,
            )
            .await?;
            info!("node {:?}: {} outgoing channels are closed", node, finalized);
            summary.outgoing_finalized += finalized;
        }

        pending = not_due;
        if let Some(next_due) = pending.iter().map(|p| p.closure_time).min() {
            info!(
                "{} outgoing channels are pending to close; the next one can be finalized after timestamp {}",
                pending.len(),
                next_due
            );
            wait_until_block_timestamp_passed(provider.as_ref(), next_due, poll_interval).await?;
        }
    }

    Ok(summary)
}

/// Close all the channels of the given nodes, on behalf of their Safe, which must be executable by the
/// `safe_owner_key` alone.
///
/// The counterparties of each node are read from Blokli: the sources of its Open or PendingToClose incoming
/// channels, and the destinations of its Open or PendingToClose outgoing channels. The channels are then closed by
/// [`close_channels_of_nodes`], which checks their on-chain status, so channels whose state indexed by Blokli is
/// outdated are handled too. Nodes unknown to Blokli have no channel and are skipped.
pub async fn close_all_channels_of_nodes<C, P>(
    blokli: &C,
    safe_owner_key: &ChainKeypair,
    channels: HoprChannelsInstance<Arc<P>>,
    nodes: &[NodeWithSafe],
    batch_size: usize,
    poll_interval: Duration,
) -> Result<ChannelClosureSummary, HelperErrors>
where
    C: BlokliQueryClient + Sync,
    P: Provider + WalletProvider,
{
    // counterparty addresses resolved from Blokli key ids
    let mut address_cache = HashMap::new();
    let mut candidates: Vec<NodeChannelCandidates> = Vec::new();
    for node in nodes {
        let Some(key_id) = get_node_key_id(blokli, node.node).await? else {
            info!("node {:?} is not known by Blokli, it has no channel", node.node);
            continue;
        };
        let not_closed = [ChannelStatus::Open, ChannelStatus::PendingToClose];
        let incoming_sources = get_channel_counterparties(
            blokli,
            key_id,
            ChannelDirection::Incoming,
            &not_closed,
            &mut address_cache,
        )
        .await?;
        let outgoing_destinations = get_channel_counterparties(
            blokli,
            key_id,
            ChannelDirection::Outgoing,
            &not_closed,
            &mut address_cache,
        )
        .await?;
        candidates.push(NodeChannelCandidates {
            node: *node,
            incoming_sources,
            outgoing_destinations,
        });
    }

    close_channels_of_nodes(safe_owner_key, channels, &candidates, batch_size, poll_interval).await
}

#[cfg(test)]
mod tests {
    use blokli_client::{
        BlokliTestClient, BlokliTestState, NopStateMutator,
        types::{Account, Channel, DateTime, TokenValueString, Uint64},
    };
    use hopr_bindings::{
        config::ContractInstances,
        constants::SAFE_MULTISEND_ADDRESS,
        exports::alloy::primitives::{U256, address, aliases::U96},
        hopr_channels::HoprChannels::{self, fundChannelSafeCall},
        hopr_node_safe_registry::HoprNodeSafeRegistry,
        hopr_token::HoprToken,
    };
    use hopr_types::crypto::keypairs::Keypair;

    use super::*;
    use crate::{
        methods::{
            MultisendTransaction, SafeTxOperation, create_rpc_client_to_anvil,
            deploy_safe_module_with_targets_and_nodes, get_chain_id_and_safe_nonce, get_notice_period_channel_closure,
            send_multisend_safe_transaction_with_threshold_one, transfer_native_tokens, transfer_or_mint_tokens,
        },
        utils::{a2h, create_anvil},
    };

    const NODE: Address = address!("1111111111111111111111111111111111111111");
    const PEER_A: Address = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const PEER_B: Address = address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const PEER_C: Address = address!("cccccccccccccccccccccccccccccccccccccccc");

    fn account(key_id: u32, address: Address) -> Account {
        Account {
            chain_key: hex::encode(address),
            keyid: i32::try_from(key_id).unwrap(),
            multi_addresses: vec![],
            packet_key: hex::encode([key_id as u8; 32]),
            safe_address: None,
        }
    }

    fn channel(source: i32, destination: i32, status: ChannelStatus) -> Channel {
        Channel {
            balance: TokenValueString("1 wxHOPR".into()),
            closure_time: None::<DateTime>,
            concrete_channel_id: format!("{source:064x}{destination:064x}"),
            destination,
            epoch: 1,
            source,
            status,
            ticket_index: Uint64("0".into()),
        }
    }

    /// Blokli test client knowing the given accounts (key id 1, 2, ... in order) and channels
    /// (`(source key id, destination key id, status)`)
    fn blokli_client_with(
        accounts: &[Address],
        channels: &[(i32, i32, ChannelStatus)],
    ) -> BlokliTestClient<NopStateMutator> {
        let mut state = BlokliTestState::default();
        state.accounts.clear();
        state.channels.clear();
        for (index, address) in accounts.iter().enumerate() {
            let key_id = u32::try_from(index + 1).unwrap();
            state.accounts.insert(key_id, account(key_id, *address));
        }
        for (source, destination, status) in channels {
            let c = channel(*source, *destination, *status);
            state.channels.insert(c.concrete_channel_id.clone(), c);
        }
        BlokliTestClient::new(state, NopStateMutator)
    }

    /// NODE (1) <-> PEER_A (2), PEER_B (3), PEER_C (4)
    fn test_client() -> BlokliTestClient<NopStateMutator> {
        blokli_client_with(
            &[NODE, PEER_A, PEER_B, PEER_C],
            &[
                // incoming
                (2, 1, ChannelStatus::Open),
                (3, 1, ChannelStatus::PendingToClose),
                (4, 1, ChannelStatus::Closed),
                // outgoing
                (1, 2, ChannelStatus::Open),
                (1, 3, ChannelStatus::Open),
                (1, 4, ChannelStatus::PendingToClose),
            ],
        )
    }

    #[test]
    fn test_closure_action_encoding_uses_safe_functions() {
        let close = ChannelClosureAction::CloseIncoming.encode(NODE, PEER_A);
        let decoded = closeIncomingChannelSafeCall::abi_decode(&close).unwrap();
        assert_eq!(decoded.selfAddress, NODE);
        assert_eq!(decoded.source, PEER_A);

        let initiate = ChannelClosureAction::InitiateOutgoingClosure.encode(NODE, PEER_B);
        let decoded = initiateOutgoingChannelClosureSafeCall::abi_decode(&initiate).unwrap();
        assert_eq!(decoded.selfAddress, NODE);
        assert_eq!(decoded.destination, PEER_B);

        let finalize = ChannelClosureAction::FinalizeOutgoingClosure.encode(NODE, PEER_C);
        let decoded = finalizeOutgoingChannelClosureSafeCall::abi_decode(&finalize).unwrap();
        assert_eq!(decoded.selfAddress, NODE);
        assert_eq!(decoded.destination, PEER_C);
    }

    #[test]
    fn test_channel_endpoints_and_accepted_status() {
        assert_eq!(
            ChannelClosureAction::CloseIncoming.channel_endpoints(NODE, PEER_A),
            (PEER_A, NODE)
        );
        assert_eq!(
            ChannelClosureAction::InitiateOutgoingClosure.channel_endpoints(NODE, PEER_A),
            (NODE, PEER_A)
        );
        assert_eq!(
            ChannelClosureAction::FinalizeOutgoingClosure.channel_endpoints(NODE, PEER_A),
            (NODE, PEER_A)
        );

        let close = ChannelClosureAction::CloseIncoming;
        assert!(!close.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_CLOSED));
        assert!(close.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_OPEN));
        assert!(close.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE));

        let initiate = ChannelClosureAction::InitiateOutgoingClosure;
        assert!(!initiate.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_CLOSED));
        assert!(initiate.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_OPEN));
        assert!(!initiate.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE));

        let finalize = ChannelClosureAction::FinalizeOutgoingClosure;
        assert!(!finalize.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_CLOSED));
        assert!(!finalize.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_OPEN));
        assert!(finalize.accepts_onchain_status(ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE));
    }

    #[test]
    fn test_channel_id_matches_hopr_types() {
        let expected =
            hopr_types::internal::channels::generate_channel_id(&crate::utils::h2a(NODE), &crate::utils::h2a(PEER_A));
        assert_eq!(get_channel_id(NODE, PEER_A).as_slice(), expected.as_ref());
        assert_ne!(get_channel_id(NODE, PEER_A), get_channel_id(PEER_A, NODE));
    }

    #[test]
    fn test_closure_is_due_only_after_closure_time() {
        // reverts with NoticePeriodNotDue while closureTime >= block.timestamp
        assert!(!is_closure_due(1_000, 999));
        assert!(!is_closure_due(1_000, 1_000));
        assert!(is_closure_due(1_000, 1_001));
    }

    #[test]
    fn test_split_and_group_due_closures() {
        let pending = vec![
            PendingOutgoingClosure {
                node: NODE,
                destination: PEER_A,
                closure_time: 100,
            },
            PendingOutgoingClosure {
                node: PEER_C,
                destination: PEER_A,
                closure_time: 150,
            },
            PendingOutgoingClosure {
                node: NODE,
                destination: PEER_B,
                closure_time: 200,
            },
            PendingOutgoingClosure {
                node: NODE,
                destination: PEER_C,
                closure_time: 120,
            },
        ];
        let (due, not_due) = split_due_closures(pending, 150);
        assert_eq!(group_destinations_by_node(&due), vec![(NODE, vec![PEER_A, PEER_C])]);
        assert_eq!(
            group_destinations_by_node(&not_due),
            vec![(PEER_C, vec![PEER_A]), (NODE, vec![PEER_B])]
        );
    }

    #[test]
    fn test_parse_blokli_address_with_and_without_prefix() {
        let expected = PEER_A;
        assert_eq!(parse_blokli_address(&hex::encode(PEER_A)).unwrap(), expected);
        assert_eq!(parse_blokli_address(&format!("{PEER_A:?}")).unwrap(), expected);
        assert!(parse_blokli_address("not-an-address").is_err());
    }

    #[test]
    fn test_new_blokli_client_rejects_invalid_url() {
        assert!(new_blokli_client("https://blokli.jura.hoprnet.link").is_ok());
        assert!(matches!(
            new_blokli_client("not a url"),
            Err(HelperErrors::ParseError(_))
        ));
    }

    #[test]
    fn test_merge_unique_addresses() {
        let merged = merge_unique_addresses([&[PEER_B, PEER_A][..], &[PEER_A, PEER_C][..], &[][..]]);
        assert_eq!(merged, vec![PEER_A, PEER_B, PEER_C]);
    }

    #[tokio::test]
    async fn test_get_node_key_id() -> anyhow::Result<()> {
        let client = test_client();
        assert_eq!(get_node_key_id(&client, NODE).await?, Some(1));
        assert_eq!(
            get_node_key_id(&client, address!("9999999999999999999999999999999999999999")).await?,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_get_incoming_channel_counterparties_excludes_closed() -> anyhow::Result<()> {
        let client = test_client();
        let mut cache = HashMap::new();
        let sources = get_channel_counterparties(
            &client,
            1,
            ChannelDirection::Incoming,
            &[ChannelStatus::Open, ChannelStatus::PendingToClose],
            &mut cache,
        )
        .await?;
        assert_eq!(sources, vec![PEER_A, PEER_B]);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_outgoing_channel_counterparties_by_status() -> anyhow::Result<()> {
        let client = test_client();
        let mut cache = HashMap::new();
        let open = get_channel_counterparties(
            &client,
            1,
            ChannelDirection::Outgoing,
            &[ChannelStatus::Open],
            &mut cache,
        )
        .await?;
        assert_eq!(open, vec![PEER_A, PEER_B]);

        let pending = get_channel_counterparties(
            &client,
            1,
            ChannelDirection::Outgoing,
            &[ChannelStatus::PendingToClose],
            &mut cache,
        )
        .await?;
        assert_eq!(pending, vec![PEER_C]);

        let none = get_channel_counterparties(&client, 1, ChannelDirection::Outgoing, &[], &mut cache).await?;
        assert!(none.is_empty());
        Ok(())
    }

    /// Close all the channels of a node through its Safe, on a HoprChannels contract with a short
    /// `NOTICE_PERIOD_CHANNEL_CLOSURE`, deployed on Anvil:
    /// - PEER_A -> node: open, closed as incoming channel
    /// - node -> PEER_A: open, its closure is initiated then finalized
    /// - node -> PEER_B: already pending to close, finalized
    /// - node -> PEER_C: indexed as open by Blokli but does not exist on-chain, skipped
    #[tokio::test]
    async fn test_close_all_channels_of_nodes_on_anvil_with_short_notice_period() -> anyhow::Result<()> {
        const NOTICE_PERIOD: u32 = 5;
        let channel_balance = U96::from(1_000_000_000_000_000_000_u128);
        let one_ether = U256::from(1_000_000_000_000_000_000_u128);

        let anvil = create_anvil(None);
        let deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let deployer_address = a2h(deployer.public().to_address());
        let client = create_rpc_client_to_anvil(&anvil, &deployer);
        let instances =
            ContractInstances::deploy_for_testing(client.clone(), deployer_address, anvil.addresses()[1]).await?;
        ContractInstances::deploy_multicall3(client.clone(), anvil.addresses()[1]).await?;
        ContractInstances::deploy_safe_suites(client.clone(), anvil.addresses()[1]).await?;

        // HoprChannels contract with a short notice period
        let channels = HoprChannels::deploy(
            client.clone(),
            *instances.token.address(),
            NOTICE_PERIOD,
            *instances.safe_registry.address(),
        )
        .await?;
        assert_eq!(
            get_notice_period_channel_closure(channels.clone()).await?,
            u64::from(NOTICE_PERIOD)
        );

        // a node with a Safe owned by the deployer, and peers without Safe
        let node_key = ChainKeypair::random();
        let node = a2h(node_key.public().to_address());
        let peer_a_key = ChainKeypair::random();
        let peer_a = a2h(peer_a_key.public().to_address());
        let peer_b = a2h(ChainKeypair::random().public().to_address());
        let peer_c = a2h(ChainKeypair::random().public().to_address());
        let (safe, _) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *channels.address(),
            *instances.token.address(),
            vec![node],
            vec![deployer_address],
            U256::ONE,
            None,
        )
        .await?;
        transfer_native_tokens(client.clone(), vec![node, peer_a], vec![one_ether, one_ether]).await?;
        transfer_or_mint_tokens(
            instances.token.clone(),
            vec![*safe.address(), peer_a],
            vec![U256::from(10) * one_ether, U256::from(10) * one_ether],
        )
        .await?;
        let node_client = create_rpc_client_to_anvil(&anvil, &node_key);
        HoprNodeSafeRegistry::new(*instances.safe_registry.address(), node_client)
            .registerSafeByNode(*safe.address())
            .send()
            .await?
            .watch()
            .await?;

        // the Safe opens node -> PEER_A and node -> PEER_B, then initiates the closure of node -> PEER_B
        let safe_tx = |data: Bytes| MultisendTransaction {
            encoded_data: data,
            tx_operation: SafeTxOperation::Call,
            to: *channels.address(),
            value: U256::ZERO,
        };
        let (chain_id, nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;
        send_multisend_safe_transaction_with_threshold_one(
            safe.clone(),
            deployer.clone(),
            SAFE_MULTISEND_ADDRESS,
            vec![
                safe_tx(
                    fundChannelSafeCall {
                        selfAddress: node,
                        account: peer_a,
                        amount: channel_balance,
                    }
                    .abi_encode()
                    .into(),
                ),
                safe_tx(
                    fundChannelSafeCall {
                        selfAddress: node,
                        account: peer_b,
                        amount: channel_balance,
                    }
                    .abi_encode()
                    .into(),
                ),
                safe_tx(ChannelClosureAction::InitiateOutgoingClosure.encode(node, peer_b)),
            ],
            chain_id,
            nonce,
        )
        .await?;

        // PEER_A opens PEER_A -> node
        let peer_a_client = create_rpc_client_to_anvil(&anvil, &peer_a_key);
        HoprToken::new(*instances.token.address(), peer_a_client.clone())
            .approve(*channels.address(), U256::from(channel_balance))
            .send()
            .await?
            .watch()
            .await?;
        HoprChannels::new(*channels.address(), peer_a_client)
            .fundChannel(node, channel_balance)
            .send()
            .await?
            .watch()
            .await?;

        let status_of = |source: Address, destination: Address| {
            let channels = channels.clone();
            async move {
                anyhow::Ok(
                    channels
                        .channels(get_channel_id(source, destination))
                        .call()
                        .await?
                        .status,
                )
            }
        };
        assert_eq!(status_of(peer_a, node).await?, ONCHAIN_CHANNEL_STATUS_OPEN);
        assert_eq!(status_of(node, peer_a).await?, ONCHAIN_CHANNEL_STATUS_OPEN);
        assert_eq!(status_of(node, peer_b).await?, ONCHAIN_CHANNEL_STATUS_PENDING_TO_CLOSE);

        // Blokli: node (1), PEER_A (2), PEER_B (3), PEER_C (4)
        let blokli = blokli_client_with(
            &[node, peer_a, peer_b, peer_c],
            &[
                (2, 1, ChannelStatus::Open),
                (1, 2, ChannelStatus::Open),
                (1, 3, ChannelStatus::PendingToClose),
                (1, 4, ChannelStatus::Open),
            ],
        );

        let safe_tokens_before = instances.token.balanceOf(*safe.address()).call().await?;
        let peer_a_tokens_before = instances.token.balanceOf(peer_a).call().await?;

        // from now on, Anvil mines a block every second (instead of one block per transaction), so that the chain
        // time moves on while waiting for the notice period, as on a live chain
        client
            .raw_request::<_, serde_json::Value>("evm_setIntervalMining".into(), [1])
            .await?;

        // batches of one channel, to send several Safe transactions per step
        let summary = close_all_channels_of_nodes(
            &blokli,
            &deployer,
            channels.clone(),
            &[NodeWithSafe {
                node,
                safe: *safe.address(),
            }],
            1,
            Duration::from_secs(1),
        )
        .await?;

        assert_eq!(
            summary,
            ChannelClosureSummary {
                incoming_closed: 1,
                outgoing_initiated: 1,
                outgoing_finalized: 2,
            }
        );
        for (source, destination) in [(peer_a, node), (node, peer_a), (node, peer_b)] {
            assert_eq!(
                status_of(source, destination).await?,
                ONCHAIN_CHANNEL_STATUS_CLOSED,
                "channel {source:?} -> {destination:?} must be closed"
            );
        }
        // balances of outgoing channels return to the Safe, the balance of the incoming one to PEER_A
        assert_eq!(
            instances.token.balanceOf(*safe.address()).call().await?,
            safe_tokens_before + U256::from(2) * U256::from(channel_balance)
        );
        assert_eq!(
            instances.token.balanceOf(peer_a).call().await?,
            peer_a_tokens_before + U256::from(channel_balance)
        );

        // nothing left to close
        let summary = close_all_channels_of_nodes(
            &blokli,
            &deployer,
            channels,
            &[NodeWithSafe {
                node,
                safe: *safe.address(),
            }],
            1,
            Duration::from_secs(1),
        )
        .await?;
        assert_eq!(summary, ChannelClosureSummary::default());
        Ok(())
    }
}
