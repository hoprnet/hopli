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
};

use blokli_client::{
    AccountSelector, BlokliClient, BlokliClientConfig, BlokliQueryClient, ChannelFilter, ChannelSelector, KeyId,
    types::ChannelStatus,
};
use hopr_bindings::{
    exports::alloy::{
        primitives::{Address, B256, Bytes, keccak256},
        sol_types::{SolCall, SolValue},
    },
    hopr_channels::HoprChannels::{
        closeIncomingChannelSafeCall, finalizeOutgoingChannelClosureSafeCall, initiateOutgoingChannelClosureSafeCall,
    },
};
use tracing::debug;

use crate::utils::HelperErrors;

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

#[cfg(test)]
mod tests {
    use blokli_client::{
        BlokliTestClient, BlokliTestState, NopStateMutator,
        types::{Account, Channel, DateTime, TokenValueString, Uint64},
    };
    use hopr_bindings::exports::alloy::primitives::address;

    use super::*;

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

    /// NODE (1) <-> PEER_A (2), PEER_B (3), PEER_C (4)
    fn test_client() -> BlokliTestClient<NopStateMutator> {
        let mut state = BlokliTestState::default();
        state.accounts.clear();
        state.channels.clear();
        for (key_id, address) in [(1, NODE), (2, PEER_A), (3, PEER_B), (4, PEER_C)] {
            state.accounts.insert(key_id, account(key_id, address));
        }
        let channels = [
            // incoming
            channel(2, 1, ChannelStatus::Open),
            channel(3, 1, ChannelStatus::PendingToClose),
            channel(4, 1, ChannelStatus::Closed),
            // outgoing
            channel(1, 2, ChannelStatus::Open),
            channel(1, 3, ChannelStatus::Open),
            channel(1, 4, ChannelStatus::PendingToClose),
        ];
        for c in channels {
            state.channels.insert(c.concrete_channel_id.clone(), c);
        }
        BlokliTestClient::new(state, NopStateMutator)
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
}
