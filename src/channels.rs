//! This module contains helpers to read the channels of HOPR nodes from a Blokli indexer,
//! via [`blokli_client`]. Channels are identified by the Blokli key ids of their endpoints,
//! which are resolved to chain addresses.
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};

use blokli_client::{
    AccountSelector, BlokliClient, BlokliClientConfig, BlokliQueryClient, ChannelFilter, ChannelSelector, KeyId,
    types::ChannelStatus,
};
use hopr_bindings::exports::alloy::primitives::Address;
use tracing::debug;

use crate::utils::HelperErrors;

/// Direction of a channel, seen from the node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDirection {
    /// The node is the destination of the channel; the counterparty is the source
    Incoming,
    /// The node is the source of the channel; the counterparty is the destination
    Outgoing,
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
