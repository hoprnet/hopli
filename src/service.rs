//! This module contains arguments and functions to interact with `HoprServiceRegistry`, the
//! permissionless on-chain registry of the services that HOPR nodes offer.
//!
//! The commands fall into three groups, which differ in who has to sign them:
//!
//! - **Entry writes** (`register`, `update`, `deregister`). The registry accepts these only from
//!   the Safe bound to the node in the node-safe registry, so they are sent as a Safe transaction
//!   rather than from an EOA. `register` and `update` cost the type's burn in wxHOPR, so they are
//!   batched behind an exact `approve` in the same MultiSend. `deregister` is free and needs no
//!   approval, so that a bound node can always delist itself.
//! - **Type-owner writes** (`register-type`, `set-requirement`, `set-registration-burn`,
//!   `set-update-burn`, `transfer-type-ownership`) and **admin/manager writes** (`set-fee`,
//!   `set-node-safe-registry`, `recover-tokens`). These come straight from the caller's key.
//! - **Reads** (`get`, `list`, `types`). Plain view calls. Both list views are paginated and their
//!   order is unstable, so a scan pins every one of its pages to a single block.
//!
//! Some sample commands:
//! - Register a node under a service type, through the node's Safe:
//! ```shell
//! hopli service register \
//!     --network anvil-localhost \
//!     --service-type gvpn:exit \
//!     --node-address 0x0123... \
//!     --metadata '{"endpoint":"https://exit.example"}' \
//!     --private-key <SAFE_OWNER_PRIVATE_KEY> \
//!     --provider-url "http://localhost:8545"
//! ```
//! - Read a single entry:
//! ```shell
//! hopli service get \
//!     --network anvil-localhost \
//!     --service-type gvpn:exit \
//!     --node-address 0x0123... \
//!     --provider-url "http://localhost:8545"
//! ```
//! - Claim a service type and become its owner:
//! ```shell
//! hopli service register-type \
//!     --network anvil-localhost \
//!     --service-type gvpn:exit \
//!     --registration-burn 1 \
//!     --update-burn 0.5 \
//!     --private-key <PRIVATE_KEY> \
//!     --provider-url "http://localhost:8545"
//! ```
use std::{path::PathBuf, str::FromStr, sync::Arc};

use clap::{Parser, builder::ValueParser};
use hopr_bindings::{
    ContractAddresses,
    constants::SAFE_MULTISEND_ADDRESS,
    exports::alloy::{
        eips::BlockId,
        primitives::{Address, B256, U256, utils::parse_units},
        providers::Provider,
        rpc::types::TransactionRequest,
    },
    hopr_node_safe_registry::HoprNodeSafeRegistry,
    hopr_service_registry::HoprServiceRegistry::{self, Entry},
};
use hopr_types::{
    crypto::keypairs::ChainKeypair,
    internal::prelude::{ServiceMetadata, ServiceType},
    primitive::prelude::ToHex,
};
use tracing::info;

use crate::{
    environment_config::{NetworkProviderArgs, RpcProvider},
    key_pair::{ArgEnvReader, PrivateKeyArgs},
    methods::{
        MultisendTransaction, SafeSingleton, SafeTxOperation, get_chain_id_and_safe_nonce,
        send_multisend_safe_transaction_with_threshold_one,
    },
    payloads::{
        approve_hopr_token_payload, recover_service_registry_tokens_payload, register_service_type_payload,
        self_deregister_service_payload, self_register_service_payload, self_update_service_payload,
        set_node_safe_registry_payload, set_self_registration_burn_payload, set_self_update_burn_payload,
        set_service_type_requirement_payload, set_type_registration_fee_payload,
        transfer_service_type_ownership_payload,
    },
    utils::{Cmd, HelperErrors},
};

/// Number of entries or types read per page when a list command scans the registry.
const DEFAULT_PAGE_SIZE: u64 = 100;

/// Parses a service type from its ASCII name, or from a full `0x` prefixed 32-byte id.
///
/// The `0x` prefix decides which reading applies, rather than the hex reading being a fallback
/// for names that fail to parse. Both readings accept a short input such as `0xab`, and taking it
/// as the name "0xab" would silently register under a different type than the caller meant.
fn parse_service_type(s: &str) -> Result<ServiceType, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        ServiceType::from_hex(s).map_err(|e| format!("invalid 32-byte service type id: {e}"))
    } else {
        ServiceType::from_str(s).map_err(|e| format!("invalid service type name: {e}"))
    }
}

/// Parses entry metadata from the bytes of the given string, enforcing the registry's length cap.
fn parse_service_metadata(s: &str) -> Result<ServiceMetadata, String> {
    ServiceMetadata::try_from(s.as_bytes().to_vec()).map_err(|e| format!("invalid service metadata: {e}"))
}

/// Parses a wxHOPR amount given in whole tokens, for example `1.5`, into wei.
fn parse_hopr_amount(s: &str) -> Result<U256, String> {
    let amount: U256 = parse_units(s, "ether")
        .map_err(|e| format!("invalid wxHOPR amount: {e}"))?
        .into();
    Ok(amount)
}

/// CLI arguments for `hopli service`
#[derive(Clone, Debug, Parser)]
pub enum ServiceSubcommands {
    /// Register a node under a service type, from the node's bound Safe
    #[command(visible_alias = "r")]
    Register {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Node whose entry is written
        #[clap(help = "Ethereum address of the node", long, short = 'o')]
        node_address: Address,

        /// Safe bound to the node; read from the node-safe registry when omitted
        #[clap(
            help = "Safe that sends the transaction; defaults to the safe bound to the node",
            long,
            short = 's'
        )]
        safe_address: Option<Address>,

        /// Entry metadata, given inline
        #[command(flatten)]
        metadata: MetadataArgs,

        /// Access to the private key of an owner of the node's Safe
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Replace the metadata of an existing entry, from the node's bound Safe
    #[command(visible_alias = "u")]
    Update {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Node whose entry is written
        #[clap(help = "Ethereum address of the node", long, short = 'o')]
        node_address: Address,

        /// Safe bound to the node; read from the node-safe registry when omitted
        #[clap(
            help = "Safe that sends the transaction; defaults to the safe bound to the node",
            long,
            short = 's'
        )]
        safe_address: Option<Address>,

        /// New entry metadata
        #[command(flatten)]
        metadata: MetadataArgs,

        /// Access to the private key of an owner of the node's Safe
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Remove an entry, from the node's bound Safe. Free, and never gated by the type's policy
    #[command(visible_alias = "d")]
    Deregister {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Node whose entry is removed
        #[clap(help = "Ethereum address of the node", long, short = 'o')]
        node_address: Address,

        /// Safe bound to the node; read from the node-safe registry when omitted
        #[clap(
            help = "Safe that sends the transaction; defaults to the safe bound to the node",
            long,
            short = 's'
        )]
        safe_address: Option<Address>,

        /// Access to the private key of an owner of the node's Safe
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Read a single entry
    #[command(visible_alias = "g")]
    Get {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Node to look up
        #[clap(help = "Ethereum address of the node", long, short = 'o')]
        node_address: Address,
    },

    /// List the entries registered under a service type
    #[command(visible_alias = "l")]
    List {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Pagination arguments
        #[command(flatten)]
        pagination: PaginationArgs,
    },

    /// List the registered service types
    Types {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Pagination arguments
        #[command(flatten)]
        pagination: PaginationArgs,
    },

    /// Claim a service type and become its owner. Costs the global type registration fee
    RegisterType {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Requirement contract gating registration, or the zero address for an open type
        #[clap(
            help = "Requirement contract address; the zero address leaves the type open",
            long,
            default_value_t = Address::ZERO
        )]
        requirement: Address,

        /// Burn charged for registering an entry, in whole wxHOPR
        #[clap(
            help = "Burn charged per registration, in whole wxHOPR",
            long,
            default_value = "0",
            value_parser = ValueParser::new(parse_hopr_amount)
        )]
        registration_burn: U256,

        /// Burn charged for updating an entry, in whole wxHOPR
        #[clap(
            help = "Burn charged per update, in whole wxHOPR",
            long,
            default_value = "0",
            value_parser = ValueParser::new(parse_hopr_amount)
        )]
        update_burn: U256,

        /// Access to the private key of the caller, who becomes the type owner
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Point a service type at a requirement contract, as its owner
    SetRequirement {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// Requirement contract, or the zero address to open the type up
        #[clap(
            help = "Requirement contract address; the zero address opens the type up",
            long,
            default_value_t = Address::ZERO
        )]
        requirement: Address,

        /// Access to the private key of the type owner
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Set the registration burn of a service type, as its owner
    SetRegistrationBurn {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// New burn, in whole wxHOPR
        #[clap(
            help = "New registration burn, in whole wxHOPR",
            long,
            short = 'a',
            value_parser = ValueParser::new(parse_hopr_amount)
        )]
        amount: U256,

        /// Access to the private key of the type owner
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Set the update burn of a service type, as its owner
    SetUpdateBurn {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// New burn, in whole wxHOPR
        #[clap(
            help = "New update burn, in whole wxHOPR",
            long,
            short = 'a',
            value_parser = ValueParser::new(parse_hopr_amount)
        )]
        amount: U256,

        /// Access to the private key of the type owner
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Hand ownership of a service type to another address, as its owner
    TransferTypeOwnership {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Service type, either an ASCII name such as `gvpn:exit` or a `0x` prefixed 32-byte id
        #[clap(
            help = "Service type, e.g. gvpn:exit or a 0x-prefixed 32-byte id",
            long,
            short = 't',
            value_parser = ValueParser::new(parse_service_type)
        )]
        service_type: ServiceType,

        /// New owner of the type
        #[clap(
            help = "New owner of the service type",
            long,
            required_unless_present = "abandon",
            conflicts_with = "abandon"
        )]
        new_owner: Option<Address>,

        /// Abandon the type instead, leaving it without an owner forever
        #[clap(
            help = "Abandon the type by transferring it to the zero address. One way and unrecoverable",
            long
        )]
        abandon: bool,

        /// Access to the private key of the type owner
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Set the global service type registration fee, as a manager
    SetFee {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// New fee, in whole wxHOPR
        #[clap(
            help = "New type registration fee, in whole wxHOPR",
            long,
            short = 'a',
            value_parser = ValueParser::new(parse_hopr_amount)
        )]
        amount: U256,

        /// Access to the private key of a manager of the service registry
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Repoint the registry at another node-safe registry, as the admin
    SetNodeSafeRegistry {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// New node-safe registry
        #[clap(help = "Address of the new node-safe registry", long)]
        node_safe_registry: Address,

        /// Node used to probe the new registry
        #[clap(help = "Node whose binding is used to probe the new registry", long)]
        probe_node: Address,

        /// Safe that the probe node must resolve to in the new registry
        #[clap(help = "Safe that the probe node must resolve to", long)]
        expected_safe: Address,

        /// Access to the private key of the admin of the service registry
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },

    /// Sweep tokens that were sent to the registry by mistake, as a manager
    RecoverTokens {
        /// Network name, contracts config file root, and customized provider, if available
        #[command(flatten)]
        network_provider: NetworkProviderArgs,

        /// Token to sweep
        #[clap(help = "Address of the token to recover", long)]
        token: Address,

        /// Recipient of the swept tokens
        #[clap(help = "Address that receives the recovered tokens", long)]
        recipient: Address,

        /// Access to the private key of a manager of the service registry
        #[command(flatten)]
        private_key: PrivateKeyArgs,
    },
}

/// Entry metadata, given either inline or as the contents of a file.
///
/// The file form is the only way to pass metadata that is not valid UTF-8.
#[derive(Clone, Debug, Parser)]
pub struct MetadataArgs {
    /// Metadata bytes, given as a string
    #[clap(
        help = "Entry metadata, as a string of at most 2048 bytes",
        long,
        short = 'm',
        value_parser = ValueParser::new(parse_service_metadata)
    )]
    pub metadata: Option<ServiceMetadata>,

    /// File holding the metadata bytes
    #[clap(
        help = "File holding the entry metadata, at most 2048 bytes",
        long,
        conflicts_with = "metadata"
    )]
    pub metadata_file: Option<PathBuf>,
}

impl MetadataArgs {
    /// Resolves the metadata, reading the file when one was given.
    ///
    /// Absent metadata is an empty entry, which the registry accepts: the schema of the bytes
    /// belongs to the service type, and a type may well define no metadata at all.
    pub fn read(&self) -> Result<ServiceMetadata, HelperErrors> {
        match (&self.metadata, &self.metadata_file) {
            (Some(metadata), _) => Ok(metadata.clone()),
            (None, Some(path)) => {
                let bytes = std::fs::read(path).map_err(HelperErrors::UnableToReadFromPath)?;
                ServiceMetadata::try_from(bytes)
                    .map_err(|e| HelperErrors::ParseError(format!("invalid service metadata in {path:?}: {e}")))
            }
            (None, None) => Ok(ServiceMetadata::default()),
        }
    }
}

/// Where a paginated scan starts and how large its pages are.
#[derive(Clone, Copy, Debug, Parser)]
pub struct PaginationArgs {
    /// Index of the first item read
    #[clap(help = "Index of the first item to read", long, default_value_t = 0)]
    pub offset: u64,

    /// Number of items read per page
    #[clap(help = "Number of items read per page", long, default_value_t = DEFAULT_PAGE_SIZE)]
    pub page_size: u64,
}

impl Default for PaginationArgs {
    fn default() -> Self {
        Self {
            offset: 0,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

/// The `bytes32` service type id as the `HoprServiceRegistry` ABI expects it.
fn service_type_id(service_type: &ServiceType) -> B256 {
    B256::from(service_type.as_encoded())
}

/// Resolves the contract addresses of the selected network, rejecting networks without a registry.
///
/// A network with no service registry deployment carries the zero address, and dialling it would
/// send calls to an account with no code that silently returns empty data.
fn addresses_with_service_registry(network_provider: &NetworkProviderArgs) -> Result<ContractAddresses, HelperErrors> {
    let addresses = network_provider.get_network_details_from_name()?.addresses;
    if addresses.service_registry.is_zero() {
        return Err(HelperErrors::ContractNotDeployed(format!(
            "HoprServiceRegistry is not deployed on network {}",
            network_provider.network
        )));
    }
    Ok(addresses)
}

/// Resolves the Safe bound to `node`, the only sender the registry accepts for that node's entries.
async fn bound_safe_of_node<P: Provider>(
    node_safe_registry_address: Address,
    node: Address,
    provider: P,
) -> Result<Address, HelperErrors> {
    let node_safe_registry = HoprNodeSafeRegistry::new(node_safe_registry_address, provider);
    let safe = node_safe_registry
        .nodeToSafe(node)
        .call()
        .await
        .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read the safe bound to node {node}: {e}")))?;

    if safe.is_zero() {
        return Err(HelperErrors::MissingParameter(format!(
            "node {node} is not bound to a safe in the node-safe registry; pass --safe-address to override"
        )));
    }
    Ok(safe)
}

/// Turns a prepared request into one `Call` leg of a Safe MultiSend.
fn multisend_leg(tx: TransactionRequest) -> Result<MultisendTransaction, HelperErrors> {
    let to = tx
        .to
        .and_then(|kind| kind.to().copied())
        .ok_or_else(|| HelperErrors::MissingParameter("transaction payload has no target address".into()))?;

    Ok(MultisendTransaction {
        encoded_data: tx.input.input().cloned().unwrap_or_default(),
        tx_operation: SafeTxOperation::Call,
        to,
        value: U256::ZERO,
    })
}

/// Sends `legs` as one Safe MultiSend from `safe_address`, in the given order.
async fn send_from_safe(
    rpc_provider: Arc<RpcProvider>,
    safe_address: Address,
    signer_key: ChainKeypair,
    legs: Vec<TransactionRequest>,
) -> Result<(), HelperErrors> {
    let safe = SafeSingleton::new(safe_address, rpc_provider);
    let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;
    let multisend_txns = legs.into_iter().map(multisend_leg).collect::<Result<Vec<_>, _>>()?;

    send_multisend_safe_transaction_with_threshold_one(
        safe,
        signer_key,
        SAFE_MULTISEND_ADDRESS,
        multisend_txns,
        chain_id,
        safe_nonce,
    )
    .await
}

/// Sends `tx` from the caller's own key and waits for it to be mined.
async fn send_from_caller(rpc_provider: Arc<RpcProvider>, tx: TransactionRequest) -> Result<(), HelperErrors> {
    rpc_provider.send_transaction(tx).await?.watch().await?;
    Ok(())
}

impl ServiceSubcommands {
    /// Registers `node` under `service_type`, paying the type's registration burn.
    ///
    /// The approval and the registration travel in one MultiSend, approval first: the registry
    /// pulls the burn inside `selfRegister`, so a separate approval transaction would leave a
    /// window in which the allowance sits unused on chain.
    pub async fn execute_register(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        node_address: Address,
        safe_address: Option<Address>,
        metadata: ServiceMetadata,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        let safe = match safe_address {
            Some(safe) => safe,
            None => bound_safe_of_node(addresses.node_safe_registry, node_address, rpc_provider.clone()).await?,
        };

        let registry = HoprServiceRegistry::new(addresses.service_registry, rpc_provider.clone());
        let burn = registry
            .selfRegistrationBurn(service_type_id(&service_type))
            .call()
            .await
            .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read the registration burn: {e}")))?;

        info!(
            %service_type, node = %node_address, safe = %safe, burn = %burn,
            metadata_len = metadata.as_ref().len(),
            "Registering a service entry through the node's safe"
        );

        let mut legs = Vec::new();
        if !burn.is_zero() {
            legs.push(approve_hopr_token_payload(
                addresses.token,
                addresses.service_registry,
                burn,
            ));
        }
        legs.push(self_register_service_payload(
            addresses.service_registry,
            &service_type,
            node_address,
            &metadata,
        ));

        send_from_safe(rpc_provider, safe, signer_private_key, legs).await
    }

    /// Replaces the metadata of the entry of `node` under `service_type`.
    ///
    /// Batched the same way as [`ServiceSubcommands::execute_register`], against the update burn.
    pub async fn execute_update(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        node_address: Address,
        safe_address: Option<Address>,
        metadata: ServiceMetadata,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        let safe = match safe_address {
            Some(safe) => safe,
            None => bound_safe_of_node(addresses.node_safe_registry, node_address, rpc_provider.clone()).await?,
        };

        let registry = HoprServiceRegistry::new(addresses.service_registry, rpc_provider.clone());
        let burn = registry
            .selfUpdateBurn(service_type_id(&service_type))
            .call()
            .await
            .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read the update burn: {e}")))?;

        info!(
            %service_type, node = %node_address, safe = %safe, burn = %burn,
            metadata_len = metadata.as_ref().len(),
            "Updating a service entry through the node's safe"
        );

        let mut legs = Vec::new();
        if !burn.is_zero() {
            legs.push(approve_hopr_token_payload(
                addresses.token,
                addresses.service_registry,
                burn,
            ));
        }
        legs.push(self_update_service_payload(
            addresses.service_registry,
            &service_type,
            node_address,
            &metadata,
        ));

        send_from_safe(rpc_provider, safe, signer_private_key, legs).await
    }

    /// Removes the entry of `node` under `service_type`.
    ///
    /// No approval leg: deregistration is free by design, so that a bound node can always delist
    /// itself even when it holds no wxHOPR at all.
    pub async fn execute_deregister(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        node_address: Address,
        safe_address: Option<Address>,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        let safe = match safe_address {
            Some(safe) => safe,
            None => bound_safe_of_node(addresses.node_safe_registry, node_address, rpc_provider.clone()).await?,
        };

        info!(
            %service_type, node = %node_address, safe = %safe,
            "Deregistering a service entry through the node's safe"
        );

        let leg = self_deregister_service_payload(addresses.service_registry, &service_type, node_address);
        send_from_safe(rpc_provider, safe, signer_private_key, vec![leg]).await
    }

    /// Reads the entry of `node` under `service_type`, if it has one.
    ///
    /// The registry returns a zeroed entry for an absent one, which this reports as `None`.
    pub async fn execute_get_entry(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        node_address: Address,
    ) -> Result<Option<Entry>, HelperErrors> {
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_without_signer().await?;
        let registry = HoprServiceRegistry::new(addresses.service_registry, rpc_provider.clone());

        let entry = registry
            .getEntry(service_type_id(&service_type), node_address)
            .call()
            .await
            .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read the service entry: {e}")))?;

        if entry.registeredAt.is_zero() {
            info!(%service_type, node = %node_address, "No service entry registered");
            return Ok(None);
        }

        info!(
            %service_type,
            node = %node_address,
            registered_at = %entry.registeredAt,
            updated_at = %entry.updatedAt,
            metadata = %hex::encode(&entry.metadata),
            "Service entry"
        );
        Ok(Some(entry))
    }

    /// Lists the entries registered under `service_type`.
    ///
    /// Every page is read at the same block: deregistration swap-and-pops the entry list, so a
    /// scan spread over several blocks can miss an entry or return one twice.
    pub async fn execute_list_entries(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        pagination: PaginationArgs,
    ) -> Result<Vec<(Address, Entry)>, HelperErrors> {
        let page_size = pagination.checked_page_size()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_without_signer().await?;
        let registry = HoprServiceRegistry::new(addresses.service_registry, rpc_provider.clone());

        let block = BlockId::number(rpc_provider.get_block_number().await?);
        let service_type_id = service_type_id(&service_type);

        let mut entries: Vec<(Address, Entry)> = Vec::new();
        let mut cursor = pagination.offset;
        loop {
            let page = registry
                .getEntriesPaginated(service_type_id, U256::from(cursor), U256::from(page_size))
                .block(block)
                .call()
                .await
                .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read a page of entries: {e}")))?;

            let page_len = page._0.len();
            entries.extend(page._0.into_iter().zip(page._1));

            if (page_len as u64) < page_size {
                break;
            }
            cursor += page_size;
        }

        info!(
            %service_type,
            count = entries.len(),
            block = %block,
            "Listed the entries of a service type"
        );
        for (node, entry) in &entries {
            info!(
                %service_type,
                node = %node,
                registered_at = %entry.registeredAt,
                updated_at = %entry.updatedAt,
                metadata = %hex::encode(&entry.metadata),
                "Service entry"
            );
        }
        Ok(entries)
    }

    /// Lists the registered service types.
    ///
    /// Pinned to a single block for the same reason as [`ServiceSubcommands::execute_list_entries`].
    pub async fn execute_list_types(
        network_provider: NetworkProviderArgs,
        pagination: PaginationArgs,
    ) -> Result<Vec<ServiceType>, HelperErrors> {
        let page_size = pagination.checked_page_size()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_without_signer().await?;
        let registry = HoprServiceRegistry::new(addresses.service_registry, rpc_provider.clone());

        let block = BlockId::number(rpc_provider.get_block_number().await?);

        let mut ids: Vec<B256> = Vec::new();
        let mut cursor = pagination.offset;
        loop {
            let page = registry
                .getServiceTypesPaginated(U256::from(cursor), U256::from(page_size))
                .block(block)
                .call()
                .await
                .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read a page of service types: {e}")))?;

            let page_len = page.len();
            ids.extend(page);

            if (page_len as u64) < page_size {
                break;
            }
            cursor += page_size;
        }

        let service_types = ids
            .into_iter()
            .map(|id| {
                ServiceType::try_from(id).map_err(|e| HelperErrors::ParseError(format!("invalid service type id: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        info!(count = service_types.len(), block = %block, "Listed the service types");
        for service_type in &service_types {
            info!(service_type = %service_type, id = %service_type.to_hex(), "Service type");
        }
        Ok(service_types)
    }

    /// Claims `service_type` for the caller, paying the global type registration fee.
    ///
    /// The approval is for exactly the fee read a moment earlier, so a fee raised in between
    /// makes the registration revert on the allowance instead of overpaying.
    pub async fn execute_register_type(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        requirement: Address,
        registration_burn: U256,
        update_burn: U256,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        let registry = HoprServiceRegistry::new(addresses.service_registry, rpc_provider.clone());
        let fee = registry
            .typeRegistrationFee()
            .call()
            .await
            .map_err(|e| HelperErrors::MiddlewareError(format!("failed to read the type registration fee: {e}")))?;

        info!(
            %service_type, %requirement, %registration_burn, %update_burn, %fee,
            "Registering a service type"
        );

        if !fee.is_zero() {
            send_from_caller(
                rpc_provider.clone(),
                approve_hopr_token_payload(addresses.token, addresses.service_registry, fee),
            )
            .await?;
        }

        send_from_caller(
            rpc_provider,
            register_service_type_payload(
                addresses.service_registry,
                &service_type,
                requirement,
                registration_burn,
                update_burn,
            ),
        )
        .await
    }

    /// Points `service_type` at `requirement`, or opens it up with the zero address.
    pub async fn execute_set_requirement(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        requirement: Address,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        info!(%service_type, %requirement, "Setting the requirement of a service type");
        send_from_caller(
            rpc_provider,
            set_service_type_requirement_payload(addresses.service_registry, &service_type, requirement),
        )
        .await
    }

    /// Sets the registration burn of `service_type`.
    pub async fn execute_set_registration_burn(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        amount: U256,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        info!(%service_type, %amount, "Setting the registration burn of a service type");
        send_from_caller(
            rpc_provider,
            set_self_registration_burn_payload(addresses.service_registry, &service_type, amount),
        )
        .await
    }

    /// Sets the update burn of `service_type`.
    pub async fn execute_set_update_burn(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        amount: U256,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        info!(%service_type, %amount, "Setting the update burn of a service type");
        send_from_caller(
            rpc_provider,
            set_self_update_burn_payload(addresses.service_registry, &service_type, amount),
        )
        .await
    }

    /// Hands ownership of `service_type` to `new_owner`, or abandons the type when `abandon` is set.
    ///
    /// Both outcomes are irreversible, and the zero address is only reachable through `abandon`
    /// so that no typo can abandon a type by accident.
    pub async fn execute_transfer_type_ownership(
        network_provider: NetworkProviderArgs,
        service_type: ServiceType,
        new_owner: Option<Address>,
        abandon: bool,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let new_owner = match (new_owner, abandon) {
            (Some(_), true) => {
                return Err(HelperErrors::MissingParameter(
                    "--new-owner and --abandon are mutually exclusive".into(),
                ));
            }
            (Some(owner), false) if owner.is_zero() => {
                return Err(HelperErrors::MissingParameter(
                    "transferring a service type to the zero address abandons it forever; pass --abandon to confirm"
                        .into(),
                ));
            }
            (Some(owner), false) => owner,
            (None, true) => Address::ZERO,
            (None, false) => {
                return Err(HelperErrors::MissingParameter(
                    "either --new-owner or --abandon must be given".into(),
                ));
            }
        };

        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        if abandon {
            info!(%service_type, "Abandoning a service type; this cannot be undone");
        } else {
            info!(%service_type, %new_owner, "Transferring the ownership of a service type");
        }

        send_from_caller(
            rpc_provider,
            transfer_service_type_ownership_payload(addresses.service_registry, &service_type, new_owner),
        )
        .await
    }

    /// Sets the global service type registration fee.
    pub async fn execute_set_fee(
        network_provider: NetworkProviderArgs,
        amount: U256,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        info!(%amount, "Setting the service type registration fee");
        send_from_caller(
            rpc_provider,
            set_type_registration_fee_payload(addresses.service_registry, amount),
        )
        .await
    }

    /// Repoints the registry at another node-safe registry.
    pub async fn execute_set_node_safe_registry(
        network_provider: NetworkProviderArgs,
        node_safe_registry: Address,
        probe_node: Address,
        expected_safe: Address,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        info!(
            %node_safe_registry, %probe_node, %expected_safe,
            "Repointing the service registry at another node-safe registry"
        );
        send_from_caller(
            rpc_provider,
            set_node_safe_registry_payload(
                addresses.service_registry,
                node_safe_registry,
                probe_node,
                expected_safe,
            ),
        )
        .await
    }

    /// Sweeps stray tokens out of the registry.
    pub async fn execute_recover_tokens(
        network_provider: NetworkProviderArgs,
        token: Address,
        recipient: Address,
        private_key: PrivateKeyArgs,
    ) -> Result<(), HelperErrors> {
        let signer_private_key = private_key.read_default()?;
        let addresses = addresses_with_service_registry(&network_provider)?;
        let rpc_provider = network_provider.get_provider_with_signer(&signer_private_key).await?;

        info!(%token, %recipient, "Recovering tokens from the service registry");
        send_from_caller(
            rpc_provider,
            recover_service_registry_tokens_payload(addresses.service_registry, token, recipient),
        )
        .await
    }
}

impl PaginationArgs {
    /// Returns the page size, rejecting zero, which would make a scan loop forever.
    fn checked_page_size(&self) -> Result<u64, HelperErrors> {
        if self.page_size == 0 {
            return Err(HelperErrors::ParseError("--page-size must be greater than zero".into()));
        }
        Ok(self.page_size)
    }
}

impl Cmd for ServiceSubcommands {
    fn run(self) -> Result<(), HelperErrors> {
        Ok(())
    }

    async fn async_run(self) -> Result<(), HelperErrors> {
        match self {
            ServiceSubcommands::Register {
                network_provider,
                service_type,
                node_address,
                safe_address,
                metadata,
                private_key,
            } => {
                let metadata = metadata.read()?;
                ServiceSubcommands::execute_register(
                    network_provider,
                    service_type,
                    node_address,
                    safe_address,
                    metadata,
                    private_key,
                )
                .await
            }
            ServiceSubcommands::Update {
                network_provider,
                service_type,
                node_address,
                safe_address,
                metadata,
                private_key,
            } => {
                let metadata = metadata.read()?;
                ServiceSubcommands::execute_update(
                    network_provider,
                    service_type,
                    node_address,
                    safe_address,
                    metadata,
                    private_key,
                )
                .await
            }
            ServiceSubcommands::Deregister {
                network_provider,
                service_type,
                node_address,
                safe_address,
                private_key,
            } => {
                ServiceSubcommands::execute_deregister(
                    network_provider,
                    service_type,
                    node_address,
                    safe_address,
                    private_key,
                )
                .await
            }
            ServiceSubcommands::Get {
                network_provider,
                service_type,
                node_address,
            } => {
                ServiceSubcommands::execute_get_entry(network_provider, service_type, node_address).await?;
                Ok(())
            }
            ServiceSubcommands::List {
                network_provider,
                service_type,
                pagination,
            } => {
                ServiceSubcommands::execute_list_entries(network_provider, service_type, pagination).await?;
                Ok(())
            }
            ServiceSubcommands::Types {
                network_provider,
                pagination,
            } => {
                ServiceSubcommands::execute_list_types(network_provider, pagination).await?;
                Ok(())
            }
            ServiceSubcommands::RegisterType {
                network_provider,
                service_type,
                requirement,
                registration_burn,
                update_burn,
                private_key,
            } => {
                ServiceSubcommands::execute_register_type(
                    network_provider,
                    service_type,
                    requirement,
                    registration_burn,
                    update_burn,
                    private_key,
                )
                .await
            }
            ServiceSubcommands::SetRequirement {
                network_provider,
                service_type,
                requirement,
                private_key,
            } => {
                ServiceSubcommands::execute_set_requirement(network_provider, service_type, requirement, private_key)
                    .await
            }
            ServiceSubcommands::SetRegistrationBurn {
                network_provider,
                service_type,
                amount,
                private_key,
            } => {
                ServiceSubcommands::execute_set_registration_burn(network_provider, service_type, amount, private_key)
                    .await
            }
            ServiceSubcommands::SetUpdateBurn {
                network_provider,
                service_type,
                amount,
                private_key,
            } => ServiceSubcommands::execute_set_update_burn(network_provider, service_type, amount, private_key).await,
            ServiceSubcommands::TransferTypeOwnership {
                network_provider,
                service_type,
                new_owner,
                abandon,
                private_key,
            } => {
                ServiceSubcommands::execute_transfer_type_ownership(
                    network_provider,
                    service_type,
                    new_owner,
                    abandon,
                    private_key,
                )
                .await
            }
            ServiceSubcommands::SetFee {
                network_provider,
                amount,
                private_key,
            } => ServiceSubcommands::execute_set_fee(network_provider, amount, private_key).await,
            ServiceSubcommands::SetNodeSafeRegistry {
                network_provider,
                node_safe_registry,
                probe_node,
                expected_safe,
                private_key,
            } => {
                ServiceSubcommands::execute_set_node_safe_registry(
                    network_provider,
                    node_safe_registry,
                    probe_node,
                    expected_safe,
                    private_key,
                )
                .await
            }
            ServiceSubcommands::RecoverTokens {
                network_provider,
                token,
                recipient,
                private_key,
            } => ServiceSubcommands::execute_recover_tokens(network_provider, token, recipient, private_key).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hopr_bindings::config::{ContractInstances, NetworksWithContractAddresses, SingleNetworkContractAddresses};
    use hopr_types::{crypto::keypairs::Keypair, primitive::prelude::BytesRepresentable};

    use super::*;
    use crate::{
        methods::{create_rpc_client_to_anvil, deploy_safe_module_with_targets_and_nodes},
        utils::{a2h, create_anvil},
    };

    #[test]
    fn test_parse_service_type_accepts_an_ascii_name() -> anyhow::Result<()> {
        assert_eq!(
            parse_service_type("gvpn:exit").map_err(anyhow::Error::msg)?,
            ServiceType::GVPN_EXIT
        );
        Ok(())
    }

    #[test]
    fn test_parse_service_type_accepts_a_name_of_the_full_width() {
        let name = "a".repeat(ServiceType::SIZE);
        assert!(parse_service_type(&name).is_ok(), "a 32 byte name should be accepted");
    }

    #[test]
    fn test_parse_service_type_rejects_a_name_wider_than_the_id() {
        // 33 bytes: one over what a `bytes32` can hold.
        let name = "a".repeat(ServiceType::SIZE + 1);
        assert!(parse_service_type(&name).is_err(), "a 33 byte name should be rejected");
    }

    #[test]
    fn test_parse_service_type_rejects_non_ascii() {
        assert!(parse_service_type("gvpn:exït").is_err(), "non-ASCII should be rejected");
    }

    #[test]
    fn test_parse_service_type_rejects_a_space() {
        // A space is indistinguishable from the right padding, so it is not a usable identifier.
        assert!(parse_service_type("gvpn exit").is_err(), "a space should be rejected");
    }

    #[test]
    fn test_parse_service_type_rejects_empty() {
        assert!(parse_service_type("").is_err(), "an empty name should be rejected");
    }

    #[test]
    fn test_parse_service_type_accepts_a_hex_id() -> anyhow::Result<()> {
        let id = "0x6776706e3a657869740000000000000000000000000000000000000000000000";
        assert_eq!(
            parse_service_type(id).map_err(anyhow::Error::msg)?,
            ServiceType::GVPN_EXIT
        );
        Ok(())
    }

    #[test]
    fn test_parse_service_type_rejects_the_zero_hex_id() {
        let id = format!("0x{}", "00".repeat(ServiceType::SIZE));
        assert!(parse_service_type(&id).is_err(), "the zero id should be rejected");
    }

    #[test]
    fn test_parse_service_type_rejects_a_hex_id_of_the_wrong_width() {
        // 33 bytes of hex: the `0x` prefix commits to the hex reading, so this cannot fall back
        // to being read as a name.
        let id = format!("0x{}", "11".repeat(ServiceType::SIZE + 1));
        assert!(parse_service_type(&id).is_err(), "a 33 byte id should be rejected");
    }

    #[test]
    fn test_parse_service_metadata_accepts_the_maximum_length() -> anyhow::Result<()> {
        let metadata = "x".repeat(ServiceMetadata::MAX_LENGTH);
        let parsed = parse_service_metadata(&metadata).map_err(anyhow::Error::msg)?;
        assert_eq!(parsed.as_ref().len(), ServiceMetadata::MAX_LENGTH);
        Ok(())
    }

    #[test]
    fn test_parse_service_metadata_rejects_one_byte_over_the_maximum() {
        let metadata = "x".repeat(ServiceMetadata::MAX_LENGTH + 1);
        assert!(
            parse_service_metadata(&metadata).is_err(),
            "2049 bytes of metadata should be rejected"
        );
    }

    #[test]
    fn test_parse_service_metadata_accepts_empty() -> anyhow::Result<()> {
        assert_eq!(
            parse_service_metadata("").map_err(anyhow::Error::msg)?,
            ServiceMetadata::default()
        );
        Ok(())
    }

    #[test]
    fn test_metadata_args_read_prefers_the_inline_value() -> anyhow::Result<()> {
        let args = MetadataArgs {
            metadata: Some(ServiceMetadata::try_from(b"inline".to_vec())?),
            metadata_file: None,
        };
        assert_eq!(args.read()?.as_ref(), b"inline");
        Ok(())
    }

    #[test]
    fn test_metadata_args_read_reads_a_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("metadata.bin");
        // Not valid UTF-8, which is exactly what the file form exists for.
        std::fs::write(&path, [0xffu8, 0xfe, 0x00, 0x01])?;

        let args = MetadataArgs {
            metadata: None,
            metadata_file: Some(path),
        };
        assert_eq!(args.read()?.as_ref(), [0xffu8, 0xfe, 0x00, 0x01]);
        Ok(())
    }

    #[test]
    fn test_metadata_args_read_rejects_a_file_over_the_maximum() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("metadata.bin");
        std::fs::write(&path, vec![0u8; ServiceMetadata::MAX_LENGTH + 1])?;

        let args = MetadataArgs {
            metadata: None,
            metadata_file: Some(path),
        };
        let err = args.read().expect_err("an oversized file should be rejected");
        assert!(
            matches!(err, HelperErrors::ParseError(_)),
            "expected ParseError, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn test_metadata_args_read_defaults_to_empty() -> anyhow::Result<()> {
        let args = MetadataArgs {
            metadata: None,
            metadata_file: None,
        };
        assert_eq!(args.read()?, ServiceMetadata::default());
        Ok(())
    }

    #[test]
    fn test_parse_hopr_amount_converts_whole_tokens_to_wei() -> anyhow::Result<()> {
        assert_eq!(
            parse_hopr_amount("1.5").map_err(anyhow::Error::msg)?,
            U256::from(1_500_000_000_000_000_000u64)
        );
        Ok(())
    }

    #[test]
    fn test_parse_hopr_amount_rejects_a_non_number() {
        assert!(parse_hopr_amount("many").is_err(), "a non-number should be rejected");
    }

    #[test]
    fn test_checked_page_size_rejects_zero() {
        // A zero page size would return an empty page forever and never terminate the scan.
        let err = PaginationArgs {
            offset: 0,
            page_size: 0,
        }
        .checked_page_size()
        .expect_err("a zero page size should be rejected");
        assert!(
            matches!(err, HelperErrors::ParseError(_)),
            "expected ParseError, got {err:?}"
        );
    }

    /// The `--network` and `--provider-url` pair every on-chain subcommand needs.
    fn network_args() -> [&'static str; 4] {
        [
            "--network",
            "anvil-localhost",
            "--provider-url",
            "http://127.0.0.1:8545",
        ]
    }

    #[test]
    fn test_cli_parses_register() -> anyhow::Result<()> {
        let parsed =
            ServiceSubcommands::try_parse_from(["hopli", "register"].into_iter().chain(network_args()).chain([
                "--service-type",
                "gvpn:exit",
                "--node-address",
                "0x00000000000000000000000000000000000000aa",
                "--metadata",
                "hello",
                "--private-key",
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            ]))?;

        match parsed {
            ServiceSubcommands::Register {
                service_type,
                node_address,
                safe_address,
                metadata,
                ..
            } => {
                assert_eq!(service_type, ServiceType::GVPN_EXIT);
                assert_eq!(
                    node_address,
                    Address::new(hex_literal::hex!("00000000000000000000000000000000000000aa"))
                );
                assert_eq!(safe_address, None, "the safe defaults to the node's binding");
                assert_eq!(metadata.read()?.as_ref(), b"hello");
            }
            other => panic!("expected Register, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_cli_rejects_metadata_given_twice() {
        let result =
            ServiceSubcommands::try_parse_from(["hopli", "register"].into_iter().chain(network_args()).chain([
                "--service-type",
                "gvpn:exit",
                "--node-address",
                "0x00000000000000000000000000000000000000aa",
                "--metadata",
                "hello",
                "--metadata-file",
                "./metadata.bin",
            ]));
        assert!(result.is_err(), "--metadata and --metadata-file should conflict");
    }

    #[test]
    fn test_cli_parses_the_abandon_flag() -> anyhow::Result<()> {
        let parsed = ServiceSubcommands::try_parse_from(
            ["hopli", "transfer-type-ownership"]
                .into_iter()
                .chain(network_args())
                .chain(["--service-type", "gvpn:exit"])
                .chain(["--abandon"]),
        )?;

        match parsed {
            ServiceSubcommands::TransferTypeOwnership { new_owner, abandon, .. } => {
                assert_eq!(new_owner, None);
                assert!(abandon);
            }
            other => panic!("expected TransferTypeOwnership, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_cli_transfer_type_ownership_needs_a_target() {
        let result = ServiceSubcommands::try_parse_from(
            ["hopli", "transfer-type-ownership"]
                .into_iter()
                .chain(network_args())
                .chain(["--service-type", "gvpn:exit"]),
        );
        assert!(result.is_err(), "one of --new-owner and --abandon should be required");
    }

    #[test]
    fn test_cli_rejects_a_new_owner_together_with_abandon() {
        let result = ServiceSubcommands::try_parse_from(
            ["hopli", "transfer-type-ownership"]
                .into_iter()
                .chain(network_args())
                .chain([
                    "--service-type",
                    "gvpn:exit",
                    "--new-owner",
                    "0x00000000000000000000000000000000000000cc",
                    "--abandon",
                ]),
        );
        assert!(result.is_err(), "--new-owner and --abandon should conflict");
    }

    #[test]
    fn test_cli_parses_register_type_burns_as_whole_tokens() -> anyhow::Result<()> {
        let parsed =
            ServiceSubcommands::try_parse_from(["hopli", "register-type"].into_iter().chain(network_args()).chain([
                "--service-type",
                "gvpn:exit",
                "--registration-burn",
                "1",
                "--update-burn",
                "0.5",
            ]))?;

        match parsed {
            ServiceSubcommands::RegisterType {
                requirement,
                registration_burn,
                update_burn,
                ..
            } => {
                assert_eq!(requirement, Address::ZERO, "a type is open unless told otherwise");
                assert_eq!(registration_burn, U256::from(1_000_000_000_000_000_000u64));
                assert_eq!(update_burn, U256::from(500_000_000_000_000_000u64));
            }
            other => panic!("expected RegisterType, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_cli_pagination_defaults_to_a_full_scan_from_the_start() -> anyhow::Result<()> {
        let parsed = ServiceSubcommands::try_parse_from(
            ["hopli", "list"]
                .into_iter()
                .chain(network_args())
                .chain(["--service-type", "gvpn:exit"]),
        )?;

        match parsed {
            ServiceSubcommands::List { pagination, .. } => {
                assert_eq!(pagination.offset, 0);
                assert_eq!(pagination.page_size, DEFAULT_PAGE_SIZE);
            }
            other => panic!("expected List, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_type_ownership_needs_abandon_for_the_zero_address() {
        let err = ServiceSubcommands::execute_transfer_type_ownership(
            NetworkProviderArgs::default(),
            ServiceType::GVPN_EXIT,
            Some(Address::ZERO),
            false,
            PrivateKeyArgs::default(),
        )
        .await
        .expect_err("a zero new owner without --abandon should be rejected");
        assert!(
            matches!(err, HelperErrors::MissingParameter(_)),
            "expected MissingParameter, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_transfer_type_ownership_needs_a_target() {
        let err = ServiceSubcommands::execute_transfer_type_ownership(
            NetworkProviderArgs::default(),
            ServiceType::GVPN_EXIT,
            None,
            false,
            PrivateKeyArgs::default(),
        )
        .await
        .expect_err("neither --new-owner nor --abandon should be rejected");
        assert!(
            matches!(err, HelperErrors::MissingParameter(_)),
            "expected MissingParameter, got {err:?}"
        );
    }

    /// Writes a `contracts-addresses.json` describing one network and returns its root directory.
    fn write_contracts_root(
        dir: &tempfile::TempDir,
        chain_id: u64,
        addresses: ContractAddresses,
    ) -> anyhow::Result<String> {
        let mut networks = BTreeMap::new();
        networks.insert(
            "anvil-localhost".to_string(),
            SingleNetworkContractAddresses {
                chain_id,
                indexer_start_block_number: 0u32,
                addresses,
            },
        );
        std::fs::write(
            dir.path().join("contracts-addresses.json"),
            serde_json::to_string_pretty(&NetworksWithContractAddresses { networks })?,
        )?;
        Ok(dir.path().to_str().expect("temp dir path is not utf-8").to_string())
    }

    #[test]
    fn test_addresses_with_service_registry_rejects_a_network_without_a_deployment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addresses = ContractAddresses {
            service_registry: Address::ZERO,
            ..Default::default()
        };
        let contracts_root = write_contracts_root(&dir, 31337, addresses)?;

        let args = NetworkProviderArgs {
            contracts_root: Some(contracts_root),
            ..Default::default()
        };
        let err = addresses_with_service_registry(&args).expect_err("a zero address should be rejected");
        assert!(
            matches!(err, HelperErrors::ContractNotDeployed(_)),
            "expected ContractNotDeployed, got {err:?}"
        );
        Ok(())
    }

    /// Drives one entry through its whole life against a local anvil.
    ///
    /// The registration and update burns are deliberately non-zero, which is what makes this a
    /// test of the MultiSend ordering: the registry pulls the burn inside `selfRegister` and
    /// `selfUpdate`, so both calls revert - taking the whole Safe transaction with them - unless
    /// the approval leg really does run first, in the same transaction, for at least the burn.
    #[tokio::test]
    async fn test_service_entry_lifecycle_through_the_bound_safe() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let registration_burn = U256::from(2_000_000_000_000_000_000u64); // 2 wxHOPR
        let update_burn = U256::from(1_000_000_000_000_000_000u64); // 1 wxHOPR

        // launch anvil and deploy the HOPR contracts, multicall and the safe suites
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(
            client.clone(),
            a2h(contract_deployer.public().to_address()),
            anvil.addresses()[1],
        )
        .await
        .expect("failed to deploy");
        ContractInstances::deploy_multicall3(client.clone(), anvil.addresses()[1]).await?;
        ContractInstances::deploy_safe_suites(client.clone(), anvil.addresses()[1]).await?;

        let node = a2h(contract_deployer.public().to_address());
        let contract_addresses = instances.get_contract_addresses();
        let channels_address = *instances.channels.address();
        let token = instances.token.clone();
        let service_registry = instances.service_registry.clone();

        // the deployer owns the safe and is also the node it registers
        let (safe, _module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            channels_address,
            vec![node],
            vec![node],
            U256::from(1),
        )
        .await?;

        // bind the node to the safe: the registry accepts writes from that safe and no other
        instances
            .safe_registry
            .registerSafeByNode(*safe.address())
            .send()
            .await?
            .watch()
            .await?;

        // the safe pays the burns, so it needs the tokens.
        //
        // This is the last transaction sent through `client`. The commands below each build their
        // own provider, with their own nonce cache, so a later `client` transaction would reuse a
        // nonce the chain has already seen.
        token
            .transfer(*safe.address(), registration_burn + update_burn)
            .send()
            .await?
            .watch()
            .await?;
        let safe_balance_before = token.balanceOf(*safe.address()).call().await?;

        let temp_dir = tempfile::tempdir()?;
        let contracts_root = write_contracts_root(&temp_dir, anvil.chain_id(), contract_addresses)?;
        let network_provider = NetworkProviderArgs {
            network: "anvil-localhost".into(),
            contracts_root: Some(contracts_root),
            provider_url: anvil.endpoint(),
        };
        let private_key = PrivateKeyArgs {
            private_key: Some(hex::encode(contract_deployer.secret().as_ref())),
        };

        // claim an open service type with non-zero burns, paying the global registration fee
        ServiceSubcommands::execute_register_type(
            network_provider.clone(),
            ServiceType::GVPN_EXIT,
            Address::ZERO,
            registration_burn,
            update_burn,
            private_key.clone(),
        )
        .await?;

        assert_eq!(
            ServiceSubcommands::execute_list_types(network_provider.clone(), PaginationArgs::default()).await?,
            vec![ServiceType::GVPN_EXIT],
            "the claimed type should be the only registered one"
        );

        // register the entry through the safe
        let metadata = ServiceMetadata::try_from(br#"{"endpoint":"https://exit.example"}"#.to_vec())?;
        ServiceSubcommands::execute_register(
            network_provider.clone(),
            ServiceType::GVPN_EXIT,
            node,
            None,
            metadata.clone(),
            private_key.clone(),
        )
        .await?;

        let entry = ServiceSubcommands::execute_get_entry(network_provider.clone(), ServiceType::GVPN_EXIT, node)
            .await?
            .expect("the entry should exist after registering");
        assert_eq!(entry.metadata.to_vec(), metadata.as_ref(), "metadata should round trip");
        assert!(
            !entry.registeredAt.is_zero(),
            "a registered entry has a registration time"
        );
        assert_eq!(
            entry.updatedAt, entry.registeredAt,
            "registration sets updatedAt to registeredAt"
        );

        assert_eq!(
            token.balanceOf(*safe.address()).call().await?,
            safe_balance_before - registration_burn,
            "exactly the registration burn should have left the safe"
        );
        assert!(
            token
                .allowance(*safe.address(), *service_registry.address())
                .call()
                .await?
                .is_zero(),
            "the exact approval should be fully consumed, leaving no standing allowance"
        );

        let registered = service_registry.Registered_filter().from_block(0).query().await?;
        assert_eq!(registered.len(), 1, "one Registered event should have been emitted");
        assert_eq!(registered[0].0.node, node);
        assert_eq!(registered[0].0.safe, *safe.address());
        assert_eq!(registered[0].0.serviceType, service_type_id(&ServiceType::GVPN_EXIT));
        assert_eq!(registered[0].0.metadata.to_vec(), metadata.as_ref());
        assert_eq!(registered[0].0.burned, registration_burn);

        let listed = ServiceSubcommands::execute_list_entries(
            network_provider.clone(),
            ServiceType::GVPN_EXIT,
            PaginationArgs::default(),
        )
        .await?;
        assert_eq!(listed.len(), 1, "the type should list exactly the one entry");
        assert_eq!(listed[0].0, node);
        assert_eq!(listed[0].1.metadata.to_vec(), metadata.as_ref());

        // update the entry through the safe
        let new_metadata = ServiceMetadata::try_from(br#"{"endpoint":"https://exit2.example"}"#.to_vec())?;
        ServiceSubcommands::execute_update(
            network_provider.clone(),
            ServiceType::GVPN_EXIT,
            node,
            None,
            new_metadata.clone(),
            private_key.clone(),
        )
        .await?;

        let updated = ServiceSubcommands::execute_get_entry(network_provider.clone(), ServiceType::GVPN_EXIT, node)
            .await?
            .expect("the entry should still exist after updating");
        assert_eq!(
            updated.metadata.to_vec(),
            new_metadata.as_ref(),
            "the new metadata should have replaced the old one"
        );
        assert_eq!(
            updated.registeredAt, entry.registeredAt,
            "an update leaves the registration time untouched"
        );

        assert_eq!(
            token.balanceOf(*safe.address()).call().await?,
            safe_balance_before - registration_burn - update_burn,
            "exactly the update burn should have left the safe"
        );

        let updates = service_registry.Updated_filter().from_block(0).query().await?;
        assert_eq!(updates.len(), 1, "one Updated event should have been emitted");
        assert_eq!(updates[0].0.metadata.to_vec(), new_metadata.as_ref());
        assert_eq!(updates[0].0.burned, update_burn);

        // deregister the entry through the safe; the safe holds no wxHOPR at this point, which is
        // exactly the case invariant I6 protects
        assert!(
            token.balanceOf(*safe.address()).call().await?.is_zero(),
            "the safe should have spent all of its wxHOPR on the burns"
        );
        ServiceSubcommands::execute_deregister(
            network_provider.clone(),
            ServiceType::GVPN_EXIT,
            node,
            None,
            private_key.clone(),
        )
        .await?;

        assert!(
            ServiceSubcommands::execute_get_entry(network_provider.clone(), ServiceType::GVPN_EXIT, node)
                .await?
                .is_none(),
            "the entry should be gone after deregistering"
        );
        assert!(
            ServiceSubcommands::execute_list_entries(
                network_provider.clone(),
                ServiceType::GVPN_EXIT,
                PaginationArgs::default()
            )
            .await?
            .is_empty(),
            "the type should list no entries after deregistering"
        );

        let deregistered = service_registry.Deregistered_filter().from_block(0).query().await?;
        assert_eq!(deregistered.len(), 1, "one Deregistered event should have been emitted");
        assert_eq!(deregistered[0].0.node, node);
        assert_eq!(deregistered[0].0.safe, *safe.address());

        Ok(())
    }
}
