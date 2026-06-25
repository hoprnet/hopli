//! This module contains definiation of arguments that specify the environment
//! and networks that a HOPR node runs in.
//!
//! Network is a collection of several major/minor releases.
use std::{collections::BTreeMap, ffi::OsStr, path::PathBuf, sync::Arc};

use clap::Parser;
use hopr_bindings::{
    config::SingleNetworkContractAddresses,
    exports::alloy::{
        network::EthereumWallet,
        providers::{
            Identity, ProviderBuilder, RootProvider,
            fillers::{
                BlobGasFiller, CachedNonceManager, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
                WalletFiller,
            },
        },
        rpc::client::ClientBuilder,
        signers::local::PrivateKeySigner,
        transports::http::ReqwestTransport,
    },
};
use hopr_types::crypto::keypairs::{ChainKeypair, Keypair};
use serde::{Deserialize, Serialize};

use crate::utils::HelperErrors;

type SharedFillerChain = JoinFill<
    JoinFill<JoinFill<JoinFill<Identity, ChainIdFiller>, NonceFiller<CachedNonceManager>>, GasFiller>,
    BlobGasFiller,
>;
pub type RpcProvider = FillProvider<JoinFill<SharedFillerChain, WalletFiller<EthereumWallet>>, RootProvider>;
pub type RpcProviderWithoutSigner = FillProvider<SharedFillerChain, RootProvider>;

/// mapping of networks with its details
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    // #[serde(flatten)]
    networks: BTreeMap<String, SingleNetworkContractAddresses>,
}

/// Arguments for getting network and ethereum RPC provider.
///
/// RPC provider specifies an endpoint that enables an application to communicate with a blockchain network
/// If not specified, it uses the default value according to the environment config
/// Network specifies a set of contracts used in HOPR network.
#[derive(Debug, Clone, Parser)]
pub struct NetworkProviderArgs {
    /// Name of the network that the node is running on
    #[clap(help = "Network name. E.g. monte_rosa", long, short)]
    network: String,

    /// Path to the files storing contract addresses (`contracts-addresses.json`).
    /// If not provided, uses embedded configuration from hopr-bindings dependency.
    #[clap(
        env = "HOPLI_CONTRACTS_ROOT",
        help = "Specify path pointing to the contracts root (optional, defaults to embedded config)",
        long,
        short
    )]
    contracts_root: Option<String>,

    /// Customized RPC provider endpoint
    #[clap(help = "Blockchain RPC provider endpoint.", long, short = 'r')]
    provider_url: String,
}

impl Default for NetworkProviderArgs {
    fn default() -> Self {
        Self {
            network: "anvil-localhost".into(),
            contracts_root: None,
            provider_url: "http://127.0.0.1:8545".into(),
        }
    }
}

/// Load every known network (contract addresses + chain id), from a local
/// `contracts-addresses.json` if `contracts_root` is provided, otherwise from
/// the embedded `hopr-bindings` configuration.
pub fn load_all_networks(
    contracts_root: Option<&str>,
) -> Result<BTreeMap<String, SingleNetworkContractAddresses>, HelperErrors> {
    if let Some(contract_root) = contracts_root {
        let contract_environment_config_path = PathBuf::from(OsStr::new(contract_root)).join("contracts-addresses.json");
        let file_read =
            std::fs::read_to_string(contract_environment_config_path).map_err(HelperErrors::UnableToReadFromPath)?;
        let cfg: NetworkConfig = serde_json::from_str(&file_read).map_err(HelperErrors::SerdeJson)?;
        Ok(cfg.networks)
    } else {
        Ok(hopr_bindings::config::NetworksWithContractAddresses::default().networks)
    }
}

/// Build a no-signer RPC provider from a URL.
pub async fn build_provider_without_signer(provider_url: &str) -> Result<Arc<RpcProviderWithoutSigner>, HelperErrors> {
    let parsed_url = url::Url::parse(provider_url).map_err(|e| HelperErrors::ParseError(e.to_string()))?;
    let transport_client = ReqwestTransport::new(parsed_url);
    let rpc_client = ClientBuilder::default().transport(transport_client.clone(), transport_client.guess_local());

    if rpc_client.is_local() {
        rpc_client.set_poll_interval(std::time::Duration::from_millis(10));
    };

    let provider = ProviderBuilder::new()
        .disable_recommended_fillers()
        .filler(ChainIdFiller::default())
        .filler(NonceFiller::new(CachedNonceManager::default()))
        .filler(GasFiller::default())
        .filler(BlobGasFiller::default())
        .connect_client(rpc_client);

    Ok(Arc::new(provider))
}

impl NetworkProviderArgs {
    /// Get the network details (contract addresses, chain id) from network names
    pub fn get_network_details_from_name(&self) -> Result<SingleNetworkContractAddresses, HelperErrors> {
        load_all_networks(self.contracts_root.as_deref())?
            .get(&self.network)
            .cloned()
            .ok_or_else(|| HelperErrors::UnknownNetwork)
    }

    /// get the provider object
    pub async fn get_provider_with_signer(&self, chain_key: &ChainKeypair) -> Result<Arc<RpcProvider>, HelperErrors> {
        // Build transport
        let parsed_url =
            url::Url::parse(self.provider_url.as_str()).map_err(|e| HelperErrors::ParseError(e.to_string()))?;
        let transport_client = ReqwestTransport::new(parsed_url);

        // Build JSON RPC client
        let rpc_client = ClientBuilder::default().transport(transport_client.clone(), transport_client.guess_local());

        if rpc_client.is_local() {
            rpc_client.set_poll_interval(std::time::Duration::from_millis(10));
        };

        // build wallet
        let wallet = PrivateKeySigner::from_slice(chain_key.secret().as_ref()).expect("failed to construct wallet");

        // Build default JSON RPC provider
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .filler(ChainIdFiller::default())
            .filler(NonceFiller::new(CachedNonceManager::default()))
            .filler(GasFiller::default())
            .filler(BlobGasFiller::default())
            .wallet(wallet)
            .connect_client(rpc_client);

        Ok(Arc::new(provider))
    }

    /// get the provider object without signer
    pub async fn get_provider_without_signer(&self) -> Result<Arc<RpcProviderWithoutSigner>, HelperErrors> {
        build_provider_without_signer(&self.provider_url).await
    }
}

#[cfg(test)]
mod tests {
    use hopr_bindings::{config::ContractInstances, exports::alloy::providers::Provider};

    use super::*;
    use crate::{
        methods::create_rpc_client_to_anvil,
        utils::{a2h, create_anvil_at_port},
    };

    #[tokio::test]
    async fn test_network_provider_with_signer() -> anyhow::Result<()> {
        // create an identity
        let chain_key = ChainKeypair::random();

        // launch local anvil instance
        let anvil = create_anvil_at_port(false);

        let network_provider_args = NetworkProviderArgs {
            network: "anvil-localhost".into(),
            contracts_root: Some("../ethereum/contracts".into()),
            provider_url: anvil.endpoint(),
        };

        let provider = network_provider_args.get_provider_with_signer(&chain_key).await?;

        let chain_id = provider.get_chain_id().await?;
        assert_eq!(chain_id, anvil.chain_id());
        Ok(())
    }

    #[tokio::test]
    async fn test_default_contracts_root() -> anyhow::Result<()> {
        // create an identity
        let chain_key = ChainKeypair::random();

        // launch local anvil instance
        let anvil = create_anvil_at_port(false);

        let network_provider_args = NetworkProviderArgs {
            network: "anvil-localhost".into(),
            contracts_root: None,
            provider_url: anvil.endpoint(),
        };

        let provider = network_provider_args.get_provider_with_signer(&chain_key).await?;

        let chain_id = provider.get_chain_id().await?;
        assert_eq!(chain_id, anvil.chain_id());
        Ok(())
    }

    #[tokio::test]
    async fn test_local_contract_creation_and_interaction() -> anyhow::Result<()> {
        // launch local anvil instance
        let anvil = create_anvil_at_port(true);

        // use the first funded identity of anvil
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let contract_deployer_address = contract_deployer.public().to_address();

        // create client
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        // deploy local contracts
        let instances = ContractInstances::deploy_for_testing(client.clone(), a2h(contract_deployer_address))
            .await
            .expect("failed to deploy");

        // temporary write the contract addresses to a json file
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let contracts_root_path = temp_dir.path().to_str().unwrap().to_string();
        let contract_addresses = SingleNetworkContractAddresses {
            chain_id: anvil.chain_id(),
            indexer_start_block_number: 0u32,
            addresses: instances.get_contract_addresses(),
        };

        let network_name = "anvil-localhost";
        let mut networks_map = BTreeMap::new();
        networks_map.insert(network_name.to_string(), contract_addresses);
        let network_config = NetworkConfig { networks: networks_map };
        let contract_environment_config_path =
            PathBuf::from(OsStr::new(&contracts_root_path)).join("contracts-addresses.json");
        let file_content = serde_json::to_string_pretty(&network_config).unwrap();
        std::fs::write(&contract_environment_config_path, file_content)
            .expect("failed to write contract addresses to temp file");

        let network_provider_args = NetworkProviderArgs {
            network: "anvil-localhost".into(),
            contracts_root: Some(contracts_root_path.into()),
            provider_url: anvil.endpoint(),
        };

        let provider = network_provider_args
            .get_provider_with_signer(&contract_deployer)
            .await?;

        let chain_id = provider.get_chain_id().await?;
        assert_eq!(chain_id, anvil.chain_id());
        Ok(())
    }

    #[test]
    fn test_load_all_networks_from_embedded_config() -> anyhow::Result<()> {
        let networks = load_all_networks(None)?;
        assert!(!networks.is_empty(), "embedded config should contain networks");
        assert!(
            networks.contains_key("anvil-localhost"),
            "embedded config should contain the anvil-localhost network"
        );
        Ok(())
    }

    #[test]
    fn test_load_all_networks_round_trip_from_file() -> anyhow::Result<()> {
        // serialise the embedded networks to a contracts-addresses.json and read them back
        let embedded = load_all_networks(None)?;
        assert!(!embedded.is_empty(), "embedded config should contain networks");

        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = temp_dir.path().join("contracts-addresses.json");
        let config = NetworkConfig {
            networks: embedded.clone(),
        };
        std::fs::write(&path, serde_json::to_string_pretty(&config)?)?;

        let from_file = load_all_networks(temp_dir.path().to_str())?;
        assert_eq!(from_file, embedded, "networks read from file should match the embedded ones");
        Ok(())
    }

    #[test]
    fn test_load_all_networks_missing_file_errors() {
        let err = load_all_networks(Some("/non/existent/contracts/root")).expect_err("missing file should error");
        assert!(
            matches!(err, HelperErrors::UnableToReadFromPath(_)),
            "expected UnableToReadFromPath, got {err:?}"
        );
    }

    #[test]
    fn test_load_all_networks_invalid_json_errors() -> anyhow::Result<()> {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = temp_dir.path().join("contracts-addresses.json");
        std::fs::write(&path, "{ this is not valid json }")?;

        let err = load_all_networks(temp_dir.path().to_str()).expect_err("invalid json should error");
        assert!(matches!(err, HelperErrors::SerdeJson(_)), "expected SerdeJson, got {err:?}");
        Ok(())
    }

    #[tokio::test]
    async fn test_build_provider_without_signer_connects() -> anyhow::Result<()> {
        let anvil = create_anvil_at_port(false);
        let provider = build_provider_without_signer(&anvil.endpoint()).await?;
        let chain_id = provider.get_chain_id().await?;
        assert_eq!(chain_id, anvil.chain_id());
        Ok(())
    }

    #[tokio::test]
    async fn test_build_provider_without_signer_rejects_invalid_url() {
        let err = build_provider_without_signer("not a url")
            .await
            .expect_err("invalid url should error");
        assert!(matches!(err, HelperErrors::ParseError(_)), "expected ParseError, got {err:?}");
    }
}
