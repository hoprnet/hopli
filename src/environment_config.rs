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
use hopr_crypto_types::keypairs::{ChainKeypair, Keypair};
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

impl NetworkProviderArgs {
    /// Get the network details (contract addresses, chain id) from network names
    pub fn get_network_details_from_name(&self) -> Result<SingleNetworkContractAddresses, HelperErrors> {
        // If contracts_root is provided, read from the local file
        // Otherwise, use the embedded configuration from hopr_bindings
        let network_config = if let Some(contract_root) = &self.contracts_root {
            let contract_environment_config_path =
                PathBuf::from(OsStr::new(contract_root)).join("contracts-addresses.json");

            let file_read = std::fs::read_to_string(contract_environment_config_path)
                .map_err(HelperErrors::UnableToReadFromPath)?;

            serde_json::from_str::<NetworkConfig>(&file_read).map_err(HelperErrors::SerdeJson)?
        } else {
            // Use embedded configuration from hopr_bindings
            let networks_with_addresses = hopr_bindings::config::NetworksWithContractAddresses::default();
            NetworkConfig {
                networks: networks_with_addresses.networks,
            }
        };

        network_config
            .networks
            .get(&self.network)
            .cloned()
            .ok_or_else(|| HelperErrors::UnknownNetwork)
    }

    /// get the provider object
    pub async fn get_provider_with_signer(&self, chain_key: &ChainKeypair) -> Result<Arc<RpcProvider>, HelperErrors> {
        // Build transport
        let parsed_url = url::Url::parse(self.provider_url.as_str()).unwrap();
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
            .filler(GasFiller)
            .filler(BlobGasFiller::default())
            .wallet(wallet)
            .connect_client(rpc_client);

        Ok(Arc::new(provider))
    }

    /// get the provider object without signer
    pub async fn get_provider_without_signer(&self) -> Result<Arc<RpcProviderWithoutSigner>, HelperErrors> {
        // Build transport
        let parsed_url = url::Url::parse(self.provider_url.as_str()).unwrap();
        let transport_client = ReqwestTransport::new(parsed_url);

        // Build JSON RPC client
        let rpc_client = ClientBuilder::default().transport(transport_client.clone(), transport_client.guess_local());

        if rpc_client.is_local() {
            rpc_client.set_poll_interval(std::time::Duration::from_millis(10));
        };

        // Build default JSON RPC provider
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            // .wallet(wallet)
            .filler(ChainIdFiller::default())
            .filler(NonceFiller::new(CachedNonceManager::default()))
            .filler(GasFiller)
            .filler(BlobGasFiller::default())
            .connect_client(rpc_client);

        Ok(Arc::new(provider))
    }
}

#[cfg(test)]
mod tests {
    use hopr_bindings::exports::alloy::providers::Provider;

    use super::*;
    use crate::{
        methods::create_rpc_client_to_anvil,
        utils::{ContractInstances, create_anvil_at_port},
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

        // create client
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        // deploy local contracts
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
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
}
