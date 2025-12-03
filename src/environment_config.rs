//! This module contains definiation of arguments that specify the environment
//! and networks that a HOPR node runs in.
//!
//! Network is a collection of several major/minor releases.
use std::{collections::BTreeMap, ffi::OsStr, path::PathBuf, sync::Arc};

use clap::Parser;
use hopr_bindings::{
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
    config::SingleNetworkContractAddresses
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
    pub async fn get_provider_with_signer(&self, chain_key: &ChainKeypair) -> Result<Arc<RpcProvider>, HelperErrors>
// ) -> Result<Arc<NonceManagerMiddleware<SignerMiddleware<Provider<JsonRpcClient>, Wallet<SigningKey>>>>, HelperErrors>
    {
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
            .filler(BlobGasFiller)
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
            .filler(BlobGasFiller)
            .connect_client(rpc_client);

        Ok(Arc::new(provider))
    }
}

#[cfg(test)]
mod tests {
    use hopr_bindings::exports::alloy::{
        node_bindings::{Anvil, AnvilInstance},
        providers::Provider,
    };

    use super::*;

    fn create_anvil_at_port(default: bool) -> AnvilInstance {
        let mut anvil = Anvil::new();

        if !default {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| panic!("Failed to bind localhost"));
            let random_port = listener
                .local_addr()
                .unwrap_or_else(|_| panic!("Failed to get local address"))
                .port();
            anvil = anvil.port(random_port);
            anvil = anvil.chain_id(random_port.into());
        } else {
            anvil = anvil.port(8545u16);
        }
        anvil.spawn()
    }

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
}
