//! Signers of the transactions that hopli sends: a private key, or an account of a hardware wallet (Ledger or
//! Trezor).
//!
//! [`HopliSigner`] turns any of them into an [`EthereumWallet`], with which a provider signs transactions (see
//! [`crate::environment_config::NetworkProviderArgs::get_provider_with_wallet`]). The rest of hopli therefore does
//! not depend on where the key is kept. Hardware wallets can sign transactions but not raw hashes; this is enough,
//! as the owner that executes a Safe transaction approves it by being its sender (see
//! [`crate::methods::pre_validated_safe_signature`]).
//!
//! Hardware wallets are behind the `ledger` and `trezor` cargo features, both enabled by default through the
//! `hardware-wallets` feature. Selecting a hardware wallet in a build without its feature returns an error.
use std::fmt;

#[cfg(any(feature = "ledger", feature = "trezor"))]
use hopr_bindings::exports::alloy::network::TxSigner;
use hopr_bindings::exports::alloy::{network::EthereumWallet, primitives::Address, signers::local::PrivateKeySigner};
use hopr_types::crypto::keypairs::{ChainKeypair, Keypair};
use tracing::info;

use crate::utils::HelperErrors;

/// Account of a hardware wallet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareAccount {
    /// Account at the given index of the standard derivation path of the device:
    /// `m/44'/60'/<index>'/0/0` (Ledger Live) on a Ledger, `m/44'/60'/0'/0/<index>` on a Trezor
    Index(usize),
    /// Account at a custom derivation path, e.g. `m/44'/60'/0'/0/1`
    DerivationPath(String),
}

/// Hardware wallet that signs transactions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareWallet {
    /// A Ledger device, with the Ethereum app open
    Ledger(HardwareAccount),
    /// A Trezor device
    Trezor(HardwareAccount),
}

impl fmt::Display for HardwareWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (device, account) = match self {
            HardwareWallet::Ledger(account) => ("Ledger", account),
            HardwareWallet::Trezor(account) => ("Trezor", account),
        };
        match account {
            HardwareAccount::Index(index) => write!(f, "{device} account #{index}"),
            HardwareAccount::DerivationPath(path) => write!(f, "{device} account at {path}"),
        }
    }
}

/// Signer of the transactions sent by hopli
#[derive(Clone)]
pub struct HopliSigner {
    address: Address,
    wallet: EthereumWallet,
    origin: String,
}

impl fmt::Debug for HopliSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopliSigner")
            .field("address", &self.address)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl HopliSigner {
    /// Signer holding a private key in memory
    pub fn from_private_key(chain_key: &ChainKeypair) -> Result<Self, HelperErrors> {
        let signer = PrivateKeySigner::from_slice(chain_key.secret().as_ref())
            .map_err(|e| HelperErrors::UnableToReadPrivateKey(format!("invalid private key: {e}")))?;
        Ok(Self {
            address: signer.address(),
            wallet: EthereumWallet::from(signer),
            origin: "private key".into(),
        })
    }

    /// Connect to an account of a hardware wallet. The device must be connected and unlocked, and it asks to
    /// confirm each transaction. `chain_id`, when known, is checked against the chain id of each transaction.
    pub async fn from_hardware_wallet(
        hardware_wallet: &HardwareWallet,
        chain_id: Option<u64>,
    ) -> Result<Self, HelperErrors> {
        info!("connecting to {hardware_wallet}");
        let (address, wallet) = match hardware_wallet {
            HardwareWallet::Ledger(account) => connect_ledger(account, chain_id).await?,
            HardwareWallet::Trezor(account) => connect_trezor(account, chain_id).await?,
        };
        info!("{hardware_wallet} has address {address:?}");
        Ok(Self {
            address,
            wallet,
            origin: hardware_wallet.to_string(),
        })
    }

    /// Address of the signer
    pub fn address(&self) -> Address {
        self.address
    }

    /// Wallet with which a provider signs transactions
    pub fn wallet(&self) -> EthereumWallet {
        self.wallet.clone()
    }
}

#[cfg(feature = "ledger")]
async fn connect_ledger(
    account: &HardwareAccount,
    chain_id: Option<u64>,
) -> Result<(Address, EthereumWallet), HelperErrors> {
    use alloy_signer_ledger::{HDPath, LedgerSigner};

    let path = match account {
        HardwareAccount::Index(index) => HDPath::LedgerLive(*index),
        HardwareAccount::DerivationPath(path) => HDPath::Other(path.clone()),
    };
    let signer = LedgerSigner::new(path, chain_id)
        .await
        .map_err(|e| HelperErrors::HardwareWallet(format!("cannot connect to the Ledger: {e}")))?;
    let address = TxSigner::address(&signer);
    Ok((address, EthereumWallet::from(signer)))
}

#[cfg(not(feature = "ledger"))]
async fn connect_ledger(
    _account: &HardwareAccount,
    _chain_id: Option<u64>,
) -> Result<(Address, EthereumWallet), HelperErrors> {
    Err(HelperErrors::HardwareWallet(
        "this hopli is built without Ledger support; build it with the `ledger` feature".into(),
    ))
}

#[cfg(feature = "trezor")]
async fn connect_trezor(
    account: &HardwareAccount,
    chain_id: Option<u64>,
) -> Result<(Address, EthereumWallet), HelperErrors> {
    use alloy_signer_trezor::{HDPath, TrezorSigner};

    let path = match account {
        HardwareAccount::Index(index) => HDPath::TrezorLive(*index),
        HardwareAccount::DerivationPath(path) => HDPath::Other(path.clone()),
    };
    let signer = TrezorSigner::new(path, chain_id)
        .await
        .map_err(|e| HelperErrors::HardwareWallet(format!("cannot connect to the Trezor: {e}")))?;
    let address = TxSigner::address(&signer);
    Ok((address, EthereumWallet::from(signer)))
}

#[cfg(not(feature = "trezor"))]
async fn connect_trezor(
    _account: &HardwareAccount,
    _chain_id: Option<u64>,
) -> Result<(Address, EthereumWallet), HelperErrors> {
    Err(HelperErrors::HardwareWallet(
        "this hopli is built without Trezor support; build it with the `trezor` feature".into(),
    ))
}

#[cfg(test)]
mod tests {
    use hopr_bindings::exports::alloy::network::NetworkWallet;

    use super::*;

    #[test]
    fn test_signer_from_private_key() -> anyhow::Result<()> {
        let chain_key = ChainKeypair::random();
        let signer = HopliSigner::from_private_key(&chain_key)?;
        let expected = crate::utils::a2h(chain_key.public().to_address());
        assert_eq!(signer.address(), expected);
        assert_eq!(
            NetworkWallet::<hopr_bindings::exports::alloy::network::Ethereum>::default_signer_address(&signer.wallet()),
            expected
        );
        assert!(!format!("{signer:?}").contains(&hex::encode(chain_key.secret().as_ref())));
        Ok(())
    }

    #[test]
    fn test_hardware_wallet_display() {
        assert_eq!(
            HardwareWallet::Ledger(HardwareAccount::Index(2)).to_string(),
            "Ledger account #2"
        );
        assert_eq!(
            HardwareWallet::Trezor(HardwareAccount::DerivationPath("m/44'/60'/0'/0/1".into())).to_string(),
            "Trezor account at m/44'/60'/0'/0/1"
        );
    }

    #[cfg(not(feature = "ledger"))]
    #[tokio::test]
    async fn test_ledger_needs_the_ledger_feature() {
        let result = HopliSigner::from_hardware_wallet(&HardwareWallet::Ledger(HardwareAccount::Index(0)), None).await;
        assert!(matches!(result, Err(HelperErrors::HardwareWallet(_))));
    }

    #[cfg(not(feature = "trezor"))]
    #[tokio::test]
    async fn test_trezor_needs_the_trezor_feature() {
        let result = HopliSigner::from_hardware_wallet(&HardwareWallet::Trezor(HardwareAccount::Index(0)), None).await;
        assert!(matches!(result, Err(HelperErrors::HardwareWallet(_))));
    }
}
