//! This module contains all the methods used for onchain interaction, especially with Safe instance, Mutlicall, and
//! Multisend contracts.
//!
//! [SafeTxOperation] corresponds to the `Operation` Enum used in Safe smart contract.
//!
//! [MultisendTransaction] struct is used for building transactions interacting with Multisend contract

#![allow(clippy::too_many_arguments)]

use std::{ops::Add, str::FromStr, sync::Arc};

use IMulticall3Extract::IMulticall3ExtractInstance;
use SafeSingleton::{SafeSingletonInstance, execTransactionCall, removeOwnerCall, setupCall};
use hex_literal::hex;
use hopr_bindings::{
    exports::alloy::{
        network::{EthereumWallet, TransactionBuilder},
        primitives::{Address, B256, Bytes, U256, keccak256, utils::format_units},
        providers::{
            CallInfoTrait, CallItem, Identity, MULTICALL3_ADDRESS, MulticallBuilder, MulticallError, Provider,
            RootProvider, WalletProvider,
            bindings::IMulticall3::{Call3, aggregate3Call},
            fillers::*,
        },
        rpc::types::TransactionRequest,
        signers::{Signer, local::PrivateKeySigner},
        sol,
        sol_types::{SolCall, SolValue},
    },
    hopr_node_management_module::HoprNodeManagementModule::{
        HoprNodeManagementModuleInstance, addChannelsAndTokenTargetCall, includeNodeCall, initializeCall,
        removeNodeCall, scopeTargetChannelsCall, scopeTargetTokenCall,
    },
    hopr_node_safe_migration::HoprNodeSafeMigration::{
        deployNewV4ModuleCall, migrateSafeV141ToL2AndMigrateToUpgradeableModuleCall,
    },
    hopr_node_safe_registry::HoprNodeSafeRegistry::{HoprNodeSafeRegistryInstance, deregisterNodeBySafeCall},
    hopr_node_stake_factory::HoprNodeStakeFactory::{HoprNodeStakeFactoryInstance, cloneCall},
    hopr_token::HoprToken::{HoprTokenInstance, approveCall},
};
use hopr_crypto_types::keypairs::{ChainKeypair, Keypair};
use tracing::{debug, info};

use crate::{
    constants::{
        DEFAULT_ANNOUNCEMENT_PERMISSIONS, DEFAULT_NODE_PERMISSIONS, DOMAIN_SEPARATOR_TYPEHASH,
        ERC_1967_PROXY_CREATION_CODE, SAFE_COMPATIBILITYFALLBACKHANDLER_ADDRESS, SAFE_MULTISEND_ADDRESS,
        SAFE_SAFE_L2_ADDRESS, SAFE_SAFEPROXYFACTORY_ADDRESS, SAFE_TX_TYPEHASH, SENTINEL_OWNERS,
    },
    payloads::{edge_node_deploy_safe_module_and_maybe_include_node, transfer_native_token_payload},
    utils::{HelperErrors, build_default_target, get_create2_address},
};

sol!(
    #![sol(abi)]
    #![sol(rpc)]
    contract SafeSingleton {
        event ExecutionSuccess(bytes32 indexed txHash, uint256 payment);

        function setup(address[],uint256,address,bytes,address,address,uint256,address);
        function execTransaction(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes memory signatures) public payable returns (bool);
        function removeOwner(address prevOwner, address owner, uint256 _threshold) public;
        function getThreshold() public view returns (uint256);
        function getOwners() public view returns (address[] memory);
        function nonce() public view returns (uint256);
        function domainSeparator() public view returns (bytes32);
        function encodeTransactionData(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) public view returns (bytes memory);
        function getTransactionHash(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) public view returns (bytes32);
        function isModuleEnabled(address module) public view returns (bool);
    }
);

sol!(
    #![sol(abi)]
    #![sol(rpc)]
    contract ModuleSingleton {
        function isNode(address) external view returns (bool);
        function getTargets() external view returns (uint256[] memory);
        function owner() public view returns (address);
    }
);

sol!(
    #![sol(abi)]
    #![sol(rpc)]
    function multiSend(bytes memory transactions) public payable;
);

sol!(
    #![sol(abi)]
    #![sol(rpc)]
    interface IMulticall3Extract {
        function getEthBalance(address addr) external view returns (uint256 balance);
    }
);

/// Enums of Safe transaction operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeTxOperation {
    Call,
    DelegateCall,
}
impl SafeTxOperation {
    /// convert the SafeTxOperation to exact one byte
    pub fn to_byte(&self) -> [u8; 1] {
        match self {
            SafeTxOperation::Call => hex!("00"),
            SafeTxOperation::DelegateCall => hex!("01"),
        }
    }
}

impl From<SafeTxOperation> for u8 {
    fn from(s: SafeTxOperation) -> u8 {
        s as u8
    }
}

/// Struct to make a multisend transaction, mainly used by safe instances
#[derive(Debug, Clone)]
pub struct MultisendTransaction {
    // data paylaod encoded with selector
    pub encoded_data: Bytes,
    // transaction type
    pub tx_operation: SafeTxOperation,
    // target address
    pub to: Address,
    // payable eth sending along the tx
    pub value: U256,
}

/// Methods for Multisend transaction
impl MultisendTransaction {
    /// encode a multisend transaction
    fn encode_packed(&self) -> Vec<u8> {
        let tx_operation_bytes: Bytes = self.tx_operation.to_byte().into();

        let value = (
            tx_operation_bytes,                  // 1 bytes
            self.to,                             // 20 bytes
            U256::from(self.value),              // 32 bytes
            U256::from(self.encoded_data.len()), // 32 bytes
            self.encoded_data.clone(),           // bytes
        );
        value.abi_encode_packed()
    }

    /// build a multisend transaction data payload
    fn build_multisend_tx(transactions: Vec<MultisendTransaction>) -> Vec<u8> {
        let mut payload: Vec<u8> = Vec::new();
        for transaction in transactions {
            payload = [payload, transaction.encode_packed()].concat();
        }
        debug!("payload {:?}", hex::encode(&payload));
        payload
    }
}

/// get the domain separator of a safe instance
/// contract_address should be safe address
fn get_domain_separator(chain_id: U256, contract_address: Address) -> [u8; 32] {
    keccak256(
        (
            B256::from_str(DOMAIN_SEPARATOR_TYPEHASH)
                .unwrap_or_else(|_| panic!("decode the DOMAIN_SEPARATOR_TYPEHASH")), // DOMAIN_SEPARATOR_TYPEHASH
            chain_id,         // getChainId
            contract_address, // this
        )
            .abi_encode(),
    )
    .into()
}

/// Implement getTransactionHash() function as in vendor/solidity/safe-contracts-1.4.1/contracts/Safe.sol
/// Note that `safeTxGas`, `baseGas`, and `gasPrice` are zero; `gasToken` is also address zero
fn get_safe_transaction_hash(
    to: Address,
    value: U256,
    data: Vec<u8>,
    operation: SafeTxOperation,
    refund_address: Address,
    nonce: U256,
    domain_separator: [u8; 32],
) -> [u8; 32] {
    // first encodeTransactionData()
    let data_hash = keccak256(data);

    let encoded = (
        B256::from_str(SAFE_TX_TYPEHASH).unwrap_or_else(|_| panic!("failed to decode the SAFE_TX_TYPEHASH")), // SAFE_TX_TYPEHASH
        to,                                                                                                   // to
        value,                                                                                                // value
        data_hash,                   // keccak256
        U256::from(operation as u8), // operation
        U256::ZERO,                  // safeTxGas
        U256::ZERO,                  // baseGas
        U256::ZERO,                  // gasPrice
        Address::ZERO,               // gasToken
        refund_address,              // refundReceiver
        nonce,                       // _nonce
    )
        .abi_encode();

    let safe_hash = keccak256(encoded);

    let encoded_transaction_data = (hex!("1901"), domain_separator, safe_hash).abi_encode_packed();

    let transaction_hash = keccak256(encoded_transaction_data);
    debug!("transaction_hash {:?}", hex::encode(transaction_hash));
    transaction_hash.0
}

/// Use safe to delegatecall to multisend contract
/// Note that when no additional signature is provided, the safe must have a threshold of one,
/// so that the transaction can be executed.
/// Note that the refund address is the caller (safe owner) wallet
pub async fn send_multisend_safe_transaction_with_threshold_one<P: WalletProvider + Provider>(
    safe: SafeSingletonInstance<Arc<P>>,
    signer_key: ChainKeypair,
    multisend_contract: Address,
    multisend_txns: Vec<MultisendTransaction>,
    chain_id: U256,
    nonce: U256,
) -> Result<(), HelperErrors> {
    // get signer
    let signer = safe.provider().default_signer_address();
    // let signer = safe.client().default_sender().expect("client must have a sender");
    let wallet = PrivateKeySigner::from_slice(signer_key.secret().as_ref()).expect("failed to construct wallet");

    // prepare a safe transaction:
    // 1. calculate total value
    let total_value = multisend_txns
        .clone()
        .into_iter()
        .fold(U256::ZERO, |acc, cur| acc.add(cur.value));
    // 2. prepare tx payload
    let tx_payload = MultisendTransaction::build_multisend_tx(multisend_txns);
    let multisend_payload = multiSendCall {
        transactions: tx_payload.into(),
    }
    .abi_encode();
    // 3. get domain separator
    let domain_separator = get_domain_separator(chain_id, *safe.address());

    debug!("multisend_payload {:?}", hex::encode(&multisend_payload));

    // get transaction hash
    let transaction_hash = get_safe_transaction_hash(
        multisend_contract,
        total_value,
        multisend_payload.clone(),
        SafeTxOperation::DelegateCall,
        signer,
        nonce,
        domain_separator,
    );

    // sign the transaction
    let signature = wallet
        .sign_hash(&B256::from_slice(&transaction_hash))
        .await
        .unwrap_or_else(|_| panic!("failed to sign a transaction hash"));
    debug!("signature {:?}", hex::encode(signature.as_bytes()));

    // execute the transaction
    let tx_receipt = safe
        .execTransaction(
            multisend_contract,
            total_value,
            multisend_payload.into(),
            SafeTxOperation::DelegateCall.into(),
            U256::ZERO,
            U256::ZERO,
            U256::ZERO,
            Address::ZERO,
            signer,
            Bytes::from(signature.as_bytes()),
        )
        .send()
        .await?
        // .unwrap_or_else(|_| panic!("failed to exeute a pending transaction"))
        .get_receipt()
        .await?;

    tx_receipt
        .decoded_log::<SafeSingleton::ExecutionSuccess>()
        .ok_or(HelperErrors::MultiSendError)?;
    Ok(())
}

/// Get chain id and safe nonce
pub async fn get_chain_id_and_safe_nonce<P: Provider>(
    safe: SafeSingletonInstance<P>,
) -> Result<(U256, U256), HelperErrors> {
    let provider = safe.provider();
    let multicall = provider.multicall().get_chain_id().add(safe.nonce());
    let (get_chain_id_return, nonce_return) = multicall.aggregate().await?;

    Ok((get_chain_id_return, nonce_return))
}

/// Get native balance and hopr token balance for given addresses
pub async fn get_native_and_token_balances<P: Provider>(
    hopr_token: HoprTokenInstance<P>,
    addresses: Vec<Address>,
) -> Result<(Vec<U256>, Vec<U256>), MulticallError> {
    let provider = hopr_token.provider();
    let multicall3_instance = IMulticall3ExtractInstance::new(MULTICALL3_ADDRESS, provider);

    // if there is less than two addresses, use multicall3 on each address
    // otherwise, make multicall on all addresses
    if addresses.is_empty() {
        Ok((vec![], vec![]))
    } else if addresses.len() == 1 {
        let address = addresses[0];
        let multicall = provider
            .multicall()
            .get_eth_balance(address)
            .add(hopr_token.balanceOf(address));

        let (native_balance, token_balance) = multicall.aggregate().await?;
        Ok((vec![native_balance], vec![token_balance]))
    } else {
        let mut native_balances_multicall = MulticallBuilder::new_dynamic(provider);
        let mut token_balances_multicall = MulticallBuilder::new_dynamic(provider);

        for address in addresses {
            native_balances_multicall =
                native_balances_multicall.add_dynamic(multicall3_instance.getEthBalance(address));
            token_balances_multicall = token_balances_multicall.add_dynamic(hopr_token.balanceOf(address));
            // balances_multicall.add_call(hopr_token.balanceOf(address));
        }

        let native_balances_return = native_balances_multicall.aggregate().await?;
        let token_balances_return = token_balances_multicall.aggregate().await?;

        Ok((native_balances_return, token_balances_return))
    }
}

/// Transfer some HOPR tokens from the caller to the list of addresses
/// Address_i receives amounts_i HOPR tokens.
/// When there's not enough token in caller's balance, if the caller is
/// a minter, mint the missing tokens. If not, returns error
///
/// Attention! Do not use this function to distribute large amount of tokens
///
/// Note that to save gas in batch funding, we use multicall to facilitate token distribution via `transferFrom`
/// To use this functionality, caller must grant Multicall3 contract the exact allowance equal to the sum of tokens
/// to be transferred. As it's a separate function, there is a window between granting the allowance and executing
/// the transactin. Attacker may take advantage of this window and steal tokens from the caller's account.
///
/// TODO: To mitigate this risk, create a MulticallErc777Recipient contract to enable receiption of tokens
/// on the multicall contract and purposely re-entrance with forwarded payload
pub async fn transfer_or_mint_tokens<P: Provider + WalletProvider>(
    hopr_token: HoprTokenInstance<Arc<P>>,
    addresses: Vec<Address>,
    amounts: Vec<U256>,
) -> Result<U256, HelperErrors> {
    let provider = hopr_token.provider();
    let caller = hopr_token.provider().default_signer_address();

    // check if two vectors have the same length
    assert_eq!(
        addresses.len(),
        amounts.len(),
        "addresses and amounts are of different lengths in transfer_or_mint_tokens"
    );

    // early return if no recipient is provided
    if addresses.is_empty() {
        return Ok(U256::ZERO);
    }

    // calculate the sum of tokens to be sent
    let total = amounts.iter().fold(U256::ZERO, |acc, cur| acc.add(cur));
    info!("total amount of HOPR tokens to be transferred {:?}", total.to_string());

    // get caller balance and its role
    let encoded_minter_role = keccak256(b"MINTER_ROLE");
    let multicall = provider
        .multicall()
        .add(
            hopr_token.balanceOf(caller), /* .method::<_, U256>("balanceOf", caller)
                                           * .map_err(|e| HelperErrors::MulticallError(e.to_string()))?,
                                           * false, */
        )
        .add(
            hopr_token.hasRole(encoded_minter_role, caller), /* hopr_token
                                                              *     .method::<_, bool>("hasRole",
                                                              * (encoded_minter_role, caller))
                                                              *     .map_err(|e|
                                                              * HelperErrors::MulticallError(e.to_string()))?,
                                                              * false, */
        );
    let (token_balance_return, has_role_return) = multicall.aggregate().await?;

    // compare the total with caller's current balance. If caller doens't have enough balance, try to mint some.
    // Otherwise, revert
    if total.gt(&token_balance_return) {
        info!("caller does not have enough balance to transfer tokens to recipients.");
        if has_role_return {
            info!("caller tries to mint tokens");
            hopr_token
                .mint(caller, total, Bytes::default(), Bytes::default())
                .send()
                .await?
                // .unwrap_or_else(|_| panic!("failed to exeute a pending transaction"))
                .watch()
                .await?;
            // .unwrap_or_else(|_| panic!("failed to resolve a transaction receipt"));
        } else {
            return Err(HelperErrors::NotAMinter);
        }
    }

    // when there are multiple recipients, use multicall; when single recipient, direct transfer
    if addresses.len() == 1 {
        info!("doing direct transfer...");

        // direct transfer
        hopr_token
            .transfer(addresses[0], amounts[0])
            .send()
            .await?
            // .unwrap_or_else(|_| panic!("failed to exeute a pending transaction"))
            .watch()
            .await?;
        // .unwrap_or_else(|_| panic!("failed to resolve a transaction receipt"));
    } else {
        info!("using multicall...");
        // use multicall
        // TODO: introduce a new ERC777Recipient contract and batch the following separated steps into one, to mitigate
        // the attack vector approve the multicall to be able to transfer from caller's wallet
        hopr_token
            .approve(MULTICALL3_ADDRESS, total)
            .send()
            .await?
            // .unwrap_or_else(|_| panic!("failed to exeute a pending transaction"))
            .watch()
            .await?;

        let calls: Vec<Call3> = addresses
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, addr)| {
                let calldata = hopr_token.transferFrom(caller, addr, amounts[i]);
                let call = Call3 {
                    target: *hopr_token.address(),
                    allowFailure: false,
                    callData: calldata.calldata().clone(),
                };
                call
            })
            .collect::<Vec<_>>();
        let aggregate3_payload = aggregate3Call { calls }.abi_encode();
        let tx = TransactionRequest::default()
            .with_to(MULTICALL3_ADDRESS)
            .with_input(aggregate3_payload);
        provider.send_transaction(tx).await?.watch().await?;
    }

    Ok(total)
}

/// Transfer some native tokens from the caller to the list of addresses
/// Address_i receives amounts_i native tokens.
pub async fn transfer_native_tokens<P: Provider + WalletProvider>(
    provider: Arc<P>,
    addresses: Vec<Address>,
    amounts: Vec<U256>,
) -> Result<U256, HelperErrors> {
    let tx = transfer_native_token_payload(addresses, amounts)?;
    provider.send_transaction(tx.clone()).await?.watch().await?;
    Ok(tx.value.unwrap_or_default())
}

/// Helper function to predict module address. Note that here the caller is the contract deployer
/// FIXME: The result mismatch from predicted module address from smart contract
pub fn predict_module_address(
    caller: Address,
    nonce: B256,
    safe_address: Address,
    announcement_address: Address,
    factory_address: Address,
    default_target: U256,
    implementation_address: Address,
) -> Result<Address, HelperErrors> {
    let module_salt = keccak256((caller, nonce).abi_encode_packed());
    // debug!("module_salt {:?}", module_salt);

    let default_announcement_target =
        U256::from_str(format!("{announcement_address:?}{DEFAULT_ANNOUNCEMENT_PERMISSIONS}").as_str()).unwrap();

    let initialize_parameters = (
        safe_address,
        SAFE_MULTISEND_ADDRESS,
        default_announcement_target,
        default_target,
    )
        .abi_encode();

    let encode_initialization = initializeCall {
        initParams: initialize_parameters.into(),
    }
    .abi_encode();

    let erc1967_initialize_code = (implementation_address, encode_initialization).abi_encode()[32..].to_vec();
    debug!("erc1967_initialize_code {:?}", hex::encode(&erc1967_initialize_code));

    let module_creation_code = (
        Bytes::copy_from_slice(ERC_1967_PROXY_CREATION_CODE),
        erc1967_initialize_code,
    )
        .abi_encode_packed();
    debug!("module_creation_code {:?}", hex::encode(&module_creation_code));
    debug!(
        "module_creation_code_hash {:?}",
        hex::encode(keccak256(&module_creation_code))
    );

    let predict_module_addr = get_create2_address(factory_address, module_salt, keccak256(&module_creation_code));
    debug!("predict_module_addr {:?}", predict_module_addr);

    Ok(predict_module_addr)
}

/// Helper function to predict safe address
pub fn predict_safe_address(
    stake_factory: Address,
    admins: Vec<Address>,
    nonce: B256,
    safe_fallback: Address,
    safe_singleton: Address,
    safe_factory: Address,
) -> Result<Address, HelperErrors> {
    let mut temp_admins = admins.clone();
    temp_admins.push(stake_factory);

    let initializer = setupCall {
        _0: temp_admins,
        _1: U256::ONE,
        _2: Address::ZERO,
        _3: Bytes::from(hex!("00")),
        _4: safe_fallback,
        _5: Address::ZERO,
        _6: U256::ZERO,
        _7: Address::ZERO,
    }
    .abi_encode();

    let safe_salt = get_salt_from_salt_nonce(initializer, nonce)?;
    debug!("safe_salt {:?}", hex::encode(safe_salt));

    let predict_safe_addr = deploy_proxy(safe_singleton, safe_salt, safe_factory)?;
    debug!("predict_safe_addr {:?}", hex::encode(predict_safe_addr));

    Ok(predict_safe_addr)
}

/// helper function to get salt nonce
fn get_salt_from_salt_nonce(initializer: Vec<u8>, salt_nonce: B256) -> Result<[u8; 32], HelperErrors> {
    let hashed_initializer = keccak256(initializer);
    let encoded = (hashed_initializer, salt_nonce).abi_encode_packed();

    Ok(keccak256(encoded).into())
}

/// helper function to compute create2 safe proxy address
fn deploy_proxy(safe_singleton: Address, safe_salt: [u8; 32], safe_factory: Address) -> Result<Address, HelperErrors> {
    let safe_creation_code = (
        Bytes::from_static(&hex!("608060405234801561001057600080fd5b506040516101e63803806101e68339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806101c46022913960400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101196000396000f3fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033496e76616c69642073696e676c65746f6e20616464726573732070726f7669646564")),
        Bytes::from_static(&hex!("000000000000000000000000")),    // pad address to bytes32
        safe_singleton,
    ).abi_encode_packed();
    debug!("safe_creation_code {:?}", hex::encode(safe_creation_code.clone()));

    let predict_safe_addr = get_create2_address(safe_factory, safe_salt, safe_creation_code);
    debug!("predict_safe_addr {:?}", hex::encode(predict_safe_addr));

    Ok(predict_safe_addr.0.into())
}

pub fn prepare_safe_tx_multicall_payload_from_owner_contract(
    deployed_safe: Address,
    target: Address,
    refund_address: Address,
    tx_payload: Vec<u8>,
) -> CallItem<execTransactionCall> {
    let approval_hash_sig = (
        Bytes::from_static(&hex!("000000000000000000000000")),
        MULTICALL3_ADDRESS,
        Bytes::from_static(&hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )),
        Bytes::from_static(&hex!("01")),
    )
        .abi_encode_packed();

    let input = execTransactionCall {
        to: target,
        value: U256::ZERO,
        data: Bytes::from(tx_payload),
        operation: 0u8,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: refund_address,
        signatures: Bytes::from(approval_hash_sig),
    }
    .abi_encode();

    CallItem::<execTransactionCall>::new(deployed_safe, input.into())
}

/// Deploy a safe and a module, while sending tokens to the safe for single edge node.
/// It's possible to only deploy a safe and a module without onboarding the node
/// Alternatively, the node will be included in the module after deployment
/// Returns safe proxy address and module proxy address
pub async fn deploy_safe_module_for_single_edge_node<P: WalletProvider + Provider>(
    hopr_node_stake_factory: HoprNodeStakeFactoryInstance<Arc<P>>,
    hopr_token_address: Address,
    hopr_channels_address: Address,
    nonce: U256,
    amount: U256,
    admins: Vec<Address>,
    should_include_node: bool,
) -> Result<(SafeSingletonInstance<Arc<P>>, HoprNodeManagementModuleInstance<Arc<P>>), HelperErrors> {
    let provider = hopr_node_stake_factory.provider();

    let tx = edge_node_deploy_safe_module_and_maybe_include_node(
        *hopr_node_stake_factory.address(),
        hopr_token_address,
        hopr_channels_address,
        nonce,
        amount,
        admins,
        should_include_node,
    )?;
    let tx_receipt = provider.send_transaction(tx).await?.get_receipt().await?;

    let safe_address_from_log = tx_receipt
        .decoded_log::<hopr_bindings::hopr_node_stake_factory::HoprNodeStakeFactory::NewHoprNodeStakeSafe>()
        .ok_or_else(|| HelperErrors::ContractNotDeployed("cannot find safe from log".into()))?
        .instance;
    let module_address_from_log = tx_receipt
        .decoded_log::<hopr_bindings::hopr_node_stake_factory::HoprNodeStakeFactory::NewHoprNodeStakeModule>()
        .ok_or_else(|| HelperErrors::ContractNotDeployed("cannot find module from log".into()))?
        .instance;
    info!("tx_receipt {:?}", tx_receipt);

    let deployed_module = HoprNodeManagementModuleInstance::new(module_address_from_log, provider.clone());
    let deployed_safe = SafeSingleton::new(safe_address_from_log, provider.clone());

    Ok((deployed_safe, deployed_module))
}

/// Deploy a safe and a module proxies via v4 HoprStakeFactory contract with default permissions and announcement
/// targets With the multicall contract, it deploys a safe proxy instance and a module proxy instance with multicall as
/// an owner, and completes necessary setup.
/// Then the multicall includes some additional steps:
/// 1. if node addresses are known, include nodes to the module by safe
/// 2. transfer safe ownership to actual admins
/// 3. set desired threshold
///
/// Returns safe proxy address and module proxy address
#[allow(clippy::too_many_arguments)]
pub async fn deploy_safe_module_with_targets_and_nodes<P: WalletProvider + Provider>(
    hopr_node_stake_factory: HoprNodeStakeFactoryInstance<Arc<P>>,
    hopr_channels_address: Address,
    node_addresses: Vec<Address>,
    admins: Vec<Address>,
    threshold: U256,
) -> Result<(SafeSingletonInstance<Arc<P>>, HoprNodeManagementModuleInstance<Arc<P>>), HelperErrors> {
    let caller = hopr_node_stake_factory.provider().default_signer_address();
    let provider = hopr_node_stake_factory.provider();

    // check safes owners are provided and threshold is valid
    assert!(!admins.is_empty(), "safe must have valid admin(s)");
    assert!(
        threshold.ge(&U256::ONE) && threshold.le(&U256::from(admins.len())),
        "safe threshold must be at least one and not greater than the total number of admins"
    );
    assert!(
        !admins.contains(&MULTICALL3_ADDRESS),
        "multicall contract cannot be an admin"
    );

    // build a new temporary admin
    let mut temporary_admins: Vec<Address> = admins.clone();
    temporary_admins.insert(0, MULTICALL3_ADDRESS);
    info!(
        "temporary_admins expands from admin from {:?} addresses to {:?}",
        admins.len(),
        temporary_admins.len()
    );

    // build the default permissions of capabilities
    let default_target = build_default_target(hopr_channels_address)?;

    // salt nonce
    let curr_nonce = provider
        .get_transaction_count(caller)
        .pending()
        .await
        .map_err(|e| HelperErrors::MiddlewareError(e.to_string()))?;
    let nonce = keccak256((caller, U256::from(curr_nonce)).abi_encode_packed());

    debug!("curr_nonce {} and nonce {:?}", curr_nonce, nonce);

    let safe_address = predict_safe_address(
        *hopr_node_stake_factory.address(),
        temporary_admins.clone(),
        nonce,
        SAFE_COMPATIBILITYFALLBACKHANDLER_ADDRESS,
        SAFE_SAFE_L2_ADDRESS,
        SAFE_SAFEPROXYFACTORY_ADDRESS,
    )?;
    debug!("predicted safe address {:?}", safe_address.to_string());

    let module_address = hopr_node_stake_factory
        .predictModuleAddress_1(MULTICALL3_ADDRESS, nonce.into(), safe_address, default_target.into())
        .call()
        .await?;
    debug!("predicted module address {:?}", module_address.to_string());

    let deployed_module = HoprNodeManagementModuleInstance::new(module_address, provider.clone());
    let deployed_safe = SafeSingleton::new(safe_address, provider.clone());

    // Use multicall to deploy a safe proxy instance and a module proxy instance with multicall as an owner
    let mut multicall_payloads: Vec<Call3> = vec![];
    let safe_address = *deployed_safe.address();
    multicall_payloads.push(Call3 {
        target: *hopr_node_stake_factory.address(),
        allowFailure: false,
        callData: cloneCall {
            nonce: nonce.into(),
            defaultTarget: default_target.into(),
            admins: temporary_admins,
        }
        .abi_encode()
        .into(),
    });
    info!("Safe and module deployment multicall payload is created");

    // if node addresses are known, include nodes to the module by safe
    if !node_addresses.is_empty() {
        for node in node_addresses {
            let node_target = U256::from_str(&format!("{node:?}{DEFAULT_NODE_PERMISSIONS}"))
                .map_err(|e| HelperErrors::ParseError(format!("Invalid node_target format: {e}")))?;

            let encoded_call = includeNodeCall {
                nodeDefaultTarget: node_target,
            }
            .abi_encode();

            let payload = prepare_safe_tx_multicall_payload_from_owner_contract(
                safe_address,
                module_address,
                caller,
                encoded_call,
            );

            multicall_payloads.push(payload.to_call3());
        }

        info!("Nodes inclusion multicall payload is created");
    } else {
        info!("No node has been provided. Skip node inclusion action for multicall payload generation");
    }

    // renounce ownership granted to multicall so that only actual admins are included. Set the threshold.
    let remove_owner_tx_payload = removeOwnerCall {
        prevOwner: Address::from_str(SENTINEL_OWNERS)
            .map_err(|e| HelperErrors::ParseError(format!("Invalid SENTINEL_OWNERS address: {e}")))?,
        owner: MULTICALL3_ADDRESS,
        _threshold: threshold,
    }
    .abi_encode();

    let multicall_payload_5 = prepare_safe_tx_multicall_payload_from_owner_contract(
        safe_address,
        safe_address,
        caller,
        remove_owner_tx_payload,
    );

    multicall_payloads.push(multicall_payload_5.to_call3());
    info!("Admins and threshold setting multicall payload is created");

    // build multicall transaction
    let aggregate3_payload = aggregate3Call {
        calls: multicall_payloads,
    }
    .abi_encode();
    let tx = TransactionRequest::default()
        .with_to(MULTICALL3_ADDRESS)
        .with_input(aggregate3_payload);
    let tx_receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    info!("multicall is sent {:?}", tx_receipt.transaction_hash.to_string());

    let safe_address_from_log = tx_receipt
        .decoded_log::<hopr_bindings::hopr_node_stake_factory::HoprNodeStakeFactory::NewHoprNodeStakeSafe>()
        .ok_or_else(|| HelperErrors::ContractNotDeployed("cannot find safe from log".into()))?
        .instance;
    let module_address_from_log = tx_receipt
        .decoded_log::<hopr_bindings::hopr_node_stake_factory::HoprNodeStakeFactory::NewHoprNodeStakeModule>()
        .ok_or_else(|| HelperErrors::ContractNotDeployed("cannot find module from log".into()))?
        .instance;
    info!("tx_receipt {:?}", tx_receipt);

    assert_eq!(
        safe_address,
        safe_address_from_log,
        "safe address mismatch: predicted {:?} actual {:?}",
        safe_address.to_string(),
        safe_address_from_log.to_string(),
    );
    assert_eq!(
        module_address,
        module_address_from_log,
        "module address mismatch: predicted {:?} actual {:?}",
        module_address.to_string(),
        module_address_from_log.to_string(),
    );
    Ok((deployed_safe, deployed_module))
}

/// Get registered safes for given nodes on the node-safe registry
pub async fn get_registered_safes_for_nodes_on_node_safe_registry<P: Provider>(
    node_safe_registry: HoprNodeSafeRegistryInstance<P>,
    node_addresses: Vec<Address>,
) -> Result<Vec<Address>, MulticallError> {
    let provider = node_safe_registry.provider();
    let mut dyn_multicall = MulticallBuilder::new_dynamic(provider);

    for node in node_addresses {
        dyn_multicall = dyn_multicall.add_dynamic(node_safe_registry.nodeToSafe(node));
    }

    let native_balances_return = dyn_multicall.aggregate().await?;

    Ok(native_balances_return)
}

/// Deregister safes and nodes from the node-safe registry.
/// It returns the number of removed nodes
/// - If nodes have been registered to a safe, remove the node
/// - If nodes have not been registered to any safe, no op
///
/// When deregsitering one node, also remove the node from the module
pub async fn deregister_nodes_from_node_safe_registry_and_remove_from_module<P: WalletProvider + Provider>(
    node_safe_registry: HoprNodeSafeRegistryInstance<Arc<P>>,
    node_addresses: Vec<Address>,
    module_addresses: Vec<Address>,
    owner_chain_key: ChainKeypair,
) -> Result<u32, HelperErrors> {
    let provider = node_safe_registry.provider();
    // check registered safes of given node addresses
    let registered_safes =
        get_registered_safes_for_nodes_on_node_safe_registry(node_safe_registry.clone(), node_addresses.clone())
            .await
            .unwrap();

    let mut nodes_to_remove_counter = 0u32;

    for (i, registered_safe) in registered_safes.iter().enumerate() {
        if registered_safe.ne(&Address::ZERO) {
            // connect to safe
            let safe = SafeSingleton::new(registered_safe.to_owned(), provider.clone());
            // update counter
            nodes_to_remove_counter += 1;
            // get chain id and nonce
            let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;

            // for each safe, prepare a multisend transaction to dergister node from safe and remove node from module
            let multisend_txns: Vec<MultisendTransaction> = vec![
                MultisendTransaction {
                    // build multisend tx payload
                    encoded_data: deregisterNodeBySafeCall {
                        nodeAddr: node_addresses[i],
                    }
                    .abi_encode()
                    .into(),
                    tx_operation: SafeTxOperation::Call,
                    to: *node_safe_registry.address(),
                    value: U256::ZERO,
                },
                MultisendTransaction {
                    // build multisend tx payload
                    encoded_data: removeNodeCall {
                        nodeAddress: node_addresses[i],
                    }
                    .abi_encode()
                    .into(),
                    tx_operation: SafeTxOperation::Call,
                    to: module_addresses[i],
                    value: U256::ZERO,
                },
            ];

            // send safe transaction
            send_multisend_safe_transaction_with_threshold_one(
                safe,
                owner_chain_key.clone(),
                SAFE_MULTISEND_ADDRESS,
                multisend_txns,
                chain_id,
                safe_nonce,
            )
            .await?;
        }
    }

    Ok(nodes_to_remove_counter)
}

/// Include nodes to the module
pub async fn include_nodes_to_module<P: WalletProvider + Provider>(
    safe: SafeSingletonInstance<Arc<P>>,
    node_addresses: Vec<Address>,
    module_address: Address,
    owner_chain_key: ChainKeypair,
) -> Result<(), HelperErrors> {
    // get chain id and nonce
    let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;

    // prepare a multisend transaction to include each node to the  module
    let mut multisend_txns: Vec<MultisendTransaction> = Vec::new();
    for node_address in node_addresses {
        let node_target = U256::from_str(format!("{node_address:?}{DEFAULT_NODE_PERMISSIONS}").as_str()).unwrap();
        multisend_txns.push(MultisendTransaction {
            encoded_data: includeNodeCall {
                nodeDefaultTarget: node_target,
            }
            .abi_encode()
            .into(),
            tx_operation: SafeTxOperation::Call,
            to: module_address,
            value: U256::ZERO,
        });
    }

    // send safe transaction
    send_multisend_safe_transaction_with_threshold_one(
        safe,
        owner_chain_key.clone(),
        SAFE_MULTISEND_ADDRESS,
        multisend_txns,
        chain_id,
        safe_nonce,
    )
    .await?;

    Ok(())
}

/// Migrate nodes to be able to run in a new network.
// - scope the Channel contract of the new network to the module as target and set default permissions.
// - scope the Announcement contract as target to the module
// - approve HOPR tokens of the Safe proxy to be transferred by the new Channels contract
pub async fn migrate_nodes<P: WalletProvider + Provider>(
    safe: SafeSingletonInstance<Arc<P>>,
    module_addresses: Address,
    channels_address: Address,
    token_address: Address,
    announcement_address: Address,
    allowance: U256,
    owner_chain_key: ChainKeypair,
) -> Result<(), HelperErrors> {
    let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;

    let mut multisend_txns: Vec<MultisendTransaction> = Vec::new();

    // scope channels and tokens contract of the network
    let default_target = build_default_target(channels_address)?;

    multisend_txns.push(MultisendTransaction {
        // build multisend tx payload
        encoded_data: addChannelsAndTokenTargetCall {
            defaultTarget: default_target,
        }
        .abi_encode()
        .into(),
        tx_operation: SafeTxOperation::Call,
        to: module_addresses,
        value: U256::ZERO,
    });

    // scope announcement contract of the new network
    let announcement_target =
        U256::from_str(format!("{announcement_address:?}{DEFAULT_ANNOUNCEMENT_PERMISSIONS}").as_str()).unwrap();

    multisend_txns.push(MultisendTransaction {
        // build multisend tx payload
        encoded_data: scopeTargetTokenCall {
            defaultTarget: announcement_target,
        }
        .abi_encode()
        .into(),
        tx_operation: SafeTxOperation::Call,
        to: module_addresses,
        value: U256::ZERO,
    });

    // approve token transfer by the new Channels contract
    multisend_txns.push(MultisendTransaction {
        // build multisend tx payload
        encoded_data: approveCall {
            spender: channels_address,
            value: allowance,
        }
        .abi_encode()
        .into(),
        tx_operation: SafeTxOperation::Call,
        to: token_address,
        value: U256::ZERO,
    });

    // send safe transaction
    send_multisend_safe_transaction_with_threshold_one(
        safe,
        owner_chain_key.clone(),
        SAFE_MULTISEND_ADDRESS,
        multisend_txns,
        chain_id,
        safe_nonce,
    )
    .await?;

    Ok(())
}

/// Create a new module and include nodes to the new module, and remove the old module from the safe
/// Calling `migrateSafeV141ToL2AndMigrateToUpgradeableModule` function on HoprNodeSafeMigration via delegatecall
pub async fn create_new_module_include_nodes_and_remove_old_module<P: WalletProvider + Provider>(
    safe: SafeSingletonInstance<Arc<P>>,
    old_module_address: Address,
    channels_address: Address,
    deployment_nonce: U256,
    node_addresses: Vec<Address>,
    owner_chain_key: ChainKeypair,
) -> Result<(), HelperErrors> {
    let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;

    // scope channels and tokens contract of the network
    let default_target = build_default_target(channels_address)?;

    let multisend_txns: Vec<MultisendTransaction> = vec![MultisendTransaction {
        // build multisend tx payload
        encoded_data: migrateSafeV141ToL2AndMigrateToUpgradeableModuleCall {
            oldModuleProxy: old_module_address,
            defaultTarget: default_target.into(),
            nonce: deployment_nonce,
            nodes: node_addresses,
        }
        .abi_encode()
        .into(),
        tx_operation: SafeTxOperation::DelegateCall,
        to: *safe.address(),
        value: U256::ZERO,
    }];

    // send safe transaction
    send_multisend_safe_transaction_with_threshold_one(
        safe,
        owner_chain_key.clone(),
        SAFE_MULTISEND_ADDRESS,
        multisend_txns,
        chain_id,
        safe_nonce,
    )
    .await?;

    Ok(())
}

/// Create a new module and include nodes to the new module. The old module is not removed from the safe
/// Calling `deployNewV4Module` function on HoprNodeSafeMigration via delegatecall
pub async fn create_new_module_and_include_nodes<P: WalletProvider + Provider>(
    safe: SafeSingletonInstance<Arc<P>>,
    channels_address: Address,
    deployment_nonce: U256,
    node_addresses: Vec<Address>,
    owner_chain_key: ChainKeypair,
) -> Result<(), HelperErrors> {
    // get chain id and safe nonce for further safe txns
    let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;

    // scope channels and tokens contract of the network
    let default_target = build_default_target(channels_address)?;

    let multisend_txns: Vec<MultisendTransaction> = vec![MultisendTransaction {
        // build multisend tx payload
        encoded_data: deployNewV4ModuleCall {
            defaultTarget: default_target.into(),
            nonce: deployment_nonce,
            nodes: node_addresses,
        }
        .abi_encode()
        .into(),
        tx_operation: SafeTxOperation::DelegateCall,
        to: *safe.address(),
        value: U256::ZERO,
    }];

    // send safe transaction
    send_multisend_safe_transaction_with_threshold_one(
        safe,
        owner_chain_key.clone(),
        SAFE_MULTISEND_ADDRESS,
        multisend_txns,
        chain_id,
        safe_nonce,
    )
    .await?;

    Ok(())
}

/// Add new network targets to an existing module, such that the existing
/// module can work with a new network
/// Calling `scopeTargetChannels` function on the module
pub async fn add_new_network_target_to_module<P: WalletProvider + Provider>(
    safe: SafeSingletonInstance<Arc<P>>,
    module_address: Address,
    channels_address: Address,
    owner_chain_key: ChainKeypair,
) -> Result<(), HelperErrors> {
    let (chain_id, safe_nonce) = get_chain_id_and_safe_nonce(safe.clone()).await?;

    let mut multisend_txns: Vec<MultisendTransaction> = Vec::new();

    // scope channels contract of the network
    let default_target = build_default_target(channels_address)?;

    // interact with the module to add new target, from a Safe transaction
    multisend_txns.push(MultisendTransaction {
        // build multisend tx payload
        encoded_data: scopeTargetChannelsCall {
            defaultTarget: default_target,
        }
        .abi_encode()
        .into(),
        tx_operation: SafeTxOperation::Call,
        to: module_address,
        value: U256::ZERO,
    });

    // send safe transaction
    send_multisend_safe_transaction_with_threshold_one(
        safe,
        owner_chain_key.clone(),
        SAFE_MULTISEND_ADDRESS,
        multisend_txns,
        chain_id,
        safe_nonce,
    )
    .await?;

    Ok(())
}

/// Quick check if the following values are correct, for one single node:
/// 1. node xDAI balance
/// 2. If node and safe are associated on Node Safe Registry
pub async fn debug_node_safe_module_setup_on_balance_and_registries<P: Provider>(
    node_safe_registry: HoprNodeSafeRegistryInstance<Arc<P>>,
    node_address: &Address,
) -> Result<Address, MulticallError> {
    let provider = node_safe_registry.provider();
    // let mut multicall = Multicall::new(provider.clone(), Some(MULTICALL_ADDRESS))
    //     .await
    //     .expect("cannot create multicall");

    info!("checking for node {:?}", node_address);
    let multicall = provider
        .multicall()
        // 1. node xDAI balance
        .get_eth_balance(*node_address)
        // 2. get the safe address from the Node Safe Registry
        .add(node_safe_registry.nodeToSafe(*node_address));

    let (node_native_balance, safe_in_nodesafe_registry) = multicall.aggregate().await?;

    info!(
        "node does{:?} have xDAI balance {:?}",
        if node_native_balance.ge(
            &U256::from_str("100000000000000000").unwrap() // 0.1 ether
        ) {
            ""
        } else {
            " NOT"
        },
        format_units(node_native_balance, "ether").unwrap_or("Unknown balance".into())
    );

    if safe_in_nodesafe_registry.eq(&Address::ZERO) {
        info!("Please start the node. It will auto-register to node-safe registry");
    } else {
        info!("safe in node-safe registry {:?}", safe_in_nodesafe_registry);
    }

    Ok(safe_in_nodesafe_registry)
}

/// Quick check if the following values are correct, for one single node:
/// 4. If Safe is owned by the correct owner(s)
/// 5. Safe’s wxHOPR balance and allowance
/// 6. if the module is enabled
/// 7. if node is included in the module
/// 8. Get all the targets of the safe (then check if channel and announcement are there)
/// 9. Get the owner of the module
pub async fn debug_node_safe_module_setup_main<P: Provider>(
    hopr_token: HoprTokenInstance<Arc<P>>,
    module_address: &Address,
    node_address: &Address,
    safe_address: &Address,
    channel_address: &Address,
    announce_address: &Address,
) -> Result<(), MulticallError> {
    let provider = hopr_token.provider();

    let safe = SafeSingleton::new(safe_address.to_owned(), provider.clone());
    let module = ModuleSingleton::new(module_address.to_owned(), provider.clone());

    info!("checking for safe {:?} module {:?}", safe_address, module_address);
    let multicall = provider
        .multicall()
        // 4. get owners of the safe
        .add(safe.getOwners())
        // 5.a. get the wxHOPR balance for the safe address
        .add(hopr_token.balanceOf(*safe_address))
        // 5.b. get the wxHOPR balance for the safe address
        .add(hopr_token.allowance(*safe_address, *channel_address))
        // 6. if the module is enabled
        .add(safe.isModuleEnabled(*module_address))
        // 7. if node is included in the module
        .add(module.isNode(*node_address))
        // 7. get targets of the safe
        .add(module.getTargets())
        // 8. get owner of the module
        .add(module.owner());

    let (
        safe_owners,
        safe_wxhopr_balance,
        safe_wxhopr_allownace,
        is_module_enabled,
        is_node_included,
        module_targets,
        module_owner,
    ) = multicall.aggregate().await?;

    info!("safe has owners: {:?}", safe_owners);
    info!(
        "safe has wxHOPR balance: {:?}",
        format_units(safe_wxhopr_balance, "ether").unwrap_or("Unknown balance".into())
    );
    info!(
        "safe has wxHOPR allowance: {:?}",
        format_units(safe_wxhopr_allownace, "ether").unwrap_or("Unknown balance".into())
    );
    info!("module is enabled: {:?}", is_module_enabled);
    info!("node is included in the module: {:?}", is_node_included);
    info!("module has targets:");
    for target in module_targets {
        let target_address = format!("{target:#x}");
        let has_channels = target_address.contains(&format!("{channel_address:#x}"));
        let has_announcement = target_address.contains(&format!("{announce_address:#x}"));
        // check if it contains channel and announcement
        info!(
            "Target {:?} has channels {:?} has announcement {:?}",
            target_address, has_channels, has_announcement
        );
    }

    info!(
        "module owner: {:?} same as safe address: {:?}",
        module_owner,
        module_owner.eq(safe_address)
    );
    Ok(())
}

pub type AnvilRpcClient = FillProvider<
    JoinFill<
        JoinFill<Identity, JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Used for testing. Creates RPC client to the local Anvil instance.
pub fn create_rpc_client_to_anvil(
    anvil: &hopr_bindings::exports::alloy::node_bindings::AnvilInstance,
    signer: &hopr_crypto_types::keypairs::ChainKeypair,
) -> Arc<AnvilRpcClient> {
    use hopr_bindings::exports::alloy::{
        providers::ProviderBuilder, rpc::client::ClientBuilder, signers::local::PrivateKeySigner,
        transports::http::ReqwestTransport,
    };
    use hopr_crypto_types::keypairs::Keypair;

    let wallet = PrivateKeySigner::from_slice(signer.secret().as_ref()).expect("failed to construct wallet");

    let transport_client = ReqwestTransport::new(anvil.endpoint_url());

    let rpc_client = ClientBuilder::default().transport(transport_client.clone(), transport_client.guess_local());

    let provider = ProviderBuilder::new().wallet(wallet).connect_client(rpc_client);

    Arc::new(provider)
}

#[cfg(test)]
mod tests {
    use std::vec;

    use hopr_bindings::{
        exports::alloy::{primitives::address, sol_types::SolValue},
        hopr_announcements::HoprAnnouncements,
        hopr_channels::HoprChannels,
        hopr_node_safe_registry::HoprNodeSafeRegistry,
        hopr_node_stake_factory::HoprNodeStakeFactory,
        hopr_token::HoprToken,
    };
    use hopr_crypto_types::keypairs::{ChainKeypair, Keypair};
    use hopr_primitive_types::prelude::BytesRepresentable;
    use tracing_subscriber::{EnvFilter, Registry, fmt, prelude::*};

    use super::*;
    use crate::utils::{ContractInstances, a2h, create_anvil};

    fn init_tracing() {
        // Use RUST_LOG if set, otherwise default to "debug" for verbose test output
        let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

        // Match main.rs formatting style
        let format = fmt::layer()
            .with_level(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(false)
            .with_test_writer(); // ensures logs show up in `cargo test`

        // Set the global subscriber (harmless no-op if already initialized)
        let _ = Registry::default().with(env_filter).with(format).try_init();
    }

    fn get_random_address_for_testing() -> Address {
        // Creates a random Ethereum address, only used for testing
        Address::new(hopr_crypto_random::random_bytes::<
            { hopr_primitive_types::primitives::Address::SIZE },
        >())
    }

    #[tokio::test]
    async fn test_native_and_token_balances_in_anvil_with_multicall() -> anyhow::Result<()> {
        // create a keypair
        let kp = ChainKeypair::random();
        let kp_address = Address::from(&kp.public().to_address().into());

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        // deploy hopr contracts
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;

        // get native and token balances
        let (native_balance, token_balance) = get_native_and_token_balances(instances.token, vec![kp_address]).await?;
        assert_eq!(native_balance.len(), 1, "invalid native balance lens");
        assert_eq!(token_balance.len(), 1, "invalid token balance lens");
        assert_eq!(native_balance[0].to::<u64>(), 0u64, "wrong native balance");
        assert_eq!(token_balance[0].to::<u64>(), 0u64, "wrong token balance");
        drop(anvil);
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_or_mint_tokens_in_anvil_with_multicall() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut addresses: Vec<Address> = Vec::new();
        for _ in 0..4 {
            addresses.push(get_random_address_for_testing());
        }
        let desired_amount = vec![U256::from(1), U256::from(2), U256::from(3), U256::from(4)];

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        // deploy hopr contracts
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        println!("deployed hopr contracts {:?}", instances);

        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // grant deployer token minter role
        let encoded_minter_role = keccak256(b"MINTER_ROLE");
        instances
            .token
            .grantRole(encoded_minter_role, a2h(contract_deployer.public().to_address()))
            .send()
            .await?
            .watch()
            .await?;

        // test the deployer has minter role now
        let check_minter_role = instances
            .token
            .hasRole(encoded_minter_role, a2h(contract_deployer.public().to_address()))
            .call()
            .await?;
        assert!(check_minter_role, "deployer does not have minter role yet");

        // transfer or mint tokens to addresses
        let total_transferred_amount =
            transfer_or_mint_tokens(instances.token.clone(), addresses.clone(), desired_amount.clone()).await?;

        // get native and token balances
        let (native_balance, token_balance) = get_native_and_token_balances(instances.token, addresses.clone()).await?;

        assert_eq!(native_balance.len(), 4, "invalid native balance lens");
        assert_eq!(token_balance.len(), 4, "invalid token balance lens");
        for (i, amount) in desired_amount.iter().enumerate() {
            assert_eq!(&token_balance[i], amount, "token balance unmatch");
        }

        assert_eq!(
            total_transferred_amount,
            U256::from(10),
            "amount transferred does not equal to the desired amount"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_or_mint_tokens_in_anvil_with_one_recipient() -> anyhow::Result<()> {
        let addresses: Vec<Address> = vec![get_random_address_for_testing()];
        let desired_amount = vec![U256::from(42)];

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        // deploy hopr contracts
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");

        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // grant deployer token minter role
        let encoded_minter_role = keccak256(b"MINTER_ROLE");
        instances
            .token
            .grantRole(encoded_minter_role, a2h(contract_deployer.public().to_address()))
            .send()
            .await?
            .watch()
            .await?;

        // test the deployer has minter role now
        let check_minter_role = instances
            .token
            .hasRole(encoded_minter_role, a2h(contract_deployer.public().to_address()))
            .call()
            .await?;
        assert!(check_minter_role, "deployer does not have minter role yet");

        // transfer or mint tokens to addresses
        let total_transferred_amount =
            transfer_or_mint_tokens(instances.token.clone(), addresses.clone(), desired_amount.clone()).await?;

        // get native and token balances
        let (native_balance, token_balance) = get_native_and_token_balances(instances.token, addresses.clone()).await?;
        assert_eq!(native_balance.len(), 1, "invalid native balance lens");
        assert_eq!(token_balance.len(), 1, "invalid token balance lens");
        for (i, amount) in desired_amount.iter().enumerate() {
            assert_eq!(&token_balance[i], amount, "token balance unmatch");
        }

        assert_eq!(
            total_transferred_amount, desired_amount[0],
            "amount transferred does not equal to the desired amount"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_or_mint_tokens_in_anvil_without_recipient() -> anyhow::Result<()> {
        let addresses: Vec<Address> = Vec::new();
        let desired_amount: Vec<U256> = Vec::new();

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        // deploy hopr contracts
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");

        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;

        // transfer or mint tokens to addresses
        let total_transferred_amount =
            transfer_or_mint_tokens(instances.token.clone(), addresses.clone(), desired_amount.clone()).await?;

        // get native and token balances
        let (native_balance, token_balance) = get_native_and_token_balances(instances.token, addresses.clone()).await?;
        assert_eq!(native_balance.len(), 0, "invalid native balance lens");
        assert_eq!(token_balance.len(), 0, "invalid token balance lens");
        // for (i, amount) in desired_amount.iter().enumerate() {
        //     assert_eq!(token_balance[i].as_u64(), amount.as_u64(), "token balance unmatch");
        // }

        assert_eq!(
            total_transferred_amount,
            U256::from(0),
            "amount transferred does not equal to the desired amount"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_native_tokens_in_anvil_with_multicall() -> anyhow::Result<()> {
        let mut addresses: Vec<Address> = Vec::new();
        for _ in 0..4 {
            addresses.push(get_random_address_for_testing());
        }
        let desired_amount = vec![U256::from(1), U256::from(2), U256::from(3), U256::from(4)];

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");

        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;

        // transfer native tokens to addresses
        let total_transferred_amount =
            transfer_native_tokens(client.clone(), addresses.clone(), desired_amount.clone()).await?;

        // get native and token balances
        let (native_balance, token_balance) = get_native_and_token_balances(instances.token, addresses.clone()).await?;
        assert_eq!(native_balance.len(), 4, "invalid native balance lens");
        assert_eq!(token_balance.len(), 4, "invalid token balance lens");
        for (i, amount) in desired_amount.iter().enumerate() {
            assert_eq!(&native_balance[i], amount, "native balance unmatch");
        }

        assert_eq!(
            total_transferred_amount,
            U256::from(10),
            "amount transferred does not equal to the desired amount"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_deploy_proxy() -> anyhow::Result<()> {
        let prediction = deploy_proxy(
            address!("41675c099f32341bf84bfc5382af534df5c7461a"),
            hex!("09e458584ce79e57b65cb303dc136c5d53e17b676599b9b7bc03815e0eef5172"),
            SAFE_SAFEPROXYFACTORY_ADDRESS,
        )?;

        assert_eq!(
            prediction,
            address!("ec5c8d045dfa1f93785125c26e187e9439f67105"),
            "cannot reproduce proxy"
        );
        Ok(())
    }
    #[tokio::test]
    async fn test_get_salt_from_salt_nonce() -> anyhow::Result<()> {
        let salt = get_salt_from_salt_nonce(
            hex!("b63e800d00000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000002a15de4410d4c8af0a7b6c12803120f43c42b8200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000098b275485c406573d042848d66eb9d63fca311c00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000").into(),
            B256::from_str("E5EAFDE6416CCB48925026B6313D62A98C0997E03591E29EB4CF1EA968D6BC8F")?// &U256::from_str("103994836888229670573364883831672511342967953907147914065931589108526220754063")?.into(),
        )?;

        assert_eq!(
            salt.to_vec(),
            Bytes::from_str("09e458584ce79e57b65cb303dc136c5d53e17b676599b9b7bc03815e0eef5172")?,
            "cannot reproduce salt"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_safe_and_module_address_prediction() -> anyhow::Result<()> {
        init_tracing();
        // testing value extracted from https://dashboard.tenderly.co/tx/xdai/0x510e3ac3dc7939cae2525a0b0f096ad709b23d94169e0fbf2e1154fdd6911c49?trace=0
        let _ = env_logger::builder().is_test(true).try_init();

        // prepare some input data
        let mut admin_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            admin_addresses.push(get_random_address_for_testing());
        }

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        let caller = client.default_signer_address();

        // build the default permissions of capabilities
        let default_target = build_default_target(*instances.channels.address())?;

        // salt nonce
        let curr_nonce = client.get_transaction_count(caller).pending().await?;
        let nonce = keccak256((caller, U256::from(curr_nonce)).abi_encode_packed());

        let safe_address = predict_safe_address(
            *instances.stake_factory.address(),
            vec![caller],
            nonce,
            SAFE_COMPATIBILITYFALLBACKHANDLER_ADDRESS,
            SAFE_SAFE_L2_ADDRESS,
            SAFE_SAFEPROXYFACTORY_ADDRESS,
        )?;

        debug!("predict_safe_address {:?}", safe_address);

        let safe_address_predicted_from_sc = instances
            .stake_factory
            .predictSafeAddress(vec![caller], nonce.into())
            .call()
            .await?;
        debug!(
            "predicted safe address from smart contract {:?}",
            safe_address_predicted_from_sc.to_string()
        );

        assert_eq!(
            safe_address, safe_address_predicted_from_sc,
            "safe address prediction local vs smart contract does not match"
        );

        let module_address_predicted_from_sc = instances
            .stake_factory
            .predictModuleAddress_1(
                caller,
                nonce.into(),
                safe_address,
                default_target.into(),
            )
            .call()
            .await?;
        info!(
            "predicted module address from smart contract {:?}",
            module_address_predicted_from_sc.to_string()
        );

        // deploy a safe proxy instance and a module proxy instance with multicall as an owner
        let deployment_receipt = instances
            .stake_factory
            .clone(
                //*instances.module_implementation.address(),
                nonce.into(),
                default_target.into(),
                vec![caller],
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        // parse the safe and module addresses
        let module_log = deployment_receipt
            .decoded_log::<HoprNodeStakeFactory::NewHoprNodeStakeModule>()
            .ok_or_else(|| anyhow::anyhow!("Module log not found"))?;

        let safe_log = deployment_receipt
            .decoded_log::<HoprNodeStakeFactory::NewHoprNodeStakeSafe>()
            .ok_or_else(|| anyhow::anyhow!("Safe log not found"))?;

        let module_addr = module_log.instance;
        let safe_addr = safe_log.instance;

        info!("deployed module address {:?}", module_addr);

        assert_eq!(safe_addr, safe_address, "safe prediction does not match");
        assert_eq!(
            module_addr, module_address_predicted_from_sc,
            "module prediction does not match"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_deploy_safe_and_module_for_edge_node() -> anyhow::Result<()> {
        init_tracing();
        let _ = env_logger::builder().is_test(true).try_init();

        // prepare some input data
        let mut admin_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            admin_addresses.push(get_random_address_for_testing());
        }

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        // grant deployer token minter role
        let encoded_minter_role = keccak256(b"MINTER_ROLE");
        instances
            .token
            .grantRole(encoded_minter_role, a2h(contract_deployer.public().to_address()))
            .send()
            .await?
            .watch()
            .await?;
        // mint tokens to the caller
        let desired_amount = U256::from(777_777_777_u128);
        transfer_or_mint_tokens(
            instances.token.clone(),
            vec![a2h(contract_deployer.public().to_address())],
            vec![desired_amount.clone()],
        )
        .await?;

        // deploy safe and module
        let (safe, node_module) = deploy_safe_module_for_single_edge_node(
            instances.stake_factory,
            *instances.token.address(),
            *instances.channels.address(),
            U256::from(123_456_u128),
            desired_amount,
            admin_addresses.clone(),
            true,
        )
        .await?;

        // check announcement is a target
        let try_get_announcement_target = node_module
            .tryGetTarget(*instances.announcements.address())
            .call()
            .await?;

        assert!(try_get_announcement_target._0, "announcement is not a target");

        // check allowance for channel contract has increased
        let allowance = instances
            .token
            .allowance(*safe.address(), *instances.channels.address())
            .call()
            .await?;

        assert_eq!(
            allowance,
            U256::from(1_000_000_000_000_000_000_000_u128),
            "allowance is not set"
        );

        // check nodes (admins) have been included in the module
        for node_address in &admin_addresses {
            let is_node_included = node_module.isNode(*node_address).call().await?;
            assert!(is_node_included, "failed to include a node");
        }

        // check owners are provided admins
        let owners = safe.getOwners().call().await?;
        let thresold = safe.getThreshold().call().await?;

        assert_eq!(owners.len(), 2, "should have 2 owners");
        for (i, owner) in owners.iter().enumerate() {
            assert_eq!(owner, &admin_addresses[i], "admin is wrong");
        }
        assert_eq!(thresold, U256::from(1), "threshold should be one");
        Ok(())
    }

    #[tokio::test]
    async fn test_deploy_safe_and_module() -> anyhow::Result<()> {
        init_tracing();
        let _ = env_logger::builder().is_test(true).try_init();

        // prepare some input data
        let mut admin_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            admin_addresses.push(get_random_address_for_testing());
        }
        let mut node_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            node_addresses.push(get_random_address_for_testing());
        }

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");

        println!("deployed hopr contracts {:?}", instances);
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        // register some nodes
        let (safe, node_module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *instances.channels.address(),
            node_addresses.clone(),
            admin_addresses.clone(),
            U256::from(2),
        )
        .await?;

        // check announcement is a target
        let try_get_announcement_target = node_module
            .tryGetTarget(*instances.announcements.address())
            .call()
            .await?;

        assert!(try_get_announcement_target._0, "announcement is not a target");

        // check allowance for channel contract has increased
        let allowance = instances
            .token
            .allowance(*safe.address(), *instances.channels.address())
            .call()
            .await?;

        assert_eq!(
            allowance,
            U256::from(1_000_000_000_000_000_000_000_u128),
            "allowance is not set"
        );

        // check nodes have been included in the module
        for node_address in node_addresses {
            let is_node_included = node_module.isNode(node_address).call().await?;
            assert!(is_node_included, "failed to include a node");
        }

        // check owners are provided admins
        let owners = safe.getOwners().call().await?;
        let thresold = safe.getThreshold().call().await?;

        assert_eq!(owners.len(), 2, "should have 2 owners");
        for (i, owner) in owners.iter().enumerate() {
            assert_eq!(owner, &admin_addresses[i], "admin is wrong");
        }
        assert_eq!(thresold, U256::from(2), "threshold should be two");
        Ok(())
    }

    #[tokio::test]
    async fn test_safe_tx_via_multisend() -> anyhow::Result<()> {
        // set allowance for token transfer for the safe multiple times
        let _ = env_logger::builder().is_test(true).try_init();

        // prepare some input data
        let desired_amount = vec![U256::from(1), U256::from(2), U256::from(3), U256::from(4)];

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        // create a safe
        let (safe, _node_module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *instances.channels.address(),
            vec![],
            vec![a2h(contract_deployer.public().to_address())],
            U256::from(1),
        )
        .await?;

        // check owner of safe
        let is_owner = safe.getOwners().call().await?;
        assert_eq!(is_owner.len(), 1, "safe has too many owners");
        assert_eq!(
            is_owner[0].0.0,
            contract_deployer.public().to_address().as_ref(),
            "safe wrong owner"
        );

        // check allowance for channel contract is zero
        let allowance = instances
            .token
            .allowance(*safe.address(), *instances.channels.address())
            .call()
            .await?;

        assert_eq!(
            allowance,
            U256::from(1_000_000_000_000_000_000_000_u128),
            "allowance is not set"
        );

        let mut multisend_txns: Vec<MultisendTransaction> = Vec::new();
        for val in desired_amount {
            multisend_txns.push(MultisendTransaction {
                // build multisend tx payload
                encoded_data: approveCall {
                    spender: *instances.channels.address(),
                    value: val,
                }
                .abi_encode()
                .into(),
                tx_operation: SafeTxOperation::Call,
                to: *instances.token.address(),
                value: U256::ZERO,
            });
        }

        // get chain_id and safe_nonce
        let chain_id = client.get_chain_id().await?;
        let safe_nonce = safe.nonce().call().await?;
        debug!("safe address {:?}", safe.address());
        debug!("chain_id {:?}", chain_id);
        debug!("safe_nonce {:?}", safe_nonce);

        // send safe transaction
        send_multisend_safe_transaction_with_threshold_one(
            safe.clone(),
            contract_deployer,
            SAFE_MULTISEND_ADDRESS,
            multisend_txns,
            U256::from(chain_id),
            safe_nonce,
        )
        .await?;

        // check allowance for channel contract is 4
        let new_allowance = instances
            .token
            .allowance(*safe.address(), *instances.channels.address())
            .call()
            .await?;

        assert_eq!(new_allowance, U256::from(4), "final allowance is not desired");
        Ok(())
    }

    #[tokio::test]
    async fn test_register_nodes_to_node_safe_registry() -> anyhow::Result<()> {
        // set allowance for token transfer for the safe multiple times
        let _ = env_logger::builder().is_test(true).try_init();

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        let deployer_vec: Vec<Address> = vec![a2h(contract_deployer.public().to_address())];

        // create a safe
        let (safe, node_module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *instances.channels.address(),
            deployer_vec.clone(),
            deployer_vec.clone(),
            U256::from(1),
        )
        .await?;

        // register one node to safe
        instances
            .safe_registry
            .registerSafeByNode(*safe.address())
            .send()
            .await?
            .watch()
            .await?;

        // get registration info
        let get_registered_safe =
            get_registered_safes_for_nodes_on_node_safe_registry(instances.safe_registry.clone(), deployer_vec.clone())
                .await?;

        assert_eq!(get_registered_safe.len(), 1, "cannot read registered safe");
        assert_eq!(&get_registered_safe[0], safe.address(), "registered safe is wrong");

        // deregister the node from safe
        deregister_nodes_from_node_safe_registry_and_remove_from_module(
            instances.safe_registry.clone(),
            deployer_vec.clone(),
            vec![*node_module.address()],
            contract_deployer.clone(),
        )
        .await?;

        // get registration info (updated)
        let get_registered_safe =
            get_registered_safes_for_nodes_on_node_safe_registry(instances.safe_registry.clone(), deployer_vec.clone())
                .await?;

        assert_eq!(get_registered_safe.len(), 1, "cannot read registered safe");
        assert_eq!(get_registered_safe[0], Address::ZERO, "node is still registered");

        // node is removed
        let is_removed = node_module
            .isNode(a2h(contract_deployer.public().to_address()))
            .call()
            .await?;
        assert!(!is_removed, "node is not removed");
        Ok(())
    }

    #[tokio::test]
    async fn test_include_nodes_to_module() -> anyhow::Result<()> {
        // set allowance for token transfer for the safe multiple times
        let _ = env_logger::builder().is_test(true).try_init();

        let mut node_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            node_addresses.push(get_random_address_for_testing());
        }

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        let deployer_vec: Vec<Address> = vec![a2h(contract_deployer.public().to_address())];

        // create a safe
        let (safe, node_module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *instances.channels.address(),
            vec![],
            deployer_vec.clone(),
            U256::from(1),
        )
        .await?;

        // check ndoes are not included
        for node_addr in node_addresses.clone() {
            // node is removed
            let node_is_not_included = node_module.isNode(node_addr).call().await?;
            assert!(!node_is_not_included, "node should not be included");
        }

        // include nodes to safe
        include_nodes_to_module(safe, node_addresses.clone(), *node_module.address(), contract_deployer).await?;

        // check nodes are included
        // check nodes are not included
        for node_addr in node_addresses {
            // node is removed
            let node_is_included = node_module.isNode(node_addr).call().await?;
            assert!(node_is_included, "node should be included");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_migrate_nodes_to_new_network() -> anyhow::Result<()> {
        // set allowance for token transfer for the safe multiple times
        let _ = env_logger::builder().is_test(true).try_init();

        let mut node_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            node_addresses.push(get_random_address_for_testing());
        }

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let self_address: Address = a2h(contract_deployer.public().to_address());
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        // deploy some new contracts for the new network
        let new_safe_registry = HoprNodeSafeRegistry::deploy(client.clone()).await?;
        let new_token = HoprToken::deploy(client.clone()).await?;
        let new_channels = HoprChannels::deploy(
            client.clone(),
            *new_token.address(),
            1_u32,
            *new_safe_registry.address(),
        )
        .await?;
        let new_announcements = HoprAnnouncements::deploy(client.clone()).await?;

        let deployer_vec: Vec<Address> = vec![self_address];

        // create a safe
        let (safe, node_module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *instances.channels.address(),
            vec![],
            deployer_vec.clone(),
            U256::from(1),
        )
        .await?;

        // check new network is not included
        let old_channels_inclusion = node_module.tryGetTarget(*instances.channels.address()).call().await?;
        assert!(old_channels_inclusion._0, "old channel should be included");
        let new_channels_inclusion = node_module.tryGetTarget(*new_channels.address()).call().await?;
        assert!(!new_channels_inclusion._0, "new channel should not be included");

        // migrate nodes
        migrate_nodes(
            safe,
            *node_module.address(),
            *new_channels.address(),
            *new_token.address(),
            *new_announcements.address(),
            U256::MAX,
            contract_deployer,
        )
        .await?;

        // check new network is included
        let old_channels_inclusion = node_module.tryGetTarget(*instances.channels.address()).call().await?;
        assert!(old_channels_inclusion._0, "old channel should still be included");
        let new_channels_inclusion = node_module.tryGetTarget(*new_channels.address()).call().await?;
        assert!(new_channels_inclusion._0, "new channel should now be included");
        Ok(())
    }

    #[tokio::test]
    async fn test_debug_node_safe_module_setup_main() -> anyhow::Result<()> {
        // set allowance for token transfer for the safe multiple times
        let _ = env_logger::builder().is_test(true).try_init();

        let mut node_addresses: Vec<Address> = Vec::new();
        for _ in 0..2 {
            node_addresses.push(get_random_address_for_testing());
        }

        // launch local anvil instance
        let anvil = create_anvil(None);
        let contract_deployer = ChainKeypair::from_secret(anvil.keys()[0].to_bytes().as_ref())?;
        let client = create_rpc_client_to_anvil(&anvil, &contract_deployer);
        let instances = ContractInstances::deploy_for_testing(client.clone(), &contract_deployer)
            .await
            .expect("failed to deploy");
        // deploy multicall contract
        ContractInstances::deploy_multicall3(client.clone()).await?;
        // deploy safe suits
        ContractInstances::deploy_safe_suites(client.clone()).await?;

        let deployer_vec: Vec<Address> = vec![a2h(contract_deployer.public().to_address())];

        // create a safe
        let (_safe, _node_module) = deploy_safe_module_with_targets_and_nodes(
            instances.stake_factory,
            *instances.channels.address(),
            vec![],
            deployer_vec.clone(),
            U256::from(1),
        )
        .await?;

        Ok(())
    }
}
