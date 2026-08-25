use std::{ops::Add, str::FromStr};

use hopr_bindings::{
    constants::{
        DEFAULT_NODE_PERMISSIONS, DEPLOYSAFEANDMODULEANDINCLUDENODES_IDENTIFIER, DEPLOYSAFEMODULE_FUNCTION_IDENTIFIER,
        SAFE_COMPATIBILITYFALLBACKHANDLER_ADDRESS, SAFE_SAFE_L2_ADDRESS, SAFE_SAFEPROXYFACTORY_ADDRESS,
        SENTINEL_OWNERS,
    },
    exports::alloy::{
        network::TransactionBuilder,
        primitives::{Address, B256, Bytes, U256, aliases::U56},
        providers::{
            CallInfoTrait, MULTICALL3_ADDRESS,
            bindings::IMulticall3::{Call3, Call3Value, aggregate3Call, aggregate3ValueCall},
        },
        rpc::types::TransactionRequest,
        sol,
        sol_types::{SolCall, SolValue},
    },
    hopr_node_management_module::HoprNodeManagementModule::includeNodeCall,
    hopr_node_stake_factory::HoprNodeStakeFactory::{cloneCall, predictModuleAddress_1Call},
    hopr_service_registry::HoprServiceRegistry::{
        recoverTokensCall, registerServiceTypeCall, selfDeregisterCall, selfRegisterCall, selfUpdateCall,
        setNodeSafeRegistryCall, setRequirementCall, setSelfRegistrationBurnCall, setSelfUpdateBurnCall,
        setTypeRegistrationFeeCall, transferTypeOwnershipCall,
    },
    hopr_token::HoprToken::{approveCall, sendCall, transferCall},
    hopr_winning_probability_oracle::HoprWinningProbabilityOracle::setWinProbCall,
};
use hopr_types::internal::prelude::{ServiceMetadata, ServiceType, WinningProbability};
use tracing::{debug, info};

use crate::{
    methods::{
        SafeSingleton::removeOwnerCall, predict_safe_address, prepare_safe_tx_multicall_payload_from_owner_contract,
    },
    utils::{HelperErrors, build_default_target},
};

pub fn transfer_hopr_token_payload(
    token_address: Address,
    address: Address,
    amount: U256,
) -> Result<TransactionRequest, HelperErrors> {
    let transfer_function_payload = transferCall {
        recipient: address,
        amount,
    }
    .abi_encode();
    let tx = TransactionRequest::default()
        .with_to(token_address)
        .with_input(transfer_function_payload);
    Ok(tx)
}

pub fn transfer_native_token_payload(
    addresses: Vec<Address>,
    amounts: Vec<U256>,
) -> Result<TransactionRequest, HelperErrors> {
    // check if two vectors have the same length
    if addresses.len() != amounts.len() {
        return Err(HelperErrors::MissingParameter(
            "Addresses and amounts length mismatch".into(),
        ));
    }

    // calculate the sum of tokens to be sent
    let total = amounts.iter().fold(U256::ZERO, |acc, cur| acc.add(cur));
    debug!(
        "total amount of native tokens to be transferred {:?}",
        total.to_string()
    );

    let calls: Vec<Call3Value> = addresses
        .into_iter()
        .zip(amounts)
        .map(|(addr, amount)| Call3Value {
            target: addr,
            allowFailure: false,
            value: amount,
            callData: Bytes::default(),
        })
        .collect::<Vec<_>>();
    let aggregate3_value_payload = aggregate3ValueCall { calls }.abi_encode();
    let tx = TransactionRequest::default()
        .with_to(MULTICALL3_ADDRESS)
        .with_input(aggregate3_value_payload)
        .with_value(total);
    Ok(tx)
}

/// Predict safe address deployed by the edge node
pub fn edge_node_predict_safe_address(
    hopr_node_stake_factory_address: Address,
    nonce: U256,
    admins: Vec<Address>,
) -> Result<Address, HelperErrors> {
    if admins.is_empty() {
        return Err(HelperErrors::MissingParameter(
            "At least one admin address must be provided".into(),
        ));
    }

    // build a new temporary admin
    let mut temporary_admins: Vec<Address> = admins.clone();
    temporary_admins.insert(0, MULTICALL3_ADDRESS);
    info!(
        "temporary_admins expands from admin from {:?} addresses to {:?}",
        admins.len(),
        temporary_admins.len()
    );

    let safe_address = predict_safe_address(
        hopr_node_stake_factory_address,
        temporary_admins.clone(),
        nonce.into(),
        SAFE_COMPATIBILITYFALLBACKHANDLER_ADDRESS,
        SAFE_SAFE_L2_ADDRESS,
        SAFE_SAFEPROXYFACTORY_ADDRESS,
    )?;
    Ok(safe_address)
}

pub fn edge_node_predict_module_address(
    hopr_channels_address: Address,
    predicted_safe_address: Address,
    nonce: U256,
) -> Result<Vec<u8>, HelperErrors> {
    // build the default permissions of capabilities
    let default_target = build_default_target(hopr_channels_address)?;

    let predict_module_address_payload = predictModuleAddress_1Call {
        caller: MULTICALL3_ADDRESS,
        nonce,
        safe: predicted_safe_address,
        defaultTarget: default_target.into(),
    }
    .abi_encode();
    Ok(predict_module_address_payload)
}

/// Payload for deploying safe module with target addresses and node addresses
/// This payload assumes the threshold is one.
/// The prediceted safe address can be obtained by calling `edge_node_predict_safe_address`
/// The predicted module address can be obtained by calling `predictModuleAddress_1` on `hopr_node_stake_factory`
/// providing MULTICALL3_ADDRESS, nonce.into(), safe_address, default_target
pub fn edge_node_deploy_safe_module_with_targets_and_nodes_payload(
    predicted_safe_address: Address,
    predicted_module_address: Address,
    hopr_node_stake_factory_address: Address,
    hopr_channels_address: Address,
    node_addresses: Vec<Address>,
    nonce: U256,
    admins: Vec<Address>,
) -> Result<TransactionRequest, HelperErrors> {
    if admins.is_empty() {
        return Err(HelperErrors::MissingParameter(
            "At least one admin address must be provided".into(),
        ));
    }

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

    // Use multicall to deploy a safe proxy instance and a module proxy instance with multicall as an owner
    let mut multicall_payloads: Vec<Call3> = vec![];
    multicall_payloads.push(Call3 {
        target: hopr_node_stake_factory_address,
        allowFailure: false,
        callData: cloneCall {
            nonce,
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
                predicted_safe_address,
                predicted_module_address,
                predicted_safe_address,
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
        _threshold: U256::from(1),
    }
    .abi_encode();

    let multicall_payload_5 = prepare_safe_tx_multicall_payload_from_owner_contract(
        predicted_safe_address,
        predicted_safe_address,
        predicted_safe_address,
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
    Ok(tx)
}

sol! (
    #![sol(all_derives)]
    struct UserData {
        bytes32 functionIdentifier;
        uint256 nonce;
        bytes32 defaultTarget;
        address[] memory admins;
    }
);

/// Deploy a safe and a module, while sending tokens to the safe for single edge node.
/// It's possible to only deploy a safe and a module without onboarding the node
/// Alternatively, the node will be included in the module after deployment
/// All the "admins" will be the nodes added to the module
/// Returns safe proxy address and module proxy address
pub fn edge_node_deploy_safe_module_and_maybe_include_node(
    hopr_node_stake_factory_address: Address,
    hopr_token_address: Address,
    hopr_channels_address: Address,
    nonce: U256,
    amount: U256,
    admins: Vec<Address>,
    should_include_node: bool,
) -> Result<TransactionRequest, HelperErrors> {
    // build the default permissions of capabilities
    let default_target = build_default_target(hopr_channels_address)?;

    let user_data = if should_include_node {
        UserData {
            functionIdentifier: DEPLOYSAFEANDMODULEANDINCLUDENODES_IDENTIFIER,
            nonce,
            defaultTarget: default_target.into(),
            admins,
        }
        .abi_encode()[32..]
            .to_vec()
    } else {
        UserData {
            functionIdentifier: DEPLOYSAFEMODULE_FUNCTION_IDENTIFIER,
            nonce,
            defaultTarget: default_target.into(),
            admins,
        }
        .abi_encode()[32..]
            .to_vec()
    };

    debug!("User data for deploying safe and module: {:?}", hex::encode(&user_data));
    let tx_payload = sendCall {
        recipient: hopr_node_stake_factory_address,
        amount,
        data: user_data.into(),
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .with_to(hopr_token_address)
        .with_input(tx_payload);
    Ok(tx)
}

/// Set the global minimum winning probability in the HoprWinningProbabilityOracle contract
pub fn set_winning_probability(
    hopr_win_prob_oracle_address: Address,
    winning_probability: f64,
) -> Result<TransactionRequest, HelperErrors> {
    // the winning probablity should be in range of 0.0 to 1.0 (inclusive)
    if !(0.0..=1.0).contains(&winning_probability) {
        return Err(HelperErrors::ParseError(
            "Winning probability must be between 0.0 and 1.0".into(),
        ));
    }
    // convert the winning probability to the format required by the contract
    let winning_probability_val = WinningProbability::try_from(winning_probability)
        .map_err(|_| HelperErrors::ParseError("Failed to convert winning probability to the required format".into()))?;

    info!(
        winning_probability = %winning_probability_val,
        win_prob_f64 = %winning_probability,
        "Setting the global minimum winning probability"
    );

    let tx_payload = setWinProbCall {
        _newWinProb: U56::from_be_slice(&winning_probability_val.as_encoded()),
    }
    .abi_encode();

    let tx = TransactionRequest::default()
        .with_to(hopr_win_prob_oracle_address)
        .with_input(tx_payload);
    Ok(tx)
}

/// The `bytes32` service type id as the `HoprServiceRegistry` ABI expects it.
fn service_type_id(service_type: &ServiceType) -> B256 {
    B256::from(service_type.as_encoded())
}

/// Builds a request carrying `payload` to `contract_address`.
fn call_payload(contract_address: Address, payload: Vec<u8>) -> TransactionRequest {
    TransactionRequest::default()
        .with_to(contract_address)
        .with_input(payload)
}

/// Approve `spender` to pull exactly `amount` wxHOPR from the caller.
///
/// The service registry pulls its fees with `transferFrom`, so every paid registry call needs an
/// allowance. The allowance is exact rather than unlimited on purpose: it is the caller's price
/// protection. A fee raised between reading it and executing the call runs out of allowance and
/// reverts, instead of silently overpaying (RFC section 3.6).
pub fn approve_hopr_token_payload(token_address: Address, spender: Address, amount: U256) -> TransactionRequest {
    call_payload(token_address, approveCall { spender, value: amount }.abi_encode())
}

/// Register `node` under `service_type` with `metadata`.
///
/// `msg.sender` must be the Safe bound to `node` in the node-safe registry, so this belongs in a
/// Safe transaction, preceded by an [`approve_hopr_token_payload`] for the type's registration
/// burn.
pub fn self_register_service_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    node: Address,
    metadata: &ServiceMetadata,
) -> TransactionRequest {
    let payload = selfRegisterCall {
        serviceType: service_type_id(service_type),
        node,
        metadata: Bytes::copy_from_slice(metadata.as_ref()),
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Replace the metadata of the entry of `node` under `service_type`.
///
/// Same caller and allowance rules as [`self_register_service_payload`], against the type's
/// update burn.
pub fn self_update_service_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    node: Address,
    metadata: &ServiceMetadata,
) -> TransactionRequest {
    let payload = selfUpdateCall {
        serviceType: service_type_id(service_type),
        node,
        metadata: Bytes::copy_from_slice(metadata.as_ref()),
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Remove the entry of `node` under `service_type`.
///
/// Gated by the node-safe binding alone: it is free and takes no allowance, so that a bound node
/// can always delist itself (invariant I6).
pub fn self_deregister_service_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    node: Address,
) -> TransactionRequest {
    let payload = selfDeregisterCall {
        serviceType: service_type_id(service_type),
        node,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Claim `service_type` and become its owner.
///
/// Callable by anyone, first come first served, and payable in the global type registration fee,
/// so it needs an [`approve_hopr_token_payload`] for that fee.
pub fn register_service_type_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    requirement: Address,
    registration_burn: U256,
    update_burn: U256,
) -> TransactionRequest {
    let payload = registerServiceTypeCall {
        serviceType: service_type_id(service_type),
        requirement,
        registrationBurn: registration_burn,
        updateBurn: update_burn,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Point `service_type` at a new requirement contract, or open it up with the zero address.
pub fn set_service_type_requirement_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    requirement: Address,
) -> TransactionRequest {
    let payload = setRequirementCall {
        serviceType: service_type_id(service_type),
        requirement,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Set the burn charged for registering an entry under `service_type`.
pub fn set_self_registration_burn_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    amount: U256,
) -> TransactionRequest {
    let payload = setSelfRegistrationBurnCall {
        serviceType: service_type_id(service_type),
        amount,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Set the burn charged for updating an entry under `service_type`.
pub fn set_self_update_burn_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    amount: U256,
) -> TransactionRequest {
    let payload = setSelfUpdateBurnCall {
        serviceType: service_type_id(service_type),
        amount,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Hand ownership of `service_type` to `new_owner`.
///
/// The zero address abandons the type, which is one way and unrecoverable (RFC section 3.1), and
/// so is a wrong live address. The caller is responsible for confirming the target.
pub fn transfer_service_type_ownership_payload(
    service_registry_address: Address,
    service_type: &ServiceType,
    new_owner: Address,
) -> TransactionRequest {
    let payload = transferTypeOwnershipCall {
        serviceType: service_type_id(service_type),
        newOwner: new_owner,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Set the global fee charged for registering a new service type.
pub fn set_type_registration_fee_payload(service_registry_address: Address, amount: U256) -> TransactionRequest {
    call_payload(
        service_registry_address,
        setTypeRegistrationFeeCall { amount }.abi_encode(),
    )
}

/// Repoint the registry at another node-safe registry.
///
/// The contract probes the new registry with `probe_node` and requires it to resolve to
/// `expected_safe`, which keeps a typo from silently orphaning every entry.
pub fn set_node_safe_registry_payload(
    service_registry_address: Address,
    node_safe_registry: Address,
    probe_node: Address,
    expected_safe: Address,
) -> TransactionRequest {
    let payload = setNodeSafeRegistryCall {
        nodeSafeRegistry_: node_safe_registry,
        probeNode: probe_node,
        expectedSafe: expected_safe,
    }
    .abi_encode();
    call_payload(service_registry_address, payload)
}

/// Sweep tokens that were transferred to the registry by mistake.
pub fn recover_service_registry_tokens_payload(
    service_registry_address: Address,
    token: Address,
    to: Address,
) -> TransactionRequest {
    call_payload(service_registry_address, recoverTokensCall { token, to }.abi_encode())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    /// `bytes32("gvpn:exit")`, the canonical GnosisVPN exit-node type id.
    const SERVICE_TYPE: ServiceType = ServiceType::GVPN_EXIT;
    const NODE: Address = Address::new(hex!("00000000000000000000000000000000000000aa"));
    const REQUIREMENT: Address = Address::new(hex!("00000000000000000000000000000000000000bb"));
    const NEW_OWNER: Address = Address::new(hex!("00000000000000000000000000000000000000cc"));
    const SPENDER: Address = Address::new(hex!("00000000000000000000000000000000000000dd"));
    const NODE_SAFE_REGISTRY: Address = Address::new(hex!("00000000000000000000000000000000000000e1"));
    const PROBE_NODE: Address = Address::new(hex!("00000000000000000000000000000000000000e2"));
    const EXPECTED_SAFE: Address = Address::new(hex!("00000000000000000000000000000000000000e3"));
    const TOKEN: Address = Address::new(hex!("00000000000000000000000000000000000000f1"));
    const RECIPIENT: Address = Address::new(hex!("00000000000000000000000000000000000000f2"));
    /// The contract under test, only ever the `to` of the request, never part of the calldata.
    const REGISTRY: Address = Address::new(hex!("0000000000000000000000000000000000000001"));

    /// 1 wxHOPR, `0x0de0b6b3a7640000`.
    fn one_token() -> U256 {
        U256::from(1_000_000_000_000_000_000u64)
    }

    /// 0.5 wxHOPR, `0x06f05b59d3b20000`.
    fn half_token() -> U256 {
        U256::from(500_000_000_000_000_000u64)
    }

    /// Returns the calldata of `tx`, asserting it targets `expected_to`.
    fn calldata(tx: &TransactionRequest, expected_to: Address) -> Vec<u8> {
        assert_eq!(
            tx.to.and_then(|kind| kind.to().copied()),
            Some(expected_to),
            "payload targets the wrong contract"
        );
        tx.input.input().expect("payload carries no calldata").to_vec()
    }

    // Every expected vector below was derived by hand, not read back from the bindings:
    // selector = first 4 bytes of keccak256 of the canonical signature, followed by the standard
    // ABI head/tail encoding of the arguments - one 32-byte word per static argument (addresses
    // right-aligned, `bytes32` left-aligned as stored), and for `bytes` a head word holding the
    // tail offset plus a tail of the length word followed by the right-padded data.

    #[test]
    fn test_self_register_service_payload_calldata() -> anyhow::Result<()> {
        // keccak256("selfRegister(bytes32,address,bytes)")[..4] = 0x326005af; three head words
        // (type, node, tail offset 0x60) then the `bytes` tail (length 5, "hello" right-padded).
        let expected = hex!(
            "326005af"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000aa"
            "0000000000000000000000000000000000000000000000000000000000000060"
            "0000000000000000000000000000000000000000000000000000000000000005"
            "68656c6c6f000000000000000000000000000000000000000000000000000000"
        );

        let metadata = ServiceMetadata::try_from(b"hello".to_vec())?;
        let tx = self_register_service_payload(REGISTRY, &SERVICE_TYPE, NODE, &metadata);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
        Ok(())
    }

    #[test]
    fn test_self_update_service_payload_calldata() -> anyhow::Result<()> {
        // keccak256("selfUpdate(bytes32,address,bytes)")[..4] = 0x210c3298; argument encoding is
        // identical to `selfRegister`.
        let expected = hex!(
            "210c3298"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000aa"
            "0000000000000000000000000000000000000000000000000000000000000060"
            "0000000000000000000000000000000000000000000000000000000000000005"
            "68656c6c6f000000000000000000000000000000000000000000000000000000"
        );

        let metadata = ServiceMetadata::try_from(b"hello".to_vec())?;
        let tx = self_update_service_payload(REGISTRY, &SERVICE_TYPE, NODE, &metadata);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
        Ok(())
    }

    #[test]
    fn test_self_deregister_service_payload_calldata() {
        // keccak256("selfDeregister(bytes32,address)")[..4] = 0x1e46f907; two static words.
        let expected = hex!(
            "1e46f907"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000aa"
        );

        let tx = self_deregister_service_payload(REGISTRY, &SERVICE_TYPE, NODE);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_register_service_type_payload_calldata() {
        // keccak256("registerServiceType(bytes32,address,uint256,uint256)")[..4] = 0x0ff55869;
        // four static words: type, requirement, 1e18 (0x0de0b6b3a7640000), 5e17 (0x06f05b59d3b20000).
        let expected = hex!(
            "0ff55869"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000bb"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
            "00000000000000000000000000000000000000000000000006f05b59d3b20000"
        );

        let tx = register_service_type_payload(REGISTRY, &SERVICE_TYPE, REQUIREMENT, one_token(), half_token());
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_set_service_type_requirement_payload_calldata() {
        // keccak256("setRequirement(bytes32,address)")[..4] = 0x326d1f22.
        let expected = hex!(
            "326d1f22"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000bb"
        );

        let tx = set_service_type_requirement_payload(REGISTRY, &SERVICE_TYPE, REQUIREMENT);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_set_self_registration_burn_payload_calldata() {
        // keccak256("setSelfRegistrationBurn(bytes32,uint256)")[..4] = 0xf13217a9.
        let expected = hex!(
            "f13217a9"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        );

        let tx = set_self_registration_burn_payload(REGISTRY, &SERVICE_TYPE, one_token());
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_set_self_update_burn_payload_calldata() {
        // keccak256("setSelfUpdateBurn(bytes32,uint256)")[..4] = 0x1cd0ad00.
        let expected = hex!(
            "1cd0ad00"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000006f05b59d3b20000"
        );

        let tx = set_self_update_burn_payload(REGISTRY, &SERVICE_TYPE, half_token());
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_transfer_service_type_ownership_payload_calldata() {
        // keccak256("transferTypeOwnership(bytes32,address)")[..4] = 0x47ce2eef.
        let expected = hex!(
            "47ce2eef"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000cc"
        );

        let tx = transfer_service_type_ownership_payload(REGISTRY, &SERVICE_TYPE, NEW_OWNER);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_transfer_service_type_ownership_payload_abandons_with_zero_address() {
        // Same selector, with the new owner word all zeroes: the one-way abandonment of RFC 3.1.
        let expected = hex!(
            "47ce2eef"
            "6776706e3a657869740000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let tx = transfer_service_type_ownership_payload(REGISTRY, &SERVICE_TYPE, Address::ZERO);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_set_type_registration_fee_payload_calldata() {
        // keccak256("setTypeRegistrationFee(uint256)")[..4] = 0xb3f618d1; 2e18 = 0x1bc16d674ec80000.
        let expected = hex!(
            "b3f618d1"
            "0000000000000000000000000000000000000000000000001bc16d674ec80000"
        );

        let tx = set_type_registration_fee_payload(REGISTRY, U256::from(2_000_000_000_000_000_000u64));
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_set_node_safe_registry_payload_calldata() {
        // keccak256("setNodeSafeRegistry(address,address,address)")[..4] = 0x48559a57.
        let expected = hex!(
            "48559a57"
            "00000000000000000000000000000000000000000000000000000000000000e1"
            "00000000000000000000000000000000000000000000000000000000000000e2"
            "00000000000000000000000000000000000000000000000000000000000000e3"
        );

        let tx = set_node_safe_registry_payload(REGISTRY, NODE_SAFE_REGISTRY, PROBE_NODE, EXPECTED_SAFE);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_recover_service_registry_tokens_payload_calldata() {
        // keccak256("recoverTokens(address,address)")[..4] = 0x056097ac.
        let expected = hex!(
            "056097ac"
            "00000000000000000000000000000000000000000000000000000000000000f1"
            "00000000000000000000000000000000000000000000000000000000000000f2"
        );

        let tx = recover_service_registry_tokens_payload(REGISTRY, TOKEN, RECIPIENT);
        assert_eq!(calldata(&tx, REGISTRY), expected.to_vec());
    }

    #[test]
    fn test_approve_hopr_token_payload_calldata() {
        // keccak256("approve(address,uint256)")[..4] = 0x095ea7b3; spender then the exact amount.
        let expected = hex!(
            "095ea7b3"
            "00000000000000000000000000000000000000000000000000000000000000dd"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        );

        let tx = approve_hopr_token_payload(TOKEN, SPENDER, one_token());
        assert_eq!(calldata(&tx, TOKEN), expected.to_vec());
    }

    #[test]
    fn test_edge_node_deploy_safe_module_and_maybe_include_node() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        let hopr_node_stake_factory_address = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let hopr_channels_address = Address::from_str("0x0000000000000000000000000000000000000002").unwrap();
        let hopr_token_address = Address::from_str("0x0000000000000000000000000000000000000003").unwrap();
        let nonce = U256::from(1);
        let amount = U256::from(1000);
        let admins = vec![
            Address::from_str("0x00000000000000000000000000000000000000e1").unwrap(),
            Address::from_str("0x00000000000000000000000000000000000000e2").unwrap(),
        ];

        let tx = edge_node_deploy_safe_module_and_maybe_include_node(
            hopr_node_stake_factory_address,
            hopr_token_address,
            hopr_channels_address,
            nonce,
            amount,
            admins,
            true,
        )?;
        println!("Transaction Request: {:?}", tx);
        Ok(())
    }
}
