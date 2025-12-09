use std::{ops::Add, str::FromStr};

use hopr_bindings::{
    exports::alloy::{
        network::TransactionBuilder,
        primitives::{Address, Bytes, U256},
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
    hopr_token::HoprToken::{sendCall, transferCall},
};
use tracing::{debug, info};

use crate::{
    constants::{
        DEFAULT_CAPABILITY_PERMISSIONS, DEFAULT_NODE_PERMISSIONS, DEPLOYSAFEANDMODULEANDINCLUDENODES_IDENTIFIER,
        DEPLOYSAFEMODULE_FUNCTION_IDENTIFIER, SAFE_COMPATIBILITYFALLBACKHANDLER_ADDRESS, SAFE_SAFE_L2_ADDRESS,
        SAFE_SAFEPROXYFACTORY_ADDRESS, SENTINEL_OWNERS,
    },
    methods::{
        SafeSingleton::removeOwnerCall, predict_safe_address, prepare_safe_tx_multicall_payload_from_owner_contract,
    },
    utils::HelperErrors,
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
        .clone()
        .into_iter()
        .enumerate()
        .map(|(i, addr)| Call3Value {
            target: addr,
            allowFailure: false,
            value: amounts[i],
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
    hopr_channels_address: Address,
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

    // build the default permissions of capabilities
    let default_target = U256::from_str(format!("{hopr_channels_address:?}{DEFAULT_CAPABILITY_PERMISSIONS}").as_str())
        .map_err(|e| HelperErrors::ParseError(format!("Invalid default_target format: {e}")))?;
    debug!("default target {:?}", default_target);

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
    let default_target = U256::from_str(format!("{hopr_channels_address:?}{DEFAULT_CAPABILITY_PERMISSIONS}").as_str())
        .map_err(|e| HelperErrors::ParseError(format!("Invalid default_target format: {e}")))?;
    debug!("default target {:?}", default_target);

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
    node_addresses: Option<Vec<Address>>,
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
    let default_target = U256::from_str(format!("{hopr_channels_address:?}{DEFAULT_CAPABILITY_PERMISSIONS}").as_str())
        .map_err(|e| HelperErrors::ParseError(format!("Invalid default_target format: {e}")))?;
    debug!("default target {:?}", default_target);

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
    if let Some(nodes) = node_addresses {
        for node in nodes {
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
    let default_target = U256::from_str(format!("{hopr_channels_address:?}{DEFAULT_CAPABILITY_PERMISSIONS}").as_str())
        .map_err(|e| HelperErrors::ParseError(format!("Invalid default_target format: {e}")))?;
    debug!("default target {:?}", default_target);

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

#[cfg(test)]
mod tests {
    use super::*;

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
