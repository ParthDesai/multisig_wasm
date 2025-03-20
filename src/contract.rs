use crate::bls_verification::verify_signature;
use crate::ContractError::{SignaturePayloadDecodeError, SignatureVerificationError};
use bit_vec::BitVec;
use blst::min_pk::Signature;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::helpers::{check_for_duplicates, try_parse_public_key};
use crate::msg::{ExecuteMsg, InstantiateMsg, Payload, QueryMsg};
use crate::state::{CURRENT_KEYSET, CURRENT_NONCE};
use crate::types::SerializableKeySet;
/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:multisig_wasm";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let public_keys = try_parse_public_key(&msg.initial_public_keys)?;
    check_for_duplicates(&public_keys)?;

    if msg.min_keys_needed == 0 {
        return Err(ContractError::InvalidMinKeysNeeded {
            min_keys_needed: msg.min_keys_needed,
        });
    }

    CURRENT_KEYSET.save(
        deps.storage,
        &SerializableKeySet {
            min_keys_needed: msg.min_keys_needed,
            set_id: 1,
            public_keys: msg.initial_public_keys,
        },
    )?;

    Ok(Response::new())
}

fn verify_signature_payload<P: Payload + serde::Serialize>(
    deps: &DepsMut,
    bit_vec: Binary,
    signature: Binary,
    payload: &P,
) -> Result<(bool, u64), ContractError> {
    let bit_vec = BitVec::from_bytes(&bit_vec);
    let signature = Signature::from_bytes(&signature)
        .map_err(|e| ContractError::SignatureDecodeError { decode_error: e })?;

    let current_nonce = CURRENT_NONCE.load(deps.storage)?;
    if payload.get_nonce() != current_nonce {
        return Err(ContractError::InvalidNonce {
            expected: current_nonce,
            got: payload.get_nonce(),
        });
    }

    let current_serialized_keyset = CURRENT_KEYSET.load(deps.storage)?;
    if current_serialized_keyset.public_keys.len() != bit_vec.len() {
        return Err(ContractError::MismatchBetweenBitVecAndPublicKeys {
            bit_vec_length: bit_vec.len() as u64,
            public_key_length: current_serialized_keyset.public_keys.len() as u64,
        });
    }

    let public_keys = try_parse_public_key(&current_serialized_keyset.public_keys)?;

    let serialized_payload =
        serde_json::to_vec(&payload).map_err(|e| SignaturePayloadDecodeError { error: e })?;
    let is_valid = verify_signature(
        &serialized_payload,
        current_serialized_keyset.min_keys_needed,
        public_keys.as_ref(),
        bit_vec,
        &signature,
    )
    .map_err(|e| SignatureVerificationError {
        verification_error: e,
    })?;
    Ok((is_valid, current_nonce))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CallContracts {
            bit_vec,
            signature,
            call,
        } => {
            let (is_valid, current_nonce) =
                verify_signature_payload(&deps, bit_vec, signature, &call)?;
            if !is_valid {
                return Err(ContractError::InvalidSignature);
            }
            CURRENT_NONCE.save(deps.storage, &(current_nonce + 1))?;
            Ok(Response::new().add_message(call.msg))
        }
        ExecuteMsg::UpdateKeySet {
            bit_vec,
            signature,
            update_key_set,
        } => {
            let (is_valid, current_nonce) =
                verify_signature_payload(&deps, bit_vec, signature, &update_key_set)?;
            if !is_valid {
                return Err(ContractError::InvalidSignature);
            }
            CURRENT_KEYSET.update(deps.storage, |mut current_key_set| {
                let _public_key = try_parse_public_key(&update_key_set.public_keys)?;

                if update_key_set.min_keys_needed == 0 {
                    return Err(ContractError::InvalidMinKeysNeeded {
                        min_keys_needed: update_key_set.min_keys_needed,
                    });
                }

                current_key_set.set_id = current_key_set.set_id + 1;
                current_key_set.min_keys_needed = update_key_set.min_keys_needed;
                current_key_set.public_keys = update_key_set.public_keys;
                Ok(current_key_set)
            })?;

            CURRENT_NONCE.save(deps.storage, &(current_nonce + 1))?;
            Ok(Response::new())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!()
}

#[cfg(test)]
mod tests {}
