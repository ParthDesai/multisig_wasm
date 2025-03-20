use std::collections::BTreeSet;
use blst::min_pk::PublicKey;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{to_json_binary, Addr, Binary, CosmosMsg, StdResult, WasmMsg};
use crate::ContractError;
use crate::msg::ExecuteMsg;

/// CwTemplateContract is a wrapper around Addr that provides a lot of helpers
/// for working with this.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct CwTemplateContract(pub Addr);

impl CwTemplateContract {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    pub fn call<T: Into<ExecuteMsg>>(&self, msg: T) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: vec![],
        }
        .into())
    }
}


pub fn check_for_duplicates(public_keys: &Vec<PublicKey>) -> Result<(), ContractError> {
    let mut public_key_set_for_duplication_detection = BTreeSet::new();

    let non_duplicate_elements: Vec<usize> = public_keys
        .iter()
        .enumerate()
        .map_while(|(i, public_key)| {
            let compressed_public_key = public_key.compress();
            if public_key_set_for_duplication_detection.contains(&compressed_public_key) {
                return None;
            }
            public_key_set_for_duplication_detection.insert(compressed_public_key);
            Some(i)
        })
        .collect();

    if public_keys.len() != non_duplicate_elements.len() {
        return Err(ContractError::PublicKeyDuplicated {
            pub_key_index: public_keys.len() - non_duplicate_elements.len(),
        });
    }

    Ok(())
}

pub fn try_parse_public_key(public_key_set: &Vec<Binary>) -> Result<Vec<PublicKey>, ContractError> {
    let parsed_public_keys: Vec<PublicKey> = public_key_set
        .iter()
        .map_while(|public_key| {
            let maybe_parsed_public_key = PublicKey::uncompress(public_key);
            if let Ok(parsed_public_key) = maybe_parsed_public_key {
                Some(parsed_public_key)
            } else {
                return None;
            }
        })
        .collect();

    if parsed_public_keys.len() != public_key_set.len() {
        return Err(ContractError::PublicKeyDecodeError {
            pub_key_index: public_key_set.len() - parsed_public_keys.len(),
        });
    }

    Ok(parsed_public_keys)
}

