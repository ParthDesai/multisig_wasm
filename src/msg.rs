use crate::types::SerializableKeySet;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, WasmMsg};

#[cw_serde]
pub struct InstantiateMsg {
    pub min_keys_needed: u64,
    pub initial_public_keys: Vec<Binary>,
}

pub trait Payload {
    fn get_nonce(&self) -> u64;
    fn get_serialized_payload(&self) -> serde_json_wasm::ser::Result<Vec<u8>>;
}

#[cw_serde]
pub struct CallPayload {
    pub nonce: u64,
    pub msg: WasmMsg,
}

impl Payload for CallPayload {
    fn get_nonce(&self) -> u64 {
        self.nonce
    }

    fn get_serialized_payload(&self) -> serde_json_wasm::ser::Result<Vec<u8>> {
        serde_json_wasm::to_vec(&self)
    }
}

#[cw_serde]
pub struct UpdateKeySetPayload {
    pub nonce: u64,
    pub min_keys_needed: u64,
    pub public_keys: Vec<Binary>,
}

impl Payload for UpdateKeySetPayload {
    fn get_nonce(&self) -> u64 {
        self.nonce
    }

    fn get_serialized_payload(&self) -> serde_json_wasm::ser::Result<Vec<u8>> {
        serde_json_wasm::to_vec(&self)
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    CallContracts {
        bit_vec: Binary,
        signature: Binary,
        call: CallPayload,
    },
    UpdateKeySet {
        bit_vec: Binary,
        signature: Binary,
        update_key_set: UpdateKeySetPayload,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(SerializableKeySet)]
    GetKeySet,
    #[returns(u64)]
    GetNonce,
}
