use bit_vec::BitVec;
use blst::min_pk::PublicKey;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, HexBinary, WasmMsg};
use serde::Serialize;
use crate::types::SerializableKeySet;

#[cw_serde]
pub struct InstantiateMsg {
    max_key_length: usize,
    min_keys_needed: usize,
    initial_public_keys: Vec<Binary>,
}

#[cw_serde]
pub struct CallPayload {
    nonce: u64,
    msg: WasmMsg
}


#[cw_serde]
pub enum ExecuteMsg {
    CallContracts {
        bit_vec: Binary,
        signature: Binary,
        call: CallPayload
    },
    UpdateKeySet {
        min_keys_needed: usize,
        new_public_keys: Vec<Binary>,
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(SerializableKeySet)]
    GetKeySet,
    #[returns(u64)]
    GetNonce
}

