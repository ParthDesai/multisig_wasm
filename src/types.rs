use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct SerializableKeySet {
    set_id: u64,
    public_keys: Vec<HexBinary>
}

#[cw_serde]
pub struct Config {
    pub max_key_length: usize,
    pub min_keys_needed: usize,
}
