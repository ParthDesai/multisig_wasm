use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;

#[cw_serde]
pub struct SerializableKeySet {
    pub set_id: u64,
    pub min_keys_needed: u64,
    pub public_keys: Vec<Binary>,
}
