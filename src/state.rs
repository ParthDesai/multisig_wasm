use crate::types::SerializableKeySet;
use cw_storage_plus::Item;

pub const CURRENT_KEYSET: Item<SerializableKeySet> = Item::new("current_keyset");

pub const CURRENT_NONCE: Item<u64> = Item::new("current_nonce");
