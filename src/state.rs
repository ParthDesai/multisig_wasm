use cw_storage_plus::Item;
use crate::types::{Config, SerializableKeySet};

const CURRENT_KEYSET: Item<SerializableKeySet> = Item::new("current_keyset");

const CURRENT_NONCE: Item<u64> = Item::new("current_nonce");

const CONFIG: Item<Config> = Item::new("config");

