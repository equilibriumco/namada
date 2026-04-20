//! Airdrop storage keys.

use namada_core::storage::{self, KeySeg};
use namada_storage::DbKeySeg;

use crate::ADDRESS;

/// Key segment for airdrop nullifiers.
pub const AIRDROP_NULLIFIERS_KEY: &str = "airdrop_nullifiers";
/// Key segment for airdrop config.
pub const AIRDROP_CONFIG_KEY: &str = "airdrop_config";

/// Creates a storage key from a prefix and key segment.
fn make_airdrop_key(prefix: &str, segment: &str) -> storage::Key {
    storage::Key::from(ADDRESS.to_db_key())
        .push(&prefix.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&segment.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Gets a key for the airdrop nullifiers storage.
pub fn airdrop_nullifier_key(nullifier: &[u8; 32]) -> storage::Key {
    make_airdrop_key(AIRDROP_NULLIFIERS_KEY, &hex::encode(nullifier))
}

/// Returns whether the given storage key is an airdrop nullifiers key.
pub fn is_airdrop_nullifier_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr),
                 DbKeySeg::StringSeg(prefix),
                 DbKeySeg::StringSeg(_nullifier),
        ] if *addr == ADDRESS && prefix == AIRDROP_NULLIFIERS_KEY)
}

/// Gets the key for the airdrop JSON config storage.
pub fn airdrop_config_key() -> storage::Key {
    storage::Key::from(ADDRESS.to_db_key())
        .push(&AIRDROP_CONFIG_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Sapling configuration storage keys.
pub mod sapling {
    use namada_core::storage;

    use super::make_airdrop_key;

    /// Key segment prefix for Sapling configuration.
    pub const AIRDROP_SAPLING_KEY: &str = "sapling";
    /// Key segment for verifying key.
    pub const VERIFYING_KEY_KEY: &str = "verifying_key";
    /// Key segment for proving key.
    pub const PROVING_KEY_KEY: &str = "proving_key";

    /// Gets a key for the Sapling verifying key storage.
    pub fn verifying_key() -> storage::Key {
        make_airdrop_key(AIRDROP_SAPLING_KEY, VERIFYING_KEY_KEY)
    }

    /// Gets a key for the Sapling proving key storage.
    pub fn proving_key() -> storage::Key {
        make_airdrop_key(AIRDROP_SAPLING_KEY, PROVING_KEY_KEY)
    }
}

/// Orchard configuration storage keys.
pub mod orchard {
    use namada_core::storage;

    use super::make_airdrop_key;

    /// Key segment prefix for Orchard configuration.
    pub const AIRDROP_ORCHARD_KEY: &str = "orchard";
    /// Key segment for parameters.
    pub const PARAMETERS_KEY: &str = "parameters";

    /// Gets a key for the Orchard parameters storage.
    pub fn parameters() -> storage::Key {
        make_airdrop_key(AIRDROP_ORCHARD_KEY, PARAMETERS_KEY)
    }
}
