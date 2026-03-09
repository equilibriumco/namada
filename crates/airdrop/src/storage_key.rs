//! Airdrop storage keys.

use namada_core::storage::{self, KeySeg};
use namada_storage::DbKeySeg;

use crate::ADDRESS;

/// Key segment for note commitment root.
pub const NOTE_COMMITMENT_ROOT_KEY: &str = "note_commitment_root";
/// Key segment for nullifier gap root.
pub const NULLIFIER_GAP_ROOT_KEY: &str = "nullifier_gap_root";
/// Key segment for value commitment scheme.
pub const VALUE_COMMITMENT_SCHEME_KEY: &str = "value_commitment_scheme";
/// Key segment for airdrop nullifiers.
pub const AIRDROP_NULLIFIERS_KEY: &str = "airdrop_nullifiers";

/// Gets a key for the airdrop nullifiers storage.
pub fn airdrop_nullifier_key(nullifier: &[u8; 32]) -> storage::Key {
    storage::Key::from(ADDRESS.to_db_key())
        .push(&AIRDROP_NULLIFIERS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&hex::encode(nullifier))
        .expect("Cannot obtain a storage key")
}

/// Returns whether the given storage key is an airdrop nullifiers key.
pub fn is_airdrop_nullifier_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr),
                 DbKeySeg::StringSeg(prefix),
                 DbKeySeg::StringSeg(_nullifier),
        ] if *addr == ADDRESS && prefix == AIRDROP_NULLIFIERS_KEY)
}

/// Sapling configuration storage keys.
pub mod sapling {
    use super::*;

    /// Key segment prefix for Sapling configuration.
    const AIRDROP_SAPLING_KEY: &str = "sapling";
    /// Key segment for verifying key.
    pub const VERIFYING_KEY_KEY: &str = "verifying_key";

    /// Gets a key for the Sapling verifying key storage.
    pub fn verifying_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_SAPLING_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&VERIFYING_KEY_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Sapling note commitment root storage.
    pub fn note_commitment_root_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_SAPLING_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&NOTE_COMMITMENT_ROOT_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Sapling nullifier gap root storage.
    pub fn nullifier_gap_root_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_SAPLING_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&NULLIFIER_GAP_ROOT_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Sapling value commitment scheme storage.
    pub fn value_commitment_scheme_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_SAPLING_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&VALUE_COMMITMENT_SCHEME_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }
}

/// Orchard configuration storage keys.
pub mod orchard {
    use super::*;

    /// Key segment prefix for Orchard configuration.
    const AIRDROP_ORCHARD_KEY: &str = "orchard";
    /// Key segment for parameters.
    pub const PARAMETERS_KEY: &str = "parameters";
    /// Key segment for target id.
    pub const TARGET_ID_KEY: &str = "target_id";

    /// Gets a key for the Orchard parameters storage.
    pub fn parameters() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_ORCHARD_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&PARAMETERS_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Orchard note commitment root storage.
    pub fn note_commitment_root_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_ORCHARD_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&NOTE_COMMITMENT_ROOT_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Orchard nullifier gap root storage.
    pub fn nullifier_gap_root_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_ORCHARD_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&NULLIFIER_GAP_ROOT_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Orchard target id storage.
    pub fn target_id_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_ORCHARD_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&TARGET_ID_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }

    /// Gets a key for the Orchard value commitment scheme storage.
    pub fn value_commitment_scheme_key() -> storage::Key {
        storage::Key::from(ADDRESS.to_db_key())
            .push(&AIRDROP_ORCHARD_KEY.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&VALUE_COMMITMENT_SCHEME_KEY.to_owned())
            .expect("Cannot obtain a storage key")
    }
}
