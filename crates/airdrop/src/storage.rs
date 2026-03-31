//! Airdrop storage functions.

use std::path::Path;

use namada_storage::{ResultExt, StorageWrite};
use zair_core::schema::config::AirdropConfiguration;

use crate::storage_key::{
    airdrop_config_key, airdrop_nullifier_key, orchard, sapling,
};

/// Writes the provided airdrop nullifier to storage.
pub fn reveal_nullifier<S: StorageWrite>(
    storage: &mut S,
    nullifier: &[u8; 32],
) -> namada_storage::Result<()> {
    let key = airdrop_nullifier_key(nullifier);
    storage.write(&key, ())
}

/// Initialize airdrop configuration from files in the airdrop
/// directory.
///
/// Reads:
/// - `<airdrop_dir>/config.json` - contains note_commitment_root,
///   nullifier_gap_root, value_commitment_scheme
/// - `<airdrop_dir>/setup-sapling-vk.params` - the Groth16 verifying key
/// - `<airdrop_dir>/setup-orchard-params.bin` - the Halo2 parameters
///
/// Stores the full JSON config in storage and sets up proving/verifying
/// keys and snapshot nullifiers.
///
/// # Panics
/// Panics if the airdrop directory or required files are missing.
pub fn init_storage<S: StorageWrite>(
    storage: &mut S,
    airdrop_dir: &Path,
) -> namada_storage::Result<()> {
    // Read Airdrop config.
    let config_path = airdrop_dir.join("config.json");
    let config_content = std::fs::read_to_string(&config_path)
        .wrap_err("Failed to read config.json")?;
    let config: AirdropConfiguration = serde_json::from_str(&config_content)
        .wrap_err("Failed to parse airdrop config.json")?;

    if config.sapling.is_none() && config.orchard.is_none() {
        return Err(namada_storage::Error::SimpleMessage(
            "Airdrop configuration did not contain a sapling or orchard \
             snapshot",
        ));
    }

    // Write the full JSON config to storage.
    storage.write_bytes(&airdrop_config_key(), config_content.as_bytes())?;

    // Initialize pool-specific storage (proving/verifying keys and snapshot
    // nullifiers).
    if config.sapling.is_some() {
        init_sapling_storage(storage, airdrop_dir)?;
    }

    if config.orchard.is_some() {
        init_orchard_storage(storage, airdrop_dir)?;
    }

    Ok(())
}

/// Initialize airdrop storage for Sapling.
///
/// Writes the verifying key, proving key, and snapshot nullifiers to storage.
fn init_sapling_storage<S: StorageWrite>(
    storage: &mut S,
    airdrop_dir: &Path,
) -> namada_storage::Result<()> {
    // Read and write verifying key.
    let vk_path = airdrop_dir.join("setup-sapling-vk.params");
    let vk_bytes = std::fs::read(&vk_path)
        .wrap_err("Failed to read Sapling verifying key")?;

    storage.write_bytes(&sapling::verifying_key(), vk_bytes)?;

    // Read and write proving key.
    let pk_path = airdrop_dir.join("setup-sapling-pk.params");
    let pk_bytes = std::fs::read(&pk_path)
        .wrap_err("Failed to read Sapling proving key")?;

    storage.write_bytes(&sapling::proving_key(), pk_bytes)?;

    // Read and write snapshot nullifiers.
    let snapshot_path = airdrop_dir.join("snapshot-sapling.bin");
    let snapshot_bytes = std::fs::read(&snapshot_path)
        .wrap_err("Failed to read Sapling snapshot nullifiers")?;
    storage.write_bytes(&sapling::snapshot_nullifiers_key(), snapshot_bytes)?;

    Ok(())
}

/// Initialize airdrop storage for Orchard.
///
/// Writes the parameters and snapshot nullifiers to storage.
fn init_orchard_storage<S: StorageWrite>(
    storage: &mut S,
    airdrop_dir: &Path,
) -> namada_storage::Result<()> {
    // Read and write parameters.
    let params_path = airdrop_dir.join("setup-orchard-params.bin");
    let params_bytes = std::fs::read(&params_path)
        .wrap_err("Failed to read Orchard parameters")?;

    storage.write_bytes(&orchard::parameters(), params_bytes)?;

    // Read and write snapshot nullifiers.
    let snapshot_path = airdrop_dir.join("snapshot-orchard.bin");
    let snapshot_bytes = std::fs::read(&snapshot_path)
        .wrap_err("Failed to read Orchard snapshot nullifiers")?;
    storage.write_bytes(&orchard::snapshot_nullifiers_key(), snapshot_bytes)?;

    Ok(())
}
