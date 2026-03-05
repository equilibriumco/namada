//! Airdrop storage functions.

use std::path::Path;

use namada_storage::{ResultExt, StorageWrite};
use zair_core::schema::config::{
    AirdropConfiguration, OrchardSnapshot, SaplingSnapshot,
    ValueCommitmentScheme,
};

use crate::storage_key::{orchard, sapling};

/// Initialize airdrop configuration from files in the airdrop
/// directory.
///
/// Reads:
/// - `<airdrop_dir>/config.json` - contains note_commitment_root,
///   nullifier_gap_root, value_commitment_scheme
/// - `<airdrop_dir>/setup-sapling-vk.params` - the Groth16 verifying key
/// - `<airdrop_dir>/setup-orchard-params.bin` - the Halo2 parameters
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

    // Initialize storage.
    if let Some(sapling_snapshot) = &config.sapling {
        init_sapling_storage(storage, airdrop_dir, sapling_snapshot)?;
    }

    if let Some(orchard_snapshot) = &config.orchard {
        init_orchard_storage(storage, airdrop_dir, orchard_snapshot)?;
    }

    Ok(())
}

/// Initialize airdrop configuration for Sapling.
fn init_sapling_storage<S: StorageWrite>(
    storage: &mut S,
    airdrop_dir: &Path,
    sapling_snapshot: &SaplingSnapshot,
) -> namada_storage::Result<()> {
    // Read and write verifying key.
    let vk_path = airdrop_dir.join("setup-sapling-vk.params");
    let vk_bytes = std::fs::read(&vk_path)
        .wrap_err("Failed to read Sapling verifying key")?;

    storage.write_bytes(&sapling::verifying_key(), vk_bytes)?;

    // Write note commitment root.
    storage.write_bytes(
        &sapling::note_commitment_root_key(),
        &sapling_snapshot.note_commitment_root,
    )?;

    // Write nullifier gap root.
    storage.write_bytes(
        &sapling::nullifier_gap_root_key(),
        &sapling_snapshot.nullifier_gap_root,
    )?;

    // Write value commitment scheme
    let scheme = match sapling_snapshot.value_commitment_scheme {
        ValueCommitmentScheme::Native => 0u8,
        ValueCommitmentScheme::Sha256 => 1u8,
    };
    storage.write(&sapling::value_commitment_scheme_key(), scheme)?;

    Ok(())
}

/// Initialize airdrop configuration for Orchard.
fn init_orchard_storage<S: StorageWrite>(
    storage: &mut S,
    airdrop_dir: &Path,
    orchard_snapshot: &OrchardSnapshot,
) -> namada_storage::Result<()> {
    // Read and write parameters.
    let params_path = airdrop_dir.join("setup-orchard-params.bin");
    let params_bytes = std::fs::read(&params_path)
        .wrap_err("Failed to read Orchard parameters")?;

    storage.write_bytes(&orchard::parameters(), params_bytes)?;

    // Write note commitment root.
    storage.write_bytes(
        &orchard::note_commitment_root_key(),
        &orchard_snapshot.note_commitment_root,
    )?;

    // Write nullifier gap root.
    storage.write_bytes(
        &orchard::nullifier_gap_root_key(),
        &orchard_snapshot.nullifier_gap_root,
    )?;

    // Write target id.
    storage
        .write_bytes(&orchard::target_id_key(), &orchard_snapshot.target_id)?;

    // Write value commitment scheme
    let scheme = match orchard_snapshot.value_commitment_scheme {
        ValueCommitmentScheme::Native => 0u8,
        ValueCommitmentScheme::Sha256 => 1u8,
    };
    storage.write(&orchard::value_commitment_scheme_key(), scheme)?;

    Ok(())
}
