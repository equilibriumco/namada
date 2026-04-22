//! SDK functions for airdrop claim operations.

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_tx::data::airdrop::{
    ClaimProofsOutput as NamadaClaimProofsOutput, Message,
};
use zair_core::base::{Nullifier, hash_message};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs;
use zair_sdk::api::{ResolvedMessageHashes, key, prove, scan, sign};
use zair_sdk::commands::GapTreeMode;
use zair_sdk::common::to_zcash_network;

use crate::borsh::BorshSerializeExt;
use crate::error::{Error, Result};

type MessagesByNullifier = BTreeMap<[u8; 32], Message>;
type HashesByNullifier = BTreeMap<Nullifier, [u8; 32]>;
#[allow(clippy::result_large_err)]
type BuildMessagesResult =
    Result<(MessagesByNullifier, HashesByNullifier, HashesByNullifier)>;

/// A single proof-nullifier pair with the fields needed for message
/// construction.
struct ProofSecret {
    airdrop_nullifier: Nullifier,
}

/// Generate the airdrop claim data by orchestrating key derivation, chain
/// scanning, proof generation, and signing via the zair SDK.
#[allow(clippy::too_many_arguments)]
pub async fn generate_airdrop_claim(
    source: &Address,
    seed_bytes: &[u8],
    account_id: u32,
    birthday: u64,
    lightwalletd_url: &Option<String>,
    config: &AirdropConfiguration,
    sapling_snapshot_nullifiers: &[u8],
    orchard_snapshot_nullifiers: &[u8],
    sapling_gap_tree_bytes: Option<&[u8]>,
    orchard_gap_tree_bytes: Option<&[u8]>,
    sapling_proving_key: Option<&[u8]>,
    orchard_params: Option<&[u8]>,
) -> Result<NamadaClaimProofsOutput> {
    let gap_tree_mode = if sapling_gap_tree_bytes.is_some()
        || orchard_gap_tree_bytes.is_some()
    {
        GapTreeMode::None
    } else {
        GapTreeMode::Sparse
    };

    let ufvk = key::derive_ufvk_from_seed(
        to_zcash_network(config.network),
        account_id,
        seed_bytes,
    )
    .map_err(|e| Error::Other(format!("Failed to derive UFVK: {e}")))?;

    let claim_inputs = scan::airdrop_claim_from_config(
        lightwalletd_url.clone(),
        sapling_snapshot_nullifiers,
        orchard_snapshot_nullifiers,
        &ufvk,
        birthday,
        config,
        gap_tree_mode,
        sapling_gap_tree_bytes,
        orchard_gap_tree_bytes,
    )
    .await
    .map_err(|e| Error::Other(format!("Chain scanning failed: {e}")))?;

    let (proofs, secrets) = prove::generate_claim_proofs_from_bytes(
        claim_inputs.clone(),
        seed_bytes,
        account_id,
        sapling_proving_key,
        orchard_params,
        config,
    )
    .await
    .map_err(|e| Error::Other(format!("Proof generation failed: {e}")))?;

    let sapling_pairs = proofs.sapling_proofs.iter().map(|p| ProofSecret {
        airdrop_nullifier: p.airdrop_nullifier,
    });
    let orchard_pairs = proofs.orchard_proofs.iter().map(|p| ProofSecret {
        airdrop_nullifier: p.airdrop_nullifier,
    });

    let (messages_by_nf, sapling_hashes, orchard_hashes) = build_messages(
        source,
        sapling_pairs,
        &claim_inputs.sapling_claim_input,
        orchard_pairs,
        &claim_inputs.orchard_claim_input,
    )?;

    let message_hashes = ResolvedMessageHashes {
        shared: None,
        sapling: sapling_hashes,
        orchard: orchard_hashes,
    };

    let claim_submission = sign::sign_claim_submission_from_bytes(
        proofs,
        secrets,
        seed_bytes,
        account_id,
        config,
        &message_hashes,
    )
    .await
    .map_err(|e| Error::Other(format!("Claim signing failed: {e}")))?;

    NamadaClaimProofsOutput::from_submission(claim_submission, &messages_by_nf)
        .map_err(|e| Error::Other(format!("Claim conversion failed: {e}")))
}

/// Build per-proof messages and per-pool message hashes.
///
/// For each proof-secret pair, looks up the corresponding note value from
/// claim inputs, constructs a `Message`, serializes it, and hashes it.
///
/// Returns `(messages_by_nf, sapling_hashes, orchard_hashes)`:
/// - `messages_by_nf`: nullifier bytes → Message (used by `from_submission`)
/// - `sapling_hashes` / `orchard_hashes`: nullifier → message hash (used by
///   `sign_claim_submission_from_bytes`)
#[allow(clippy::result_large_err)]
fn build_messages<S, O>(
    source: &Address,
    sapling_pairs: impl Iterator<Item = ProofSecret>,
    sapling_inputs: &[S],
    orchard_pairs: impl Iterator<Item = ProofSecret>,
    orchard_inputs: &[O],
) -> BuildMessagesResult
where
    S: InputAmounts,
    O: InputAmounts,
{
    let mut messages_by_nf = BTreeMap::new();
    let mut sapling_hashes = BTreeMap::new();
    let mut orchard_hashes = BTreeMap::new();

    add_messages(
        sapling_pairs,
        sapling_inputs,
        source,
        "Sapling",
        &mut messages_by_nf,
        &mut sapling_hashes,
    )?;
    add_messages(
        orchard_pairs,
        orchard_inputs,
        source,
        "Orchard",
        &mut messages_by_nf,
        &mut orchard_hashes,
    )?;

    Ok((messages_by_nf, sapling_hashes, orchard_hashes))
}

/// Insert messages for a batch of proof-secret pairs, looking up amounts
/// from the corresponding claim inputs.
#[allow(clippy::result_large_err)]
fn add_messages<I: InputAmounts>(
    pairs: impl Iterator<Item = ProofSecret>,
    claim_inputs: &[I],
    source: &Address,
    label: &str,
    messages_by_nf: &mut BTreeMap<[u8; 32], Message>,
    hashes: &mut BTreeMap<Nullifier, [u8; 32]>,
) -> Result<()> {
    let amounts: BTreeMap<_, _> = claim_inputs
        .iter()
        .map(|input| (input.airdrop_nullifier(), input.value()))
        .collect();

    for ps in pairs {
        let nf_bytes = *ps.airdrop_nullifier.as_ref();
        let amount = *amounts.get(&ps.airdrop_nullifier).ok_or_else(|| {
            Error::Other(format!(
                "Missing amount for {label} nullifier {:?}",
                ps.airdrop_nullifier
            ))
        })?;

        let message = Message {
            target: source.clone(),
            amount,
        };
        hashes.insert(
            ps.airdrop_nullifier,
            hash_message(&message.serialize_to_vec()),
        );
        messages_by_nf.insert(nf_bytes, message);
    }
    Ok(())
}

/// Trait to extract nullifier and value from claim input types.
trait InputAmounts {
    fn airdrop_nullifier(&self) -> Nullifier;
    fn value(&self) -> u64;
}

impl InputAmounts
    for proof_inputs::ClaimInput<proof_inputs::SaplingPrivateInputs>
{
    fn airdrop_nullifier(&self) -> Nullifier {
        self.public_inputs.airdrop_nullifier
    }

    fn value(&self) -> u64 {
        self.private_inputs.value
    }
}

impl InputAmounts
    for proof_inputs::ClaimInput<proof_inputs::OrchardPrivateInputs>
{
    fn airdrop_nullifier(&self) -> Nullifier {
        self.public_inputs.airdrop_nullifier
    }

    fn value(&self) -> u64 {
        self.private_inputs.value
    }
}
