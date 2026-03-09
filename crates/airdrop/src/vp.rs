//! Airdrop VP

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::collections::HashSet;
use namada_core::storage::Key;
use namada_tx::BatchedTxRef;
use namada_tx::action::{Action, AirdropAction, ClaimProofsOutput};
use namada_tx::data::airdrop::util::reversed_hex_encode;
use namada_tx::data::airdrop::{Message, OrchardClaimProof, SaplingClaimProof};
use namada_vp_env::{Error, Result, VpEnv};
use thiserror::Error;
use zair_core::base::cv_sha256 as compute_cv_sha256;
use zair_orchard_proofs::{
    ValueCommitmentScheme as OrchardValueCommitmentScheme,
    read_params_from_bytes, verify_claim_proof as verify_orchard_proof,
};
use zair_sapling_proofs::{
    ValueCommitmentScheme as SaplingValueCommitmentScheme, VerifyingKey,
    prepare_verifying_key, verify_claim_proof_bytes as verify_sapling_proof,
};

use crate::storage_key::{
    airdrop_nullifier_key, is_airdrop_nullifier_key, orchard, sapling,
};

#[derive(Error, Debug)]
pub enum VpError {
    #[error("Airdrop action not authorized by {0}")]
    Unauthorized(Address),
    #[error("No Airdrop action found")]
    NoAction,

    #[error("zk proof verification failed: {0}")]
    ZkProofVerificationFailed(String),

    #[error("Missing verifying key in storage")]
    MissingVerifyingKey,
    #[error("Invalid verifying key: {0}")]
    InvalidVerifyingKey(String),

    #[error("Missing orchard parameters in storage")]
    MissingOrchardParameters,
    #[error("Invalid orchard parameters: {0}")]
    InvalidOrchardParameters(String),

    #[error("Missing sapling note commitment root in storage")]
    MissingNoteCommitmentRoot,
    #[error("Missing sapling nullifier gap root in storage")]
    MissingNullifierGapRoot,
    #[error("Missing target id in storage")]
    MissingTargetId,

    #[error("Invalid bytes found for: {0}")]
    InvalidBytes(String),

    #[error("Missing value commitment scheme in storage")]
    MissingValueCommitmentScheme,
    #[error("Invalid value commitment scheme: {0}")]
    InvalidValueCommitmentScheme(String),
    #[error("Unsupported value commitment scheme")]
    UnsupportedValueCommitmentScheme,
    #[error(
        "Computed value commitment is different from provided value commitment"
    )]
    ValueCommitmentMismatch,
    #[error("Missing cv_sha256 in proof")]
    MissingCvSha256,

    #[error("NullifierAlreadyUsed: {0}")]
    NullifierAlreadyUsed(String),
    #[error("Nullifier not properly committed")]
    NullifierNotCommitted,
    #[error("Unexpected nullifier key changed: {0}")]
    UnexpectedNullifierKey(Key),

    #[error("Message target {0} does not match action target {1}")]
    MessageTargetMismatch(Address, Address),
}

impl From<VpError> for Error {
    fn from(value: VpError) -> Self {
        Error::new(value)
    }
}

/// Airdrop VP
pub struct AirdropVp<'ctx, CTX> {
    pub _marker: PhantomData<&'ctx CTX>,
}

impl<'ctx, CTX> AirdropVp<'ctx, CTX>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        _batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        let actions = ctx.read_actions()?;
        if actions.is_empty() {
            return Err(VpError::NoAction.into());
        }

        let mut revealed_nullifiers = HashSet::new();
        for action in &actions {
            if let Action::Airdrop(AirdropAction::Claim {
                target,
                claim_data,
            }) = action
            {
                if !verifiers.contains(&target) {
                    return Err(VpError::Unauthorized(target.clone()).into());
                }

                // Check if airdrop nullifiers have already been used.
                check_airdrop_nullifiers(
                    ctx,
                    &claim_data,
                    &mut revealed_nullifiers,
                )?;

                // Verify all message targets match the action target.
                verify_message_targets(claim_data, target)?;

                // zk proof verification.
                verify_sapling_zk_proofs(ctx, &claim_data.sapling_proofs)?;
                verify_orchard_zk_proofs(ctx, &claim_data.orchard_proofs)?;
            }
        }

        // Final sanity check that nullifiers were revealed and only expected
        // keys were written.
        if revealed_nullifiers.is_empty() {
            return Err(VpError::NoAction.into());
        }

        for nullifier_key in keys_changed
            .iter()
            .filter(|key| is_airdrop_nullifier_key(key))
        {
            if !revealed_nullifiers.contains(nullifier_key) {
                return Err(VpError::UnexpectedNullifierKey(
                    nullifier_key.clone(),
                )
                .into());
            }
        }

        Ok(())
    }
}

/// Checks if airdrop nullifiers have already been used.
fn check_airdrop_nullifiers<'ctx, CTX>(
    ctx: &'ctx CTX,
    claim_data: &ClaimProofsOutput,
    revealed_nullifiers: &mut HashSet<Key>,
) -> Result<()>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    for nullifier in claim_data.nullifier_iter() {
        let airdrop_nullifier_key = airdrop_nullifier_key(nullifier);

        // Check if nullifier has already been used before.
        if ctx.has_key_pre(&airdrop_nullifier_key)? {
            return Err(VpError::NullifierAlreadyUsed(reversed_hex_encode(
                nullifier,
            ))
            .into());
        }

        // Check if nullifier was previously used in this transaction.
        if revealed_nullifiers.contains(&airdrop_nullifier_key) {
            return Err(VpError::NullifierAlreadyUsed(reversed_hex_encode(
                nullifier,
            ))
            .into());
        }

        // Check that the nullifier was properly commited to store.
        ctx.read_bytes_post(&airdrop_nullifier_key)?
            .is_some_and(|value| value.is_empty())
            .then_some(())
            .ok_or(VpError::NullifierNotCommitted)?;

        revealed_nullifiers.insert(airdrop_nullifier_key);
    }

    Ok(())
}

/// Verifies that all message targets match the action target.
fn verify_message_targets(
    claim_data: &ClaimProofsOutput,
    target: &Address,
) -> Result<()> {
    for message in claim_data.message_iter() {
        if &message.target != target {
            return Err(VpError::MessageTargetMismatch(
                message.target.clone(),
                target.clone(),
            )
            .into());
        }
    }

    Ok(())
}

/// Checks that the SHA256 value comitment is valid.
///
/// This computes that `cv = SHA256(b'Zair || LE64(amount) || rcv)`.
fn check_sha256_value_commitment(
    cv: &[u8; 32],
    Message { amount, rcv, .. }: &Message,
) -> Result<()> {
    let computed_cv = compute_cv_sha256(*amount, *rcv);
    if computed_cv != *cv {
        return Err(VpError::ValueCommitmentMismatch.into());
    }

    Ok(())
}

/// Verifies all Sapling zk proofs for a claim.
fn verify_sapling_zk_proofs<'ctx, CTX>(
    ctx: &'ctx CTX,
    sapling_proofs: &[SaplingClaimProof],
) -> Result<()>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    // Read verifying key from storage.
    let vk_bytes: Vec<u8> = ctx
        .read_bytes_post(&sapling::verifying_key())?
        .ok_or(VpError::MissingVerifyingKey)?;

    let vk = VerifyingKey::read(&vk_bytes[..])
        .map_err(|e| VpError::InvalidVerifyingKey(e.to_string()))?;
    let pvk = prepare_verifying_key(&vk);

    // Read note commitment root from storage.
    let note_commitment_root_bytes: [u8; 32] = ctx
        .read_bytes_post(&sapling::note_commitment_root_key())?
        .ok_or(VpError::MissingNoteCommitmentRoot)?
        .try_into()
        .map_err(|_| {
            VpError::InvalidBytes("note_commitment_root".to_string())
        })?;

    // Read nullifier gap root from storage.
    let nullifier_gap_root_bytes: [u8; 32] = ctx
        .read_bytes_post(&sapling::nullifier_gap_root_key())?
        .ok_or(VpError::MissingNullifierGapRoot)?
        .try_into()
        .map_err(|_| VpError::InvalidBytes("nullifier_gap_root".to_string()))?;

    // Read value commitment scheme from storage.
    let scheme_id: u8 = ctx
        .read_bytes_post(&sapling::value_commitment_scheme_key())?
        .ok_or(VpError::MissingValueCommitmentScheme)?
        .pop()
        .ok_or(VpError::MissingValueCommitmentScheme)?;

    let scheme = match scheme_id {
        0 => SaplingValueCommitmentScheme::Native,
        1 => SaplingValueCommitmentScheme::Sha256,
        n => {
            return Err(
                VpError::InvalidValueCommitmentScheme(n.to_string()).into()
            );
        }
    };

    // Finally, verify the proofs sequentially.
    for SaplingClaimProof { proof, message } in sapling_proofs {
        if scheme != SaplingValueCommitmentScheme::Sha256 {
            return Err(VpError::UnsupportedValueCommitmentScheme.into());
        }

        let cv = proof.cv_sha256.ok_or(VpError::MissingCvSha256)?;
        check_sha256_value_commitment(&cv, message)?;

        verify_sapling_proof(
            &pvk,
            &proof.zkproof,
            scheme,
            &proof.rk,
            proof.cv.as_ref(),
            proof.cv_sha256.as_ref(),
            &note_commitment_root_bytes,
            &proof.airdrop_nullifier,
            &nullifier_gap_root_bytes,
        )
        .map_err(|e| VpError::ZkProofVerificationFailed(e.to_string()))?;
    }

    Ok(())
}

// Verifies all Orchard zk proof for a claim.
fn verify_orchard_zk_proofs<'ctx, CTX>(
    ctx: &'ctx CTX,
    orchard_proofs: &[OrchardClaimProof],
) -> Result<()>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    // Read orchard parameters from storage.
    let params_bytes: Vec<u8> = ctx
        .read_bytes_post(&orchard::parameters())?
        .ok_or(VpError::MissingOrchardParameters)?;

    let params = read_params_from_bytes(&params_bytes)
        .map_err(|e| VpError::InvalidOrchardParameters(e.to_string()))?;

    // Read note commitment root from storage.
    let note_commitment_root_bytes: [u8; 32] = ctx
        .read_bytes_post(&orchard::note_commitment_root_key())?
        .ok_or(VpError::MissingNoteCommitmentRoot)?
        .try_into()
        .map_err(|_| {
            VpError::InvalidBytes("note_commitment_root".to_string())
        })?;

    // Read nullifier gap root from storage.
    let nullifier_gap_root_bytes: [u8; 32] = ctx
        .read_bytes_post(&orchard::nullifier_gap_root_key())?
        .ok_or(VpError::MissingNullifierGapRoot)?
        .try_into()
        .map_err(|_| VpError::InvalidBytes("nullifier_gap_root".to_string()))?;

    // Read target id from storage.
    let target_id: Vec<u8> = ctx
        .read_bytes_post(&orchard::target_id_key())?
        .ok_or(VpError::MissingTargetId)?
        .try_into()
        .map_err(|_| VpError::InvalidBytes("target_id".to_string()))?;

    // Read value commitment scheme from storage.
    let scheme_id: u8 = ctx
        .read_bytes_post(&orchard::value_commitment_scheme_key())?
        .ok_or(VpError::MissingValueCommitmentScheme)?
        .pop()
        .ok_or(VpError::MissingValueCommitmentScheme)?;

    let scheme = match scheme_id {
        0 => OrchardValueCommitmentScheme::Native,
        1 => OrchardValueCommitmentScheme::Sha256,
        n => {
            return Err(
                VpError::InvalidValueCommitmentScheme(n.to_string()).into()
            );
        }
    };

    // Finally, verify the proofs.
    for OrchardClaimProof { proof, message } in orchard_proofs {
        if scheme != OrchardValueCommitmentScheme::Sha256 {
            return Err(VpError::UnsupportedValueCommitmentScheme.into());
        }

        let cv = proof.cv_sha256.ok_or(VpError::MissingCvSha256)?;
        check_sha256_value_commitment(&cv, message)?;

        verify_orchard_proof(
            &params,
            &proof.zkproof,
            &proof.cv,
            &proof.cv_sha256,
            &proof.airdrop_nullifier,
            &proof.rk,
            &note_commitment_root_bytes,
            &nullifier_gap_root_bytes,
            scheme,
            &target_id,
        )
        .map_err(|e| VpError::ZkProofVerificationFailed(e.to_string()))?;
    }

    Ok(())
}
