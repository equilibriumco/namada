//! Orchard VP related functions.

use namada_tx::data::airdrop::{OrchardClaimProof, OrchardSignedClaim};
use namada_vp_env::{Error, Result, VpEnv};
use zair_core::base::{Pool, signature_digest};
use zair_orchard_proofs::{
    ValueCommitmentScheme as OrchardValueCommitmentScheme,
    hash_orchard_proof_fields, read_params_from_bytes,
    verify_claim_proof as verify_orchard_proof,
};

use super::{VpError, check_sha256_value_commitment};
use crate::storage_key::orchard as orchard_key;

/// Verifies that the Orchard spend-auth signature is valid.
fn verify_signature(
    target_id: &[u8],
    proof: &OrchardSignedClaim,
    message_hash: &[u8; 32],
) -> Result<()> {
    let proof_hash = hash_orchard_proof_fields(
        &proof.zkproof,
        &proof.rk,
        proof.cv,
        proof.cv_sha256,
        proof.airdrop_nullifier.into(),
    )
    .map_err(|_| VpError::InvalidSpendAuthSignature)?;

    let digest =
        signature_digest(Pool::Orchard, target_id, &proof_hash, message_hash)
            .map_err(|_| VpError::InvalidSpendAuthSignature)?;
    zair_orchard_proofs::verify_signature(
        proof.rk,
        proof.spend_auth_sig,
        &digest,
    )
    .map_err(|_| VpError::InvalidSpendAuthSignature)?;

    Ok(())
}

// Verifies all Orchard airdrop claims.
pub fn verify_airdrop_claims<'ctx, CTX>(
    ctx: &'ctx CTX,
    orchard_proofs: &[OrchardClaimProof],
) -> Result<()>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    // Read orchard parameters from storage.
    let params_bytes: Vec<u8> = ctx
        .read_bytes_post(&orchard_key::parameters())?
        .ok_or(VpError::MissingOrchardParameters)?;

    let params = read_params_from_bytes(&params_bytes)
        .map_err(|e| VpError::InvalidOrchardParameters(e.to_string()))?;

    // Read note commitment root from storage.
    let note_commitment_root_bytes: [u8; 32] = ctx
        .read_bytes_post(&orchard_key::note_commitment_root_key())?
        .ok_or(VpError::MissingNoteCommitmentRoot)?
        .try_into()
        .map_err(|_| {
            VpError::InvalidBytes("note_commitment_root".to_string())
        })?;

    // Read nullifier gap root from storage.
    let nullifier_gap_root_bytes: [u8; 32] = ctx
        .read_bytes_post(&orchard_key::nullifier_gap_root_key())?
        .ok_or(VpError::MissingNullifierGapRoot)?
        .try_into()
        .map_err(|_| VpError::InvalidBytes("nullifier_gap_root".to_string()))?;

    // Read target id from storage.
    let target_id: Vec<u8> = ctx
        .read_bytes_post(&orchard_key::target_id_key())?
        .ok_or(VpError::MissingTargetId)?
        .try_into()
        .map_err(|_| VpError::InvalidBytes("target_id".to_string()))?;

    // Read value commitment scheme from storage.
    let scheme_id: u8 = ctx
        .read_bytes_post(&orchard_key::value_commitment_scheme_key())?
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
        verify_signature(&target_id, proof, &message.hash())?;

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
