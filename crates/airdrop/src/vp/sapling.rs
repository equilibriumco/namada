//! Sapling VP related functions.

use namada_tx::data::airdrop::{SaplingClaimProof, SaplingSignedClaim};
use namada_vp_env::{Error, Result, VpEnv};
use zair_core::base::{Pool, signature_digest};
use zair_sapling_proofs::{
    ValueCommitmentScheme as SaplingValueCommitmentScheme, VerifyingKey,
    hash_sapling_proof_fields, prepare_verifying_key,
    verify_claim_proof_bytes as verify_sapling_proof,
};

use super::{VpError, check_sha256_value_commitment};
use crate::storage_key::sapling as sapling_key;

/// Verifies that the Sapling spend-auth signature is valid.
fn verify_signature(
    target_id: &[u8],
    proof: &SaplingSignedClaim,
    message_hash: &[u8; 32],
) -> Result<()> {
    let proof_hash = hash_sapling_proof_fields(
        &proof.zkproof,
        &proof.rk,
        proof.cv,
        proof.cv_sha256,
        proof.airdrop_nullifier.into(),
    );

    let digest =
        signature_digest(Pool::Sapling, target_id, &proof_hash, message_hash)
            .map_err(|_| VpError::InvalidSpendAuthSignature)?;
    zair_sapling_proofs::verify_signature(
        proof.rk,
        proof.spend_auth_sig,
        &digest,
    )
    .map_err(|_| VpError::InvalidSpendAuthSignature)?;

    Ok(())
}

/// Verifies all Sapling airdrop claims.
pub fn verify_airdrop_claims<'ctx, CTX>(
    ctx: &'ctx CTX,
    sapling_proofs: &[SaplingClaimProof],
) -> Result<()>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    // Read verifying key from storage.
    let vk_bytes: Vec<u8> = ctx
        .read_bytes_pre(&sapling_key::verifying_key())?
        .ok_or(VpError::MissingVerifyingKey)?;

    let vk = VerifyingKey::read(&vk_bytes[..])
        .map_err(|e| VpError::InvalidVerifyingKey(e.to_string()))?;
    let pvk = prepare_verifying_key(&vk);

    // Read note commitment root from storage.
    let note_commitment_root_bytes: [u8; 32] = ctx
        .read_bytes_pre(&sapling_key::note_commitment_root_key())?
        .ok_or(VpError::MissingNoteCommitmentRoot)?
        .try_into()
        .map_err(|_| {
            VpError::InvalidBytes("note_commitment_root".to_string())
        })?;

    // Read nullifier gap root from storage.
    let nullifier_gap_root_bytes: [u8; 32] = ctx
        .read_bytes_pre(&sapling_key::nullifier_gap_root_key())?
        .ok_or(VpError::MissingNullifierGapRoot)?
        .try_into()
        .map_err(|_| VpError::InvalidBytes("nullifier_gap_root".to_string()))?;

    // Read target id from storage.
    let target_id: Vec<u8> = ctx
        .read_bytes_pre(&sapling_key::target_id_key())?
        .ok_or(VpError::MissingTargetId)?;

    // Read value commitment scheme from storage.
    let scheme_id: u8 = ctx
        .read_pre(&sapling_key::value_commitment_scheme_key())?
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
        verify_signature(&target_id, proof, &message.hash())?;

        // Check that value commitment matches.
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
