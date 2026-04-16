//! Orchard VP related functions.

use namada_tx::data::airdrop::{OrchardClaimProof, OrchardSignedClaim};
use namada_vp_env::{Error, Result, VpEnv};
use zair_core::base::{Pool, signature_digest};
use zair_core::schema::config::OrchardSnapshot;
use zair_orchard_proofs::{
    ValueCommitmentScheme as OrchardValueCommitmentScheme,
    hash_orchard_proof_fields, read_params_from_bytes,
    verify_claim_proof as verify_orchard_proof,
};

use super::{VpError, check_plain_value_commitment};
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
        None,
        None,
        Some(proof.value),
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

/// Verifies all Orchard airdrop claims.
pub fn verify_airdrop_claims<'ctx, CTX>(
    ctx: &'ctx CTX,
    snapshot: Option<OrchardSnapshot>,
    orchard_proofs: &[OrchardClaimProof],
) -> Result<()>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    // Extract snapshot config.
    let snapshot = snapshot.ok_or(VpError::MissingOrchardConfig)?;

    // Read orchard parameters from storage.
    let params_bytes: Vec<u8> = ctx
        .read_bytes_pre(&orchard_key::parameters())?
        .ok_or(VpError::MissingOrchardParameters)?;

    let params = read_params_from_bytes(&params_bytes)
        .map_err(|e| VpError::InvalidOrchardParameters(e.to_string()))?;

    let note_commitment_root_bytes = snapshot.note_commitment_root;
    let nullifier_gap_root_bytes = snapshot.nullifier_gap_root;
    let target_id = snapshot.target_id.as_bytes().to_vec();

    // Verify the proofs.
    for OrchardClaimProof { proof, message } in orchard_proofs {
        verify_signature(&target_id, proof, &message.hash())?;

        check_plain_value_commitment(proof.value, message)?;

        verify_orchard_proof(
            &params,
            &proof.zkproof,
            &None,
            &None,
            &Some(proof.value),
            &proof.airdrop_nullifier,
            &proof.rk,
            &note_commitment_root_bytes,
            &nullifier_gap_root_bytes,
            OrchardValueCommitmentScheme::Plain,
            &target_id,
        )
        .map_err(|e| VpError::ZkProofVerificationFailed(e.to_string()))?;
    }

    Ok(())
}
