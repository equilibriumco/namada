//! Orchard VP related functions.

use namada_tx::data::airdrop::{OrchardClaimProof, OrchardSignedClaim};
use namada_vp_env::{Error, Result, VpEnv};
use zair_core::base::{Pool, signature_digest};
use zair_core::schema::config::{AirdropConfiguration, ValueCommitmentScheme};
use zair_orchard_proofs::{
    ValueCommitmentScheme as OrchardValueCommitmentScheme,
    hash_orchard_proof_fields, read_params_from_bytes,
    verify_claim_proof as verify_orchard_proof,
};

use super::{VpError, check_sha256_value_commitment};
use crate::storage_key::{airdrop_config_key, orchard as orchard_key};

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
        .read_bytes_pre(&orchard_key::parameters())?
        .ok_or(VpError::MissingOrchardParameters)?;

    let params = read_params_from_bytes(&params_bytes)
        .map_err(|e| VpError::InvalidOrchardParameters(e.to_string()))?;

    // Read airdrop config from storage and extract orchard fields.
    let config_bytes: Vec<u8> = ctx
        .read_bytes_pre(&airdrop_config_key())?
        .ok_or(VpError::MissingAirdropConfig)?;
    let config: AirdropConfiguration = serde_json::from_slice(&config_bytes)
        .map_err(|e| VpError::InvalidAirdropConfig(e.to_string()))?;
    let orchard = config.orchard.ok_or(VpError::MissingOrchardConfig)?;

    let note_commitment_root_bytes = orchard.note_commitment_root;
    let nullifier_gap_root_bytes = orchard.nullifier_gap_root;
    let target_id = orchard.target_id.as_bytes().to_vec();

    let scheme = match orchard.value_commitment_scheme {
        ValueCommitmentScheme::Native => OrchardValueCommitmentScheme::Native,
        ValueCommitmentScheme::Sha256 => OrchardValueCommitmentScheme::Sha256,
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
