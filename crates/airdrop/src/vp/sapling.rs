//! Sapling VP related functions.

use namada_tx::data::airdrop::{SaplingClaimProof, SaplingSignedClaim};
use namada_vp_env::{Error, Result, VpEnv};
use zair_core::base::{Pool, signature_digest};
use zair_core::schema::config::AirdropConfiguration;
use zair_sapling_proofs::{
    ValueCommitmentScheme as SaplingValueCommitmentScheme, VerifyingKey,
    hash_sapling_proof_fields, prepare_verifying_key,
    verify_claim_proof_bytes as verify_sapling_proof,
};

use super::{VpError, check_plain_value_commitment};
use crate::storage_key::{airdrop_config_key, sapling as sapling_key};

/// Verifies that the Sapling spend-auth signature is valid.
fn verify_signature(
    target_id: &[u8],
    proof: &SaplingSignedClaim,
    message_hash: &[u8; 32],
) -> Result<()> {
    let proof_hash = hash_sapling_proof_fields(
        &proof.zkproof,
        &proof.rk,
        None,
        None,
        Some(proof.value),
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

    // Read airdrop config from storage and extract sapling fields.
    let config_bytes: Vec<u8> = ctx
        .read_bytes_pre(&airdrop_config_key())?
        .ok_or(VpError::MissingAirdropConfig)?;
    let config: AirdropConfiguration = serde_json::from_slice(&config_bytes)
        .map_err(|e| VpError::InvalidAirdropConfig(e.to_string()))?;
    let sapling = config.sapling.ok_or(VpError::MissingSaplingConfig)?;

    let note_commitment_root_bytes = sapling.note_commitment_root;
    let nullifier_gap_root_bytes = sapling.nullifier_gap_root;
    let target_id = sapling.target_id.as_bytes().to_vec();

    // Finally, verify the proofs sequentially.
    for SaplingClaimProof { proof, message } in sapling_proofs {
        verify_signature(&target_id, proof, &message.hash())?;

        check_plain_value_commitment(proof.value, message)?;

        verify_sapling_proof(
            &pvk,
            &proof.zkproof,
            SaplingValueCommitmentScheme::Plain,
            &proof.rk,
            None,
            None,
            Some(proof.value),
            &note_commitment_root_bytes,
            &proof.airdrop_nullifier,
            &nullifier_gap_root_bytes,
        )
        .map_err(|e| VpError::ZkProofVerificationFailed(e.to_string()))?;
    }

    Ok(())
}
