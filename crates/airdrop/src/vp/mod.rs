//! Airdrop VP

use std::collections::BTreeSet;
use std::marker::PhantomData;

use error::VpError;
use namada_core::address::Address;
use namada_core::collections::HashSet;
use namada_core::storage::Key;
use namada_tx::BatchedTxRef;
use namada_tx::action::{Action, AirdropAction, ClaimProofsOutput};
use namada_tx::data::airdrop::Message;
use namada_tx::data::airdrop::util::reversed_hex_encode;
use namada_vp_env::{Error, Result, VpEnv};
use zair_core::base::cv_sha256 as compute_cv_sha256;

use crate::storage_key::{airdrop_nullifier_key, is_airdrop_nullifier_key};

mod error;
mod orchard;
mod sapling;

/// Airdrop VP
pub struct AirdropVp<'ctx, CTX> {
    _marker: PhantomData<&'ctx CTX>,
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
                if !verifiers.contains(target) {
                    return Err(VpError::Unauthorized(target.clone()).into());
                }

                // Check if airdrop nullifiers have already been used.
                check_airdrop_nullifiers(
                    ctx,
                    claim_data,
                    &mut revealed_nullifiers,
                )?;

                // Verify all message targets match the action target.
                verify_message_targets(claim_data, target)?;

                // zk proof verification.
                sapling::verify_airdrop_claims(ctx, &claim_data.sapling)?;
                orchard::verify_airdrop_claims(ctx, &claim_data.orchard)?;
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
