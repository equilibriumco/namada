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
use zair_core::schema::config::AirdropConfiguration;

use crate::storage_key::{
    airdrop_config_key, airdrop_nullifier_key, is_airdrop_nullifier_key,
};

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
    /// Runs the validity predicate for airdrop claims.
    ///
    /// This VP validates that:
    /// - All airdrop claim actions are authorized by the target address
    /// - Nullifiers have not been previously used
    /// - All message targets match the action target
    /// - Zero-knowledge proofs are valid
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `Err(VpError::NoAction)` if no actions were taken
    /// - `Err(VpError::Unauthorized(target))` if `target` is not in `verifiers`
    /// - `Err(VpError::NullifierAlreadyUsed(..))` if a nullifier has already
    ///   been claimed or was used twice in the same transaction
    /// - `Err(VpError::NullifierNotCommitted)` if a nullifier was not properly
    ///   committed to storage
    /// - `Err(VpError::MessageTargetMismatch(..))` if a message target does not
    ///   match the action target
    /// - `Err(VpError::UnexpectedNullifierKey(..))` if a nullifier key was
    ///   modified but was not revealed in the transaction
    /// - Errors from [`sapling::verify_airdrop_claims`] or
    ///   [`orchard::verify_airdrop_claims`] if zk proof verification fails
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

                // Read airdrop config from storage
                let config_bytes: Vec<u8> = ctx
                    .read_bytes_pre(&airdrop_config_key())?
                    .ok_or(VpError::MissingAirdropConfig)?;
                let config: AirdropConfiguration =
                    serde_json::from_slice(&config_bytes).map_err(|e| {
                        VpError::InvalidAirdropConfig(e.to_string())
                    })?;

                // zk proof verification.
                sapling::verify_airdrop_claims(
                    ctx,
                    config.sapling,
                    &claim_data.sapling,
                )?;
                orchard::verify_airdrop_claims(
                    ctx,
                    config.orchard,
                    &claim_data.orchard,
                )?;
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

        // Check that the nullifier was properly committed to store.
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

/// Checks that the plain value commitment is valid by comparing the proof
/// value directly with the message amount.
fn check_plain_value_commitment(
    value: u64,
    Message { amount, .. }: &Message,
) -> Result<()> {
    if value != *amount {
        return Err(VpError::ValueCommitmentMismatch.into());
    }

    Ok(())
}
