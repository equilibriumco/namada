//! Airdrop VP

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::storage::Key;
use namada_tx::BatchedTxRef;
use namada_tx::action::{Action, AirdropAction};
use namada_vp_env::{Error, Result, VpEnv};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VpError {
    #[error("Airdrop action not authorized by {0}")]
    Unauthorized(Address),
    #[error("No Airdrop action found")]
    NoAction,
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
        _keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        let actions = ctx.read_actions()?;

        for action in &actions {
            if let Action::Airdrop(AirdropAction::Claim { target, .. }) = action
            {
                if !verifiers.contains(target) {
                    return Err(VpError::Unauthorized(target.clone()).into());
                }
                return Ok(());
            }
        }

        Err(VpError::NoAction.into())
    }
}
