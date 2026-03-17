//! Airdrop functions for transactions

use namada_airdrop::storage::reveal_nullifier;
use namada_core::address::{Address, InternalAddress};
use namada_token::{self, Amount};
use namada_tx::action::{Action, AirdropAction, ClaimProofsOutput, Write};

use super::*;

/// A constant scaling factor for the Airdrop value. This is used to scale the
/// value of the claim to NAM tokens.
pub const ZAIR_SCALING_FACTOR: u128 = 1_000;

impl Ctx {
    /// Claim airdrop tokens
    pub fn claim_airdrop(
        &mut self,
        token_addr: &Address,
        target: &Address,
        claim_data: ClaimProofsOutput,
    ) -> TxResult {
        self.insert_verifier(&Address::Internal(InternalAddress::Airdrop))?;
        self.insert_verifier(target)?;

        for nullifier in claim_data.nullifier_iter() {
            reveal_nullifier(self, nullifier)?;
        }

        self.push_action(Action::Airdrop(AirdropAction::Claim {
            target: target.clone(),
            claim_data: claim_data.clone(),
        }))?;

        // Mint tokens for each proof's message
        for message in claim_data.message_iter() {
            let amount =
                (message.amount as u128).saturating_mul(ZAIR_SCALING_FACTOR);
            namada_token::mint_tokens(
                self,
                &Address::Internal(InternalAddress::Airdrop),
                token_addr,
                &message.target,
                Amount::from_u128(amount),
            )?;
        }

        Ok(())
    }
}
