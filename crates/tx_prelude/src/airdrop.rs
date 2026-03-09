//! Airdrop functions for transactions

use namada_airdrop::storage::reveal_nullifier;
use namada_core::address::{Address, InternalAddress};
use namada_token;
use namada_tx::action::{Action, AirdropAction, ClaimProofsOutput, Write};

use super::*;

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
            namada_token::mint_tokens(
                self,
                &Address::Internal(InternalAddress::Airdrop),
                token_addr,
                &message.target,
                message.amount,
            )?;
        }

        Ok(())
    }
}
