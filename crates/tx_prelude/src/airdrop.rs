//! Airdrop functions for transactions

use namada_core::address::{Address, InternalAddress};
use namada_core::token::Amount;
use namada_token;
use namada_tx::action::{Action, AirdropAction, Write};

use super::*;

impl Ctx {
    /// Claim airdrop tokens
    pub fn claim_airdrop(
        &mut self,
        target: &Address,
        token_addr: &Address,
        amount: Amount,
    ) -> TxResult {
        self.insert_verifier(&Address::Internal(InternalAddress::Airdrop))?;
        self.insert_verifier(target)?;

        self.push_action(Action::Airdrop(AirdropAction::Claim {
            target: target.clone(),
            amount,
        }))?;

        // Mint tokens with Airdrop as minter
        namada_token::mint_tokens(
            self,
            &Address::Internal(InternalAddress::Airdrop),
            token_addr,
            target,
            amount,
        )?;

        Ok(())
    }
}
