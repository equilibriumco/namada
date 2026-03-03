use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::token::Amount;
use serde::{Deserialize, Serialize};

/// A tx data type to hold airdrop claim data.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct ClaimAirdrop {
    /// The target of the airdrop.
    pub target: Address,
    /// Token address to claim.
    pub token: Address,
    /// Amount to claim.
    pub amount: Amount,
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for airdrop transactions.
pub mod tests {
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::token::testing::arb_amount;
    use proptest::prop_compose;

    use super::*;

    prop_compose! {
        /// Generate an arbitrary airdrop claim.
        pub fn arb_airdrop_claim()(
            target in arb_non_internal_address(),
            token in arb_non_internal_address(),
            amount in arb_amount(),
        ) -> ClaimAirdrop {
            ClaimAirdrop { target, token, amount  }
        }
    }
}
