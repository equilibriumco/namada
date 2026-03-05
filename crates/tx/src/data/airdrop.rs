use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::token::Amount;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use zair_core::base::ReversedHex;

/// Output format for claim proofs.
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
pub struct ClaimProofsOutput {
    /// Sapling claim proofs.
    pub sapling_proofs: Vec<SaplingClaimProofResult>,
    /// Orchard claim proofs.
    pub orchard_proofs: Vec<OrchardClaimProofResult>,
}

/// Serializable output of a single Sapling claim proof.
#[serde_as]
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
pub struct SaplingClaimProofResult {
    /// The Groth16 proof (192 bytes)
    #[serde_as(as = "Hex")]
    pub zkproof: [u8; 192],
    /// The re-randomized spend verification key (rk)
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// The native value commitment (cv), if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// The SHA-256 value commitment (`cv_sha256`), if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// The airdrop nullifier (airdrop-specific nullifier for double-claim
    /// prevention).
    #[serde_as(as = "ReversedHex")]
    pub airdrop_nullifier: [u8; 32],
}

/// Serializable output of a single Orchard claim proof.
#[serde_as]
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
pub struct OrchardClaimProofResult {
    /// The Halo2 proof bytes.
    #[serde_as(as = "Hex")]
    pub zkproof: Vec<u8>,
    /// The re-randomized spend verification key (rk).
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// The native value commitment (`cv`), if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// The SHA-256 value commitment (`cv_sha256`), if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// The airdrop nullifier (airdrop-specific nullifier for double-claim prevention).
    #[serde_as(as = "ReversedHex")]
    pub airdrop_nullifier: [u8; 32],
}

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
    /// Claim data containing ZK proof information.
    pub claim_data: ClaimProofsOutput,
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for airdrop transactions.
pub mod tests {
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::token::testing::arb_amount;
    use proptest::prelude::any;
    use proptest::prop_compose;

    use super::*;
    
    prop_compose! {
        /// Generate an arbitrary claim proofs output.
        pub fn arb_claim_data()(
            sapling_proofs in proptest::collection::vec(arb_sapling_claim_proof(), 0..10),
            orchard_proofs in proptest::collection::vec(arb_orchard_claim_proof(), 0..10),
        ) -> ClaimProofsOutput {
            ClaimProofsOutput { sapling_proofs, orchard_proofs }
        }
    }
    
    prop_compose! {
        /// Generate an arbitrary Sapling claim proof.
        pub fn arb_sapling_claim_proof()(
            zkproof in any::<[u8; 192]>(),
            rk in any::<[u8; 32]>(),
            cv in any::<[u8; 32]>(),
            airdrop_nullifier in any::<[u8; 32]>(),
        ) -> SaplingClaimProofResult {
            SaplingClaimProofResult {
                zkproof,
                rk,
                cv: Some(cv),
                cv_sha256: None,
                airdrop_nullifier,
            }
        }
    }
    
    prop_compose! {
        /// Generate an arbitrary Orchard claim proof.
        pub fn arb_orchard_claim_proof()(
            zkproof in any::<Vec<u8>>(),
            rk in any::<[u8; 32]>(),
            cv in any::<[u8; 32]>(),
            airdrop_nullifier in any::<[u8; 32]>(),
        ) -> OrchardClaimProofResult {
            OrchardClaimProofResult {
                zkproof,
                rk,
                cv: Some(cv),
                cv_sha256: None,
                airdrop_nullifier,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary airdrop claim.
        pub fn arb_airdrop_claim()(
            target in arb_non_internal_address(),
            token in arb_non_internal_address(),
            amount in arb_amount(),
            claim_data in arb_claim_data(),
        ) -> ClaimAirdrop {
            ClaimAirdrop { target, token, amount, claim_data }
        }
    }
}
