use std::convert::{TryFrom, TryInto};

use indexmap::IndexMap;
use namada_core::address::Address;
use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use thiserror::Error;
use util::reversed_hex_encode;
use zair_core::base::{ReversedHex, hash_message};

pub mod util;

/// Error type for building ClaimProofsOutput from input files.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum ClaimProofsError {
    /// Missing message error.
    #[error("Missing message for proof with nullifier: {nullifier}")]
    MissingMessage {
        /// The nullifier (hex encoded).
        nullifier: String,
    },
    /// Unused message error.
    #[error("Unused message with nullifier: {nullifier}")]
    UnusedMessage {
        /// The nullifier (hex encoded).
        nullifier: String,
    },
    /// Type conversion error.
    #[error("Failed to convert message input: {0}")]
    MessageConversion(String),
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
    /// Token address to claim.
    pub token: Address,
    /// The target of the airdrop.
    pub target: Address,
    /// Claim data containing ZK proof information.
    pub claim_data: ClaimProofsOutput,
}

/// Output format for claim proofs, with each proof paired with its message.
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
    /// Sapling claim proofs, each paired with its message.
    pub sapling: Vec<SaplingClaimProof>,
    /// Orchard claim proofs, each paired with its message.
    pub orchard: Vec<OrchardClaimProof>,
}

/// A Sapling claim proof paired with its message.
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
pub struct SaplingClaimProof {
    /// The ZK proof result.
    pub proof: SaplingSignedClaim,
    /// The message associated with this proof.
    pub message: Message,
}

/// An Orchard claim proof paired with its message.
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
pub struct OrchardClaimProof {
    /// The ZK proof result.
    pub proof: OrchardSignedClaim,
    /// The message associated with this proof.
    pub message: Message,
}

impl ClaimProofsOutput {
    /// Build a `ClaimProofsOutput` from parsed input files.
    ///
    /// Pairs proofs with messages by nullifier.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A proof has no corresponding message
    /// - A message has no corresponding proof
    /// - There's an error converting MessageInput to Message
    pub fn from_input_files(
        proofs: ClaimProofsInputFile,
        messages: ClaimMessagesInputFile,
    ) -> Result<Self, ClaimProofsError> {
        // Build a map of nullifiers to messages.
        let mut sapling_messages: IndexMap<String, Message> = IndexMap::new();
        for msg in messages.sapling {
            let nullifier_hex = msg.airdrop_nullifier.clone();
            let message: Message = msg.try_into()?;
            sapling_messages.insert(nullifier_hex, message);
        }

        let mut orchard_messages: IndexMap<String, Message> = IndexMap::new();
        for msg in messages.orchard {
            let nullifier_hex = msg.airdrop_nullifier.clone();
            let message: Message = msg.try_into()?;
            orchard_messages.insert(nullifier_hex, message);
        }

        let mut sapling_proofs = Vec::new();
        for proof in proofs.sapling {
            let nullifier_hex = reversed_hex_encode(&proof.airdrop_nullifier);
            let message = sapling_messages.shift_remove(&nullifier_hex).ok_or(
                ClaimProofsError::MissingMessage {
                    nullifier: nullifier_hex,
                },
            )?;
            sapling_proofs.push(SaplingClaimProof { proof, message });
        }

        // Map proofs to messages using the nullifier-message map.
        let mut orchard_proofs = Vec::new();
        for proof in proofs.orchard {
            let nullifier_hex = reversed_hex_encode(&proof.airdrop_nullifier);
            let message = orchard_messages.shift_remove(&nullifier_hex).ok_or(
                ClaimProofsError::MissingMessage {
                    nullifier: nullifier_hex,
                },
            )?;
            orchard_proofs.push(OrchardClaimProof { proof, message });
        }

        // Check for unused messages.
        if !sapling_messages.is_empty() {
            if let Some((nullifier, _)) = sapling_messages.into_iter().next() {
                return Err(ClaimProofsError::UnusedMessage { nullifier });
            }
        }
        if !orchard_messages.is_empty() {
            if let Some((nullifier, _)) = orchard_messages.into_iter().next() {
                return Err(ClaimProofsError::UnusedMessage { nullifier });
            }
        }

        Ok(ClaimProofsOutput {
            sapling: sapling_proofs,
            orchard: orchard_proofs,
        })
    }

    /// Returns an iterator over the airdrop nullifiers of the proofs.
    pub fn nullifier_iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.sapling
            .iter()
            .map(|p| &p.proof.airdrop_nullifier)
            .chain(
                self.orchard
                    .iter()
                    .map(|p| &p.proof.airdrop_nullifier),
            )
    }

    /// Returns an iterator over all messages.
    pub fn message_iter(&self) -> impl Iterator<Item = &Message> {
        self.sapling
            .iter()
            .map(|p| &p.message)
            .chain(self.orchard.iter().map(|p| &p.message))
    }

    /// Returns an iterator over all (proof, message) pairs for Sapling.
    pub fn sapling_iter(
        &self,
    ) -> impl Iterator<Item = (&SaplingSignedClaim, &Message)> {
        self.sapling.iter().map(|p| (&p.proof, &p.message))
    }

    /// Returns an iterator over all (proof, message) pairs for Orchard.
    pub fn orchard_iter(
        &self,
    ) -> impl Iterator<Item = (&OrchardSignedClaim, &Message)> {
        self.orchard.iter().map(|p| (&p.proof, &p.message))
    }
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
pub struct SaplingSignedClaim {
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
    /// Hash of this claim's unsigned proof fields.
    #[serde_as(as = "Hex")]
    pub proof_hash: [u8; 32],
    /// Hash of this claim's external message payload.
    #[serde_as(as = "Hex")]
    pub message_hash: [u8; 32],
    /// Spend authorization signature over the submission digest.
    #[serde_as(as = "Hex")]
    pub spend_auth_sig: [u8; 64],
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
pub struct OrchardSignedClaim {
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
    /// The airdrop nullifier (airdrop-specific nullifier for double-claim
    /// prevention).
    #[serde_as(as = "ReversedHex")]
    pub airdrop_nullifier: [u8; 32],
    /// Hash of this claim's unsigned proof fields.
    #[serde_as(as = "Hex")]
    pub proof_hash: [u8; 32],
    /// Hash of this claim's external message payload.
    #[serde_as(as = "Hex")]
    pub message_hash: [u8; 32],
    /// Spend authorization signature over the submission digest.
    #[serde_as(as = "Hex")]
    pub spend_auth_sig: [u8; 64],
}

/// Message containing further claim details needed for validation.
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
pub struct Message {
    /// The target of the airdrop.
    pub target: Address,
    /// Amount to claim.
    pub amount: u64,
    /// Commitment value randomness.
    pub rcv: [u8; 32],
}

impl Message {
    /// Returns the hash of this message.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.serialize_to_vec();
        hash_message(&bytes)
    }
}

/// Input format for a single message entry in the messages file. Not to be used
/// directly, prefer [`Message`] instead.
#[serde_as]
#[derive(Debug, Deserialize)]
pub struct MessageInput {
    /// Airdrop nullifier as hex string (to match with proofs).
    pub airdrop_nullifier: String,
    /// Target address as bech32 string.
    pub target: String,
    /// Amount to claim.
    pub amount: u64,
    /// Value commitment randomness.
    #[serde_as(as = "Hex")]
    pub rcv: [u8; 32],
}

impl TryFrom<MessageInput> for Message {
    type Error = ClaimProofsError;

    fn try_from(input: MessageInput) -> Result<Self, Self::Error> {
        let target = Address::decode(&input.target).map_err(|e| {
            ClaimProofsError::MessageConversion(format!(
                "Invalid target address: {}",
                e
            ))
        })?;

        Ok(Message {
            target,
            amount: input.amount,
            rcv: input.rcv,
        })
    }
}

/// Input wrapper for deserializing proofs file.
#[derive(Debug, Deserialize)]
pub struct ClaimProofsInputFile {
    /// Sapling proofs from the file.
    pub sapling: Vec<SaplingSignedClaim>,
    /// Orchard proofs from the file.
    pub orchard: Vec<OrchardSignedClaim>,
}

/// Input wrapper for deserializing the messages file.
#[derive(Debug, Deserialize)]
pub struct ClaimMessagesInputFile {
    /// Sapling messages.
    pub sapling: Vec<MessageInput>,
    /// Orchard messages.
    pub orchard: Vec<MessageInput>,
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for airdrop transactions.
pub mod tests {
    use namada_core::address::testing::arb_non_internal_address;
    use proptest::prelude::any;
    use proptest::prop_compose;

    use super::*;

    prop_compose! {
        /// Generate an arbitrary claim proofs output.
        pub fn arb_claim_data()(
            sapling in proptest::collection::vec(arb_sapling_claim_proof(), 0..10),
            orchard in proptest::collection::vec(arb_orchard_claim_proof(), 0..10),
        ) -> ClaimProofsOutput {
            ClaimProofsOutput { sapling, orchard }
        }
    }

    prop_compose! {
        /// Generate an arbitrary Sapling claim proof with message.
        pub fn arb_sapling_claim_proof()(
            proof in arb_sapling_proof_result(),
            message in arb_message(),
        ) -> SaplingClaimProof {
            SaplingClaimProof { proof, message }
        }
    }

    prop_compose! {
        /// Generate an arbitrary Sapling claim proof result.
        pub fn arb_sapling_proof_result()(
            zkproof in any::<[u8; 192]>(),
            rk in any::<[u8; 32]>(),
            cv in any::<[u8; 32]>(),
            airdrop_nullifier in any::<[u8; 32]>(),
            proof_hash in any::<[u8; 32]>(),
            message_hash in any::<[u8; 32]>(),
            spend_auth_sig in any::<[u8; 64]>(),
        ) -> SaplingSignedClaim {
            SaplingSignedClaim {
                zkproof,
                rk,
                cv: Some(cv),
                cv_sha256: None,
                airdrop_nullifier,
                proof_hash,
                message_hash,
                spend_auth_sig,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary Orchard claim proof with message.
        pub fn arb_orchard_claim_proof()(
            proof in arb_orchard_proof_result(),
            message in arb_message(),
        ) -> OrchardClaimProof {
            OrchardClaimProof { proof, message }
        }
    }

    prop_compose! {
        /// Generate an arbitrary Orchard claim proof result.
        pub fn arb_orchard_proof_result()(
            zkproof in any::<Vec<u8>>(),
            rk in any::<[u8; 32]>(),
            cv in any::<[u8; 32]>(),
            airdrop_nullifier in any::<[u8; 32]>(),
            proof_hash in any::<[u8; 32]>(),
            message_hash in any::<[u8; 32]>(),
            spend_auth_sig in any::<[u8; 64]>(),
        ) -> OrchardSignedClaim {
            OrchardSignedClaim {
                zkproof,
                rk,
                cv: Some(cv),
                cv_sha256: None,
                airdrop_nullifier,
                proof_hash,
                message_hash,
                spend_auth_sig,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary message.
        pub fn arb_message()(
            target in arb_non_internal_address(),
            amount in any::<u64>(),
            rcv in any::<[u8; 32]>(),
        ) -> Message {
            Message { target, amount, rcv }
        }
    }

    prop_compose! {
        /// Generate an arbitrary airdrop claim.
        pub fn arb_airdrop_claim()(
            token in arb_non_internal_address(),
            target in arb_non_internal_address(),
            claim_data in arb_claim_data(),
        ) -> ClaimAirdrop {
            ClaimAirdrop {
                token,
                target,
                claim_data,
            }
        }
    }
}
