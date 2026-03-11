//! Error types for the VP module.

use namada_core::address::Address;
use namada_vp_env::{Error, Key};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VpError {
    #[error("Airdrop action not authorized by {0}")]
    Unauthorized(Address),
    #[error("No Airdrop action found")]
    NoAction,

    #[error("zk proof verification failed: {0}")]
    ZkProofVerificationFailed(String),

    // Sapling verifying key error types.
    #[error("Missing verifying key in storage")]
    MissingVerifyingKey,
    #[error("Invalid verifying key: {0}")]
    InvalidVerifyingKey(String),

    // Orchard parameters error types.
    #[error("Missing orchard parameters in storage")]
    MissingOrchardParameters,
    #[error("Invalid orchard parameters: {0}")]
    InvalidOrchardParameters(String),

    // Storage error types.
    #[error("Missing note commitment root in storage")]
    MissingNoteCommitmentRoot,
    #[error("Missing nullifier gap root in storage")]
    MissingNullifierGapRoot,
    #[error("Missing target id in storage")]
    MissingTargetId,
    #[error("Invalid bytes found for: {0}")]
    InvalidBytes(String),

    // Value commitment error types.
    #[error("Missing value commitment scheme in storage")]
    MissingValueCommitmentScheme,
    #[error("Invalid value commitment scheme: {0}")]
    InvalidValueCommitmentScheme(String),
    #[error("Unsupported value commitment scheme")]
    UnsupportedValueCommitmentScheme,
    #[error(
        "Computed value commitment is different from provided value commitment"
    )]
    ValueCommitmentMismatch,
    #[error("Missing cv_sha256 in proof")]
    MissingCvSha256,

    // Nullifier commitment error types.
    #[error("NullifierAlreadyUsed: {0}")]
    NullifierAlreadyUsed(String),
    #[error("Nullifier not properly committed")]
    NullifierNotCommitted,
    #[error("Unexpected nullifier key changed: {0}")]
    UnexpectedNullifierKey(Key),

    // Message error types.
    #[error("Message target {0} does not match action target {1}")]
    MessageTargetMismatch(Address, Address),
    #[error("Invalid spend auth signature")]
    InvalidSpendAuthSignature,
}

impl From<VpError> for Error {
    fn from(value: VpError) -> Self {
        Error::new(value)
    }
}
