//! Cryptographic error types

use core::fmt;

/// Cryptographic operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub enum CryptoError {
    /// Unsupported signature version
    UnsupportedVersion(u8),

    /// Invalid signature length
    InvalidSignatureLength {
        /// Expected length
        expected: usize,
        /// Actual length
        got: usize,
    },

    /// Missing post-quantum signature component
    MissingPostQuantumSignature,

    /// Algorithm mismatch between keys
    AlgorithmMismatch,

    /// Key length mismatch
    KeyLengthMismatch,

    /// Invalid key format
    InvalidKeyFormat,

    /// Signature verification failed
    SignatureVerificationFailed,

    /// Unsupported algorithm
    UnsupportedAlgorithm(String),

    /// Domain separation required but not provided
    DomainSeparationRequired,

    /// Policy violation
    PolicyViolation(String),

    /// Serialization error
    SerializationError(String),

    /// Post-quantum cryptography error
    PqError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::UnsupportedVersion(v) => {
                write!(f, "Unsupported signature version: {v}")
            }
            CryptoError::InvalidSignatureLength { expected, got } => {
                write!(f, "Invalid signature length: expected {expected}, got {got}")
            }
            CryptoError::MissingPostQuantumSignature => {
                write!(f, "Missing post-quantum signature for hybrid algorithm")
            }
            CryptoError::AlgorithmMismatch => {
                write!(f, "Algorithm mismatch between keys")
            }
            CryptoError::KeyLengthMismatch => {
                write!(f, "Key length mismatch")
            }
            CryptoError::InvalidKeyFormat => {
                write!(f, "Invalid key format")
            }
            CryptoError::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
            CryptoError::UnsupportedAlgorithm(name) => {
                write!(f, "Unsupported algorithm: {name}")
            }
            CryptoError::DomainSeparationRequired => {
                write!(f, "Domain separation required but not provided")
            }
            CryptoError::PolicyViolation(desc) => {
                write!(f, "Policy violation: {desc}")
            }
            CryptoError::SerializationError(msg) => {
                write!(f, "Serialization error: {msg}")
            }
            CryptoError::PqError(msg) => {
                write!(f, "PQ cryptography error: {msg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

#[cfg(feature = "std")]
impl From<Box<dyn std::error::Error>> for CryptoError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        CryptoError::PqError(err.to_string())
    }
}

#[cfg(feature = "serde-support")]
impl From<serde_cbor::Error> for CryptoError {
    fn from(err: serde_cbor::Error) -> Self {
        CryptoError::SerializationError(err.to_string())
    }
}

