//! Cryptographic error types

use core::fmt;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub enum CryptoError {
    /// Unsupported algorithm
    UnsupportedAlgorithm(String),
    /// Invalid key format or length
    InvalidKey(String),
    /// Invalid signature format
    InvalidSignature(String),
    /// Signature verification failed
    VerificationFailed,
    /// Serialization error
    SerializationError(String),
    /// Domain separation error
    DomainError(String),
    /// Algorithm not available (missing feature flag)
    AlgorithmNotAvailable(String),
    /// Internal error
    InternalError(String),
    /// Algorithm mismatch between signature and public key
    AlgorithmMismatch,
    /// Policy violation during verification
    PolicyViolation(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::UnsupportedAlgorithm(algo) =>
                write!(f, "Unsupported algorithm: {}", algo),
            CryptoError::InvalidKey(msg) =>
                write!(f, "Invalid key: {}", msg),
            CryptoError::InvalidSignature(msg) =>
                write!(f, "Invalid signature: {}", msg),
            CryptoError::VerificationFailed =>
                write!(f, "Signature verification failed"),
            CryptoError::SerializationError(msg) =>
                write!(f, "Serialization error: {}", msg),
            CryptoError::DomainError(msg) =>
                write!(f, "Domain error: {}", msg),
            CryptoError::AlgorithmNotAvailable(algo) =>
                write!(f, "Algorithm not available: {}", algo),
            CryptoError::InternalError(msg) =>
                write!(f, "Internal error: {}", msg),
            CryptoError::AlgorithmMismatch =>
                write!(f, "Algorithm mismatch between signature and public key"),
            CryptoError::PolicyViolation(msg) =>
                write!(f, "Policy violation: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = CryptoError::UnsupportedAlgorithm("TestAlgo".to_string());
        assert_eq!(format!("{}", error), "Unsupported algorithm: TestAlgo");

        let error = CryptoError::VerificationFailed;
        assert_eq!(format!("{}", error), "Signature verification failed");
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(
            CryptoError::UnsupportedAlgorithm("test".to_string()),
            CryptoError::UnsupportedAlgorithm("test".to_string())
        );
        assert_ne!(
            CryptoError::UnsupportedAlgorithm("test1".to_string()),
            CryptoError::UnsupportedAlgorithm("test2".to_string())
        );
    }
}