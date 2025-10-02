//! Hybrid cryptographic signature types

use core::fmt;
use crate::{AlgorithmId, CryptoResult};

/// Hybrid cryptographic signature with versioning
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridSignature {
    /// Format version for backward compatibility
    pub version: u8,
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Ed25519 signature (always present)
    pub ed25519_sig: Vec<u8>,
    /// Post-quantum signature (optional)
    pub pq_sig: Option<Vec<u8>>,
}

impl HybridSignature {
    /// Current signature format version
    pub const CURRENT_VERSION: u8 = 1;

    /// Create new signature
    pub fn new(
        algorithm: AlgorithmId,
        ed25519_sig: Vec<u8>,
        pq_sig: Option<Vec<u8>>,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            algorithm,
            ed25519_sig,
            pq_sig,
        }
    }

    /// Create Ed25519-only signature
    pub fn ed25519_only(ed25519_sig: Vec<u8>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            algorithm: AlgorithmId::Ed25519,
            ed25519_sig,
            pq_sig: None,
        }
    }

    /// Check if signature is valid for the algorithm
    pub fn is_valid_for_algorithm(&self) -> bool {
        match self.algorithm {
            AlgorithmId::Ed25519 => self.pq_sig.is_none(),
            _ => self.pq_sig.is_some(),
        }
    }

    /// Get expected size of this signature
    pub fn expected_size(&self) -> usize {
        self.algorithm.signature_size()
    }
}

impl fmt::Display for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridSignature(v{}, {}, ed25519: {} bytes, pq: {} bytes)",
            self.version,
            self.algorithm,
            self.ed25519_sig.len(),
            self.pq_sig.as_ref().map(|s| s.len()).unwrap_or(0)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signature_creation() {
        let ed25519_sig = vec![1, 2, 3, 4, 5];
        let signature = HybridSignature::ed25519_only(ed25519_sig.clone());

        assert_eq!(signature.version, HybridSignature::CURRENT_VERSION);
        assert_eq!(signature.algorithm, AlgorithmId::Ed25519);
        assert_eq!(signature.ed25519_sig, ed25519_sig);
        assert!(signature.pq_sig.is_none());
        assert!(signature.is_valid_for_algorithm());
    }

    #[test]
    fn test_hybrid_signature_with_pq() {
        let ed25519_sig = vec![1u8; 64];
        let pq_sig = vec![2u8; 32];
        let signature = HybridSignature::new(
            AlgorithmId::MlDsa65,
            ed25519_sig.clone(),
            Some(pq_sig.clone())
        );

        assert_eq!(signature.version, HybridSignature::CURRENT_VERSION);
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa65);
        assert_eq!(signature.ed25519_sig, ed25519_sig);
        assert_eq!(signature.pq_sig, Some(pq_sig));
        assert!(signature.is_valid_for_algorithm());
    }

    #[test]
    fn test_signature_expected_size() {
        let signature = HybridSignature::ed25519_only(vec![0u8; 64]);
        assert_eq!(signature.expected_size(), 64);

        let signature = HybridSignature::new(
            AlgorithmId::MlDsa65,
            vec![0u8; 64],
            Some(vec![0u8; 3302])
        );
        assert_eq!(signature.expected_size(), 64 + 3302);
    }

    #[test]
    fn test_signature_display() {
        let signature = HybridSignature::ed25519_only(vec![0u8; 64]);
        let display = format!("{}", signature);
        assert!(display.contains("HybridSignature"));
        assert!(display.contains("Ed25519"));
        assert!(display.contains("64 bytes"));
    }
}