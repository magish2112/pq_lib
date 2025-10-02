//! Hybrid cryptographic signature types

use core::fmt;
use crate::{AlgorithmId, CryptoResult};

/// A hybrid cryptographic signature supporting both classical and post-quantum algorithms.
///
/// This structure represents a digital signature that can contain both Ed25519
/// (classical) and post-quantum algorithm components. The signature includes
/// versioning for backward compatibility and domain separation for security.
///
/// # Structure
///
/// - `version`: Format version for backward compatibility
/// - `algorithm`: The cryptographic algorithm used
/// - `ed25519_sig`: Ed25519 signature component (always present)
/// - `pq_sig`: Post-quantum signature component (optional)
/// - `domain`: Domain separator used during signing
///
/// # Security Features
///
/// - **Domain Separation**: Prevents signature reuse across different contexts
/// - **Versioning**: Enables backward compatibility during upgrades
/// - **Hybrid Design**: Combines classical and post-quantum security
///
/// # Examples
///
/// ```rust
/// use pq_lib::{HybridSignature, AlgorithmId, DomainSeparator};
///
/// let ed25519_sig = vec![0u8; 64]; // 64-byte Ed25519 signature
/// let signature = HybridSignature::ed25519_only(ed25519_sig);
///
/// assert_eq!(signature.algorithm, AlgorithmId::Ed25519);
/// assert!(signature.pq_sig.is_none());
/// assert!(signature.is_valid_for_algorithm());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridSignature {
    /// Format version for backward compatibility and future extensibility
    pub version: u8,
    /// The cryptographic algorithm used for this signature
    pub algorithm: AlgorithmId,
    /// The Ed25519 signature component (always present for compatibility)
    pub ed25519_sig: Vec<u8>,
    /// The post-quantum signature component (optional, depends on algorithm)
    pub pq_sig: Option<Vec<u8>>,
    /// Domain separator used during signing to prevent cross-protocol attacks
    pub domain: crate::DomainSeparator,
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

    /// Validate signature format and consistency
    pub fn validate_format(&self) -> CryptoResult<()> {
        // Check version
        if self.version != Self::CURRENT_VERSION {
            return Err(CryptoError::InvalidSignature(
                format!("Unsupported signature version: {}", self.version)
            ));
        }

        // Check Ed25519 signature size
        if self.ed25519_sig.len() != 64 {
            return Err(CryptoError::InvalidSignature(
                format!("Invalid Ed25519 signature size: {}", self.ed25519_sig.len())
            ));
        }

        // Check algorithm consistency
        if !self.is_valid_for_algorithm() {
            return Err(CryptoError::InvalidSignature(
                "Signature format inconsistent with algorithm".to_string()
            ));
        }

        Ok(())
    }

    /// Check if signature has PQ component
    pub fn has_pq_signature(&self) -> bool {
        self.pq_sig.is_some()
    }

    /// Get PQ signature (returns None if not present)
    pub fn pq_sig(&self) -> Option<&Vec<u8>> {
        self.pq_sig.as_ref()
    }

    /// Get Ed25519 signature
    pub fn ed25519_sig(&self) -> &[u8] {
        &self.ed25519_sig
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