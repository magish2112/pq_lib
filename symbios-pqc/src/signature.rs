//! Hybrid cryptographic signature types

use core::fmt;

use crate::{AlgorithmId, DomainSeparator, CryptoResult};

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
    /// Domain separator used for signing
    pub domain: DomainSeparator,
}

impl HybridSignature {
    /// Current signature format version
    pub const CURRENT_VERSION: u8 = 1;

    /// Create new signature
    pub fn new(
        algorithm: AlgorithmId,
        ed25519_sig: Vec<u8>,
        pq_sig: Option<Vec<u8>>,
        domain: DomainSeparator,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            algorithm,
            ed25519_sig,
            pq_sig,
            domain,
        }
    }

    /// Create Ed25519-only signature
    pub fn ed25519_only(ed25519_sig: Vec<u8>, domain: DomainSeparator) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            algorithm: AlgorithmId::Ed25519,
            ed25519_sig,
            pq_sig: None,
            domain,
        }
    }

    /// Check if signature has post-quantum component
    pub const fn has_pq_signature(&self) -> bool {
        self.pq_sig.is_some()
    }

    /// Get PQ signature reference (panics if not present)
    pub fn pq_sig(&self) -> &[u8] {
        self.pq_sig.as_ref().expect("PQ signature not present")
    }

    /// Validate signature format
    pub fn validate_format(&self) -> CryptoResult<()> {
        if self.version > Self::CURRENT_VERSION {
            return Err(crate::CryptoError::UnsupportedVersion(self.version));
        }

        if self.ed25519_sig.len() != 64 {
            return Err(crate::CryptoError::InvalidSignatureLength {
                expected: 64,
                got: self.ed25519_sig.len(),
            });
        }

        if self.algorithm.is_post_quantum() && self.pq_sig.is_none() {
            return Err(crate::CryptoError::MissingPostQuantumSignature);
        }

        Ok(())
    }

    /// Get total signature size in bytes
    pub fn size(&self) -> usize {
        let mut size = 1 + 1 + 4 + self.ed25519_sig.len() + 1; // version + algorithm + domain + ed25519 + pq_flag
        if let Some(ref pq_sig) = self.pq_sig {
            size += 4 + pq_sig.len(); // length prefix + pq signature
        }
        size
    }
}

impl fmt::Display for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridSignature(v{}, {}, domain={:?}, pq_present={})",
            self.version,
            self.algorithm,
            self.domain,
            self.pq_sig.is_some()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlgorithmId;

    #[test]
    fn test_signature_creation() {
        let ed25519_sig = HybridSignature::ed25519_only(vec![1; 64], DomainSeparator::Transaction);
        assert_eq!(ed25519_sig.algorithm, AlgorithmId::Ed25519);
        assert!(!ed25519_sig.has_pq_signature());

        let hybrid_sig = HybridSignature::new(
            AlgorithmId::MlDsa65,
            vec![1; 64],
            Some(vec![2; 100]),
            DomainSeparator::Block,
        );
        assert_eq!(hybrid_sig.algorithm, AlgorithmId::MlDsa65);
        assert!(hybrid_sig.has_pq_signature());
        assert_eq!(hybrid_sig.domain, DomainSeparator::Block);
    }

    #[test]
    fn test_signature_validation() {
        // Valid Ed25519 signature
        let valid_sig = HybridSignature::ed25519_only(vec![1; 64], DomainSeparator::Transaction);
        assert!(valid_sig.validate_format().is_ok());

        // Invalid Ed25519 length
        let invalid_sig = HybridSignature::ed25519_only(vec![1; 32], DomainSeparator::Transaction);
        assert!(invalid_sig.validate_format().is_err());

        // Missing PQ signature for PQ algorithm
        let missing_pq = HybridSignature::new(
            AlgorithmId::MlDsa65,
            vec![1; 64],
            None,
            DomainSeparator::Transaction,
        );
        assert!(missing_pq.validate_format().is_err());
    }

    #[test]
    fn test_signature_size() {
        let ed25519_sig = HybridSignature::ed25519_only(vec![1; 64], DomainSeparator::Transaction);
        let base_size = ed25519_sig.size();

        let hybrid_sig = HybridSignature::new(
            AlgorithmId::MlDsa65,
            vec![1; 64],
            Some(vec![2; 100]),
            DomainSeparator::Transaction,
        );
        let hybrid_size = hybrid_sig.size();

        assert!(hybrid_size > base_size);
    }
}

