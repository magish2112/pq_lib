//! Hybrid cryptographic key types

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AlgorithmId, CryptoResult};

/// Hybrid cryptographic public key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPublicKey {
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Ed25519 public key (always present for backward compatibility)
    pub ed25519_key: Vec<u8>,
    /// Post-quantum public key (optional)
    pub pq_key: Option<Vec<u8>>,
}

impl HybridPublicKey {
    /// Create from Ed25519-only key
    pub fn from_ed25519(ed25519_bytes: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            ed25519_key: ed25519_bytes,
            pq_key: None,
        }
    }

    /// Create hybrid key
    pub fn new(algorithm: AlgorithmId, ed25519_bytes: Vec<u8>, pq_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            ed25519_key: ed25519_bytes,
            pq_key: Some(pq_key),
        }
    }

    /// Check if key supports post-quantum operations
    pub const fn has_pq_key(&self) -> bool {
        self.pq_key.is_some()
    }

    /// Get PQ key reference (panics if not present)
    pub fn pq_key(&self) -> &[u8] {
        self.pq_key.as_ref().expect("PQ key not present")
    }

    /// Validate key format
    pub fn validate(&self) -> CryptoResult<()> {
        if self.ed25519_key.len() != 32 {
            return Err(crate::CryptoError::InvalidKeyFormat);
        }

        if self.algorithm.is_post_quantum() && self.pq_key.is_none() {
            return Err(crate::CryptoError::InvalidKeyFormat);
        }

        Ok(())
    }
}

impl fmt::Display for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridPublicKey({}, ed25519_key_len={}, pq_key_present={})",
            self.algorithm,
            self.ed25519_key.len(),
            self.pq_key.is_some()
        )
    }
}

/// Hybrid cryptographic private key with zeroization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
#[serde(transparent)]
pub struct HybridPrivateKey {
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Ed25519 private key (always present)
    pub ed25519_key: Vec<u8>,
    /// Post-quantum private key (optional)
    pub pq_key: Option<Vec<u8>>,
}

impl HybridPrivateKey {
    /// Create from Ed25519-only key
    pub fn from_ed25519(ed25519_bytes: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            ed25519_key: ed25519_bytes,
            pq_key: None,
        }
    }

    /// Create hybrid key
    pub fn new(algorithm: AlgorithmId, ed25519_bytes: Vec<u8>, pq_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            ed25519_key: ed25519_bytes,
            pq_key: Some(pq_key),
        }
    }

    /// Check if key supports post-quantum operations
    pub const fn has_pq_key(&self) -> bool {
        self.pq_key.is_some()
    }

    /// Get PQ key reference (panics if not present)
    pub fn pq_key(&self) -> &[u8] {
        self.pq_key.as_ref().expect("PQ key not present")
    }

    /// Validate key format
    pub fn validate(&self) -> CryptoResult<()> {
        if self.ed25519_key.len() != 32 {
            return Err(crate::CryptoError::InvalidKeyFormat);
        }

        if self.algorithm.is_post_quantum() && self.pq_key.is_none() {
            return Err(crate::CryptoError::InvalidKeyFormat);
        }

        Ok(())
    }
}

impl Zeroize for HybridPrivateKey {
    fn zeroize(&mut self) {
        self.ed25519_key.zeroize();
        if let Some(ref mut pq_key) = self.pq_key {
            pq_key.zeroize();
        }
    }
}

impl ZeroizeOnDrop for HybridPrivateKey {}

impl Drop for HybridPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Hybrid keypair combining public and private keys
#[derive(Debug, Clone)]
pub struct HybridKeypair {
    /// Public key
    pub public_key: HybridPublicKey,
    /// Private key
    pub private_key: HybridPrivateKey,
}

impl HybridKeypair {
    /// Create new keypair
    pub fn new(public_key: HybridPublicKey, private_key: HybridPrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Validate keypair consistency
    pub fn validate(&self) -> CryptoResult<()> {
        self.public_key.validate()?;
        self.private_key.validate()?;

        if self.public_key.algorithm != self.private_key.algorithm {
            return Err(crate::CryptoError::AlgorithmMismatch);
        }

        if self.public_key.ed25519_key != self.private_key.ed25519_key {
            return Err(crate::CryptoError::KeyLengthMismatch);
        }

        Ok(())
    }
}

impl From<HybridKeypair> for (HybridPublicKey, HybridPrivateKey) {
    fn from(keypair: HybridKeypair) -> (HybridPublicKey, HybridPrivateKey) {
        (keypair.public_key, keypair.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlgorithmId;

    #[test]
    fn test_public_key_creation() {
        let ed25519_key = HybridPublicKey::from_ed25519(vec![1; 32]);
        assert_eq!(ed25519_key.algorithm, AlgorithmId::Ed25519);
        assert!(!ed25519_key.has_pq_key());

        let hybrid_key = HybridPublicKey::new(AlgorithmId::MlDsa65, vec![1; 32], vec![2; 64]);
        assert_eq!(hybrid_key.algorithm, AlgorithmId::MlDsa65);
        assert!(hybrid_key.has_pq_key());
    }

    #[test]
    fn test_private_key_creation() {
        let ed25519_key = HybridPrivateKey::from_ed25519(vec![1; 32]);
        assert_eq!(ed25519_key.algorithm, AlgorithmId::Ed25519);
        assert!(!ed25519_key.has_pq_key());

        let hybrid_key = HybridPrivateKey::new(AlgorithmId::MlDsa65, vec![1; 32], vec![2; 64]);
        assert_eq!(hybrid_key.algorithm, AlgorithmId::MlDsa65);
        assert!(hybrid_key.has_pq_key());
    }

    #[test]
    fn test_keypair_validation() {
        let public_key = HybridPublicKey::from_ed25519(vec![1; 32]);
        let private_key = HybridPrivateKey::from_ed25519(vec![1; 32]);
        let keypair = HybridKeypair::new(public_key, private_key);

        assert!(keypair.validate().is_ok());

        // Test mismatched algorithms
        let bad_public = HybridPublicKey::new(AlgorithmId::MlDsa65, vec![1; 32], vec![2; 64]);
        let bad_keypair = HybridKeypair::new(bad_public, keypair.private_key);
        assert!(bad_keypair.validate().is_err());
    }

    #[test]
    fn test_zeroization() {
        let mut private_key = HybridPrivateKey::from_ed25519(vec![42; 32]);
        assert_eq!(private_key.ed25519_key, vec![42; 32]);

        private_key.zeroize();
        assert_eq!(private_key.ed25519_key, vec![0; 32]);
    }
}

