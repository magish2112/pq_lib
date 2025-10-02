//! Hybrid cryptographic keypair types

use core::fmt;
use crate::{AlgorithmId, CryptoResult};

/// Hybrid cryptographic keypair
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridKeypair {
    /// Public key
    pub public_key: HybridPublicKey,
    /// Private key
    pub private_key: HybridPrivateKey,
}

impl HybridKeypair {
    /// Create new keypair
    pub const fn new(public_key: HybridPublicKey, private_key: HybridPrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

/// Hybrid public key
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPublicKey {
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Ed25519 public key
    pub ed25519_key: Vec<u8>,
    /// Post-quantum public key (optional)
    pub pq_key: Option<Vec<u8>>,
}

impl HybridPublicKey {
    /// Create Ed25519-only public key
    pub fn from_ed25519(ed25519_key: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            ed25519_key,
            pq_key: None,
        }
    }

    /// Create hybrid public key
    pub fn new(algorithm: AlgorithmId, ed25519_key: Vec<u8>, pq_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            ed25519_key,
            pq_key: Some(pq_key),
        }
    }

    /// Get the expected size of this public key
    pub fn expected_size(&self) -> usize {
        self.algorithm.public_key_size()
    }
}

/// Hybrid private key with zeroization
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPrivateKey {
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Ed25519 private key
    pub ed25519_key: Vec<u8>,
    /// Post-quantum private key (optional)
    pub pq_key: Option<Vec<u8>>,
}

impl HybridPrivateKey {
    /// Create Ed25519-only private key
    pub fn from_ed25519(ed25519_key: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            ed25519_key,
            pq_key: None,
        }
    }

    /// Create hybrid private key
    pub fn new(algorithm: AlgorithmId, ed25519_key: Vec<u8>, pq_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            ed25519_key,
            pq_key: Some(pq_key),
        }
    }

    /// Check if private key has PQ component
    pub fn has_pq_key(&self) -> bool {
        self.pq_key.is_some()
    }

    /// Get PQ key (returns None if not present)
    pub fn pq_key(&self) -> Option<&Vec<u8>> {
        self.pq_key.as_ref()
    }

    /// Get Ed25519 private key
    pub fn ed25519_key(&self) -> &[u8] {
        &self.ed25519_key
    }
}

impl HybridPublicKey {
    /// Create Ed25519-only public key
    pub fn from_ed25519(ed25519_key: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            ed25519_key,
            pq_key: None,
        }
    }

    /// Create hybrid public key
    pub fn new(algorithm: AlgorithmId, ed25519_key: Vec<u8>, pq_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            ed25519_key,
            pq_key: Some(pq_key),
        }
    }

    /// Check if public key has PQ component
    pub fn has_pq_key(&self) -> bool {
        self.pq_key.is_some()
    }

    /// Get PQ key (returns None if not present)
    pub fn pq_key(&self) -> Option<&Vec<u8>> {
        self.pq_key.as_ref()
    }

    /// Get Ed25519 public key
    pub fn ed25519_key(&self) -> &[u8] {
        &self.ed25519_key
    }
}

// Zeroize implementation for secure cleanup
#[cfg(feature = "std")]
impl Drop for HybridPrivateKey {
    fn drop(&mut self) {
        // In a real implementation, use zeroize crate
        self.ed25519_key.iter_mut().for_each(|b| *b = 0);
        if let Some(pq_key) = &mut self.pq_key {
            pq_key.iter_mut().for_each(|b| *b = 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keypair_creation() {
        let ed25519_key = vec![1, 2, 3, 4];
        let public_key = HybridPublicKey::from_ed25519(ed25519_key.clone());
        let private_key = HybridPrivateKey::from_ed25519(ed25519_key);

        let keypair = HybridKeypair::new(public_key.clone(), private_key.clone());

        assert_eq!(keypair.public_key, public_key);
        assert_eq!(keypair.private_key, private_key);
        assert_eq!(keypair.public_key.algorithm, AlgorithmId::Ed25519);
        assert_eq!(keypair.private_key.algorithm, AlgorithmId::Ed25519);
    }

    #[test]
    fn test_hybrid_public_key_sizes() {
        let ed25519_key = vec![0u8; 32];
        let public_key = HybridPublicKey::from_ed25519(ed25519_key);

        assert_eq!(public_key.expected_size(), 32);
        assert_eq!(public_key.algorithm, AlgorithmId::Ed25519);
        assert!(public_key.pq_key.is_none());
    }

    #[test]
    fn test_hybrid_private_key() {
        let ed25519_key = vec![1u8; 32];
        let private_key = HybridPrivateKey::from_ed25519(ed25519_key);

        assert_eq!(private_key.algorithm, AlgorithmId::Ed25519);
        assert!(private_key.pq_key.is_none());
        assert_eq!(private_key.ed25519_key.len(), 32);
    }
}