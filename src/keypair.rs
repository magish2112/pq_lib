//! Hybrid cryptographic keypair types

use core::fmt;
use crate::{AlgorithmId, CryptoResult};

/// A hybrid cryptographic keypair combining classical and post-quantum keys.
///
/// This structure holds both the public and private components of a hybrid
/// cryptographic keypair. The keypair supports various algorithms including
/// Ed25519 (classical) and ML-DSA/SLH-DSA (post-quantum) for maximum security
/// and forward compatibility.
///
/// # Examples
///
/// ```rust
/// use pq_lib::{HybridSigner, AlgorithmId};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;
///
///     println!("Public key algorithm: {}", keypair.public_key.algorithm);
///     println!("Private key algorithm: {}", keypair.private_key.algorithm);
///
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridKeypair {
    /// The public key component of the keypair
    pub public_key: HybridPublicKey,
    /// The private key component of the keypair
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

/// A hybrid public key containing both classical and post-quantum components.
///
/// This structure represents a public key that can contain both Ed25519
/// (classical) and post-quantum algorithm components. The presence of
/// post-quantum components depends on the algorithm used.
///
/// # Security Considerations
///
/// The public key is safe to share and store publicly. It contains no
/// sensitive information and can be freely distributed.
///
/// # Examples
///
/// ```rust
/// use pq_lib::{HybridPublicKey, AlgorithmId};
///
/// let ed25519_key = vec![0u8; 32]; // 32-byte Ed25519 public key
/// let public_key = HybridPublicKey::from_ed25519(ed25519_key);
///
/// assert_eq!(public_key.algorithm, AlgorithmId::Ed25519);
/// assert!(public_key.pq_key.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPublicKey {
    /// The cryptographic algorithm this key is designed for
    pub algorithm: AlgorithmId,
    /// The Ed25519 public key component (always present)
    pub ed25519_key: Vec<u8>,
    /// The post-quantum public key component (optional, depends on algorithm)
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

/// A hybrid private key with automatic memory zeroization for security.
///
/// This structure represents a private key that can contain both Ed25519
/// (classical) and post-quantum algorithm components. The key is designed
/// to be used for signing operations and includes automatic zeroization
/// of sensitive data when dropped.
///
/// # Security Considerations
///
/// **⚠️ CRITICAL:** Never store, log, or transmit private keys. They contain
/// sensitive cryptographic material that could compromise security if exposed.
/// The key implements automatic zeroization on drop for memory safety.
///
/// # Examples
///
/// ```rust
/// use pq_lib::{HybridPrivateKey, AlgorithmId};
///
/// let ed25519_key = vec![0u8; 32]; // 32-byte Ed25519 private key
/// let private_key = HybridPrivateKey::from_ed25519(ed25519_key);
///
/// assert_eq!(private_key.algorithm, AlgorithmId::Ed25519);
/// assert!(private_key.pq_key.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPrivateKey {
    /// The cryptographic algorithm this key is designed for
    pub algorithm: AlgorithmId,
    /// The Ed25519 private key component (always present)
    pub ed25519_key: Vec<u8>,
    /// The post-quantum private key component (optional, depends on algorithm)
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