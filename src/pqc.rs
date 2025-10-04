//! Post-Quantum Cryptography operations
//!
//! This module provides implementations for NIST post-quantum algorithms
//! including ML-DSA and SLH-DSA for hybrid cryptographic operations.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec, string::ToString};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec, string::ToString};

use crate::{AlgorithmId, CryptoResult, CryptoError};

/// Post-quantum keypair for hybrid operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcKeypair {
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Private key bytes
    pub private_key: Vec<u8>,
}

impl PqcKeypair {
    /// Create a new PQC keypair
    pub fn new(algorithm: AlgorithmId, public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            public_key,
            private_key,
        }
    }

    /// Get the expected public key size for the algorithm
    pub fn expected_public_key_size(&self) -> usize {
        match self.algorithm {
            AlgorithmId::MlDsa65 => 1952,
            AlgorithmId::MlDsa87 => 2592,
            AlgorithmId::SlhDsaShake256f => 32,
            _ => 0,
        }
    }

    /// Get the expected private key size for the algorithm
    pub fn expected_private_key_size(&self) -> usize {
        match self.algorithm {
            AlgorithmId::MlDsa65 => 4032,
            AlgorithmId::MlDsa87 => 4896,
            AlgorithmId::SlhDsaShake256f => 64,
            _ => 0,
        }
    }
}

/// Post-quantum signature
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcSignature {
    /// Algorithm identifier
    pub algorithm: AlgorithmId,
    /// Signature bytes
    pub signature: Vec<u8>,
}

impl PqcSignature {
    /// Create a new PQC signature
    pub fn new(algorithm: AlgorithmId, signature: Vec<u8>) -> Self {
        Self {
            algorithm,
            signature,
        }
    }

    /// Get the expected signature size for the algorithm
    pub fn expected_size(&self) -> usize {
        match self.algorithm {
            AlgorithmId::MlDsa65 => 3309,
            AlgorithmId::MlDsa87 => 4627,
            AlgorithmId::SlhDsaShake256f => 7856,
            _ => 0,
        }
    }
}

/// PQC cryptographic operations trait
pub trait PqcOperations: Send + Sync {
    /// Generate a new PQC keypair
    fn generate_keypair(&self, algorithm: AlgorithmId) -> CryptoResult<PqcKeypair>;

    /// Sign data with a PQC private key
    fn sign(&self, data: &[u8], private_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<PqcSignature>;

    /// Verify a PQC signature against data
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<bool>;
}

/// Mock implementation for PQC operations (for demonstration)
pub struct MockPqcOps;

impl PqcOperations for MockPqcOps {
    fn generate_keypair(&self, algorithm: AlgorithmId) -> CryptoResult<PqcKeypair> {
        // Mock keypair generation without external dependencies
        let seed = b"mock_seed_for_deterministic_testing";

        let (public_size, private_size) = match algorithm {
            AlgorithmId::MlDsa65 => (1952, 4032),
            AlgorithmId::MlDsa87 => (2592, 4896),
            AlgorithmId::SlhDsaShake256f => (32, 64),
            _ => return Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        };

        // Mock key generation using simple deterministic approach
        let public_key: Vec<u8> = (0..public_size).map(|i| (seed[i % seed.len()] ^ (i as u8)) as u8).collect();
        let private_key: Vec<u8> = (0..private_size).map(|i| (seed[i % seed.len()] ^ ((i + 1) as u8)) as u8).collect();

        Ok(PqcKeypair::new(algorithm, public_key, private_key))
    }

    fn sign(&self, data: &[u8], private_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<PqcSignature> {
        let signature_size = match algorithm {
            AlgorithmId::MlDsa65 => 3309,
            AlgorithmId::MlDsa87 => 4627,
            AlgorithmId::SlhDsaShake256f => 7856,
            _ => return Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        };

        // Mock signature: simple XOR-based approach for demonstration
        let mut signature = vec![0u8; signature_size];

        // Simple mock: XOR data with private key
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = private_key[i % private_key.len()];
            signature[i % signature_size] ^= byte ^ key_byte;
        }

        // Add algorithm identifier
        signature[0] ^= algorithm as u8;

        Ok(PqcSignature::new(algorithm, signature))
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<bool> {
        let expected_size = match algorithm {
            AlgorithmId::MlDsa65 => 3309,
            AlgorithmId::MlDsa87 => 4627,
            AlgorithmId::SlhDsaShake256f => 7856,
            _ => return Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        };

        if signature.len() != expected_size {
            return Ok(false);
        }

        // Mock verification: recreate signature and compare
        let mut recreated_signature = vec![0u8; expected_size];

        // Recreate the signature using the same logic
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = public_key[i % public_key.len()];
            recreated_signature[i % expected_size] ^= byte ^ key_byte;
        }

        // Add algorithm identifier
        recreated_signature[0] ^= algorithm as u8;

        // Compare signatures (mock verification)
        Ok(signature == recreated_signature.as_slice())
    }
}

/// Real PQC implementation using dedicated ML-DSA and SLH-DSA crates
#[cfg(feature = "ml-dsa")]
pub struct RealPqcOps;

#[cfg(feature = "ml-dsa")]
impl PqcOperations for RealPqcOps {
    fn generate_keypair(&self, algorithm: AlgorithmId) -> CryptoResult<PqcKeypair> {
        match algorithm {
            AlgorithmId::MlDsa65 => {
                let (pk, sk) = ml_dsa::ml_dsa_65::Keypair::generate();
                Ok(PqcKeypair::new(algorithm, pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
            },
            AlgorithmId::MlDsa87 => {
                let (pk, sk) = ml_dsa::ml_dsa_87::Keypair::generate();
                Ok(PqcKeypair::new(algorithm, pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
            },
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }

    fn sign(&self, data: &[u8], private_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<PqcSignature> {
        match algorithm {
            AlgorithmId::MlDsa65 => {
                let sk = ml_dsa::ml_dsa_65::SecretKey::try_from_bytes(private_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA private key".to_string()))?;
                let signature = sk.sign(data);
                Ok(PqcSignature::new(algorithm, signature.to_bytes().to_vec()))
            },
            AlgorithmId::MlDsa87 => {
                let sk = ml_dsa::ml_dsa_87::SecretKey::try_from_bytes(private_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA private key".to_string()))?;
                let signature = sk.sign(data);
                Ok(PqcSignature::new(algorithm, signature.to_bytes().to_vec()))
            },
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<bool> {
        match algorithm {
            AlgorithmId::MlDsa65 => {
                let pk = ml_dsa::ml_dsa_65::PublicKey::try_from_bytes(public_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA public key".to_string()))?;
                let sig = ml_dsa::ml_dsa_65::Signature::try_from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA signature".to_string()))?;
                Ok(pk.verify(data, &sig).is_ok())
            },
            AlgorithmId::MlDsa87 => {
                let pk = ml_dsa::ml_dsa_87::PublicKey::try_from_bytes(public_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA public key".to_string()))?;
                let sig = ml_dsa::ml_dsa_87::Signature::try_from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA signature".to_string()))?;
                Ok(pk.verify(data, &sig).is_ok())
            },
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }
}

/// Real SLH-DSA implementation
#[cfg(feature = "slh-dsa")]
pub struct SlhDsaPqcOps;

#[cfg(feature = "slh-dsa")]
impl PqcOperations for SlhDsaPqcOps {
    fn generate_keypair(&self, algorithm: AlgorithmId) -> CryptoResult<PqcKeypair> {
        match algorithm {
            AlgorithmId::SlhDsaShake256f => {
                let (pk, sk) = slh_dsa::slh_dsa_shake_256f::Keypair::generate();
                Ok(PqcKeypair::new(algorithm, pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
            },
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }

    fn sign(&self, data: &[u8], private_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<PqcSignature> {
        match algorithm {
            AlgorithmId::SlhDsaShake256f => {
                let sk = slh_dsa::slh_dsa_shake_256f::SecretKey::try_from_bytes(private_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA private key".to_string()))?;
                let signature = sk.sign(data);
                Ok(PqcSignature::new(algorithm, signature.to_bytes().to_vec()))
            },
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8], algorithm: AlgorithmId) -> CryptoResult<bool> {
        match algorithm {
            AlgorithmId::SlhDsaShake256f => {
                let pk = slh_dsa::slh_dsa_shake_256f::PublicKey::try_from_bytes(public_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA public key".to_string()))?;
                let sig = slh_dsa::slh_dsa_shake_256f::Signature::try_from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA signature".to_string()))?;
                Ok(pk.verify(data, &sig).is_ok())
            },
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }
}

/// Get the appropriate PQC operations implementation for the given algorithm
pub fn get_pqc_ops_for_algorithm(algorithm: AlgorithmId) -> CryptoResult<Box<dyn PqcOperations>> {
    match algorithm {
        #[cfg(feature = "ml-dsa")]
        AlgorithmId::MlDsa65 | AlgorithmId::MlDsa87 => {
            Ok(Box::new(RealPqcOps))
        },
        #[cfg(feature = "slh-dsa")]
        AlgorithmId::SlhDsaShake256f => {
            Ok(Box::new(SlhDsaPqcOps))
        },
        _ => Ok(Box::new(MockPqcOps)), // Fallback to mock for unsupported algorithms
    }
}

/// Get the default PQC operations implementation (ML-DSA if available, otherwise mock)
pub fn get_pqc_ops() -> Box<dyn PqcOperations> {
    #[cfg(feature = "ml-dsa")]
    {
        Box::new(RealPqcOps)
    }
    #[cfg(all(not(feature = "ml-dsa"), feature = "slh-dsa"))]
    {
        Box::new(SlhDsaPqcOps)
    }
    #[cfg(not(any(feature = "ml-dsa", feature = "slh-dsa")))]
    {
        Box::new(MockPqcOps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_pqc_keypair_generation() {
        let ops = MockPqcOps;
        let keypair = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        assert_eq!(keypair.algorithm, AlgorithmId::MlDsa65);
        assert_eq!(keypair.public_key.len(), keypair.expected_public_key_size());
        assert_eq!(keypair.private_key.len(), keypair.expected_private_key_size());
    }

    #[test]
    fn test_mock_pqc_signing() {
        let ops = MockPqcOps;
        let keypair = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        let data = b"test data";

        let signature = ops.sign(data, &keypair.private_key, AlgorithmId::MlDsa65).unwrap();
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa65);
        assert_eq!(signature.signature.len(), signature.expected_size());

        let is_valid = ops.verify(data, &signature.signature, &keypair.public_key, AlgorithmId::MlDsa65).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_mock_pqc_verification_fails_with_wrong_data() {
        let ops = MockPqcOps;
        let keypair = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        let data = b"test data";

        let signature = ops.sign(data, &keypair.private_key, AlgorithmId::MlDsa65).unwrap();
        let wrong_data = b"wrong data";

        let is_valid = ops.verify(wrong_data, &signature.signature, &keypair.public_key, AlgorithmId::MlDsa65).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_pqc_keypair_sizes() {
        let ops = MockPqcOps;
        let keypair = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        assert_eq!(keypair.expected_public_key_size(), 1952);
        assert_eq!(keypair.expected_private_key_size(), 4032);

        let keypair = ops.generate_keypair(AlgorithmId::MlDsa87).unwrap();
        assert_eq!(keypair.expected_public_key_size(), 2592);
        assert_eq!(keypair.expected_private_key_size(), 4896);

        let keypair = ops.generate_keypair(AlgorithmId::SlhDsaShake256f).unwrap();
        assert_eq!(keypair.expected_public_key_size(), 32);
        assert_eq!(keypair.expected_private_key_size(), 64);
    }

    #[test]
    fn test_pqc_signature_sizes() {
        let ops = MockPqcOps;
        let keypair = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        let signature = ops.sign(b"test", &keypair.private_key, AlgorithmId::MlDsa65).unwrap();
        assert_eq!(signature.expected_size(), 3309);

        let keypair = ops.generate_keypair(AlgorithmId::MlDsa87).unwrap();
        let signature = ops.sign(b"test", &keypair.private_key, AlgorithmId::MlDsa87).unwrap();
        assert_eq!(signature.expected_size(), 4627);

        let keypair = ops.generate_keypair(AlgorithmId::SlhDsaShake256f).unwrap();
        let signature = ops.sign(b"test", &keypair.private_key, AlgorithmId::SlhDsaShake256f).unwrap();
        assert_eq!(signature.expected_size(), 7856);
    }

    #[test]
    fn test_deterministic_key_generation() {
        let ops = MockPqcOps;
        // Test that key generation is deterministic for the same algorithm
        let keypair1 = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        let keypair2 = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();

        // Keys should be the same (deterministic generation)
        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.private_key, keypair2.private_key);
    }

    #[test]
    fn test_pqc_trait_object() {
        let ops: Box<dyn PqcOperations> = Box::new(MockPqcOps);

        let keypair = ops.generate_keypair(AlgorithmId::MlDsa65).unwrap();
        assert_eq!(keypair.algorithm, AlgorithmId::MlDsa65);

        let signature = ops.sign(b"test", &keypair.private_key, AlgorithmId::MlDsa65).unwrap();
        assert_eq!(signature.algorithm, AlgorithmId::MlDsa65);

        let is_valid = ops.verify(b"test", &signature.signature, &keypair.public_key, AlgorithmId::MlDsa65).unwrap();
        assert!(is_valid);
    }
}
