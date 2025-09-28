//! Post-Quantum Cryptography Module
//!
//! This module provides post-quantum cryptographic primitives for Symbios Network.
//! Implements real PQ algorithms:
//! - ML-KEM (Kyber) for key encapsulation
//! - ML-DSA (Dilithium) for digital signatures
//! - SLH-DSA (SPHINCS+) for stateless hash-based signatures

use pqcrypto::kem::mlkem1024::*;
use pqcrypto::sign::mldsa65::*;
use pqcrypto::sign::slhdsa_shake_256f::*;
use crate::types::{PublicKey, PrivateKey, Signature, Hash};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Post-quantum keypair for digital signatures
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PQKeyPair {
    pub public_key: PQPublicKey,
    pub private_key: PQPrivateKey,
}

/// Post-quantum public key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PQPublicKey(Vec<u8>);

/// Post-quantum private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQPrivateKey(Vec<u8>);

/// Post-quantum signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PQSignature(Vec<u8>);

/// ML-KEM (Kyber) key encapsulation mechanism
pub struct MLKEM;

impl MLKEM {
    /// Key generation - returns (public_key_bytes, private_key_bytes)
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let (public_key, private_key) = keypair();
        Ok((
            public_key.as_bytes().to_vec(),
            private_key.as_bytes().to_vec()
        ))
    }

    /// Encapsulate (generate shared secret and ciphertext)
    /// Returns (shared_secret, ciphertext)
    pub fn encapsulate(public_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        if public_key_bytes.len() != PUBLICKEYBYTES {
            return Err("Invalid public key length".into());
        }

        let public_key = PublicKey::from_bytes(public_key_bytes)?;
        let (shared_secret, ciphertext) = encapsulate(&public_key);

        Ok((
            shared_secret.as_bytes().to_vec(),
            ciphertext.as_bytes().to_vec()
        ))
    }

    /// Decapsulate (recover shared secret from ciphertext)
    pub fn decapsulate(ciphertext_bytes: &[u8], private_key_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if ciphertext_bytes.len() != CIPHERTEXTBYTES {
            return Err("Invalid ciphertext length".into());
        }
        if private_key_bytes.len() != SECRETKEYBYTES {
            return Err("Invalid private key length".into());
        }

        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes)?;
        let private_key = SecretKey::from_bytes(private_key_bytes)?;
        let shared_secret = decapsulate(&ciphertext, &private_key);

        Ok(shared_secret.as_bytes().to_vec())
    }
}

/// ML-DSA (Dilithium) digital signature algorithm
pub struct MLDSA;

impl MLDSA {
    /// Key generation
    pub fn keygen() -> Result<(PQPublicKey, PQPrivateKey), Box<dyn std::error::Error>> {
        let (public_key, private_key) = keypair();
        Ok((
            PQPublicKey(public_key.as_bytes().to_vec()),
            PQPrivateKey(private_key.as_bytes().to_vec())
        ))
    }

    /// Sign message
    pub fn sign(message: &[u8], private_key: &PQPrivateKey) -> Result<PQSignature, Box<dyn std::error::Error>> {
        if private_key.0.len() != SECRETKEYBYTES {
            return Err("Invalid private key length".into());
        }

        let secret_key = SecretKey::from_bytes(&private_key.0)?;
        let signature = detached_sign(message, &secret_key);

        Ok(PQSignature(signature.as_bytes().to_vec()))
    }

    /// Verify signature
    pub fn verify(message: &[u8], signature: &PQSignature, public_key: &PQPublicKey) -> Result<bool, Box<dyn std::error::Error>> {
        if public_key.0.len() != PUBLICKEYBYTES {
            return Err("Invalid public key length".into());
        }
        if signature.0.len() != BYTES {
            return Err("Invalid signature length".into());
        }

        let public_key = PublicKey::from_bytes(&public_key.0)?;
        let sig = Signature::from_bytes(&signature.0)?;

        match verify_detached_signature(&sig, message, &public_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// SLH-DSA (SPHINCS+) stateless hash-based signatures
pub struct SLHDSA;

impl SLHDSA {
    /// Key generation
    pub fn keygen() -> Result<(PQPublicKey, PQPrivateKey), Box<dyn std::error::Error>> {
        let (public_key, private_key) = keypair();
        Ok((
            PQPublicKey(public_key.as_bytes().to_vec()),
            PQPrivateKey(private_key.as_bytes().to_vec())
        ))
    }

    /// Sign message
    pub fn sign(message: &[u8], private_key: &PQPrivateKey) -> Result<PQSignature, Box<dyn std::error::Error>> {
        if private_key.0.len() != SECRETKEYBYTES {
            return Err("Invalid private key length".into());
        }

        let secret_key = SecretKey::from_bytes(&private_key.0)?;
        let signature = detached_sign(message, &secret_key);

        Ok(PQSignature(signature.as_bytes().to_vec()))
    }

    /// Verify signature
    pub fn verify(message: &[u8], signature: &PQSignature, public_key: &PQPublicKey) -> Result<bool, Box<dyn std::error::Error>> {
        if public_key.0.len() != PUBLICKEYBYTES {
            return Err("Invalid public key length".into());
        }
        if signature.0.len() != BYTES {
            return Err("Invalid signature length".into());
        }

        let public_key = PublicKey::from_bytes(&public_key.0)?;
        let sig = Signature::from_bytes(&signature.0)?;

        match verify_detached_signature(&sig, message, &public_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// High-level PQ cryptography interface
pub struct PQCrypto;

impl PQCrypto {
    /// Generate a new keypair for ML-DSA signing
    pub fn generate_signing_keypair() -> Result<PQKeyPair, Box<dyn std::error::Error>> {
        let (public_key, private_key) = MLDSA::keygen()?;
        Ok(PQKeyPair { public_key, private_key })
    }

    /// Generate a new keypair for SLH-DSA signing (for long-term security)
    pub fn generate_slh_signing_keypair() -> Result<PQKeyPair, Box<dyn std::error::Error>> {
        let (public_key, private_key) = SLHDSA::keygen()?;
        Ok(PQKeyPair { public_key, private_key })
    }

    /// Sign data with PQ signature (ML-DSA)
    pub fn sign(data: &[u8], private_key: &PQPrivateKey) -> Result<PQSignature, Box<dyn std::error::Error>> {
        MLDSA::sign(data, private_key)
    }

    /// Sign data with SLH-DSA signature (for long-term security)
    pub fn sign_slh(data: &[u8], private_key: &PQPrivateKey) -> Result<PQSignature, Box<dyn std::error::Error>> {
        SLHDSA::sign(data, private_key)
    }

    /// Verify PQ signature (ML-DSA)
    pub fn verify(data: &[u8], signature: &PQSignature, public_key: &PQPublicKey) -> Result<bool, Box<dyn std::error::Error>> {
        MLDSA::verify(data, signature, public_key)
    }

    /// Verify SLH-DSA signature
    pub fn verify_slh(data: &[u8], signature: &PQSignature, public_key: &PQPublicKey) -> Result<bool, Box<dyn std::error::Error>> {
        SLHDSA::verify(data, signature, public_key)
    }

    /// Generate key encapsulation keypair (ML-KEM)
    pub fn generate_kem_keypair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        MLKEM::keygen()
    }

    /// Perform key encapsulation (ML-KEM)
    pub fn encapsulate_key(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        MLKEM::encapsulate(public_key)
    }

    /// Perform key decapsulation (ML-KEM)
    pub fn decapsulate_key(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        MLKEM::decapsulate(ciphertext, private_key)
    }

    /// Get cryptographic parameters for documentation
    pub fn get_crypto_info() -> String {
        format!(
            "Post-Quantum Cryptography Parameters:\n\
             ML-KEM-1024: Public Key: {} bytes, Ciphertext: {} bytes\n\
             ML-DSA-65: Public Key: {} bytes, Signature: {} bytes\n\
             SLH-DSA-SHAKE256f: Public Key: {} bytes, Signature: {} bytes",
            pqcrypto::kem::mlkem1024::PUBLICKEYBYTES,
            pqcrypto::kem::mlkem1024::CIPHERTEXTBYTES,
            pqcrypto::sign::mldsa65::PUBLICKEYBYTES,
            pqcrypto::sign::mldsa65::BYTES,
            pqcrypto::sign::slhdsa_shake_256f::PUBLICKEYBYTES,
            pqcrypto::sign::slhdsa_shake_256f::BYTES,
        )
    }
}

/// PQ Crypto metrics
pub struct PQCryptoMetrics {
    pub signature_operations: u64,
    pub verification_operations: u64,
    pub key_generation_operations: u64,
    pub kem_operations: u64,
}

impl Default for PQCryptoMetrics {
    fn default() -> Self {
        Self {
            signature_operations: 0,
            verification_operations: 0,
            key_generation_operations: 0,
            kem_operations: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_keygen() {
        let result = MLKEM::keygen();
        assert!(result.is_ok());
        let (public_key, private_key) = result.unwrap();
        assert_eq!(public_key.len(), pqcrypto::kem::mlkem1024::PUBLICKEYBYTES);
        assert_eq!(private_key.len(), pqcrypto::kem::mlkem1024::SECRETKEYBYTES);
    }

    #[test]
    fn test_ml_kem_encapsulate_decapsulate() {
        let (public_key, private_key) = MLKEM::keygen().unwrap();
        let (shared_secret1, ciphertext) = MLKEM::encapsulate(&public_key).unwrap();
        let shared_secret2 = MLKEM::decapsulate(&ciphertext, &private_key).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), pqcrypto::kem::mlkem1024::SSBYTES);
        assert_eq!(ciphertext.len(), pqcrypto::kem::mlkem1024::CIPHERTEXTBYTES);
    }

    #[test]
    fn test_ml_dsa_sign_verify() {
        let (public_key, private_key) = MLDSA::keygen().unwrap();
        let message = b"Hello, post-quantum world!";
        let signature = MLDSA::sign(message, &private_key).unwrap();
        let is_valid = MLDSA::verify(message, &signature, &public_key).unwrap();

        assert!(is_valid);
        assert_eq!(signature.0.len(), pqcrypto::sign::mldsa65::BYTES);
    }

    #[test]
    fn test_slh_dsa_sign_verify() {
        let (public_key, private_key) = SLHDSA::keygen().unwrap();
        let message = b"Hello, hash-based signatures!";
        let signature = SLHDSA::sign(message, &private_key).unwrap();
        let is_valid = SLHDSA::verify(message, &signature, &public_key).unwrap();

        assert!(is_valid);
        assert_eq!(signature.0.len(), pqcrypto::sign::slhdsa_shake_256f::BYTES);
    }

    #[test]
    fn test_pq_crypto_interface() {
        let keypair = PQCrypto::generate_signing_keypair().unwrap();
        let message = b"Test message for PQ crypto";
        let signature = PQCrypto::sign(message, &keypair.private_key).unwrap();
        let is_valid = PQCrypto::verify(message, &signature, &keypair.public_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_pq_crypto_slh_interface() {
        let keypair = PQCrypto::generate_slh_signing_keypair().unwrap();
        let message = b"Test message for SLH-DSA crypto";
        let signature = PQCrypto::sign_slh(message, &keypair.private_key).unwrap();
        let is_valid = PQCrypto::verify_slh(message, &signature, &keypair.public_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Test ML-KEM with invalid key lengths
        let result = MLKEM::encapsulate(&[0u8; 10]);
        assert!(result.is_err());

        let result = MLKEM::decapsulate(&[0u8; 10], &[0u8; 10]);
        assert!(result.is_err());

        // Test ML-DSA with invalid key lengths
        let invalid_private_key = PQPrivateKey(vec![0u8; 10]);
        let result = MLDSA::sign(b"test", &invalid_private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_crypto_info() {
        let info = PQCrypto::get_crypto_info();
        assert!(info.contains("ML-KEM-1024"));
        assert!(info.contains("ML-DSA-65"));
        assert!(info.contains("SLH-DSA-SHAKE256f"));
        println!("{}", info);
    }
}

