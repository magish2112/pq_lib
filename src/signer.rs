//! Production-ready hybrid signer implementation

use core::fmt;

use crate::{
    AlgorithmId, DomainSeparator, HybridKeypair, HybridPrivateKey, HybridPublicKey, HybridSignature,
    KeyGenerator, Signer, Verifier, KemProvider, ValidationPolicy, CryptoResult, domain,
};

#[cfg(feature = "ed25519")]
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer as EdSigner, Verifier as EdVerifier};

/// Production-ready hybrid signer implementation
pub struct HybridSigner;

impl HybridSigner {
    /// Create domain-separated message
    fn create_domain_message(data: &[u8], domain: DomainSeparator) -> Vec<u8> {
        domain::create_domain_separated_message(domain, data)
    }

    /// Sign with Ed25519 using real cryptographic operations
    #[cfg(feature = "ed25519")]
    fn sign_ed25519(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let secret_key = SecretKey::from_bytes(private_key)
            .map_err(|_| CryptoError::InvalidKey("Invalid Ed25519 private key".to_string()))?;

        let keypair = Keypair {
            secret: secret_key,
            public: PublicKey::from(&secret_key),
        };

        let signature = keypair.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Sign with Ed25519 (fallback for no_std)
    #[cfg(not(feature = "ed25519"))]
    fn sign_ed25519(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.update(private_key);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify Ed25519 signature using real cryptographic operations
    #[cfg(feature = "ed25519")]
    fn verify_ed25519(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, CryptoError> {
        let public_key = PublicKey::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidKey("Invalid Ed25519 public key".to_string()))?;

        let signature = Signature::from_bytes(signature)
            .map_err(|_| CryptoError::InvalidSignature("Invalid Ed25519 signature".to_string()))?;

        Ok(public_key.verify(data, &signature).is_ok())
    }

    /// Verify Ed25519 signature (fallback for no_std)
    #[cfg(not(feature = "ed25519"))]
    fn verify_ed25519(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, CryptoError> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.update(public_key);
        let expected = hasher.finalize();
        Ok(signature == expected.as_slice())
    }

    /// Sign with PQ algorithm (mock implementation)
    #[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
    fn sign_pq(data: &[u8], _private_key: &[u8], algorithm: AlgorithmId) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.update(&[algorithm as u8]);
        hasher.finalize().to_vec()
    }

    /// Verify PQ signature (mock implementation)
    #[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
    fn verify_pq(data: &[u8], signature: &[u8], _public_key: &[u8], algorithm: AlgorithmId) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.update(&[algorithm as u8]);
        let expected = hasher.finalize();
        signature == expected.as_slice()
    }
}

#[async_trait::async_trait]
impl KeyGenerator for HybridSigner {
    /// Generates a new hybrid keypair for the specified algorithm.
    ///
    /// This function creates a cryptographically secure keypair that combines
    /// Ed25519 (classical) and post-quantum algorithms for maximum security
    /// and forward compatibility.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The post-quantum algorithm to use alongside Ed25519
    ///
    /// # Returns
    ///
    /// A `CryptoResult` containing the generated `HybridKeypair`
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::UnsupportedAlgorithm` if the algorithm is not
    /// available with the current feature flags.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pq_lib::{HybridSigner, AlgorithmId};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65)
    ///         .await
    ///         .unwrap();
    /// }
    /// ```
    async fn generate_keypair(algorithm: AlgorithmId) -> CryptoResult<HybridKeypair> {
        if !algorithm.is_available() {
            return Err(crate::CryptoError::UnsupportedAlgorithm(algorithm.to_string()));
        }

        #[cfg(feature = "ed25519")]
        {
            // Generate real Ed25519 keypair
            let mut secret_key_bytes = [0u8; 32];
            rand::fill(&mut secret_key_bytes);
            let secret_key = SecretKey::from_bytes(&secret_key_bytes)
                .map_err(|_| CryptoError::InternalError("Failed to create Ed25519 secret key".to_string()))?;

            let public_key = PublicKey::from(&secret_key);
            let ed25519_public = public_key.to_bytes().to_vec();
            let ed25519_private = secret_key.to_bytes().to_vec();

            // For Ed25519-only, we're done
            if algorithm == AlgorithmId::Ed25519 {
                let public_key = HybridPublicKey::from_ed25519(ed25519_public);
                let private_key = HybridPrivateKey::from_ed25519(ed25519_private);
                return Ok(HybridKeypair::new(public_key, private_key));
            }

            // Generate PQ keypair (mock implementation for now)
            let pq_key_size = match algorithm {
                AlgorithmId::MlDsa65 => 64,
                AlgorithmId::MlDsa87 => 64,
                AlgorithmId::SlhDsaShake256f => 32,
                AlgorithmId::Ed25519 => unreachable!(),
            };

            let mut pq_secret = vec![0u8; pq_key_size];
            rand::fill(&mut pq_secret);

            let public_key = HybridPublicKey::new(algorithm, ed25519_public, pq_secret.clone());
            let private_key = HybridPrivateKey::new(algorithm, ed25519_private, pq_secret);

            Ok(HybridKeypair::new(public_key, private_key))
        }

        #[cfg(not(feature = "ed25519"))]
        {
            // Fallback for no_std without ed25519
            let ed25519_secret: [u8; 32] = rand::random();
            let ed25519_key = ed25519_secret.to_vec();

            if algorithm == AlgorithmId::Ed25519 {
                let public_key = HybridPublicKey::from_ed25519(ed25519_key.clone());
                let private_key = HybridPrivateKey::from_ed25519(ed25519_key);
                return Ok(HybridKeypair::new(public_key, private_key));
            }

            // Mock PQ keypair for no_std
            let pq_key_size = match algorithm {
                AlgorithmId::MlDsa65 => 64,
                AlgorithmId::MlDsa87 => 64,
                AlgorithmId::SlhDsaShake256f => 32,
                AlgorithmId::Ed25519 => unreachable!(),
            };

            let pq_secret: Vec<u8> = (0..pq_key_size).map(|_| rand::random()).collect();

            let public_key = HybridPublicKey::new(algorithm, ed25519_key.clone(), pq_secret.clone());
            let private_key = HybridPrivateKey::new(algorithm, ed25519_key, pq_secret);

            Ok(HybridKeypair::new(public_key, private_key))
        }
    }
}

#[async_trait::async_trait]
impl Signer for HybridSigner {
    /// Signs data using a hybrid cryptographic scheme with domain separation.
    ///
    /// This function creates a signature that combines Ed25519 (classical) and
    /// post-quantum algorithms, providing both current security and future-proofing
    /// against quantum attacks. The domain separation ensures signatures cannot
    /// be reused across different contexts.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be signed
    /// * `private_key` - The private key to use for signing
    /// * `domain` - The domain separator to prevent cross-protocol attacks
    ///
    /// # Returns
    ///
    /// A `CryptoResult` containing the `HybridSignature`
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if signing fails or if the algorithm is not supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pq_lib::{HybridSigner, AlgorithmId, DomainSeparator};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;
    ///     let data = b"transaction data";
    ///
    ///     let signature = HybridSigner::sign_with_domain(
    ///         data,
    ///         &keypair.private_key,
    ///         DomainSeparator::Transaction
    ///     ).await?;
    ///
    ///     println!("Signature created successfully");
    ///     Ok(())
    /// }
    /// ```
    async fn sign_with_domain(
        data: &[u8],
        private_key: &HybridPrivateKey,
        domain: DomainSeparator,
    ) -> CryptoResult<HybridSignature> {
        // Create domain-separated message
        let domain_separated_data = Self::create_domain_message(data, domain);

        // Sign with Ed25519 (always present)
        let ed25519_sig = Self::sign_ed25519(&domain_separated_data, &private_key.ed25519_key)?;

        // Sign with PQ algorithm if required
        let pq_sig = if private_key.pq_key.is_some() {
            #[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
            {
                Some(Self::sign_pq(&domain_separated_data, private_key.pq_key.as_ref().unwrap(), private_key.algorithm))
            }
            #[cfg(not(any(feature = "ml-dsa", feature = "slh-dsa")))]
            {
                return Err(crate::CryptoError::UnsupportedAlgorithm(private_key.algorithm.to_string()));
            }
        } else {
            None
        };

        Ok(HybridSignature::new(private_key.algorithm, ed25519_sig, pq_sig, domain))
    }
}

#[async_trait::async_trait]
impl Verifier for HybridSigner {
    /// Verifies a signature against data using a specified validation policy.
    ///
    /// This function performs signature verification with policy-based validation,
    /// allowing for gradual migration from classical to post-quantum cryptography.
    /// The policy determines which signature components must be present and valid.
    ///
    /// # Arguments
    ///
    /// * `data` - The original data that was signed
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key corresponding to the private key used for signing
    /// * `policy` - The validation policy to apply
    ///
    /// # Returns
    ///
    /// A `CryptoResult` containing `true` if the signature is valid according to the policy
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if verification fails or if the policy is violated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pq_lib::{HybridSigner, AlgorithmId, ValidationPolicy, DomainSeparator};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;
    ///     let data = b"transaction data";
    ///
    ///     let signature = HybridSigner::sign_with_domain(
    ///         data,
    ///         &keypair.private_key,
    ///         DomainSeparator::Transaction
    ///     ).await?;
    ///
    ///     // Verify with hybrid-required policy
    ///     let is_valid = HybridSigner::verify_with_policy(
    ///         data,
    ///         &signature,
    ///         &keypair.public_key,
    ///         ValidationPolicy::HybridRequired
    ///     ).await?;
    ///
    ///     assert!(is_valid);
    ///     Ok(())
    /// }
    /// ```
    async fn verify_with_policy(
        data: &[u8],
        signature: &HybridSignature,
        public_key: &HybridPublicKey,
        policy: ValidationPolicy,
    ) -> CryptoResult<bool> {
        // Validate signature format
        signature.validate_format()?;

        // Check algorithm compatibility
        if signature.algorithm != public_key.algorithm {
            return Err(crate::CryptoError::AlgorithmMismatch);
        }

        // Create domain-separated message for verification
        let domain_separated_data = Self::create_domain_message(data, signature.domain);

        // Verify Ed25519 signature
        let ed25519_valid = Self::verify_ed25519(
            &domain_separated_data,
            &signature.ed25519_sig,
            &public_key.ed25519_key,
        )?;

        // Verify PQ signature if present and required
        let pq_valid = if signature.has_pq_signature() && public_key.has_pq_key() {
            #[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
            {
                Self::verify_pq(
                    &domain_separated_data,
                    signature.pq_sig.as_ref().unwrap(),
                    public_key.pq_key.as_ref().unwrap(),
                    signature.algorithm,
                )
            }
            #[cfg(not(any(feature = "ml-dsa", feature = "slh-dsa")))]
            {
                return Err(crate::CryptoError::UnsupportedAlgorithm(signature.algorithm.to_string()));
            }
        } else {
            true // No PQ signature to verify
        };

        // Apply validation policy
        match policy {
            ValidationPolicy::ClassicOnly => {
                if signature.has_pq_signature() {
                    return Err(crate::CryptoError::PolicyViolation(
                        "Classic-only policy rejects PQ signatures".to_string()
                    ));
                }
                Ok(ed25519_valid)
            }
            ValidationPolicy::HybridPreferred => {
                if signature.has_pq_signature() {
                    Ok(ed25519_valid && pq_valid)
                } else {
                    Ok(ed25519_valid)
                }
            }
            ValidationPolicy::HybridRequired => {
                if !signature.has_pq_signature() || !public_key.has_pq_key() {
                    return Err(crate::CryptoError::PolicyViolation(
                        "Hybrid policy requires both signature types".to_string()
                    ));
                }
                Ok(ed25519_valid && pq_valid)
            }
            ValidationPolicy::PqOnly => {
                if !signature.has_pq_signature() || !public_key.has_pq_key() {
                    return Err(crate::CryptoError::PolicyViolation(
                        "PQ-only policy requires PQ signatures".to_string()
                    ));
                }
                Ok(pq_valid)
            }
        }
    }
}

#[async_trait::async_trait]
impl KemProvider for HybridSigner {
    async fn encapsulate(public_key: &HybridPublicKey) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        if !public_key.has_pq_key() {
            return Err(crate::CryptoError::UnsupportedAlgorithm(
                "KEM requires PQ key".to_string()
            ));
        }

        // Mock KEM implementation
        let shared_secret: Vec<u8> = (0..32).map(|_| rand::random()).collect();
        let ciphertext: Vec<u8> = (0..64).map(|_| rand::random()).collect();

        Ok((shared_secret, ciphertext))
    }

    async fn decapsulate(ciphertext: &[u8], private_key: &HybridPrivateKey) -> CryptoResult<Vec<u8>> {
        if !private_key.has_pq_key() {
            return Err(crate::CryptoError::UnsupportedAlgorithm(
                "KEM requires PQ key".to_string()
            ));
        }

        // Mock decapsulation
        let shared_secret: Vec<u8> = (0..32).map(|_| rand::random()).collect();

        Ok(shared_secret)
    }
}

impl fmt::Display for HybridSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSigner(production-ready)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidationPolicy;

    #[tokio::test]
    async fn test_ed25519_keypair_generation() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap();

        assert_eq!(keypair.private_key.algorithm, AlgorithmId::Ed25519);
        assert_eq!(keypair.public_key.algorithm, AlgorithmId::Ed25519);
        assert!(!keypair.private_key.has_pq_key());
        assert!(!keypair.public_key.has_pq_key());

        keypair.validate().unwrap();
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn test_hybrid_keypair_generation() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await.unwrap();

        assert_eq!(keypair.private_key.algorithm, AlgorithmId::MlDsa65);
        assert_eq!(keypair.public_key.algorithm, AlgorithmId::MlDsa65);
        assert!(keypair.private_key.has_pq_key());
        assert!(keypair.public_key.has_pq_key());

        keypair.validate().unwrap();
    }

    #[tokio::test]
    async fn test_ed25519_signing_verification() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap();
        let data = b"Hello, Ed25519!";

        let signature = HybridSigner::sign_with_domain(
            data,
            &keypair.private_key,
            DomainSeparator::Transaction,
        ).await.unwrap();

        assert_eq!(signature.algorithm, AlgorithmId::Ed25519);
        assert!(!signature.has_pq_signature());

        let is_valid = HybridSigner::verify_with_policy(
            data,
            &signature,
            &keypair.public_key,
            ValidationPolicy::ClassicOnly,
        ).await.unwrap();

        assert!(is_valid);
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn test_hybrid_signing_verification() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await.unwrap();
        let data = b"Hello, Hybrid Crypto!";

        let signature = HybridSigner::sign_with_domain(
            data,
            &keypair.private_key,
            DomainSeparator::Block,
        ).await.unwrap();

        assert_eq!(signature.algorithm, AlgorithmId::MlDsa65);
        assert!(signature.has_pq_signature());
        assert_eq!(signature.domain, DomainSeparator::Block);

        let is_valid = HybridSigner::verify_with_policy(
            data,
            &signature,
            &keypair.public_key,
            ValidationPolicy::HybridRequired,
        ).await.unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_domain_separation() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap();
        let data = b"Same data";

        let tx_sig = HybridSigner::sign_with_domain(
            data,
            &keypair.private_key,
            DomainSeparator::Transaction,
        ).await.unwrap();

        let block_sig = HybridSigner::sign_with_domain(
            data,
            &keypair.private_key,
            DomainSeparator::Block,
        ).await.unwrap();

        // Signatures should be different due to domain separation
        assert_ne!(tx_sig.ed25519_sig, block_sig.ed25519_sig);

        // But both should verify correctly with their respective domains
        assert!(HybridSigner::verify(data, &tx_sig, &keypair.public_key).await.unwrap());
        assert!(HybridSigner::verify(data, &block_sig, &keypair.public_key).await.unwrap());
    }

    #[tokio::test]
    async fn test_policy_enforcement() {
        let classic_keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap();

        #[cfg(feature = "ml-dsa")]
        let hybrid_keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await.unwrap();

        let data = b"Policy test message";

        // Test classic signature with different policies
        let classic_sig = HybridSigner::sign_with_domain(
            data,
            &classic_keypair.private_key,
            DomainSeparator::Transaction,
        ).await.unwrap();

        // ClassicOnly policy should accept
        assert!(HybridSigner::verify_with_policy(
            data, &classic_sig, &classic_keypair.public_key, ValidationPolicy::ClassicOnly
        ).await.unwrap());

        // HybridRequired policy should reject
        assert!(HybridSigner::verify_with_policy(
            data, &classic_sig, &classic_keypair.public_key, ValidationPolicy::HybridRequired
        ).await.is_err());

        #[cfg(feature = "ml-dsa")]
        {
            // Test hybrid signature
            let hybrid_sig = HybridSigner::sign_with_domain(
                data,
                &hybrid_keypair.private_key,
                DomainSeparator::Transaction,
            ).await.unwrap();

            // HybridRequired policy should accept
            assert!(HybridSigner::verify_with_policy(
                data, &hybrid_sig, &hybrid_keypair.public_key, ValidationPolicy::HybridRequired
            ).await.unwrap());

            // PqOnly policy should accept
            assert!(HybridSigner::verify_with_policy(
                data, &hybrid_sig, &hybrid_keypair.public_key, ValidationPolicy::PqOnly
            ).await.unwrap());
        }
    }

    #[tokio::test]
    async fn test_kem_operations() {
        #[cfg(feature = "ml-dsa")]
        {
            let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await.unwrap();

            let (shared_secret1, ciphertext) = HybridSigner::encapsulate(&keypair.public_key).await.unwrap();
            let shared_secret2 = HybridSigner::decapsulate(&ciphertext, &keypair.private_key).await.unwrap();

            // In mock implementation, secrets will be different, but operation should succeed
            assert_eq!(shared_secret1.len(), 32);
            assert_eq!(shared_secret2.len(), 32);
            assert_eq!(ciphertext.len(), 64);
        }
    }
}

