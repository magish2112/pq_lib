//! Cryptographic trait definitions

use crate::{
    AlgorithmId, CryptoResult, DomainSeparator, HybridKeypair, HybridPrivateKey, HybridPublicKey,
    HybridSignature, ValidationPolicy,
};

/// Key generation trait
#[async_trait::async_trait]
pub trait KeyGenerator {
    /// Generate new keypair for specified algorithm
    async fn generate_keypair(algorithm: AlgorithmId) -> CryptoResult<HybridKeypair>;
}

/// Signing trait
#[async_trait::async_trait]
pub trait Signer {
    /// Sign data with domain separation
    async fn sign_with_domain(
        data: &[u8],
        private_key: &HybridPrivateKey,
        domain: DomainSeparator,
    ) -> CryptoResult<HybridSignature>;

    /// Sign data without domain separation (legacy compatibility)
    async fn sign(data: &[u8], private_key: &HybridPrivateKey) -> CryptoResult<HybridSignature> {
        Self::sign_with_domain(data, private_key, DomainSeparator::Transaction).await
    }
}

/// Verification trait
#[async_trait::async_trait]
pub trait Verifier {
    /// Verify signature with validation policy
    async fn verify_with_policy(
        data: &[u8],
        signature: &HybridSignature,
        public_key: &HybridPublicKey,
        policy: ValidationPolicy,
    ) -> CryptoResult<bool>;

    /// Verify signature with default hybrid policy
    async fn verify(
        data: &[u8],
        signature: &HybridSignature,
        public_key: &HybridPublicKey,
    ) -> CryptoResult<bool> {
        Self::verify_with_policy(
            data,
            signature,
            public_key,
            ValidationPolicy::HybridPreferred,
        )
        .await
    }
}

/// KEM provider trait for key encapsulation
#[async_trait::async_trait]
pub trait KemProvider {
    /// Encapsulate shared secret for recipient
    async fn encapsulate(public_key: &HybridPublicKey) -> CryptoResult<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate shared secret using private key
    async fn decapsulate(
        ciphertext: &[u8],
        private_key: &HybridPrivateKey,
    ) -> CryptoResult<Vec<u8>>;
}

/// Batch operations trait for performance optimization
#[async_trait::async_trait]
pub trait BatchSigner {
    /// Sign multiple messages with the same key
    async fn sign_batch(
        messages: &[&[u8]],
        private_key: &HybridPrivateKey,
        domain: DomainSeparator,
    ) -> CryptoResult<Vec<HybridSignature>>;
}

/// Batch verification trait
#[async_trait::async_trait]
pub trait BatchVerifier {
    /// Verify multiple signatures
    async fn verify_batch(
        messages: &[&[u8]],
        signatures: &[HybridSignature],
        public_keys: &[HybridPublicKey],
        policy: ValidationPolicy,
    ) -> CryptoResult<Vec<bool>>;
}

/// Key derivation trait for hierarchical keys
#[async_trait::async_trait]
pub trait KeyDerivation {
    /// Derive child key from parent key
    async fn derive_key(
        parent_key: &HybridPrivateKey,
        derivation_path: &[u8],
    ) -> CryptoResult<HybridKeypair>;

    /// Derive public key from parent public key
    fn derive_public_key(
        parent_public: &HybridPublicKey,
        derivation_path: &[u8],
    ) -> CryptoResult<HybridPublicKey>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementation for testing traits
    pub struct MockSigner;

    #[async_trait::async_trait]
    impl KeyGenerator for MockSigner {
        async fn generate_keypair(_algorithm: AlgorithmId) -> CryptoResult<HybridKeypair> {
            Ok(HybridKeypair::new(
                HybridPublicKey::from_ed25519(vec![1; 32]),
                HybridPrivateKey::from_ed25519(vec![2; 32]),
            ))
        }
    }

    #[async_trait::async_trait]
    impl Signer for MockSigner {
        async fn sign_with_domain(
            _data: &[u8],
            _private_key: &HybridPrivateKey,
            domain: DomainSeparator,
        ) -> CryptoResult<HybridSignature> {
            Ok(HybridSignature::ed25519_only(vec![42; 64], domain))
        }
    }

    #[async_trait::async_trait]
    impl Verifier for MockSigner {
        async fn verify_with_policy(
            _data: &[u8],
            _signature: &HybridSignature,
            _public_key: &HybridPublicKey,
            _policy: ValidationPolicy,
        ) -> CryptoResult<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_trait_bounds() {
        // This test ensures our trait bounds are correct
        fn _test_key_generator<T: KeyGenerator>() {}
        fn _test_signer<T: Signer>() {}
        fn _test_verifier<T: Verifier>() {}

        _test_key_generator::<MockSigner>();
        _test_signer::<MockSigner>();
        _test_verifier::<MockSigner>();
    }
}
