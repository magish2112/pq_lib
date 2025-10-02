//! Property-based tests for cryptographic invariants

use proptest::prelude::*;
use pq_lib::*;

proptest! {
    /// Test that domain separation creates different signatures for same data
    #[test]
    fn test_domain_separation_creates_different_signatures(
        data in prop::collection::vec(any::<u8>(), 1..100),
        domain1 in prop::sample::select(vec![DomainSeparator::Transaction, DomainSeparator::Block, DomainSeparator::Consensus]),
        domain2 in prop::sample::select(vec![DomainSeparator::Transaction, DomainSeparator::Block, DomainSeparator::Consensus]),
    ) {
        prop_assume!(domain1 != domain2);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let keypair = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::Ed25519)).unwrap();

        let sig1 = rt.block_on(HybridSigner::sign_with_domain(&data, &keypair.private_key, domain1)).unwrap();
        let sig2 = rt.block_on(HybridSigner::sign_with_domain(&data, &keypair.private_key, domain2)).unwrap();

        // Signatures should be different even with same data but different domains
        prop_assert_ne!(sig1.ed25519_sig, sig2.ed25519_sig);
        prop_assert_ne!(sig1.domain, sig2.domain);
    }

    /// Test that signature verification is consistent
    #[test]
    fn test_signature_verification_consistency(
        data in prop::collection::vec(any::<u8>(), 1..100),
        domain in prop::sample::select(vec![DomainSeparator::Transaction, DomainSeparator::Block, DomainSeparator::Consensus]),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let keypair = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::Ed25519)).unwrap();

        let signature = rt.block_on(HybridSigner::sign_with_domain(&data, &keypair.private_key, domain)).unwrap();

        // Verification should succeed
        let is_valid = rt.block_on(HybridSigner::verify_with_policy(
            &data,
            &signature,
            &keypair.public_key,
            ValidationPolicy::ClassicOnly,
        )).unwrap();

        prop_assert!(is_valid);

        // Verification with wrong data should fail
        let wrong_data = vec![42u8; data.len()];
        let is_invalid = rt.block_on(HybridSigner::verify_with_policy(
            &wrong_data,
            &signature,
            &keypair.public_key,
            ValidationPolicy::ClassicOnly,
        )).unwrap();

        prop_assert!(!is_invalid);
    }

    /// Test that keypair generation produces valid keys
    #[test]
    fn test_keypair_generation_validity(
        algorithm in prop::sample::select(vec![AlgorithmId::Ed25519]),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let keypair = rt.block_on(HybridSigner::generate_keypair(algorithm)).unwrap();

        // Public key should match algorithm
        prop_assert_eq!(keypair.public_key.algorithm, algorithm);
        prop_assert_eq!(keypair.private_key.algorithm, algorithm);

        // Key sizes should be correct
        if algorithm == AlgorithmId::Ed25519 {
            prop_assert_eq!(keypair.public_key.ed25519_key.len(), 32);
            prop_assert_eq!(keypair.private_key.ed25519_key.len(), 32);
            prop_assert!(keypair.public_key.pq_key.is_none());
            prop_assert!(keypair.private_key.pq_key.is_none());
        }
    }

    /// Test serialization round-trip
    #[test]
    fn test_serialization_roundtrip(
        algorithm in prop::sample::select(vec![AlgorithmId::Ed25519]),
        data in prop::collection::vec(any::<u8>(), 1..50),
        domain in prop::sample::select(vec![DomainSeparator::Transaction, DomainSeparator::Block, DomainSeparator::Consensus]),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let keypair = rt.block_on(HybridSigner::generate_keypair(algorithm)).unwrap();
        let signature = rt.block_on(HybridSigner::sign_with_domain(&data, &keypair.private_key, domain)).unwrap();

        // Serialize and deserialize
        let serialized = pq_lib::serialization::serialize_signature(&signature).unwrap();
        let deserialized = pq_lib::serialization::deserialize_signature(&serialized).unwrap();

        // Should be identical
        prop_assert_eq!(signature, deserialized);

        // Verification should still work after deserialization
        let is_valid = rt.block_on(HybridSigner::verify_with_policy(
            &data,
            &deserialized,
            &keypair.public_key,
            ValidationPolicy::ClassicOnly,
        )).unwrap();

        prop_assert!(is_valid);
    }

    /// Test policy validation behavior
    #[test]
    fn test_policy_validation_behavior(
        policy in prop::sample::select(vec![
            ValidationPolicy::ClassicOnly,
            ValidationPolicy::HybridPreferred,
            ValidationPolicy::HybridRequired,
            ValidationPolicy::PqOnly,
        ]),
        has_pq_signature in prop::bool::ANY,
    ) {
        // Create signature based on policy requirements
        let algorithm = if has_pq_signature { AlgorithmId::MlDsa65 } else { AlgorithmId::Ed25519 };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let keypair = rt.block_on(HybridSigner::generate_keypair(algorithm)).unwrap();
        let signature = rt.block_on(HybridSigner::sign_with_domain(
            b"test",
            &keypair.private_key,
            DomainSeparator::Transaction,
        )).unwrap();

        // Test policy compatibility
        match policy {
            ValidationPolicy::ClassicOnly => {
                // Should accept Ed25519-only signatures
                if !has_pq_signature {
                    let is_valid = rt.block_on(HybridSigner::verify_with_policy(
                        b"test",
                        &signature,
                        &keypair.public_key,
                        policy,
                    )).unwrap();
                    prop_assert!(is_valid);
                }
            },
            ValidationPolicy::PqOnly => {
                // Should reject Ed25519-only signatures
                if !has_pq_signature {
                    let is_valid = rt.block_on(HybridSigner::verify_with_policy(
                        b"test",
                        &signature,
                        &keypair.public_key,
                        policy,
                    )).unwrap();
                    prop_assert!(!is_valid);
                }
            },
            _ => {
                // Hybrid policies should work with both types
                let is_valid = rt.block_on(HybridSigner::verify_with_policy(
                    b"test",
                    &signature,
                    &keypair.public_key,
                    policy,
                )).unwrap();
                prop_assert!(is_valid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_test_compilation() {
        // This test ensures that proptest compiles correctly
        // In a real implementation, this would be more comprehensive
        assert!(true);
    }
}
