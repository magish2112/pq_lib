//! Integration tests for pq_lib

use pq_lib::*;

/// Test basic functionality of core types
#[test]
fn test_core_types_integration() {
    // Test AlgorithmId
    assert!(!AlgorithmId::Ed25519.is_post_quantum());
    assert!(AlgorithmId::MlDsa65.is_post_quantum());
    assert_eq!(AlgorithmId::Ed25519.signature_size(), 64);
    assert_eq!(AlgorithmId::MlDsa65.signature_size(), 64 + 3302);

    // Test HybridPublicKey
    let ed25519_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                          17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let public_key = HybridPublicKey::from_ed25519(ed25519_key.clone());
    assert_eq!(public_key.algorithm, AlgorithmId::Ed25519);
    assert_eq!(public_key.ed25519_key, ed25519_key);
    assert!(public_key.pq_key.is_none());

    // Test HybridPrivateKey
    let private_key = HybridPrivateKey::from_ed25519(ed25519_key.clone());
    assert_eq!(private_key.algorithm, AlgorithmId::Ed25519);
    assert_eq!(private_key.ed25519_key, ed25519_key);
    assert!(private_key.pq_key.is_none());

    // Test HybridKeypair
    let keypair = HybridKeypair::new(public_key.clone(), private_key.clone());
    assert_eq!(keypair.public_key, public_key);
    assert_eq!(keypair.private_key, private_key);

    // Test HybridSignature
    let sig_data = vec![1, 2, 3, 4, 5];
    let signature = HybridSignature::ed25519_only(sig_data.clone());
    assert_eq!(signature.version, HybridSignature::CURRENT_VERSION);
    assert_eq!(signature.algorithm, AlgorithmId::Ed25519);
    assert_eq!(signature.ed25519_sig, sig_data);
    assert!(signature.pq_sig.is_none());
    assert!(signature.is_valid_for_algorithm());
}

/// Test error handling
#[test]
fn test_error_handling() {
    let error = CryptoError::UnsupportedAlgorithm("TestAlgo".to_string());
    match error {
        CryptoError::UnsupportedAlgorithm(algo) => assert_eq!(algo, "TestAlgo"),
        _ => panic!("Wrong error variant"),
    }

    let error = CryptoError::VerificationFailed;
    match error {
        CryptoError::VerificationFailed => {} // Expected
        _ => panic!("Wrong error variant"),
    }
}

/// Test algorithm iterator
#[test]
fn test_algorithm_iterator() {
    let algorithms: Vec<_> = available_algorithms().collect();
    assert!(!algorithms.is_empty());

    // Should include Ed25519
    assert!(algorithms.contains(&AlgorithmId::Ed25519));
}
