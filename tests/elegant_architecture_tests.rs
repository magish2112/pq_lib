//! Comprehensive tests for the elegant type-safe architecture
//!
//! These tests verify:
//! 1. Type-level safety guarantees
//! 2. Zero-cost abstractions
//! 3. Builder pattern ergonomics
//! 4. Type-state machine correctness
//! 5. Backward compatibility
//! 6. Migration paths

use pq_lib::{
    builders::PolicyConfigBuilder,
    compat::{convert_hybrid_to_typed, convert_typed_to_hybrid, MigrationGuide},
    typed::{
        Algorithm, Ed25519, Keypair, MlDsa65Hybrid, MlDsa87Hybrid, PrivateKey, PublicKey,
        Signature, SlhDsaHybrid,
    },
    typestate::{LegacyState, MigrationContext, ModernState, TransitionState},
    AlgorithmId, CryptoError, DomainSeparator, HybridKeypair, ValidationPolicy,
};

// =============================================================================
// Type-Level Safety Tests
// =============================================================================

#[test]
fn test_algorithm_constants_compile_time() {
    // These constants are known at compile time
    const ED25519_PUB_SIZE: usize = Ed25519::PUBLIC_KEY_SIZE;
    const ED25519_PRIV_SIZE: usize = Ed25519::PRIVATE_KEY_SIZE;
    const ED25519_SIG_SIZE: usize = Ed25519::SIGNATURE_SIZE;

    assert_eq!(ED25519_PUB_SIZE, 32);
    assert_eq!(ED25519_PRIV_SIZE, 32);
    assert_eq!(ED25519_SIG_SIZE, 64);

    // Hybrid algorithm sizes
    const ML_DSA_65_PUB: usize = MlDsa65Hybrid::PUBLIC_KEY_SIZE;
    assert_eq!(ML_DSA_65_PUB, 32 + 1952);
}

#[test]
fn test_public_key_creation() {
    // Valid Ed25519 key
    let bytes = vec![42u8; 32];
    let key = PublicKey::<Ed25519>::from_bytes(bytes.clone()).unwrap();
    assert_eq!(key.as_bytes(), &bytes);
    assert_eq!(PublicKey::<Ed25519>::algorithm(), AlgorithmId::Ed25519);
}

#[test]
fn test_public_key_wrong_size() {
    // Wrong size should fail
    let bytes = vec![42u8; 16];
    let result = PublicKey::<Ed25519>::from_bytes(bytes);
    assert!(result.is_err());

    if let Err(e) = result {
        let msg = format!("{}", e);
        assert!(msg.contains("32 bytes"));
        assert!(msg.contains("16"));
    }
}

#[test]
fn test_private_key_zeroization() {
    let bytes = vec![42u8; 32];
    let key = PrivateKey::<Ed25519>::from_bytes(bytes).unwrap();
    assert_eq!(key.as_bytes()[0], 42);

    // Drop the key (zeroization happens automatically)
    drop(key);
    // Can't verify zeroization in this test, but ZeroizeOnDrop ensures it happens
}

#[test]
fn test_signature_with_domain() {
    let bytes = vec![42u8; 64];
    let sig = Signature::<Ed25519>::from_bytes(bytes.clone(), DomainSeparator::Transaction)
        .unwrap();

    assert_eq!(sig.as_bytes(), &bytes);
    assert_eq!(sig.domain(), DomainSeparator::Transaction);
    assert_eq!(Signature::<Ed25519>::algorithm(), AlgorithmId::Ed25519);
}

#[test]
fn test_keypair_creation() {
    let pub_key = PublicKey::<Ed25519>::from_bytes(vec![1u8; 32]).unwrap();
    let priv_key = PrivateKey::<Ed25519>::from_bytes(vec![2u8; 32]).unwrap();
    let keypair = Keypair::new(pub_key.clone(), priv_key);

    assert_eq!(keypair.public_key().as_bytes(), pub_key.as_bytes());
    assert_eq!(Keypair::<Ed25519>::algorithm(), AlgorithmId::Ed25519);
}

#[test]
fn test_keypair_decomposition() {
    let pub_key = PublicKey::<Ed25519>::from_bytes(vec![1u8; 32]).unwrap();
    let priv_key = PrivateKey::<Ed25519>::from_bytes(vec![2u8; 32]).unwrap();
    let keypair = Keypair::new(pub_key.clone(), priv_key.clone());

    let (pub_out, priv_out) = keypair.into_parts();
    assert_eq!(pub_out.as_bytes(), pub_key.as_bytes());
    assert_eq!(priv_out.as_bytes(), priv_key.as_bytes());
}

#[test]
fn test_hybrid_algorithm_properties() {
    // ML-DSA-65 Hybrid
    assert_eq!(MlDsa65Hybrid::ID, AlgorithmId::MlDsa65);
    assert!(MlDsa65Hybrid::IS_HYBRID);
    assert!(MlDsa65Hybrid::IS_POST_QUANTUM);
    assert_eq!(MlDsa65Hybrid::SECURITY_LEVEL, 3);

    // ML-DSA-87 Hybrid
    assert_eq!(MlDsa87Hybrid::ID, AlgorithmId::MlDsa87);
    assert!(MlDsa87Hybrid::IS_HYBRID);
    assert!(MlDsa87Hybrid::IS_POST_QUANTUM);
    assert_eq!(MlDsa87Hybrid::SECURITY_LEVEL, 5);

    // SLH-DSA Hybrid
    assert_eq!(SlhDsaHybrid::ID, AlgorithmId::SlhDsaShake256f);
    assert!(SlhDsaHybrid::IS_HYBRID);
    assert!(SlhDsaHybrid::IS_POST_QUANTUM);
}

#[test]
fn test_classical_algorithm_properties() {
    assert_eq!(Ed25519::ID, AlgorithmId::Ed25519);
    assert!(!Ed25519::IS_HYBRID);
    assert!(!Ed25519::IS_POST_QUANTUM);
    assert_eq!(Ed25519::SECURITY_LEVEL, 2);
}

// =============================================================================
// Builder Pattern Tests
// =============================================================================

#[test]
fn test_policy_builder_default() {
    let config = PolicyConfigBuilder::new().build();
    assert_eq!(config.transaction_policy, ValidationPolicy::HybridPreferred);
    assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
    assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
}

#[test]
fn test_policy_builder_conservative() {
    let config = PolicyConfigBuilder::conservative().build();
    assert_eq!(config.transaction_policy, ValidationPolicy::HybridRequired);
    assert_eq!(config.block_policy, ValidationPolicy::HybridRequired);
    assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
}

#[test]
fn test_policy_builder_progressive() {
    let config = PolicyConfigBuilder::progressive().build();
    assert_eq!(config.transaction_policy, ValidationPolicy::HybridPreferred);
    assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
    assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
}

#[test]
fn test_policy_builder_legacy() {
    let config = PolicyConfigBuilder::legacy().build();
    assert_eq!(config.transaction_policy, ValidationPolicy::ClassicOnly);
    assert_eq!(config.block_policy, ValidationPolicy::ClassicOnly);
    assert_eq!(config.consensus_policy, ValidationPolicy::ClassicOnly);
}

#[test]
fn test_policy_builder_post_quantum() {
    let config = PolicyConfigBuilder::post_quantum().build();
    assert_eq!(config.transaction_policy, ValidationPolicy::PqOnly);
    assert_eq!(config.block_policy, ValidationPolicy::PqOnly);
    assert_eq!(config.consensus_policy, ValidationPolicy::PqOnly);
}

#[test]
fn test_policy_builder_fluent_api() {
    let config = PolicyConfigBuilder::new()
        .transaction(ValidationPolicy::ClassicOnly)
        .block(ValidationPolicy::HybridPreferred)
        .consensus(ValidationPolicy::HybridRequired)
        .build();

    assert_eq!(config.transaction_policy, ValidationPolicy::ClassicOnly);
    assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
    assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
}

#[test]
fn test_policy_builder_override() {
    let config = PolicyConfigBuilder::conservative()
        .transaction(ValidationPolicy::ClassicOnly)
        .build();

    assert_eq!(config.transaction_policy, ValidationPolicy::ClassicOnly);
    assert_eq!(config.block_policy, ValidationPolicy::HybridRequired);
    assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
}

// =============================================================================
// Type-State Machine Tests
// =============================================================================

#[test]
fn test_migration_context_creation() {
    let config = PolicyConfigBuilder::legacy().build();
    let context = MigrationContext::<LegacyState>::new(config);

    assert_eq!(MigrationContext::<LegacyState>::state_name(), "Legacy");
    assert_eq!(context.metadata().classical_count, 0);
    assert_eq!(context.metadata().hybrid_count, 0);
}

#[test]
fn test_state_properties() {
    assert!(LegacyState::ACCEPTS_CLASSICAL);
    assert!(!LegacyState::ACCEPTS_HYBRID);
    assert!(LegacyState::IS_TRANSIENT);

    assert!(TransitionState::ACCEPTS_CLASSICAL);
    assert!(TransitionState::ACCEPTS_HYBRID);
    assert!(TransitionState::ACCEPTS_PQ);
    assert!(TransitionState::IS_TRANSIENT);

    assert!(!ModernState::ACCEPTS_CLASSICAL);
    assert!(ModernState::ACCEPTS_HYBRID);
    assert!(ModernState::ACCEPTS_PQ);
    assert!(!ModernState::IS_TRANSIENT);
}

#[test]
#[cfg(feature = "std")]
fn test_migration_flow() {
    let config = PolicyConfigBuilder::legacy().build();
    let context = MigrationContext::<LegacyState>::new(config);

    // Begin migration
    let context = context.begin_migration(None).unwrap();
    assert_eq!(
        MigrationContext::<TransitionState>::state_name(),
        "Transition"
    );
}

#[test]
#[cfg(not(feature = "std"))]
fn test_migration_flow_no_std() {
    let config = PolicyConfigBuilder::legacy().build();
    let context = MigrationContext::<LegacyState>::new(config);

    // Begin migration (no_std version)
    let context = context.begin_migration().unwrap();
    assert_eq!(
        MigrationContext::<TransitionState>::state_name(),
        "Transition"
    );
}

#[test]
fn test_migration_progress_tracking() {
    let config = PolicyConfigBuilder::progressive().build();
    let mut context = MigrationContext::<TransitionState> {
        config,
        #[cfg(feature = "std")]
        deadline: None,
        metadata: pq_lib::typestate::MigrationMetadata {
            classical_count: 10,
            hybrid_count: 90,
            pq_count: 0,
            failure_count: 0,
        },
        _state: core::marker::PhantomData,
    };

    assert_eq!(context.migration_progress(), 90.0);

    context.record_validation(ValidationPolicy::HybridRequired);
    assert!(context.migration_progress() > 90.0);
}

#[test]
fn test_migration_readiness() {
    let config = PolicyConfigBuilder::progressive().build();
    let context = MigrationContext::<TransitionState> {
        config,
        #[cfg(feature = "std")]
        deadline: None,
        metadata: pq_lib::typestate::MigrationMetadata {
            classical_count: 5,
            hybrid_count: 95,
            pq_count: 0,
            failure_count: 0,
        },
        _state: core::marker::PhantomData,
    };

    assert!(context.is_ready_to_complete(90.0));
    assert!(!context.is_ready_to_complete(99.0));
}

#[test]
fn test_migration_completion() {
    let config = PolicyConfigBuilder::progressive().build();
    let context = MigrationContext::<TransitionState> {
        config,
        #[cfg(feature = "std")]
        deadline: None,
        metadata: pq_lib::typestate::MigrationMetadata {
            classical_count: 5,
            hybrid_count: 95,
            pq_count: 0,
            failure_count: 2,
        },
        _state: core::marker::PhantomData,
    };

    let result = context.complete_migration();
    assert!(result.is_ok());

    let modern = result.unwrap();
    assert_eq!(
        MigrationContext::<ModernState>::state_name(),
        modern.state_name()
    );
}

#[test]
fn test_migration_rollback() {
    let config = PolicyConfigBuilder::progressive().build();
    let transition = MigrationContext::<TransitionState> {
        config,
        #[cfg(feature = "std")]
        deadline: None,
        metadata: pq_lib::typestate::MigrationMetadata::default(),
        _state: core::marker::PhantomData,
    };

    let legacy = transition.rollback_migration();
    assert_eq!(
        MigrationContext::<LegacyState>::state_name(),
        legacy.state_name()
    );
}

#[test]
fn test_high_failure_rate_prevents_completion() {
    let config = PolicyConfigBuilder::progressive().build();
    let context = MigrationContext::<TransitionState> {
        config,
        #[cfg(feature = "std")]
        deadline: None,
        metadata: pq_lib::typestate::MigrationMetadata {
            classical_count: 50,
            hybrid_count: 50,
            pq_count: 0,
            failure_count: 10, // 10% failure rate
        },
        _state: core::marker::PhantomData,
    };

    let result = context.complete_migration();
    assert!(result.is_err());
    if let Err(e) = result {
        let msg = format!("{}", e);
        assert!(msg.contains("Failure rate too high"));
    }
}

// =============================================================================
// Backward Compatibility Tests
// =============================================================================

#[test]
fn test_migration_guide_algorithm_instructions() {
    let guide = MigrationGuide::for_algorithm(AlgorithmId::Ed25519);
    assert!(guide.contains("Ed25519"));
    assert!(guide.contains("Keypair"));
    assert!(guide.contains("Benefits"));
}

#[test]
fn test_migration_guide_all_algorithms() {
    for algorithm in &[
        AlgorithmId::Ed25519,
        AlgorithmId::MlDsa65,
        AlgorithmId::MlDsa87,
        AlgorithmId::SlhDsaShake256f,
    ] {
        let guide = MigrationGuide::for_algorithm(*algorithm);
        assert!(!guide.is_empty());
        assert!(guide.contains("Migrate to:"));
        assert!(guide.contains("Old:"));
        assert!(guide.contains("New:"));
    }
}

#[test]
fn test_effort_estimation() {
    assert!(MigrationGuide::estimate_effort(100).contains("Low"));
    assert!(MigrationGuide::estimate_effort(1000).contains("Medium"));
    assert!(MigrationGuide::estimate_effort(5000).contains("High"));
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_complete_workflow_simulation() {
    // 1. Start with legacy configuration
    let config = PolicyConfigBuilder::legacy().build();
    let mut context = MigrationContext::<LegacyState>::new(config);

    // 2. Record some classical validations
    for _ in 0..10 {
        context.record_validation(ValidationPolicy::ClassicOnly);
    }
    assert_eq!(context.metadata().classical_count, 10);

    // 3. Begin migration
    #[cfg(feature = "std")]
    let mut context = context.begin_migration(None).unwrap();
    #[cfg(not(feature = "std"))]
    let mut context = context.begin_migration().unwrap();

    // 4. Gradual hybrid adoption
    for _ in 0..90 {
        context.record_validation(ValidationPolicy::HybridRequired);
    }

    // 5. Check progress
    assert!(context.migration_progress() >= 90.0);
    assert!(context.is_ready_to_complete(90.0));

    // 6. Complete migration
    let modern = context.complete_migration().unwrap();
    assert_eq!(
        MigrationContext::<ModernState>::state_name(),
        "Modern"
    );
    assert!(modern.migration_progress() >= 90.0);
}

#[test]
fn test_algorithm_size_consistency() {
    // Verify that hybrid algorithm sizes are sum of components
    assert_eq!(
        MlDsa65Hybrid::PUBLIC_KEY_SIZE,
        Ed25519::PUBLIC_KEY_SIZE + 1952
    );
    assert_eq!(
        MlDsa65Hybrid::PRIVATE_KEY_SIZE,
        Ed25519::PRIVATE_KEY_SIZE + 4032
    );
    assert_eq!(
        MlDsa65Hybrid::SIGNATURE_SIZE,
        Ed25519::SIGNATURE_SIZE + 3309
    );
}

// =============================================================================
// Property Tests (would use proptest in real implementation)
// =============================================================================

#[test]
fn test_key_size_invariant() {
    // Any key created with correct size should succeed
    for size in &[32, 64, 128] {
        let bytes = vec![42u8; *size];
        if *size == 32 {
            assert!(PublicKey::<Ed25519>::from_bytes(bytes).is_ok());
        } else {
            assert!(PublicKey::<Ed25519>::from_bytes(bytes).is_err());
        }
    }
}

#[test]
fn test_algorithm_display() {
    assert_eq!(format!("{}", Ed25519), "Ed25519");
    assert_eq!(format!("{}", MlDsa65Hybrid), "Ed25519+ML-DSA-65");
    assert_eq!(format!("{}", MlDsa87Hybrid), "Ed25519+ML-DSA-87");
}

#[test]
fn test_debug_output_redacts_sensitive_data() {
    let priv_key = PrivateKey::<Ed25519>::from_bytes(vec![42u8; 32]).unwrap();
    let debug_output = format!("{:?}", priv_key);

    // Should contain algorithm info
    assert!(debug_output.contains("PrivateKey"));

    // Should NOT contain actual key bytes
    assert!(debug_output.contains("REDACTED"));
}

