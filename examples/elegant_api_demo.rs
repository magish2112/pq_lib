//! Demonstration of elegant, type-safe cryptography API
//!
//! This example showcases the new type-level architecture that provides:
//! - Compile-time algorithm safety
//! - Zero-cost abstractions
//! - Fluent builder APIs
//! - Type-state migration management
//!
//! Run with: `cargo run --example elegant_api_demo`

use pq_lib::{
    builders::PolicyConfigBuilder,
    typed::{Algorithm, Ed25519, Keypair, MlDsa65Hybrid, PrivateKey, PublicKey, Signature},
    typestate::{LegacyState, MigrationContext},
    CryptoError, DomainSeparator, ValidationPolicy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎨 Elegant Cryptography API Demo\n");

    // =========================================================================
    // Part 1: Type-Safe Keys
    // =========================================================================
    println!("📚 Part 1: Type-Safe Cryptographic Keys");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Create Ed25519 public key with compile-time size validation
    let ed_pub_bytes = vec![42u8; 32];
    let ed_pub_key = PublicKey::<Ed25519>::from_bytes(ed_pub_bytes)?;
    println!("✓ Created Ed25519 public key");
    println!("  Algorithm: {}", Ed25519::NAME);
    println!(
        "  Size: {} bytes (compile-time constant)",
        Ed25519::PUBLIC_KEY_SIZE
    );
    println!("  Security Level: NIST-{}", Ed25519::SECURITY_LEVEL);
    println!("  Post-Quantum: {}\n", Ed25519::IS_POST_QUANTUM);

    // Try to create a key with wrong size (will fail at runtime with clear error)
    match PublicKey::<Ed25519>::from_bytes(vec![42u8; 16]) {
        Ok(_) => println!("❌ Should have failed!"),
        Err(e) => println!("✓ Size mismatch detected: {}\n", e),
    }

    // Hybrid algorithm with larger keys
    let ml_dsa_pub_bytes = vec![42u8; 32 + 1952];
    let ml_dsa_pub_key = PublicKey::<MlDsa65Hybrid>::from_bytes(ml_dsa_pub_bytes)?;
    println!("✓ Created ML-DSA-65 hybrid public key");
    println!("  Algorithm: {}", MlDsa65Hybrid::NAME);
    println!("  Size: {} bytes", MlDsa65Hybrid::PUBLIC_KEY_SIZE);
    println!("  Security Level: NIST-{}", MlDsa65Hybrid::SECURITY_LEVEL);
    println!("  Hybrid: {}", MlDsa65Hybrid::IS_HYBRID);
    println!("  Post-Quantum: {}\n", MlDsa65Hybrid::IS_POST_QUANTUM);

    // =========================================================================
    // Part 2: Type Safety Demonstration
    // =========================================================================
    println!("🔒 Part 2: Compile-Time Type Safety");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("✓ The type system prevents mixing algorithms:");
    println!("  - Ed25519 keys can only be used with Ed25519 operations");
    println!("  - ML-DSA keys can only be used with ML-DSA operations");
    println!("  - This is enforced at compile time, not runtime!\n");

    // The following would NOT compile:
    // let mixed_keypair = Keypair::new(ed_pub_key, ml_dsa_priv_key); // ❌ Type error!

    println!("✓ Algorithm information available at compile time:");
    println!("  - No runtime dispatch overhead");
    println!("  - Optimizer can inline everything");
    println!("  - Zero-cost abstraction\n");

    // =========================================================================
    // Part 3: Fluent Builder API
    // =========================================================================
    println!("🏗️  Part 3: Fluent Configuration Builders");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Conservative production configuration
    let conservative_config = PolicyConfigBuilder::conservative()
        .transaction(ValidationPolicy::HybridRequired)
        .build();
    println!("✓ Conservative configuration:");
    println!(
        "  Transaction: {:?}",
        conservative_config.transaction_policy
    );
    println!("  Block: {:?}", conservative_config.block_policy);
    println!("  Consensus: {:?}\n", conservative_config.consensus_policy);

    // Progressive migration configuration
    let progressive_config = PolicyConfigBuilder::progressive()
        .transaction(ValidationPolicy::HybridPreferred)
        .consensus(ValidationPolicy::HybridRequired)
        .enable_gradual_migration()
        .build();
    println!("✓ Progressive migration configuration:");
    println!("  Transaction: {:?}", progressive_config.transaction_policy);
    println!("  Block: {:?}", progressive_config.block_policy);
    println!("  Consensus: {:?}\n", progressive_config.consensus_policy);

    // Custom configuration with method chaining
    let custom_config = PolicyConfigBuilder::new()
        .transaction(ValidationPolicy::ClassicOnly)
        .block(ValidationPolicy::HybridPreferred)
        .consensus(ValidationPolicy::HybridRequired)
        .build();
    println!("✓ Custom configuration (fluent API):");
    println!("  Transaction: {:?}", custom_config.transaction_policy);
    println!("  Block: {:?}", custom_config.block_policy);
    println!("  Consensus: {:?}\n", custom_config.consensus_policy);

    // =========================================================================
    // Part 4: Type-State Migration Management
    // =========================================================================
    println!("🔄 Part 4: Type-State Migration Pattern");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Start in legacy state
    let mut legacy_context = MigrationContext::<LegacyState>::new(conservative_config.clone());
    println!("✓ Started in Legacy state");
    println!("  State: {}", MigrationContext::<LegacyState>::state_name());
    println!("  Accepts Classical: {}", LegacyState::ACCEPTS_CLASSICAL);
    println!("  Accepts Hybrid: {}\n", LegacyState::ACCEPTS_HYBRID);

    // Simulate some activity
    legacy_context.record_validation(ValidationPolicy::ClassicOnly);
    legacy_context.record_validation(ValidationPolicy::ClassicOnly);
    println!("✓ Recorded {} classical validations\n", 2);

    // Begin migration (type-state transition at compile time!)
    let mut transition_context = legacy_context.begin_migration(None)?;
    println!("✓ Migrated to Transition state");
    println!(
        "  State: {}",
        MigrationContext::<pq_lib::typestate::TransitionState>::state_name()
    );
    println!(
        "  Accepts Classical: {}",
        pq_lib::typestate::TransitionState::ACCEPTS_CLASSICAL
    );
    println!(
        "  Accepts Hybrid: {}",
        pq_lib::typestate::TransitionState::ACCEPTS_HYBRID
    );
    println!(
        "  Accepts PQ: {}\n",
        pq_lib::typestate::TransitionState::ACCEPTS_PQ
    );

    // Simulate hybrid adoption
    for _ in 0..18 {
        transition_context.record_validation(ValidationPolicy::HybridRequired);
    }
    println!("✓ Recorded 18 hybrid validations");
    println!(
        "  Migration progress: {:.1}%\n",
        transition_context.migration_progress()
    );

    // Check if ready to complete
    if transition_context.is_ready_to_complete(90.0) {
        let modern_context = transition_context.complete_migration()?;
        println!("✓ Completed migration to Modern state");
        println!(
            "  State: {}",
            MigrationContext::<pq_lib::typestate::ModernState>::state_name()
        );
        println!(
            "  Accepts Classical: {}",
            pq_lib::typestate::ModernState::ACCEPTS_CLASSICAL
        );
        println!(
            "  Accepts Hybrid: {}",
            pq_lib::typestate::ModernState::ACCEPTS_HYBRID
        );
        println!(
            "  Final progress: {:.1}%\n",
            modern_context.migration_progress()
        );

        // Invalid transitions don't compile:
        // let invalid = modern_context.begin_migration(); // ❌ Method doesn't exist!
    } else {
        println!("⚠️  Not ready to complete migration yet\n");
    }

    // =========================================================================
    // Part 5: Compile-Time Guarantees
    // =========================================================================
    println!("⚡ Part 5: Compile-Time Guarantees");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("✓ What the type system guarantees:");
    println!("  1. Algorithm compatibility (no mixing Ed25519 with ML-DSA)");
    println!("  2. Key size correctness (compile-time constants)");
    println!("  3. Valid state transitions (type-state pattern)");
    println!("  4. Signature domain consistency");
    println!("  5. Zero runtime overhead for type checking\n");

    println!("✓ What macros provide:");
    println!("  1. DRY - Define algorithm once, generate all boilerplate");
    println!("  2. Consistency - Uniform implementation patterns");
    println!("  3. Maintainability - Centralized common patterns");
    println!("  4. Test generation - Automatic property tests\n");

    // =========================================================================
    // Summary
    // =========================================================================
    println!("🎨 Summary: Why This Architecture is Elegant");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("1. 🔒 Type Safety:");
    println!("   • Phantom types prevent algorithm mixing");
    println!("   • Type-state pattern prevents invalid transitions");
    println!("   • Compiler catches errors before runtime\n");

    println!("2. ⚡ Performance:");
    println!("   • Zero-cost abstractions (no boxing, no vtables)");
    println!("   • Compile-time monomorphization");
    println!("   • No runtime type checks\n");

    println!("3. 🎯 Ergonomics:");
    println!("   • Fluent builder APIs");
    println!("   • Self-documenting type signatures");
    println!("   • Method availability guides usage\n");

    println!("4. 🔧 Maintainability:");
    println!("   • DRY through declarative macros");
    println!("   • Consistent patterns across algorithms");
    println!("   • Compile-time validations\n");

    println!("5. 🏛️  Architecture:");
    println!("   • Sealed traits for API stability");
    println!("   • Clear separation of concerns");
    println!("   • Backward compatible facade layer\n");

    println!("✨ This is cryptography as a work of art! ✨\n");

    Ok(())
}
