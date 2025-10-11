//! Migration demonstration example
//!
//! This example shows how to use policy-based validation for gradual
//! migration from classical to post-quantum cryptography.

use pq_lib::*;

#[cfg(feature = "std")]
async fn run_migration_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 pq_lib Migration Demonstration");
    println!("=================================");
    println!();

    // Simulate a blockchain scenario with gradual PQ migration
    println!("🏛️  Blockchain Migration Scenario:");
    println!("--------------------------------");

    // Step 1: Start with classical-only signatures
    println!("📋 Phase 1: Classical-only signatures");
    let classical_keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await?;

    let tx_data = b"Blockchain transaction data";
    let classical_signature = HybridSigner::sign_with_domain(
        tx_data,
        &classical_keypair.private_key,
        DomainSeparator::Transaction,
    )
    .await?;

    // Verify with classical-only policy
    let classical_valid = HybridSigner::verify_with_policy(
        tx_data,
        &classical_signature,
        &classical_keypair.public_key,
        ValidationPolicy::ClassicOnly,
    )
    .await?;

    println!("  ✅ Classical signature valid: {}", classical_valid);
    assert!(classical_valid);

    // Step 2: Introduce hybrid signatures
    println!("\n📋 Phase 2: Introduce hybrid signatures");
    let hybrid_keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;

    let hybrid_signature = HybridSigner::sign_with_domain(
        tx_data,
        &hybrid_keypair.private_key,
        DomainSeparator::Transaction,
    )
    .await?;

    // Verify with hybrid-preferred policy (accepts both)
    let hybrid_preferred_valid = HybridSigner::verify_with_policy(
        tx_data,
        &hybrid_signature,
        &hybrid_keypair.public_key,
        ValidationPolicy::HybridPreferred,
    )
    .await?;

    println!(
        "  ✅ Hybrid signature (preferred) valid: {}",
        hybrid_preferred_valid
    );
    assert!(hybrid_preferred_valid);

    // Still accept classical signatures
    let classical_still_valid = HybridSigner::verify_with_policy(
        tx_data,
        &classical_signature,
        &classical_keypair.public_key,
        ValidationPolicy::HybridPreferred,
    )
    .await?;

    println!(
        "  ✅ Classical signature (backward compatible) valid: {}",
        classical_still_valid
    );
    assert!(classical_still_valid);

    // Step 3: Require hybrid signatures
    println!("\n📋 Phase 3: Require hybrid signatures");

    // Classical signature should fail hybrid-required policy
    let classical_fails_hybrid_required = HybridSigner::verify_with_policy(
        tx_data,
        &classical_signature,
        &classical_keypair.public_key,
        ValidationPolicy::HybridRequired,
    )
    .await?;

    println!(
        "  ❌ Classical signature (hybrid required) valid: {}",
        classical_fails_hybrid_required
    );
    assert!(!classical_fails_hybrid_required);

    // Hybrid signature should pass hybrid-required policy
    let hybrid_required_valid = HybridSigner::verify_with_policy(
        tx_data,
        &hybrid_signature,
        &hybrid_keypair.public_key,
        ValidationPolicy::HybridRequired,
    )
    .await?;

    println!(
        "  ✅ Hybrid signature (required) valid: {}",
        hybrid_required_valid
    );
    assert!(hybrid_required_valid);

    // Step 4: Policy configuration example
    println!("\n📋 Policy Configuration Example:");
    println!("------------------------------");

    let conservative_config = PolicyConfig::conservative();
    println!("  Conservative config:");
    println!(
        "    - Transactions: {:?}",
        conservative_config.transaction_policy
    );
    println!("    - Blocks: {:?}", conservative_config.block_policy);
    println!(
        "    - Consensus: {:?}",
        conservative_config.consensus_policy
    );

    let strict_config = PolicyConfig::strict();
    println!("  Strict config:");
    println!("    - Transactions: {:?}", strict_config.transaction_policy);
    println!("    - Blocks: {:?}", strict_config.block_policy);
    println!("    - Consensus: {:?}", strict_config.consensus_policy);

    // Step 5: Migration configuration
    println!("\n📋 Migration Configuration:");
    println!("--------------------------");

    let mut migration_config = MigrationConfig::new(
        ValidationPolicy::HybridPreferred,
        ValidationPolicy::HybridRequired,
    );

    println!("  Current policy: {:?}", migration_config.current_policy);
    println!("  Target policy: {:?}", migration_config.target_policy);
    println!("  Migration active: {}", migration_config.migration_active);

    // Simulate deadline enforcement (would need actual time checking)
    migration_config.deadline = Some(0); // Simulate deadline passed
    println!(
        "  After deadline - effective policy: {:?}",
        migration_config.effective_policy()
    );

    // Step 6: Domain-specific policies
    println!("\n📋 Domain-Specific Policies:");
    println!("---------------------------");

    let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;

    // Sign same data with different domains
    let tx_signature =
        HybridSigner::sign_with_domain(tx_data, &keypair.private_key, DomainSeparator::Transaction)
            .await?;

    let block_signature =
        HybridSigner::sign_with_domain(tx_data, &keypair.private_key, DomainSeparator::Block)
            .await?;

    println!(
        "  Transaction domain signature: {} bytes",
        tx_signature.ed25519_sig().len()
    );
    println!(
        "  Block domain signature: {} bytes",
        block_signature.ed25519_sig().len()
    );
    println!(
        "  Signatures are different (domain separation): {}",
        tx_signature.ed25519_sig() != block_signature.ed25519_sig()
    );

    // Verify with different policies based on domain
    let tx_valid = HybridSigner::verify_with_policy(
        tx_data,
        &tx_signature,
        &keypair.public_key,
        conservative_config.policy_for_domain(DomainSeparator::Transaction),
    )
    .await?;

    let block_valid = HybridSigner::verify_with_policy(
        tx_data,
        &block_signature,
        &keypair.public_key,
        conservative_config.policy_for_domain(DomainSeparator::Block),
    )
    .await?;

    println!(
        "  Transaction verification (hybrid preferred): {}",
        tx_valid
    );
    println!("  Block verification (hybrid preferred): {}", block_valid);

    println!();
    println!("🎯 Migration Summary:");
    println!("-------------------");
    println!("✅ Domain separation prevents signature reuse");
    println!("✅ Policy validation supports gradual migration");
    println!("✅ Backward compatibility maintained");
    println!("✅ Forward compatibility with PQ algorithms");
    println!("✅ Configurable policies for different contexts");

    Ok(())
}

#[cfg(feature = "std")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_migration_demo().await
}

#[cfg(not(feature = "std"))]
fn main() {
    println!("❌ Migration demo requires std feature");
    println!("   Enable with: cargo run --features std --example migration_demo");
}
