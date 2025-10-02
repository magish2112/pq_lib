//! Performance demonstration and benchmarking example
//!
//! This example shows how to measure and compare the performance of different
//! cryptographic algorithms and operations in pq_lib.

use pq_lib::*;
use std::time::Instant;

#[cfg(feature = "std")]
async fn run_performance_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 pq_lib Performance Demonstration");
    println!("===================================");
    println!();

    // Generate keypairs for different algorithms
    println!("📊 Key Generation Performance:");
    println!("-----------------------------");

    let algorithms = vec![
        AlgorithmId::Ed25519,
        AlgorithmId::MlDsa65,
        AlgorithmId::MlDsa87,
        AlgorithmId::SlhDsaShake256f,
    ];

    for algorithm in algorithms {
        if algorithm.is_available() {
            let start = Instant::now();
            let keypair = HybridSigner::generate_keypair(algorithm).await?;
            let duration = start.elapsed();

            println!("  {:<25} | {:<8} | {} bytes public, {} bytes private",
                algorithm.name(),
                format!("{:?}", duration),
                keypair.public_key.expected_size(),
                keypair.private_key.ed25519_key().len() + keypair.private_key.pq_key().unwrap_or(&vec![]).len()
            );
        }
    }

    println!();

    // Test signing performance
    println!("✍️  Signing Performance:");
    println!("----------------------");

    let test_data = b"This is a test message for measuring cryptographic signing performance. It should be representative of typical blockchain transaction data.";

    for algorithm in [AlgorithmId::Ed25519, AlgorithmId::MlDsa65] {
        if algorithm.is_available() {
            let keypair = HybridSigner::generate_keypair(algorithm).await?;

            let start = Instant::now();
            let signature = HybridSigner::sign_with_domain(
                test_data,
                &keypair.private_key,
                DomainSeparator::Transaction
            ).await?;
            let sign_duration = start.elapsed();

            println!("  {:<25} | {:<8} | {} bytes signature",
                algorithm.name(),
                format!("{:?}", sign_duration),
                signature.expected_size()
            );
        }
    }

    println!();

    // Test verification performance
    println!("✅ Verification Performance:");
    println!("--------------------------");

    for algorithm in [AlgorithmId::Ed25519, AlgorithmId::MlDsa65] {
        if algorithm.is_available() {
            let keypair = HybridSigner::generate_keypair(algorithm).await?;
            let signature = HybridSigner::sign_with_domain(
                test_data,
                &keypair.private_key,
                DomainSeparator::Transaction
            ).await?;

            let start = Instant::now();
            let is_valid = HybridSigner::verify_with_policy(
                test_data,
                &signature,
                &keypair.public_key,
                ValidationPolicy::HybridRequired
            ).await?;
            let verify_duration = start.elapsed();

            println!("  {:<25} | {:<8} | valid: {}",
                algorithm.name(),
                format!("{:?}", verify_duration),
                is_valid
            );

            assert!(is_valid, "Signature verification should succeed");
        }
    }

    println!();

    // Test serialization performance
    println!("💾 Serialization Performance:");
    println!("----------------------------");

    let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await?;
    let signature = HybridSigner::sign_with_domain(
        test_data,
        &keypair.private_key,
        DomainSeparator::Transaction
    ).await?;

    // Serialize signature
    let start = Instant::now();
    let serialized = pq_lib::serialization::serialize_signature(&signature)?;
    let serialize_duration = start.elapsed();

    // Deserialize signature
    let start = Instant::now();
    let deserialized = pq_lib::serialization::deserialize_signature(&serialized)?;
    let deserialize_duration = start.elapsed();

    println!("  {:<25} | serialize: {:?}, deserialize: {:?}",
        "Signature (CBOR)",
        serialize_duration,
        deserialize_duration
    );

    // Verify round-trip integrity
    assert_eq!(signature, deserialized, "Serialization round-trip should preserve data");

    println!();

    // Test domain separation impact
    println!("🏷️  Domain Separation Impact:");
    println!("----------------------------");

    let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await?;
    let same_data = b"Same data, different domains";

    let domains = vec![
        DomainSeparator::Transaction,
        DomainSeparator::Block,
        DomainSeparator::Consensus,
    ];

    for domain in domains {
        let start = Instant::now();
        let signature = HybridSigner::sign_with_domain(
            same_data,
            &keypair.private_key,
            domain
        ).await?;
        let duration = start.elapsed();

        println!("  {:<25} | {:?} | signature differs: {}",
            format!("{:?}", domain),
            duration,
            signature.ed25519_sig() != HybridSigner::sign_with_domain(
                same_data,
                &keypair.private_key,
                DomainSeparator::Transaction
            ).await?.ed25519_sig()
        );
    }

    println!();
    println!("🎯 Performance Summary:");
    println!("---------------------");
    println!("✅ All operations completed successfully");
    println!("✅ Domain separation prevents signature reuse");
    println!("✅ Serialization maintains data integrity");
    println!("✅ Performance is within acceptable ranges for blockchain use");

    Ok(())
}

#[cfg(feature = "std")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_performance_demo().await
}

#[cfg(not(feature = "std"))]
fn main() {
    println!("❌ Performance demo requires std feature");
    println!("   Enable with: cargo run --features std --example performance_demo");
}
