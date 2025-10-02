//! Basic usage example for Symbios PQC

use symbios_pqc::{HybridSigner, AlgorithmId, ValidationPolicy, DomainSeparator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Symbios PQC - Basic Usage Example");
    println!("=====================================");

    // Generate different types of keypairs
    let algorithms = vec![
        AlgorithmId::Ed25519,
        AlgorithmId::MlDsa65,
        // AlgorithmId::SlhDsaShake256f, // Uncomment if slh-dsa feature is enabled
    ];

    for algorithm in algorithms {
        if !algorithm.is_available() {
            println!("⚠️  Skipping {} - feature not enabled", algorithm);
            continue;
        }

        println!("\n🧪 Testing {}:", algorithm);

        // Generate keypair
        let keypair = HybridSigner::generate_keypair(algorithm).await?;
        println!("  ✅ Generated keypair");

        // Test data
        let message = b"Hello, Symbios PQC!";
        println!("  📝 Message: {}", String::from_utf8_lossy(message));

        // Sign with different domains
        let domains = vec![
            DomainSeparator::Transaction,
            DomainSeparator::Block,
            DomainSeparator::Consensus,
        ];

        for domain in domains {
            // Sign
            let signature = HybridSigner::sign_with_domain(message, &keypair.private_key, domain).await?;
            println!("  ✅ Signed with {} domain", domain.name());

            // Verify with different policies
            let policies = vec![
                ValidationPolicy::ClassicOnly,
                ValidationPolicy::HybridPreferred,
                ValidationPolicy::HybridRequired,
                ValidationPolicy::PqOnly,
            ];

            for policy in policies {
                let result = HybridSigner::verify_with_policy(
                    message, &signature, &keypair.public_key, policy
                ).await;

                match result {
                    Ok(true) => println!("    ✅ {} policy: VALID", policy.name()),
                    Ok(false) => println!("    ❌ {} policy: INVALID", policy.name()),
                    Err(e) => println!("    ⚠️  {} policy: ERROR - {}", policy.name(), e),
                }
            }
        }

        // Test KEM if PQ key is available
        if keypair.public_key.has_pq_key() {
            println!("  🔑 Testing KEM operations:");
            let (shared_secret, ciphertext) = HybridSigner::encapsulate(&keypair.public_key).await?;
            println!("    ✅ Encapsulated shared secret ({} bytes)", shared_secret.len());
            println!("    📦 Ciphertext size: {} bytes", ciphertext.len());

            let recovered_secret = HybridSigner::decapsulate(&ciphertext, &keypair.private_key).await?;
            println!("    ✅ Decapsulated shared secret ({} bytes)", recovered_secret.len());
        }
    }

    println!("\n🎉 All tests completed successfully!");
    Ok(())
}

