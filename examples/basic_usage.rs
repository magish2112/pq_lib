//! Basic usage example for pq_lib

use pq_lib::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("pq_lib Basic Usage Example");
    println!("==========================");

    // Demonstrate AlgorithmId
    println!("\nAvailable algorithms:");
    for algo in available_algorithms() {
        println!("  - {}: {} bytes signature, security level {}",
                algo.name(),
                algo.signature_size(),
                algo.security_level());
    }

    // Demonstrate key types
    let ed25519_key = vec![42; 32]; // Mock key for demo
    let public_key = HybridPublicKey::from_ed25519(ed25519_key.clone());
    let private_key = HybridPrivateKey::from_ed25519(ed25519_key);

    println!("\nKey Information:");
    println!("  Public key algorithm: {}", public_key.algorithm);
    println!("  Public key size: {} bytes", public_key.ed25519_key.len());
    println!("  Private key algorithm: {}", private_key.algorithm);
    println!("  Private key size: {} bytes", private_key.ed25519_key.len());

    // Demonstrate signature
    let signature_data = b"Hello, pq_lib!";
    let signature = HybridSignature::ed25519_only(signature_data.to_vec());

    println!("\nSignature Information:");
    println!("  Version: {}", signature.version);
    println!("  Algorithm: {}", signature.algorithm);
    println!("  Ed25519 signature size: {} bytes", signature.ed25519_sig.len());
    println!("  Has PQ signature: {}", signature.pq_sig.is_some());
    println!("  Valid for algorithm: {}", signature.is_valid_for_algorithm());

    println!("\n✅ Basic usage example completed successfully!");
    Ok(())
}