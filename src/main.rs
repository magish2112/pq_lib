//! Simple main for testing basic functionality

use pq_lib::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("pq_lib Basic Test");
    println!("=================");

    // Test AlgorithmId
    println!("Available algorithms:");
    for algo in available_algorithms() {
        println!("  - {} (PQ: {})", algo.name(), algo.is_post_quantum());
    }

    // Test basic types
    let key_data = vec![42; 32];
    let public_key = HybridPublicKey::from_ed25519(key_data.clone());
    let private_key = HybridPrivateKey::from_ed25519(key_data);
    let keypair = HybridKeypair::new(public_key, private_key);

    println!("Created keypair for algorithm: {}", keypair.public_key.algorithm);

    // Test signature
    let sig_data = b"test message";
    let signature = HybridSignature::ed25519_only(sig_data.to_vec());
    println!("Created signature: {}", signature);

    println!("✅ Basic test completed!");
    Ok(())
}
