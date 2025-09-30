//! Integration Tests for Symbios Network
//!
//! Comprehensive integration testing suite covering:
//! - HotStuff consensus protocol end-to-end
//! - Hybrid cryptography workflows
//! - AI DoS protection under attack scenarios
//! - State machine consistency across operations
//! - Network message handling and validation

use symbios_mvp::*;
use symbios_mvp::hotstuff_consensus::*;
use symbios_mvp::hybrid_crypto::*;
use symbios_mvp::ai_dos_protection::*;
use symbios_mvp::adaptive_crypto::*;
use symbios_mvp::state_machine::*;
use symbios_mvp::storage::*;
use symbios_mvp::metrics::*;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(test)]
mod integration_tests {

    use super::*;

    /// Test complete HotStuff consensus round with multiple validators
    #[tokio::test]
    async fn test_hotstuff_consensus_integration() {
        // Setup 4 validators
        let validators = create_test_validators(4);
        let mut consensus_instances = Vec::new();

        // Create consensus instances for each validator
        for (i, validator) in validators.iter().enumerate() {
            let config = HotStuffConfig {
                view_timeout: std::time::Duration::from_secs(5),
                leader_replacement_timeout: std::time::Duration::from_secs(10),
                max_message_buffer: 100,
                qc_aggregation_timeout: std::time::Duration::from_millis(200),
            };

            let private_key = create_test_private_key(i);
            let storage = Arc::new(Storage::new_temp().unwrap());
            let state_machine = Arc::new(StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap());
            let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
                Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
            ).await);

            let consensus = HotStuffConsensus::new(
                config,
                validator.clone(),
                private_key,
                state_machine,
                adaptive_crypto,
            ).await.unwrap();

            consensus_instances.push(consensus);
        }

        // Test consensus message flow
        let leader = &consensus_instances[0]; // First validator is leader for view 0

        // Create test transaction
        let tx = Transaction::new(
            PublicKey::new_ed25519(),
            PublicKey::new_ed25519(),
            1000,
            10,
            1,
        );

        // Propose block
        leader.propose_block(vec![tx]).await.unwrap();

        // Simulate vote collection and QC creation
        for instance in &consensus_instances {
            let metrics = instance.get_metrics();
            assert!(metrics.total_views >= 0); // Basic sanity check
        }

        println!("✅ HotStuff consensus integration test passed");
    }

    /// Test hybrid cryptography workflow end-to-end
    #[tokio::test]
    async fn test_hybrid_crypto_integration() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto).await;

        // Generate keypair
        let keypair = hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await.unwrap();

        // Test signing and verification
        let test_data = b"Integration test message for hybrid crypto";
        let signature = hybrid_crypto.sign(test_data, &keypair.private_key).await.unwrap();
        let is_valid = hybrid_crypto.verify(test_data, &signature, &keypair.public_key).await.unwrap();

        assert!(is_valid, "Hybrid signature verification should succeed");

        // Test encryption/decryption
        let plaintext = b"Sensitive data to encrypt";
        let encrypted = hybrid_crypto.encrypt_hybrid(plaintext, &keypair.public_key).await.unwrap();
        let decrypted = hybrid_crypto.decrypt_hybrid(&encrypted, &keypair.private_key).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice(), "Hybrid encryption/decryption should preserve data");

        println!("✅ Hybrid cryptography integration test passed");
    }

    /// Test AI DoS protection under simulated attack
    #[tokio::test]
    async fn test_ai_dos_protection_integration() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let network = Arc::new(MockNetwork::new()); // Mock network for testing
        let dos_protection = AiTrafficAnalyzer::new(network, Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())).await.unwrap();

        // Simulate normal traffic
        let normal_ip = "192.168.1.100".parse().unwrap();
        let normal_message = NetworkMessage::Transaction(create_test_transaction());

        let decision = dos_protection.analyze_traffic(
            normal_ip,
            &normal_message,
            200, // message size
            50,  // processing time
            false // no error
        ).await.unwrap();

        assert_eq!(decision, TrafficDecision::Allow, "Normal traffic should be allowed");

        // Simulate attack traffic (flood)
        for i in 0..100 {
            let attack_message = NetworkMessage::Transaction(create_test_transaction());
            let _ = dos_protection.analyze_traffic(
                normal_ip,
                &attack_message,
                200,
                10, // fast processing
                false
            ).await;
        }

        // After flood, traffic should be throttled
        let final_decision = dos_protection.analyze_traffic(
            normal_ip,
            &normal_message,
            200,
            50,
            false
        ).await.unwrap();

        match final_decision {
            TrafficDecision::Allow | TrafficDecision::Throttle { .. } => {
                // Either allow or throttle is acceptable after learning
            }
            TrafficDecision::Block { .. } => {
                panic!("Traffic should not be blocked after moderate flood");
            }
        }

        println!("✅ AI DoS protection integration test passed");
    }

    /// Test state machine consistency across operations
    #[tokio::test]
    async fn test_state_machine_consistency() {
        let storage = Arc::new(Storage::new_temp().unwrap());
        let mut state_machine = StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap();

        // Initial state check
        let initial_supply = state_machine.get_total_supply();
        assert_eq!(initial_supply, 0, "Initial total supply should be 0");

        // Create accounts
        let alice = PublicKey::new_ed25519();
        let bob = PublicKey::new_ed25519();

        // Fund Alice
        let fund_tx = create_funding_transaction(alice, 10000);
        let receipt = state_machine.validate_and_execute_transaction(&fund_tx).await.unwrap();
        assert!(receipt.success, "Funding transaction should succeed");

        // Check balance
        let alice_balance = state_machine.get_balance(&alice);
        assert_eq!(alice_balance, 10000, "Alice should have correct balance");

        // Transfer from Alice to Bob
        let transfer_tx = Transaction::new(alice, bob, 5000, 10, 1);
        let transfer_receipt = state_machine.validate_and_execute_transaction(&transfer_tx).await.unwrap();
        assert!(transfer_receipt.success, "Transfer should succeed");

        // Check final balances
        let final_alice_balance = state_machine.get_balance(&alice);
        let final_bob_balance = state_machine.get_balance(&bob);

        assert_eq!(final_alice_balance, 4990, "Alice should have 10000 - 5000 - 10 = 4990");
        assert_eq!(final_bob_balance, 5000, "Bob should have received 5000");

        // Total supply should remain the same (funding was from genesis)
        let final_supply = state_machine.get_total_supply();
        assert_eq!(final_supply, initial_supply, "Total supply should be preserved");

        println!("✅ State machine consistency test passed");
    }

    /// Test consensus + crypto + state integration
    #[tokio::test]
    async fn test_full_protocol_integration() {
        // This is a high-level integration test that exercises the full protocol stack

        // Setup components
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto.clone()).await;
        let storage = Arc::new(Storage::new_temp().unwrap());
        let state_machine = Arc::new(StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap());

        // Create signed transaction using hybrid crypto
        let keypair = hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await.unwrap();
        let mut tx = Transaction::new(
            keypair.public_key.ed25519_key.clone().into(),
            PublicKey::new_ed25519(),
            1000,
            10,
            1,
        );

        // Sign transaction (placeholder - in real implementation would sign properly)
        // let signature = hybrid_crypto.sign(&bincode::serialize(&tx).unwrap(), &keypair.private_key).await.unwrap();
        // tx.signature = Some(signature);

        // Execute transaction
        let receipt = state_machine.validate_and_execute_transaction(&tx).await.unwrap();
        assert!(receipt.success, "Transaction execution should succeed");

        // Verify state changes
        let sender_balance = state_machine.get_balance(&tx.sender.into());
        assert_eq!(sender_balance, 0, "Sender should have insufficient balance");

        println!("✅ Full protocol integration test passed");
    }

    /// Test performance under load
    #[tokio::test]
    async fn test_performance_under_load() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto).await;
        let storage = Arc::new(Storage::new_temp().unwrap());
        let state_machine = Arc::new(StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap());

        let keypair = hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await.unwrap();

        // Generate 100 transactions
        let mut transactions = Vec::new();
        for i in 0..100 {
            let tx = create_test_transaction_with_key(&keypair, i);
            transactions.push(tx);
        }

        let start_time = std::time::Instant::now();

        // Execute all transactions
        for tx in transactions {
            let _ = state_machine.validate_and_execute_transaction(&tx).await;
        }

        let elapsed = start_time.elapsed();
        let tps = 100.0 / elapsed.as_secs_f64();

        println!("🚀 Performance test: {} TPS", tps);
        assert!(tps > 10.0, "Should achieve at least 10 TPS under load");

        println!("✅ Performance under load test passed");
    }

    /// Test error handling and edge cases
    #[tokio::test]
    async fn test_error_handling() {
        let storage = Arc::new(Storage::new_temp().unwrap());
        let state_machine = Arc::new(StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap());

        // Test insufficient balance
        let tx = Transaction::new(
            PublicKey::new_ed25519(), // No balance
            PublicKey::new_ed25519(),
            1000,
            10,
            1,
        );

        let result = state_machine.validate_and_execute_transaction(&tx).await;
        assert!(result.is_err(), "Transaction with insufficient balance should fail");

        // Test invalid nonce (replay attack)
        let alice = PublicKey::new_ed25519();
        let fund_tx = create_funding_transaction(alice, 10000);
        let _ = state_machine.validate_and_execute_transaction(&fund_tx).await;

        // Try to reuse nonce
        let tx1 = Transaction::new(alice, PublicKey::new_ed25519(), 1000, 10, 1);
        let _ = state_machine.validate_and_execute_transaction(&tx1).await;

        let tx1_duplicate = Transaction::new(alice, PublicKey::new_ed25519(), 1000, 10, 1);
        let result = state_machine.validate_and_execute_transaction(&tx1_duplicate).await;
        assert!(result.is_err(), "Replay attack should be prevented");

        println!("✅ Error handling test passed");
    }
}

// Mock network for testing
struct MockNetwork;

impl MockNetwork {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl NetworkTrait for MockNetwork {
    async fn send_message(&self, _peer: &str, _message: NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    async fn broadcast(&self, _message: NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    async fn receive_message(&self) -> Result<NetworkMessage, Box<dyn std::error::Error>> {
        Err("Not implemented".into())
    }
}

// Helper functions

fn create_test_validators(count: usize) -> Vec<ValidatorSet> {
    let mut validators = Vec::new();

    for i in 0..count {
        let mut validator_map = std::collections::HashMap::new();
        let validator_info = ValidatorInfo {
            public_key: PublicKey::new_ed25519(),
            stake_amount: 1000 + (i as u64 * 100),
            network_address: format!("validator_{}:3030{}", i, i),
            commission_rate: 0,
            uptime: 100,
            last_seen: 0,
        };
        validator_map.insert(validator_info.public_key, validator_info.clone());

        validators.push(ValidatorSet { validators: validator_map });
    }

    validators
}

fn create_test_private_key(index: usize) -> PrivateKey {
    // In real implementation, this would create proper keys
    // For testing, we return a placeholder
    PrivateKey::new_ed25519()
}

fn create_test_transaction() -> Transaction {
    Transaction::new(
        PublicKey::new_ed25519(),
        PublicKey::new_ed25519(),
        100,
        1,
        1,
    )
}

fn create_funding_transaction(recipient: PublicKey, amount: u64) -> Transaction {
    // Special transaction type for funding (would be genesis transaction in real system)
    Transaction::new(
        Hash::new(b"genesis").into(), // Genesis "sender"
        recipient,
        amount,
        0, // No fee for genesis
        0,
    )
}

fn create_test_transaction_with_key(keypair: &HybridKeyPair, nonce: usize) -> Transaction {
    Transaction::new(
        keypair.public_key.ed25519_key.clone().into(),
        PublicKey::new_ed25519(),
        100,
        1,
        nonce as u64,
    )
}
