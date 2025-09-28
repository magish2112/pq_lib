//! Property-based tests and fuzz testing for Symbios components

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::types::{Transaction, PublicKey, PrivateKey, Block, State, Hash};
    use crate::pqcrypto::PQCrypto;
    use crate::storage::Storage;
    use tempfile::TempDir;
    use std::collections::HashMap;

    // Strategies for generating test data
    fn arb_public_key() -> impl Strategy<Value = PublicKey> {
        "[a-zA-Z0-9]{1,32}".prop_map(|s| PublicKey::new(s))
    }

    fn arb_private_key() -> impl Strategy<Value = PrivateKey> {
        "[a-zA-Z0-9]{1,32}".prop_map(|s| PrivateKey::new(s))
    }

    fn arb_amount() -> impl Strategy<Value = u64> {
        prop_oneof![
            0u64..=1000,      // Small amounts
            1000u64..=100000, // Medium amounts
            100000u64..=u64::MAX, // Large amounts
        ]
    }

    fn arb_nonce() -> impl Strategy<Value = u64> {
        any::<u64>()
    }

    fn arb_fee() -> impl Strategy<Value = u64> {
        prop_oneof![
            0u64..=100,     // Zero to small fees
            100u64..=1000,  // Medium fees
        ]
    }

    fn arb_transaction() -> impl Strategy<Value = Transaction> {
        (arb_public_key(), arb_public_key(), arb_amount(), arb_fee(), arb_nonce())
            .prop_map(|(sender, receiver, amount, fee, nonce)| {
                Transaction::new(sender, receiver, amount, fee, nonce)
            })
    }

    fn arb_signed_transaction() -> impl Strategy<Value = Transaction> {
        (arb_public_key(), arb_public_key(), arb_amount(), arb_fee(), arb_nonce(), arb_private_key())
            .prop_map(|(sender, receiver, amount, fee, nonce, private_key)| {
                let mut tx = Transaction::new(sender, receiver, amount, fee, nonce);
                let _ = tx.sign(&private_key); // Ignore result for fuzzing
                tx
            })
    }

    fn arb_block() -> impl Strategy<Value = Block> {
        (any::<u64>(), arb_public_key()).prop_map(|(height, validator)| {
            Block::new(Hash::new(b"genesis"), height, vec![], validator)
        })
    }

    proptest! {
        #[test]
        fn test_transaction_hash_consistency(tx in arb_transaction()) {
            let hash1 = tx.calculate_hash();
            let hash2 = tx.calculate_hash();
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_transaction_signing_roundtrip(sender in arb_public_key(), receiver in arb_public_key(), amount in arb_amount(), fee in arb_fee(), nonce in arb_nonce()) {
            let (actual_sender, private_key) = Transaction::generate_keypair();

            // Create transaction with generated sender
            let mut tx = Transaction::new(actual_sender, receiver, amount, fee, nonce);

            // Sign and verify
            let sign_result = tx.sign(&private_key);
            prop_assert!(sign_result.is_ok(), "Transaction signing should succeed");

            let verify_result = tx.verify();
            prop_assert!(verify_result.is_ok(), "Transaction verification should succeed");
            prop_assert!(verify_result.unwrap(), "Transaction should be valid");
        }

        #[test]
        fn test_transaction_with_pq_signing(sender in arb_public_key(), receiver in arb_public_key(), amount in arb_amount(), fee in arb_fee(), nonce in arb_nonce()) {
            let pq_result = Transaction::generate_keypair_with_pq();
            prop_assert!(pq_result.is_ok(), "PQ keypair generation should succeed");

            let (actual_sender, private_key) = pq_result.unwrap();

            // Create transaction with PQ sender
            let mut tx = Transaction::new(actual_sender, receiver, amount, fee, nonce);

            // Sign and verify
            let sign_result = tx.sign(&private_key);
            prop_assert!(sign_result.is_ok(), "PQ transaction signing should succeed");

            let verify_result = tx.verify();
            prop_assert!(verify_result.is_ok(), "PQ transaction verification should succeed");
            prop_assert!(verify_result.unwrap(), "PQ transaction should be valid");
        }

        #[test]
        fn test_block_hash_consistency(block in arb_block()) {
            let hash1 = block.hash();
            let hash2 = block.hash();
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_block_signing_roundtrip(height in any::<u64>(), validator in arb_public_key()) {
            let private_key = PrivateKey::new("test_key".to_string());

            let mut block = Block::new(Hash::new(b"genesis"), height, vec![], validator);

            // Sign and verify
            let sign_result = block.sign(&private_key);
            prop_assert!(sign_result.is_ok(), "Block signing should succeed");

            let verify_result = block.verify();
            prop_assert!(verify_result.is_ok(), "Block verification should succeed");
            prop_assert!(verify_result.unwrap(), "Block should be valid");
        }

        #[test]
        fn test_state_transaction_application(tx in arb_transaction()) {
            let mut state = State::new();

            let result = state.apply_transaction(&tx);
            prop_assert!(result.is_ok(), "Transaction application should succeed");

            // Check that sender balance decreased and receiver balance increased
            let sender_balance = state.accounts.get(&tx.sender).cloned().unwrap_or(0);
            let receiver_balance = state.accounts.get(&tx.receiver).cloned().unwrap_or(0);

            // In simple state, sender balance goes negative
            prop_assert!(sender_balance <= 0, "Sender balance should be negative or zero");
            prop_assert_eq!(receiver_balance as i128, tx.amount as i128, "Receiver should get the amount");
        }

        #[test]
        fn test_state_block_application(height in 1..u64::MAX) {
            let mut state = State::new();
            let validator = PublicKey::new("validator".to_string());
            let private_key = PrivateKey::new("validator_key".to_string());

            let mut block = Block::new(state.last_block_hash, height, vec![], validator);
            block.sign(&private_key).unwrap();

            let result = state.apply_block(&block);
            prop_assert!(result.is_ok(), "Block application should succeed");
            prop_assert_eq!(state.height, height, "State height should be updated");
            prop_assert_eq!(state.last_block_hash, block.hash(), "Last block hash should be updated");
        }

        #[test]
        fn test_hash_different_inputs_give_different_outputs(
            data1 in prop::collection::vec(any::<u8>(), 1..100),
            data2 in prop::collection::vec(any::<u8>(), 1..100)
        ) {
            // Ensure different inputs give different hashes (with very high probability)
            let hash1 = Hash::new(&data1);
            let hash2 = Hash::new(&data2);

            // If inputs are different, hashes should be different (birthday paradox is negligible here)
            if data1 != data2 {
                prop_assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
            } else {
                prop_assert_eq!(hash1, hash2, "Same inputs should produce same hashes");
            }
        }

        #[test]
        fn test_public_key_backward_compatibility(key_str in "[a-zA-Z0-9]{1,64}") {
            let key = PublicKey::new(key_str.clone());
            prop_assert_eq!(key.ed25519_key.len(), 32, "Ed25519 key should be 32 bytes");
            prop_assert!(key.pq_key.is_none(), "Should not have PQ key by default");
            prop_assert!(!key.has_pq_key(), "Should report no PQ key");
        }

        #[test]
        fn test_public_key_with_pq_compatibility(key_str in "[a-zA-Z0-9]{1,32}") {
            let result = PublicKey::new_with_pq(key_str);
            prop_assert!(result.is_ok(), "PQ public key creation should succeed");

            let key = result.unwrap();
            prop_assert_eq!(key.ed25519_key.len(), 32, "Ed25519 key should be 32 bytes");
            prop_assert!(key.pq_key.is_some(), "Should have PQ key");
            prop_assert!(key.has_pq_key(), "Should report having PQ key");
        }

        #[test]
        fn test_private_key_backward_compatibility(key_str in "[a-zA-Z0-9]{1,64}") {
            let key = PrivateKey::new(key_str.clone());
            prop_assert_eq!(key.ed25519_key.len(), 32, "Ed25519 key should be 32 bytes");
            prop_assert!(key.pq_key.is_none(), "Should not have PQ key by default");
            prop_assert!(!key.has_pq_key(), "Should report no PQ key");
        }

        #[test]
        fn test_private_key_with_pq_compatibility(key_str in "[a-zA-Z0-9]{1,32}") {
            let result = PrivateKey::new_with_pq(key_str);
            prop_assert!(result.is_ok(), "PQ private key creation should succeed");

            let key = result.unwrap();
            prop_assert_eq!(key.ed25519_key.len(), 32, "Ed25519 key should be 32 bytes");
            prop_assert!(key.pq_key.is_some(), "Should have PQ key");
            prop_assert!(key.has_pq_key(), "Should report having PQ key");
        }

        #[test]
        fn test_transaction_with_large_amounts(amount in 1000000000000u64..u64::MAX) {
            let sender = PublicKey::new("sender".to_string());
            let receiver = PublicKey::new("receiver".to_string());

            let tx = Transaction::new(sender, receiver, amount, 0, 0);

            let mut state = State::new();
            let result = state.apply_transaction(&tx);
            prop_assert!(result.is_ok(), "Large amount transactions should be handled");

            let receiver_balance = state.accounts.get(&tx.receiver).cloned().unwrap_or(0);
            prop_assert_eq!(receiver_balance, amount, "Large amounts should be stored correctly");
        }

        #[test]
        fn test_transaction_with_zero_amount() {
            let sender = PublicKey::new("sender".to_string());
            let receiver = PublicKey::new("receiver".to_string());

            let tx = Transaction::new(sender.clone(), receiver.clone(), 0, 0, 0);

            let mut state = State::new();
            let result = state.apply_transaction(&tx);
            prop_assert!(result.is_ok(), "Zero amount transactions should be allowed");

            let sender_balance = state.accounts.get(&tx.sender).cloned().unwrap_or(0);
            let receiver_balance = state.accounts.get(&tx.receiver).cloned().unwrap_or(0);

            prop_assert_eq!(sender_balance, 0, "Sender balance should be unchanged");
            prop_assert_eq!(receiver_balance, 0, "Receiver balance should be unchanged");
        }

        #[test]
        fn test_block_with_many_transactions(num_txs in 1..50usize) {
            let validator = PublicKey::new("validator".to_string());
            let private_key = PrivateKey::new("validator_key".to_string());

            // Create multiple transactions
            let mut transactions = vec![];
            for i in 0..num_txs {
                let sender = PublicKey::new(format!("sender{}", i));
                let receiver = PublicKey::new(format!("receiver{}", i));
                transactions.push(Transaction::new(sender, receiver, 100, 0, i as u64));
            }

            let mut block = Block::new(Hash::new(b"genesis"), 1, transactions, validator);
            let sign_result = block.sign(&private_key);
            prop_assert!(sign_result.is_ok(), "Block with many transactions should sign successfully");

            let verify_result = block.verify();
            prop_assert!(verify_result.is_ok(), "Block with many transactions should verify successfully");
            prop_assert!(verify_result.unwrap(), "Block should be valid");
        }

        #[test]
        fn test_state_with_many_accounts(num_accounts in 10..100usize) {
            let mut state = State::new();

            // Add many accounts with random balances
            for i in 0..num_accounts {
                let pub_key = PublicKey::new(format!("account{}", i));
                let balance = (i as u64) * 100;
                state.accounts.insert(pub_key, balance);
            }

            prop_assert_eq!(state.accounts.len(), num_accounts, "Should have correct number of accounts");

            // Verify all balances are stored correctly
            for i in 0..num_accounts {
                let pub_key = PublicKey::new(format!("account{}", i));
                let expected_balance = (i as u64) * 100;
                let actual_balance = state.accounts.get(&pub_key).cloned().unwrap_or(0);
                prop_assert_eq!(actual_balance, expected_balance, "Balance should be stored correctly");
            }
        }

        #[test]
        fn test_transaction_fee_logic(fee in arb_fee(), amount in arb_amount()) {
            let sender = PublicKey::new("sender".to_string());
            let receiver = PublicKey::new("receiver".to_string());

            let tx = Transaction::new_with_fee(sender, receiver, amount, fee, 0);

            prop_assert_eq!(tx.amount, amount, "Amount should be set correctly");
            prop_assert_eq!(tx.fee, fee, "Fee should be set correctly");

            // Transaction hash should include fee
            let hash1 = tx.calculate_hash();
            let hash2 = tx.calculate_hash();
            prop_assert_eq!(hash1, hash2, "Hash should be consistent with fee");
        }

        #[test]
        fn test_merkle_root_calculation(
            tx_count in 1..20usize
        ) {
            // Create random transactions
            let mut transactions = vec![];
            for i in 0..tx_count {
                let sender = PublicKey::new(format!("sender{}", i));
                let receiver = PublicKey::new(format!("receiver{}", i));
                transactions.push(Transaction::new(sender, receiver, 100, 0, i as u64));
            }

            let root1 = Block::calculate_simple_merkle(&transactions);
            let root2 = Block::calculate_simple_merkle(&transactions);

            prop_assert_eq!(root1, root2, "Merkle root should be consistent");

            // Empty block should have different root
            let empty_root = Block::calculate_simple_merkle(&[]);
            if !transactions.is_empty() {
                prop_assert_ne!(root1, empty_root, "Non-empty block should have different root than empty");
            }
        }

        #[test]
        fn test_storage_transaction_operations(tx in arb_signed_transaction()) {
            let temp_dir = TempDir::new().unwrap();
            let storage = Storage::new(temp_dir.path()).unwrap();

            // Store transaction synchronously for property testing
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let store_result = storage.store_transaction(&tx).await;
                prop_assert!(store_result.is_ok(), "Transaction storage should succeed");

                let retrieve_result = storage.get_transaction(&tx.id).await;
                prop_assert!(retrieve_result.is_ok(), "Transaction retrieval should succeed");

                let retrieved = retrieve_result.unwrap();
                prop_assert!(retrieved.is_some(), "Transaction should be found");
                prop_assert_eq!(retrieved.unwrap().id, tx.id, "Retrieved transaction should match");
            });
        }

        #[test]
        fn test_storage_block_operations(height in 1..1000u64) {
            let validator = PublicKey::new("validator".to_string());
            let private_key = PrivateKey::new("validator_key".to_string());
            let mut block = Block::new(Hash::new(b"genesis"), height, vec![], validator);
            block.sign(&private_key).unwrap();

            let temp_dir = TempDir::new().unwrap();
            let storage = Storage::new(temp_dir.path()).unwrap();

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let store_result = storage.store_block(&block).await;
                prop_assert!(store_result.is_ok(), "Block storage should succeed");

                let retrieve_by_hash_result = storage.get_block(&block.hash()).await;
                prop_assert!(retrieve_by_hash_result.is_ok(), "Block retrieval by hash should succeed");
                prop_assert!(retrieve_by_hash_result.unwrap().is_some(), "Block should be found by hash");

                let retrieve_by_height_result = storage.get_block_by_height(height).await;
                prop_assert!(retrieve_by_height_result.is_ok(), "Block retrieval by height should succeed");
                prop_assert!(retrieve_by_height_result.unwrap().is_some(), "Block should be found by height");
            });
        }

        #[test]
        fn test_network_request_serialization(request in prop_oneof![
            Just(crate::network::NetworkRequest::Ping),
            arb_public_key().prop_map(|pk| crate::network::NetworkRequest::GetNodeInfo),
        ]) {
            // Test that requests can be serialized and deserialized
            let serialized = serde_json::to_string(&request);
            prop_assert!(serialized.is_ok(), "Request serialization should succeed");

            let deserialized: Result<crate::network::NetworkRequest, _> = serde_json::from_str(&serialized.unwrap());
            prop_assert!(deserialized.is_ok(), "Request deserialization should succeed");
            prop_assert_eq!(request, deserialized.unwrap(), "Roundtrip should preserve request");
        }

        #[test]
        fn test_network_response_serialization(response in prop_oneof![
            Just(crate::network::NetworkResponse::Pong),
        ]) {
            // Test that responses can be serialized and deserialized
            let serialized = serde_json::to_string(&response);
            prop_assert!(serialized.is_ok(), "Response serialization should succeed");

            let deserialized: Result<crate::network::NetworkResponse, _> = serde_json::from_str(&serialized.unwrap());
            prop_assert!(deserialized.is_ok(), "Response deserialization should succeed");
            prop_assert_eq!(response, deserialized.unwrap(), "Roundtrip should preserve response");
        }
    }

    // Fuzz-like tests for edge cases
    #[test]
    fn test_extreme_values() {
        // Test with maximum values
        let max_tx = Transaction::new(
            PublicKey::new("max_sender".to_string()),
            PublicKey::new("max_receiver".to_string()),
            u64::MAX,
            u64::MAX,
            u64::MAX
        );

        let hash = max_tx.calculate_hash();
        assert_eq!(hash.as_bytes().len(), 32); // Should still produce valid hash

        // Test with empty strings
        let empty_tx = Transaction::new(
            PublicKey::new("".to_string()),
            PublicKey::new("".to_string()),
            0,
            0,
            0
        );

        let empty_hash = empty_tx.calculate_hash();
        assert_eq!(empty_hash.as_bytes().len(), 32);

        // Test state with extreme values
        let mut state = State::new();
        let max_key = PublicKey::new("max_key".to_string());
        state.accounts.insert(max_key.clone(), u64::MAX);
        state.height = u64::MAX;

        assert_eq!(*state.accounts.get(&max_key).unwrap(), u64::MAX);
        assert_eq!(state.height, u64::MAX);
    }

    #[test]
    fn test_memory_safety_under_load() {
        // Test that operations don't cause memory issues under load
        let mut transactions = vec![];

        // Create many transactions
        for i in 0..10000 {
            let tx = Transaction::new(
                PublicKey::new(format!("sender{}", i)),
                PublicKey::new(format!("receiver{}", i)),
                i as u64,
                0,
                i as u64
            );
            transactions.push(tx);
        }

        // Calculate hashes for all transactions
        for tx in &transactions {
            let _hash = tx.calculate_hash();
        }

        // Apply all transactions to state
        let mut state = State::new();
        for tx in &transactions {
            state.apply_transaction(tx).unwrap();
        }

        // Verify final state
        assert_eq!(state.accounts.len(), 20000); // 10000 senders + 10000 receivers
    }

    #[test]
    fn test_concurrent_hash_calculation() {
        use std::sync::Arc;
        use std::thread;

        let transactions: Vec<_> = (0..1000).map(|i| {
            Arc::new(Transaction::new(
                PublicKey::new(format!("sender{}", i)),
                PublicKey::new(format!("receiver{}", i)),
                i as u64,
                0,
                i as u64
            ))
        }).collect();

        let mut handles = vec![];

        // Spawn threads that calculate hashes concurrently
        for _ in 0..10 {
            let txs = transactions.clone();
            let handle = thread::spawn(move || {
                for tx in txs {
                    let _hash = tx.calculate_hash();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
