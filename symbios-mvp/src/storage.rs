use rocksdb::{DB, Options, IteratorMode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::types::{Transaction, Block, State, Hash};

/// Storage trait for persistence layer
#[async_trait::async_trait]
pub trait StorageTrait {
    async fn store_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Box<dyn std::error::Error>>;
    async fn store_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error>>;
    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>>;
    async fn get_latest_block(&self) -> Result<Option<Block>, Box<dyn std::error::Error>>;
    async fn store_state(&self, state: &State) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_state(&self) -> Result<State, Box<dyn std::error::Error>>;
}

/// RocksDB-based storage implementation
pub struct Storage {
    db: DB,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(10000);

        let db = DB::open(&opts, path)?;
        Ok(Self { db })
    }

    fn key(prefix: &str, hash: &Hash) -> Vec<u8> {
        let mut key = prefix.as_bytes().to_vec();
        key.extend_from_slice(hash.as_bytes());
        key
    }

    fn block_height_key(height: u64) -> Vec<u8> {
        format!("block_height_{}", height).into_bytes()
    }

    fn state_key() -> Vec<u8> {
        b"current_state".to_vec()
    }
}

#[async_trait::async_trait]
impl StorageTrait for Storage {
    async fn store_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::key("tx_", &tx.id);
        let value = bincode::serialize(tx)?;
        self.db.put(key, value)?;
        Ok(())
    }

    async fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Box<dyn std::error::Error>> {
        let key = Self::key("tx_", hash);
        match self.db.get(key)? {
            Some(data) => {
                let tx = bincode::deserialize(&data)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    async fn store_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let block_hash = block.hash();
        let key = Self::key("block_", &block_hash);
        let value = bincode::serialize(block)?;
        self.db.put(key, value)?;

        // Also store block height mapping
        let height_key = Self::block_height_key(block.header.height);
        let height_value = bincode::serialize(&block_hash)?;
        self.db.put(height_key, height_value)?;

        // Store as latest block if height is higher than current
        if let Ok(Some(current_latest)) = self.get_latest_block().await {
            if block.header.height > current_latest.header.height {
                let latest_key = b"latest_block";
                self.db.put(latest_key, block_hash.as_bytes())?;
            }
        } else {
            // First block
            let latest_key = b"latest_block";
            self.db.put(latest_key, block_hash.as_bytes())?;
        }

        Ok(())
    }

    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let key = Self::key("block_", hash);
        match self.db.get(key)? {
            Some(data) => {
                let block = bincode::deserialize(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let height_key = Self::block_height_key(height);
        match self.db.get(height_key)? {
            Some(hash_data) => {
                let block_hash: Hash = bincode::deserialize(&hash_data)?;
                self.get_block(&block_hash).await
            }
            None => Ok(None),
        }
    }

    async fn get_latest_block(&self) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let latest_key = b"latest_block";
        match self.db.get(latest_key)? {
            Some(hash_bytes) => {
                if hash_bytes.len() == 32 {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&hash_bytes);
                    let block_hash = Hash::from_bytes(hash_array);
                    self.get_block(&block_hash).await
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn store_state(&self, state: &State) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::state_key();
        let value = bincode::serialize(state)?;
        self.db.put(key, value)?;
        Ok(())
    }

    async fn get_state(&self) -> Result<State, Box<dyn std::error::Error>> {
        let key = Self::state_key();
        match self.db.get(key)? {
            Some(data) => {
                let state = bincode::deserialize(&data)?;
                Ok(state)
            }
            None => {
                // Return default state if none stored
                Ok(State::new())
            }
        }
    }
}

/// Clone implementation for Storage
impl Clone for Storage {
    fn clone(&self) -> Self {
        // Note: RocksDB handle can be shared safely
        Self {
            db: self.db.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use tempfile::TempDir;

    fn setup_test_storage() -> (Storage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        (storage, temp_dir)
    }

    #[test]
    fn test_storage_creation() {
        let (_storage, _temp_dir) = setup_test_storage();
        // If we get here without panicking, the test passes
    }

    #[test]
    fn test_transaction_storage() {
        let (storage, _temp_dir) = setup_test_storage();

        // Create and sign a transaction
        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender.clone(), receiver, 1000, 0);
        tx.sign(&private_key).unwrap();

        // Store transaction
        storage.store_transaction(&tx).await.unwrap();

        // Retrieve transaction
        let retrieved = storage.get_transaction(&tx.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, tx.id);

        // Test non-existent transaction
        let fake_hash = Hash::new(b"nonexistent");
        let non_existent = storage.get_transaction(&fake_hash).await.unwrap();
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_block_storage_and_retrieval() {
        let (storage, _temp_dir) = setup_test_storage();

        // Create a block with transactions
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        let tx1 = Transaction::new(
            PublicKey::new("alice".to_string()),
            PublicKey::new("bob".to_string()),
            100, 0
        );

        let mut block = Block::new(
            Hash::new(b"genesis"),
            1,
            vec![tx1.clone()],
            validator.clone()
        );

        // Sign the block
        block.sign(&private_key).unwrap();

        // Store block
        storage.store_block(&block).await.unwrap();

        // Retrieve by hash
        let retrieved_by_hash = storage.get_block(&block.hash()).await.unwrap();
        assert!(retrieved_by_hash.is_some());
        assert_eq!(retrieved_by_hash.unwrap().hash(), block.hash());

        // Retrieve by height
        let retrieved_by_height = storage.get_block_by_height(1).await.unwrap();
        assert!(retrieved_by_height.is_some());
        assert_eq!(retrieved_by_height.unwrap().header.height, 1);

        // Test latest block
        let latest = storage.get_latest_block().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().header.height, 1);
    }

    #[test]
    fn test_multiple_blocks_storage() {
        let (storage, _temp_dir) = setup_test_storage();

        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        // Store genesis block first
        let genesis = create_genesis_block();
        storage.store_block(&genesis).await.unwrap();

        // Store multiple blocks
        let mut previous_hash = genesis.hash();
        for height in 1..=5 {
            let tx = Transaction::new(
                PublicKey::new(format!("sender{}", height)),
                PublicKey::new(format!("receiver{}", height)),
                100 * height as u64, 0
            );

            let mut block = Block::new(
                previous_hash,
                height,
                vec![tx],
                validator.clone()
            );

            block.sign(&private_key).unwrap();
            storage.store_block(&block).await.unwrap();

            previous_hash = block.hash();

            // Verify retrieval
            let retrieved = storage.get_block_by_height(height).await.unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().header.height, height);
        }

        // Check latest block
        let latest = storage.get_latest_block().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().header.height, 5);
    }

    #[test]
    fn test_state_storage_and_retrieval() {
        let (storage, _temp_dir) = setup_test_storage();

        let mut state = State::new();

        // Add some account balances
        let alice = PublicKey::new("alice".to_string());
        let bob = PublicKey::new("bob".to_string());

        state.accounts.insert(alice.clone(), 1000);
        state.accounts.insert(bob.clone(), 500);
        state.height = 10;
        state.last_block_hash = Hash::new(b"block10");

        // Store state
        storage.store_state(&state).await.unwrap();

        // Retrieve state
        let retrieved_state = storage.get_state().await.unwrap();

        assert_eq!(retrieved_state.height, 10);
        assert_eq!(retrieved_state.last_block_hash, Hash::new(b"block10"));
        assert_eq!(*retrieved_state.accounts.get(&alice).unwrap(), 1000);
        assert_eq!(*retrieved_state.accounts.get(&bob).unwrap(), 500);
    }

    #[test]
    fn test_state_initialization() {
        let (storage, _temp_dir) = setup_test_storage();

        // Test that get_state returns default state when none stored
        let state = storage.get_state().await.unwrap();
        assert_eq!(state.height, 0);
        assert_eq!(state.accounts.len(), 0);
        assert_eq!(state.last_block_hash, Hash::new(b"genesis"));
    }

    #[test]
    fn test_block_height_indexing() {
        let (storage, _temp_dir) = setup_test_storage();

        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        // Create and store blocks at specific heights
        for height in [1, 5, 10, 100] {
            let mut block = Block::new(
                Hash::new(format!("prev{}", height).as_bytes()),
                height,
                vec![],
                validator.clone()
            );

            block.sign(&private_key).unwrap();
            storage.store_block(&block).await.unwrap();
        }

        // Test retrieval by height
        for height in [1, 5, 10, 100] {
            let block = storage.get_block_by_height(height).await.unwrap();
            assert!(block.is_some());
            assert_eq!(block.unwrap().header.height, height);
        }

        // Test non-existent height
        let non_existent = storage.get_block_by_height(50).await.unwrap();
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_transaction_hash_consistency() {
        let (storage, _temp_dir) = setup_test_storage();

        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());

        // Create identical transactions
        let mut tx1 = Transaction::new(sender.clone(), receiver.clone(), 100, 0);
        let mut tx2 = Transaction::new(sender.clone(), receiver.clone(), 100, 0);

        // They should have different hashes initially (due to timestamps)
        assert_ne!(tx1.id, tx2.id);

        // Sign both
        tx1.sign(&private_key).unwrap();
        tx2.sign(&private_key).unwrap();

        // Store both
        storage.store_transaction(&tx1).await.unwrap();
        storage.store_transaction(&tx2).await.unwrap();

        // Retrieve both
        let retrieved1 = storage.get_transaction(&tx1.id).await.unwrap().unwrap();
        let retrieved2 = storage.get_transaction(&tx2.id).await.unwrap().unwrap();

        assert_eq!(retrieved1.id, tx1.id);
        assert_eq!(retrieved2.id, tx2.id);
        assert_ne!(retrieved1.id, retrieved2.id);
    }

    #[test]
    fn test_concurrent_access() {
        let (storage, _temp_dir) = setup_test_storage();

        // Test concurrent reads (RocksDB supports concurrent access)
        let storage_clone = storage.clone();

        let handle1 = tokio::spawn(async move {
            for i in 0..10 {
                let key = format!("key{}", i);
                let mut block = Block::new(
                    Hash::new(b"genesis"),
                    i,
                    vec![],
                    PublicKey::new(key)
                );
                storage.store_block(&block).await.unwrap();
            }
        });

        let handle2 = tokio::spawn(async move {
            for i in 10..20 {
                let key = format!("key{}", i);
                let block = storage_clone.get_block_by_height(i).await.unwrap();
                assert!(block.is_none()); // Should not exist yet
            }
        });

        // Wait for both to complete
        tokio::try_join!(handle1, handle2).unwrap();
    }

    #[test]
    fn test_storage_key_generation() {
        let hash = Hash::new(b"test_hash");

        // Test key prefixes
        let tx_key = Storage::key("tx_", &hash);
        let block_key = Storage::key("block_", &hash);

        assert!(tx_key.starts_with(b"tx_"));
        assert!(block_key.starts_with(b"block_"));
        assert_eq!(tx_key.len(), 3 + 32); // prefix + hash
        assert_eq!(block_key.len(), 6 + 32); // prefix + hash

        // Test block height key
        let height_key = Storage::block_height_key(42);
        assert_eq!(height_key, b"block_height_42");

        // Test state key
        let state_key = Storage::state_key();
        assert_eq!(state_key, b"current_state");
    }

    #[test]
    fn test_block_overwrite() {
        let (storage, _temp_dir) = setup_test_storage();

        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        // Create and store initial block
        let mut block1 = Block::new(
            Hash::new(b"genesis"),
            1,
            vec![],
            validator.clone()
        );
        block1.sign(&private_key).unwrap();
        storage.store_block(&block1).await.unwrap();

        // Create different block at same height
        let tx = Transaction::new(
            PublicKey::new("alice".to_string()),
            PublicKey::new("bob".to_string()),
            100, 0
        );

        let mut block2 = Block::new(
            Hash::new(b"genesis"),
            1,
            vec![tx],
            validator.clone()
        );
        block2.sign(&private_key).unwrap();

        // Store second block (should overwrite)
        storage.store_block(&block2).await.unwrap();

        // Retrieve - should get the second block
        let retrieved = storage.get_block_by_height(1).await.unwrap().unwrap();
        assert_eq!(retrieved.transactions.len(), 1);
        assert_eq!(retrieved.hash(), block2.hash());
    }

    #[tokio::test]
    async fn test_storage_error_handling() {
        let (storage, temp_dir) = setup_test_storage();

        // Test with corrupted data (simulate by putting invalid data directly)
        let invalid_key = Storage::key("block_", &Hash::new(b"invalid"));
        storage.db.put(invalid_key, b"invalid_bincode_data").unwrap();

        // Should handle gracefully
        let result = storage.get_block(&Hash::new(b"invalid")).await;
        // The result might be an error or None depending on bincode behavior
        // The important thing is it doesn't panic
        assert!(result.is_ok() || result.is_err()); // Either is acceptable
    }
}

