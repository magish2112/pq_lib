//! Minimal Storage Engine for Resource-Constrained Environments
//!
//! This module implements a lightweight, efficient storage system designed to
//! work on minimal hardware while maintaining good performance.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;
use crate::types::{Transaction, Block, State, Hash};

/// Storage entry types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum EntryType {
    Transaction,
    Block,
    State,
    TransactionReceipt,
}

/// Storage entry with metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StorageEntry {
    entry_type: EntryType,
    key: Vec<u8>,
    data: Vec<u8>,
    timestamp: u64,
    checksum: u32,
}

impl StorageEntry {
    fn new(entry_type: EntryType, key: Vec<u8>, data: Vec<u8>) -> Self {
        // Use deterministic timestamp for testing/reproducibility
        // In production, this should be provided by the caller
        let timestamp = 0u64;

        let checksum = Self::calculate_checksum(&data);

        Self {
            entry_type,
            key,
            data,
            timestamp,
            checksum,
        }
    }

    fn calculate_checksum(data: &[u8]) -> u32 {
        // Simple checksum for data integrity
        let mut checksum: u32 = 0;
        for (i, &byte) in data.iter().enumerate() {
            checksum ^= (byte as u32) << (i % 4 * 8);
        }
        checksum
    }

    fn verify_checksum(&self) -> bool {
        Self::calculate_checksum(&self.data) == self.checksum
    }
}

/// Minimal storage engine
pub struct MinimalStorage {
    file: Arc<RwLock<File>>,
    index: Arc<RwLock<HashMap<Vec<u8>, u64>>>, // key -> file position
    path: PathBuf,
    max_file_size: u64, // Maximum file size before rotation
    current_size: Arc<RwLock<u64>>,
}

impl MinimalStorage {
    pub fn new<P: AsRef<Path>>(path: P, max_file_size_mb: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref().to_path_buf();

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let mut storage = Self {
            file: Arc::new(RwLock::new(file)),
            index: Arc::new(RwLock::new(HashMap::new())),
            path,
            max_file_size: (max_file_size_mb * 1024 * 1024) as u64,
            current_size: Arc::new(RwLock::new(0)),
        };

        // Load existing index
        storage.load_index()?;

        Ok(storage)
    }

    /// Load index from file
    fn load_index(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = self.file.try_write().unwrap();
        let file_size = file.metadata()?.len();

        if file_size == 0 {
            return Ok(());
        }

        file.seek(SeekFrom::Start(0))?;

        let mut pos = 0u64;
        let mut index = HashMap::new();

        while pos < file_size {
            // Read entry size
            let mut size_buf = [0u8; 8];
            if file.read_exact(&mut size_buf).is_err() {
                break; // End of file or corrupted
            }
            let entry_size = u64::from_le_bytes(size_buf);

            // Read entry
            let mut entry_buf = vec![0u8; entry_size as usize];
            if file.read_exact(&mut entry_buf).is_err() {
                break;
            }

            match bincode::deserialize::<StorageEntry>(&entry_buf) {
                Ok(entry) => {
                    if entry.verify_checksum() {
                        index.insert(entry.key, pos);
                    }
                }
                Err(_) => {
                    log::warn!("Corrupted entry at position {}", pos);
                }
            }

            pos += 8 + entry_size;
        }

        *self.current_size.try_write().unwrap() = pos;
        *self.index.try_write().unwrap() = index;

        Ok(())
    }

    /// Store entry to file
    async fn store_entry(&self, entry: StorageEntry) -> Result<(), Box<dyn std::error::Error>> {
        let entry_data = bincode::serialize(&entry)?;
        let entry_size = entry_data.len() as u64;
        let total_size = 8 + entry_size; // 8 bytes for size + entry data

        // Check if we need to rotate file
        let current_size = *self.current_size.read().await;
        if current_size + total_size > self.max_file_size {
            self.rotate_file().await?;
        }

        let mut file = self.file.write().await;
        let pos = file.seek(SeekFrom::End(0))?;

        // Write entry size
        file.write_all(&entry_size.to_le_bytes())?;

        // Write entry data
        file.write_all(&entry_data)?;

        // Update index
        {
            let mut index = self.index.write().await;
            index.insert(entry.key, pos);
        }

        // Update current size
        {
            let mut size = self.current_size.write().await;
            *size += total_size;
        }

        file.flush()?;
        // fsync for durability - ensure data is written to disk
        file.sync_data()?;
        Ok(())
    }

    /// Rotate storage file when it gets too large
    async fn rotate_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create backup
        let backup_path = self.path.with_extension("bak");
        std::fs::copy(&self.path, &backup_path)?;

        // Truncate current file
        {
            let mut file = self.file.write().await;
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
        }

        // Clear index and size
        {
            let mut index = self.index.write().await;
            index.clear();
        }
        {
            let mut size = self.current_size.write().await;
            *size = 0;
        }

        log::info!("Storage file rotated, backup created at {:?}", backup_path);
        Ok(())
    }

    /// Retrieve entry from file
    async fn retrieve_entry(&self, key: &[u8]) -> Result<Option<StorageEntry>, Box<dyn std::error::Error>> {
        let pos = {
            let index = self.index.read().await;
            match index.get(key) {
                Some(&pos) => pos,
                None => return Ok(None),
            }
        };

        let mut file = self.file.write().await;
        file.seek(SeekFrom::Start(pos))?;

        // Read entry size
        let mut size_buf = [0u8; 8];
        file.read_exact(&mut size_buf)?;
        let entry_size = u64::from_le_bytes(size_buf);

        // Read entry data
        let mut entry_buf = vec![0u8; entry_size as usize];
        file.read_exact(&mut entry_buf)?;

        let entry: StorageEntry = bincode::deserialize(&entry_buf)?;
        if entry.verify_checksum() {
            Ok(Some(entry))
        } else {
            Err("Data corruption detected".into())
        }
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> StorageStats {
        let index = self.index.read().await;
        let current_size = *self.current_size.read().await;

        StorageStats {
            total_entries: index.len(),
            file_size: current_size,
            max_file_size: self.max_file_size,
            fragmentation_ratio: current_size as f64 / self.max_file_size as f64,
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_entries: usize,
    pub file_size: u64,
    pub max_file_size: u64,
    pub fragmentation_ratio: f64,
}

#[async_trait]
impl crate::storage::StorageTrait for MinimalStorage {
    async fn store_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("tx_{}", hex::encode(&tx.id.as_bytes()[..8])).into_bytes();
        let data = bincode::serialize(tx)?;
        let entry = StorageEntry::new(EntryType::Transaction, key, data);
        self.store_entry(entry).await
    }

    async fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Box<dyn std::error::Error>> {
        let key = format!("tx_{}", hex::encode(&hash.as_bytes()[..8])).into_bytes();
        match self.retrieve_entry(key.as_slice()).await? {
            Some(entry) => {
                let tx: Transaction = bincode::deserialize(&entry.data)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    async fn store_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("block_{}", hex::encode(&block.hash().as_bytes()[..8])).into_bytes();
        let data = bincode::serialize(block)?;
        let entry = StorageEntry::new(EntryType::Block, key, data);

        self.store_entry(entry).await?;

        // Also store height mapping
        let height_key = format!("height_{}", block.header.height).into_bytes();
        let height_data = bincode::serialize(&block.hash())?;
        let height_entry = StorageEntry::new(EntryType::Block, height_key, height_data);
        self.store_entry(height_entry).await?;

        // Store as latest block
        let latest_key = b"latest_block";
        let latest_data = bincode::serialize(&block.hash())?;
        let latest_entry = StorageEntry::new(EntryType::Block, latest_key.to_vec(), latest_data);
        self.store_entry(latest_entry).await
    }

    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let key = format!("block_{}", hex::encode(&hash.as_bytes()[..8])).into_bytes();
        match self.retrieve_entry(key.as_slice()).await? {
            Some(entry) => {
                let block: Block = bincode::deserialize(&entry.data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let height_key = format!("height_{}", height).into_bytes();
        match self.retrieve_entry(&height_key).await? {
            Some(entry) => {
                let block_hash: Hash = bincode::deserialize(&entry.data)?;
                self.get_block(&block_hash).await
            }
            None => Ok(None),
        }
    }

    async fn get_latest_block(&self) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let latest_key = b"latest_block";
        match self.retrieve_entry(latest_key).await? {
            Some(entry) => {
                let block_hash: Hash = bincode::deserialize(&entry.data)?;
                self.get_block(&block_hash).await
            }
            None => Ok(None),
        }
    }

    async fn store_state(&self, state: &State) -> Result<(), Box<dyn std::error::Error>> {
        let key = b"current_state";
        let data = bincode::serialize(state)?;
        let entry = StorageEntry::new(EntryType::State, key.to_vec(), data);
        self.store_entry(entry).await
    }

    async fn get_state(&self) -> Result<State, Box<dyn std::error::Error>> {
        let key = b"current_state";
        match self.retrieve_entry(key.as_slice()).await? {
            Some(entry) => {
                let state: State = bincode::deserialize(&entry.data)?;
                Ok(state)
            }
            None => Ok(State::new()),
        }
    }

    async fn store_transaction_receipt(&self, receipt: &crate::state_machine::TransactionReceipt) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("receipt_{}", hex::encode(&receipt.tx_hash.as_bytes()[..8])).into_bytes();
        let data = bincode::serialize(receipt)?;
        let entry = StorageEntry::new(EntryType::TransactionReceipt, key, data);
        self.store_entry(entry).await
    }

    async fn get_transaction_receipt(&self, tx_hash: &Hash) -> Result<Option<crate::state_machine::TransactionReceipt>, Box<dyn std::error::Error>> {
        let key = format!("receipt_{}", hex::encode(&tx_hash.as_bytes()[..8])).into_bytes();
        match self.retrieve_entry(key.as_slice()).await? {
            Some(entry) => {
                let receipt: crate::state_machine::TransactionReceipt = bincode::deserialize(&entry.data)?;
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_minimal_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MinimalStorage::new(temp_dir.path().join("test.db"), 10).unwrap();

        let stats = storage.get_stats().await;
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn test_transaction_storage() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MinimalStorage::new(temp_dir.path().join("test.db"), 10).unwrap();

        // Create test transaction
        let sender = crate::types::PublicKey(vec![1; 32]);
        let receiver = crate::types::PublicKey(vec![2; 32]);
        let tx = Transaction::new(sender, receiver, 100, 0);

        // Store transaction
        storage.store_transaction(&tx).await.unwrap();

        // Retrieve transaction
        let retrieved = storage.get_transaction(&tx.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, tx.id);

        let stats = storage.get_stats().await;
        assert_eq!(stats.total_entries, 1);
    }

    #[tokio::test]
    async fn test_block_storage() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MinimalStorage::new(temp_dir.path().join("test.db"), 10).unwrap();

        // Create test block
        let genesis = crate::types::create_genesis_block();
        storage.store_block(&genesis).await.unwrap();

        // Retrieve block
        let retrieved = storage.get_block(&genesis.hash()).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash(), genesis.hash());

        // Retrieve by height
        let by_height = storage.get_block_by_height(0).await.unwrap();
        assert!(by_height.is_some());
        assert_eq!(by_height.unwrap().hash(), genesis.hash());

        // Test latest block
        let latest = storage.get_latest_block().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().hash(), genesis.hash());
    }
}

