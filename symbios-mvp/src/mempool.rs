use std::collections::{HashSet, VecDeque};
use async_trait::async_trait;
use crate::types::{Transaction, Hash};
use crate::storage::{Storage, StorageTrait};

/// Mempool trait for transaction management
#[async_trait]
pub trait MempoolTrait {
    async fn add_transaction(&mut self, tx: Transaction) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_pending_transactions(&self, limit: usize) -> Result<Vec<Transaction>, Box<dyn std::error::Error>>;
    async fn remove_transaction(&mut self, hash: &Hash) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_transaction_count(&self) -> usize;
    async fn clear(&mut self) -> Result<(), Box<dyn std::error::Error>>;
}

/// Simple FIFO mempool implementation
pub struct Mempool {
    storage: Storage,
    pending_txs: VecDeque<Transaction>,
    seen_txs: HashSet<Hash>,
    max_size: usize,
}

impl Mempool {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            max_size: 10000, // Configurable limit
        }
    }

    /// Basic transaction validation
    fn validate_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        // Check if transaction is already seen
        if self.seen_txs.contains(&tx.id) {
            return Err("Transaction already in mempool".into());
        }

        // Basic validation
        if tx.amount == 0 {
            return Err("Transaction amount must be greater than 0".into());
        }

        if tx.sender == tx.receiver {
            return Err("Sender and receiver cannot be the same".into());
        }

        // Verify Ed25519 signature
        if !tx.verify()? {
            return Err("Invalid transaction signature".into());
        }

        Ok(())
    }

    /// Check if mempool is at capacity
    fn is_full(&self) -> bool {
        self.pending_txs.len() >= self.max_size
    }

    /// Remove oldest transactions if mempool is full (simple FIFO eviction)
    fn evict_if_needed(&mut self) {
        while self.is_full() && !self.pending_txs.is_empty() {
            if let Some(oldest_tx) = self.pending_txs.pop_front() {
                self.seen_txs.remove(&oldest_tx.id);
            }
        }
    }
}

#[async_trait]
impl MempoolTrait for Mempool {
    async fn add_transaction(&mut self, tx: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        // Validate transaction
        self.validate_transaction(&tx)?;

        // Create a basic receipt for the transaction
        let receipt = crate::state_machine::TransactionReceipt {
            tx_hash: tx.id.clone(),
            block_hash: Hash::new(b"pending"),
            block_height: 0,
            gas_used: 21000,
            gas_price: tx.fee,
            status: crate::state_machine::ExecutionStatus::Success,
            logs: vec![],
            contract_address: None,
        };

        // Store transaction receipt persistently
        self.storage.store_transaction_receipt(&receipt).await?;

        // Evict old transactions if needed
        self.evict_if_needed();

        // Add to in-memory pool
        self.pending_txs.push_back(tx.clone());
        self.seen_txs.insert(tx.id);

        Ok(())
    }

    async fn get_pending_transactions(&self, limit: usize) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        let count = std::cmp::min(limit, self.pending_txs.len());
        let transactions: Vec<Transaction> = self.pending_txs
            .iter()
            .take(count)
            .cloned()
            .collect();

        Ok(transactions)
    }

    async fn remove_transaction(&mut self, hash: &Hash) -> Result<(), Box<dyn std::error::Error>> {
        // Remove from pending queue
        self.pending_txs.retain(|tx| tx.id != *hash);

        // Remove from seen set
        self.seen_txs.remove(hash);

        Ok(())
    }

    async fn get_transaction_count(&self) -> usize {
        self.pending_txs.len()
    }

    async fn clear(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.pending_txs.clear();
        self.seen_txs.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PublicKey, PrivateKey};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_add_valid_transaction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        let mut mempool = Mempool::new(storage);

        let sender = PublicKey(vec![1; 32]);
        let receiver = PublicKey(vec![2; 32]);
        let mut tx = Transaction::new(sender, receiver, 100, 0);
        let private_key = PrivateKey(vec![3; 32]);
        tx.sign(&private_key).unwrap();

        let result = mempool.add_transaction(tx).await;
        assert!(result.is_ok());
        assert_eq!(mempool.get_transaction_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_duplicate_transaction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        let mut mempool = Mempool::new(storage);

        let sender = PublicKey(vec![1; 32]);
        let receiver = PublicKey(vec![2; 32]);
        let mut tx = Transaction::new(sender, receiver, 100, 0);
        let private_key = PrivateKey(vec![3; 32]);
        tx.sign(&private_key).unwrap();

        // Add first time
        mempool.add_transaction(tx.clone()).await.unwrap();
        assert_eq!(mempool.get_transaction_count().await, 1);

        // Try to add duplicate
        let result = mempool.add_transaction(tx).await;
        assert!(result.is_err());
        assert_eq!(mempool.get_transaction_count().await, 1);
    }

    #[tokio::test]
    async fn test_get_pending_transactions() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        let mut mempool = Mempool::new(storage);

        let sender = PublicKey(vec![1; 32]);
        let receiver = PublicKey(vec![2; 32]);
        let private_key = PrivateKey(vec![3; 32]);

        // Add multiple transactions
        for i in 0..5 {
            let mut tx = Transaction::new(sender.clone(), receiver.clone(), 100 + i, i as u64);
            tx.sign(&private_key).unwrap();
            mempool.add_transaction(tx).await.unwrap();
        }

        let pending = mempool.get_pending_transactions(3).await.unwrap();
        assert_eq!(pending.len(), 3);

        let all_pending = mempool.get_pending_transactions(10).await.unwrap();
        assert_eq!(all_pending.len(), 5);
    }
}

