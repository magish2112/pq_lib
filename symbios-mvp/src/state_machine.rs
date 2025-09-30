//! Production-Grade State Machine for Symbios Network
//!
//! This module provides a robust, thread-safe state machine implementation
//! with proper transaction validation, state transitions, and atomic operations.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use crate::types::{Transaction, Block, PublicKey, Hash, Address, Amount, Nonce};
use crate::storage::StorageTrait;

/// State machine errors
#[derive(Debug, Clone)]
pub enum StateError {
    InsufficientBalance { account: PublicKey, required: u64, available: u64 },
    AccountNotFound(PublicKey),
    TransactionAlreadyProcessed(Hash),
    InvalidNonce { account: PublicKey, expected: u64, got: u64 },
    InvalidSignature,
    StateCorrupted(String),
    LockPoisoned,
}

/// State machine result type
pub type StateResult<T> = Result<T, StateError>;

/// Account state with nonce tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: Option<Hash>, // For smart contracts (future)
}

impl AccountState {
    pub fn new() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            code_hash: None,
        }
    }

    pub fn can_afford(&self, amount: u64) -> bool {
        self.balance >= amount
    }

    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }
}

/// Transaction receipt for tracking execution results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: Hash,
    pub block_hash: Hash,
    pub block_height: u64,
    pub gas_used: u64,
    pub gas_price: u64,
    pub status: ExecutionStatus,
    pub logs: Vec<LogEntry>,
    pub contract_address: Option<Address>,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
    Failed(String),
    Reverted(String),
}

/// Log entry for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

/// Main state machine structure
pub struct StateMachine<S: StorageTrait> {
    /// Account states with RwLock for thread safety
    accounts: Arc<RwLock<HashMap<PublicKey, AccountState>>>,
    /// Processed transaction hashes to prevent replay attacks
    processed_txs: Arc<RwLock<HashSet<Hash>>>,
    /// Storage backend
    storage: Arc<S>,
    /// Genesis block hash
    genesis_hash: Hash,
    /// Current block height
    height: Arc<RwLock<u64>>,
}

impl<S: StorageTrait> StateMachine<S> {
    /// Create a new state machine
    pub fn new(storage: S, genesis_hash: Hash) -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            processed_txs: Arc::new(RwLock::new(HashSet::new())),
            storage: Arc::new(storage),
            genesis_hash,
            height: Arc::new(RwLock::new(0)),
        }
    }

    /// Get current block height
    pub fn get_height(&self) -> StateResult<u64> {
        self.height.read().map_err(|_| StateError::LockPoisoned).map(|h| *h)
    }

    /// Validate and execute a transaction
    pub fn validate_and_execute_transaction(
        &self,
        tx: &Transaction,
        block_height: u64,
    ) -> StateResult<TransactionReceipt> {
        // Check if transaction was already processed
        if self.is_transaction_processed(&tx.id)? {
            return Err(StateError::TransactionAlreadyProcessed(tx.id));
        }

        // Validate transaction signature
        if !tx.verify().map_err(|_| StateError::InvalidSignature)? {
            return Err(StateError::InvalidSignature);
        }

        // Validate nonce
        self.validate_nonce(tx)?;

        // Validate balance
        self.validate_balance(tx)?;

        // Execute transaction atomically
        let receipt = self.execute_transaction(tx, block_height)?;

        // Mark transaction as processed
        self.mark_transaction_processed(&tx.id)?;

        Ok(receipt)
    }

    /// Validate transaction nonce
    fn validate_nonce(&self, tx: &Transaction) -> StateResult<()> {
        let accounts = self.accounts.read().map_err(|_| StateError::LockPoisoned)?;

        if let Some(account_state) = accounts.get(&tx.sender) {
            if account_state.nonce != tx.nonce {
                return Err(StateError::InvalidNonce {
                    account: tx.sender.clone(),
                    expected: account_state.nonce,
                    got: tx.nonce,
                });
            }
        } else {
            // New account should have nonce 0
            if tx.nonce != 0 {
                return Err(StateError::InvalidNonce {
                    account: tx.sender.clone(),
                    expected: 0,
                    got: tx.nonce,
                });
            }
        }

        Ok(())
    }

    /// Validate transaction balance
    fn validate_balance(&self, tx: &Transaction) -> StateResult<()> {
        let accounts = self.accounts.read().map_err(|_| StateError::LockPoisoned)?;

        if let Some(account_state) = accounts.get(&tx.sender) {
            let total_cost = tx.amount + tx.fee;
            if !account_state.can_afford(total_cost) {
                return Err(StateError::InsufficientBalance {
                    account: tx.sender.clone(),
                    required: total_cost,
                    available: account_state.balance,
                });
            }
        } else {
            // New account cannot send transactions
            return Err(StateError::AccountNotFound(tx.sender.clone()));
        }

        Ok(())
    }

    /// Execute transaction atomically
    fn execute_transaction(
        &self,
        tx: &Transaction,
        block_height: u64,
    ) -> StateResult<TransactionReceipt> {
        let mut accounts = self.accounts.write().map_err(|_| StateError::LockPoisoned)?;
        let mut processed_txs = self.processed_txs.write().map_err(|_| StateError::LockPoisoned)?;

        // Get sender account
        let sender_account = accounts.get_mut(&tx.sender)
            .ok_or_else(|| StateError::AccountNotFound(tx.sender.clone()))?;

        // Get or create receiver account
        let receiver_account = accounts.entry(tx.receiver.clone())
            .or_insert_with(AccountState::new);

        // Calculate total cost (amount + fee)
        let total_cost = tx.amount + tx.fee;

        // Check balance again under write lock
        if !sender_account.can_afford(total_cost) {
            return Err(StateError::InsufficientBalance {
                account: tx.sender.clone(),
                required: total_cost,
                available: sender_account.balance,
            });
        }

        // Execute transfer
        sender_account.balance -= total_cost;
        sender_account.increment_nonce();
        receiver_account.balance += tx.amount;

        // Create receipt
        let receipt = TransactionReceipt {
            tx_hash: tx.id,
            block_hash: Hash::new(&block_height.to_be_bytes()),
            block_height,
            gas_used: 21000, // Standard gas cost for simple transfer
            gas_price: tx.fee,
            status: ExecutionStatus::Success,
            logs: Vec::new(),
            contract_address: None,
        };

        // Store state changes
        self.store_state_changes(&receipt)?;

        Ok(receipt)
    }

    /// Check if transaction was already processed
    fn is_transaction_processed(&self, tx_hash: &Hash) -> StateResult<bool> {
        let processed_txs = self.processed_txs.read().map_err(|_| StateError::LockPoisoned)?;
        Ok(processed_txs.contains(tx_hash))
    }

    /// Mark transaction as processed
    fn mark_transaction_processed(&self, tx_hash: &Hash) -> StateResult<()> {
        let mut processed_txs = self.processed_txs.write().map_err(|_| StateError::LockPoisoned)?;
        processed_txs.insert(tx_hash.clone());
        Ok(())
    }

    /// Store state changes to persistent storage
    fn store_state_changes(&self, receipt: &TransactionReceipt) -> StateResult<()> {
        // Store transaction receipt
        self.storage.store_transaction_receipt(receipt)
            .map_err(|e| StateError::StateCorrupted(format!("Storage error: {}", e)))?;

        Ok(())
    }

    /// Apply a validated block to the state
    pub fn apply_block(&self, block: &Block) -> StateResult<Vec<TransactionReceipt>> {
        let mut receipts = Vec::new();

        // Validate block
        self.validate_block(block)?;

        // Process all transactions in the block
        for tx in &block.transactions {
            let receipt = self.validate_and_execute_transaction(tx, block.height)?;
            receipts.push(receipt);
        }

        // Update block height
        *self.height.write().map_err(|_| StateError::LockPoisoned)? = block.height;

        // Store block
        self.storage.store_block(block)
            .map_err(|e| StateError::StateCorrupted(format!("Storage error: {}", e)))?;

        Ok(receipts)
    }

    /// Validate block integrity
    fn validate_block(&self, block: &Block) -> StateResult<()> {
        // Verify block signature
        if !block.verify().map_err(|_| StateError::InvalidSignature)? {
            return Err(StateError::InvalidSignature);
        }

        // Verify block hash
        let calculated_hash = block.calculate_hash();
        if calculated_hash != block.hash() {
            return Err(StateError::StateCorrupted("Invalid block hash".to_string()));
        }

        // Verify transaction count matches block data
        if block.transactions.len() != block.transaction_count as usize {
            return Err(StateError::StateCorrupted("Transaction count mismatch".to_string()));
        }

        Ok(())
    }

    /// Get account balance
    pub fn get_balance(&self, account: &PublicKey) -> StateResult<u64> {
        let accounts = self.accounts.read().map_err(|_| StateError::LockPoisoned)?;
        Ok(accounts.get(account).map(|a| a.balance).unwrap_or(0))
    }

    /// Get account nonce
    pub fn get_nonce(&self, account: &PublicKey) -> StateResult<u64> {
        let accounts = self.accounts.read().map_err(|_| StateError::LockPoisoned)?;
        Ok(accounts.get(account).map(|a| a.nonce).unwrap_or(0))
    }

    /// Get total supply
    pub fn get_total_supply(&self) -> StateResult<u64> {
        let accounts = self.accounts.read().map_err(|_| StateError::LockPoisoned)?;
        Ok(accounts.values().map(|a| a.balance).sum())
    }

    /// Create genesis state
    pub fn create_genesis(&self, initial_accounts: HashMap<PublicKey, u64>) -> StateResult<()> {
        let mut accounts = self.accounts.write().map_err(|_| StateError::LockPoisoned)?;

        for (account, balance) in initial_accounts {
            accounts.insert(account, AccountState {
                balance,
                nonce: 0,
                code_hash: None,
            });
        }

        Ok(())
    }

    /// Get state root hash (for Merkle tree verification)
    pub fn get_state_root(&self) -> StateResult<Hash> {
        // TODO: Implement proper Merkle tree state root calculation
        let accounts = self.accounts.read().map_err(|_| StateError::LockPoisoned)?;
        let data = bincode::serialize(&*accounts)
            .map_err(|e| StateError::StateCorrupted(format!("Serialization error: {}", e)))?;
        Ok(Hash::new(&data))
    }

    /// Rollback to previous state (for fork resolution)
    pub fn rollback_to_height(&self, target_height: u64) -> StateResult<()> {
        let current_height = self.get_height()?;

        if target_height >= current_height {
            return Ok(()); // Already at or beyond target
        }

        // TODO: Implement state rollback mechanism
        // This would require storing state snapshots at each block height
        Err(StateError::StateCorrupted("Rollback not yet implemented".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use tempfile::TempDir;

    fn create_test_state_machine() -> StateMachine<Storage> {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        let genesis_hash = Hash::new(b"genesis");

        StateMachine::new(storage, genesis_hash)
    }

    #[test]
    fn test_state_machine_creation() {
        let sm = create_test_state_machine();
        assert_eq!(sm.get_height().unwrap(), 0);
        assert_eq!(sm.get_total_supply().unwrap(), 0);
    }

    #[test]
    fn test_genesis_creation() {
        let sm = create_test_state_machine();
        let mut initial_accounts = HashMap::new();
        initial_accounts.insert(PublicKey::new("alice".to_string()), 1000);
        initial_accounts.insert(PublicKey::new("bob".to_string()), 500);

        sm.create_genesis(initial_accounts.clone()).unwrap();

        assert_eq!(sm.get_balance(&PublicKey::new("alice".to_string())).unwrap(), 1000);
        assert_eq!(sm.get_balance(&PublicKey::new("bob".to_string())).unwrap(), 500);
        assert_eq!(sm.get_total_supply().unwrap(), 1500);
    }

    #[test]
    fn test_transaction_validation_and_execution() {
        let sm = create_test_state_machine();

        // Create genesis with initial balance
        let mut initial_accounts = HashMap::new();
        initial_accounts.insert(PublicKey::new("alice".to_string()), 1000);
        sm.create_genesis(initial_accounts).unwrap();

        // Create transaction
        let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender_key, receiver, 100, 10, 0);
        tx.sign(&private_key).unwrap();

        // Execute transaction
        let receipt = sm.validate_and_execute_transaction(&tx, 1).unwrap();

        assert!(matches!(receipt.status, ExecutionStatus::Success));
        assert_eq!(receipt.gas_used, 21000);
        assert_eq!(sm.get_balance(&sender_key).unwrap(), 890); // 1000 - 100 - 10
        assert_eq!(sm.get_balance(&receiver).unwrap(), 100);
    }

    #[test]
    fn test_insufficient_balance() {
        let sm = create_test_state_machine();

        // Create genesis with small balance
        let mut initial_accounts = HashMap::new();
        initial_accounts.insert(PublicKey::new("alice".to_string()), 50);
        sm.create_genesis(initial_accounts).unwrap();

        // Try to send more than available
        let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender_key, receiver, 100, 10, 0);
        tx.sign(&private_key).unwrap();

        let result = sm.validate_and_execute_transaction(&tx, 1);
        assert!(matches!(result, Err(StateError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_nonce_validation() {
        let sm = create_test_state_machine();

        // Create genesis
        let mut initial_accounts = HashMap::new();
        initial_accounts.insert(PublicKey::new("alice".to_string()), 1000);
        sm.create_genesis(initial_accounts).unwrap();

        // First transaction
        let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx1 = Transaction::new(sender_key.clone(), receiver.clone(), 100, 10, 0);
        tx1.sign(&private_key.clone()).unwrap();

        sm.validate_and_execute_transaction(&tx1, 1).unwrap();

        // Second transaction should have nonce 1
        let mut tx2 = Transaction::new(sender_key, receiver, 100, 10, 1);
        tx2.sign(&private_key).unwrap();

        sm.validate_and_execute_transaction(&tx2, 2).unwrap();

        // Third transaction with wrong nonce should fail
        let mut tx3 = Transaction::new(sender_key, receiver, 100, 10, 1); // Wrong nonce (should be 2)
        tx3.sign(&private_key).unwrap();

        let result = sm.validate_and_execute_transaction(&tx3, 3);
        assert!(matches!(result, Err(StateError::InvalidNonce { .. })));
    }

    #[test]
    fn test_transaction_replay_protection() {
        let sm = create_test_state_machine();

        // Create genesis
        let mut initial_accounts = HashMap::new();
        initial_accounts.insert(PublicKey::new("alice".to_string()), 1000);
        sm.create_genesis(initial_accounts).unwrap();

        // Create transaction
        let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender_key, receiver, 100, 10, 0);
        tx.sign(&private_key).unwrap();

        // Execute first time
        sm.validate_and_execute_transaction(&tx, 1).unwrap();

        // Try to execute again (should fail)
        let result = sm.validate_and_execute_transaction(&tx, 2);
        assert!(matches!(result, Err(StateError::TransactionAlreadyProcessed(_))));
    }
}
