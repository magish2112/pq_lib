use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::path::Path;
use crate::types::{Transaction, Block, State, Hash};

/// Storage trait for persistence layer
#[async_trait::async_trait]
pub trait StorageTrait: Send + Sync {
    async fn store_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Box<dyn std::error::Error>>;
    async fn store_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error>>;
    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, String>;
    async fn get_latest_block(&self) -> Result<Option<Block>, String>;
    async fn store_state(&self, state: &State) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_state(&self) -> Result<State, Box<dyn std::error::Error>>;
    async fn store_transaction_receipt(&self, receipt: &crate::state_machine::TransactionReceipt) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_transaction_receipt(&self, tx_hash: &Hash) -> Result<Option<crate::state_machine::TransactionReceipt>, Box<dyn std::error::Error>>;
}

/// In-memory storage implementation for demo purposes
pub struct Storage {
    transactions: RwLock<HashMap<Hash, Transaction>>,
    blocks: RwLock<HashMap<Hash, Block>>,
    blocks_by_height: RwLock<HashMap<u64, Block>>,
    state: RwLock<State>,
    receipts: RwLock<HashMap<Hash, crate::state_machine::TransactionReceipt>>,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            transactions: RwLock::new(HashMap::new()),
            blocks: RwLock::new(HashMap::new()),
            blocks_by_height: RwLock::new(HashMap::new()),
            state: RwLock::new(State::default()),
            receipts: RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait::async_trait]
impl StorageTrait for Storage {
    async fn store_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        let mut transactions = self.transactions.write().map_err(|_| "Poisoned lock")?;
        transactions.insert(tx.id.clone(), tx.clone());
        Ok(())
    }

    async fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Box<dyn std::error::Error>> {
        let transactions = self.transactions.read().map_err(|_| "Poisoned lock")?;
        Ok(transactions.get(hash).cloned())
    }

    async fn store_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let block_hash = block.hash();
        let mut blocks = self.blocks.write().map_err(|_| "Poisoned lock")?;
        let mut blocks_by_height = self.blocks_by_height.write().map_err(|_| "Poisoned lock")?;

        blocks.insert(block_hash.clone(), block.clone());
        blocks_by_height.insert(block.header.height.as_u64(), block.clone());

        Ok(())
    }

    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let blocks = self.blocks.read().map_err(|_| "Poisoned lock")?;
        Ok(blocks.get(hash).cloned())
    }

    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let blocks_by_height = self.blocks_by_height.read().map_err(|_| "Poisoned lock")?;
        Ok(blocks_by_height.get(&height).cloned())
    }

    async fn get_latest_block(&self) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let blocks_by_height = self.blocks_by_height.read().map_err(|_| "Poisoned lock")?;
        let max_height = blocks_by_height.keys().max().copied();
        match max_height {
            Some(height) => Ok(blocks_by_height.get(&height).cloned()),
            None => Ok(None),
        }
    }

    async fn store_state(&self, state: &State) -> Result<(), Box<dyn std::error::Error>> {
        let mut current_state = self.state.write().map_err(|_| "Poisoned lock")?;
        *current_state = state.clone();
        Ok(())
    }

    async fn get_state(&self) -> Result<State, Box<dyn std::error::Error>> {
        let state = self.state.read().map_err(|_| "Poisoned lock")?;
        Ok(state.clone())
    }

    async fn store_transaction_receipt(&self, receipt: &crate::state_machine::TransactionReceipt) -> Result<(), Box<dyn std::error::Error>> {
        let mut receipts = self.receipts.write().map_err(|_| "Poisoned lock")?;
        receipts.insert(receipt.tx_hash.clone(), receipt.clone());
        Ok(())
    }

    async fn get_transaction_receipt(&self, tx_hash: &Hash) -> Result<Option<crate::state_machine::TransactionReceipt>, Box<dyn std::error::Error>> {
        let receipts = self.receipts.read().map_err(|_| "Poisoned lock")?;
        Ok(receipts.get(tx_hash).cloned())
    }
}