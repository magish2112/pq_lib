//! Efficient Parallel Transaction Execution Engine
//!
//! This module implements an optimized parallel execution engine designed for
//! resource-constrained environments. It uses optimistic concurrency control
//! with minimal memory overhead and efficient conflict detection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;
use crate::types::{Transaction, Block, State, PublicKey, Hash};

/// Execution context for a single transaction
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub tx: Transaction,
    pub read_set: HashSet<PublicKey>,    // Accounts read by transaction
    pub write_set: HashSet<PublicKey>,   // Accounts written by transaction
    pub result: Option<ExecutionResult>,
}

/// Result of transaction execution
#[derive(Debug, Clone)]
pub enum ExecutionResult {
    Success { gas_used: u64 },
    Failed { error: String },
    Pending,
}

/// Conflict graph for optimistic concurrency control
#[derive(Debug)]
pub struct ConflictGraph {
    nodes: HashMap<Hash, ExecutionContext>,
    edges: HashMap<Hash, HashSet<Hash>>, // Transaction -> conflicting transactions
    committed: HashSet<Hash>,
    aborted: HashSet<Hash>,
}

impl ConflictGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            committed: HashSet::new(),
            aborted: HashSet::new(),
        }
    }

    /// Add transaction to conflict graph
    pub fn add_transaction(&mut self, ctx: ExecutionContext) {
        let tx_hash = ctx.tx.id;

        // Check for conflicts with existing transactions
        for (other_hash, other_ctx) in &self.nodes {
            if self.has_conflict(&ctx, other_ctx) {
                self.edges.entry(tx_hash).or_insert_with(HashSet::new).insert(other_hash.clone());
                self.edges.entry(other_hash.clone()).or_insert_with(HashSet::new).insert(tx_hash.clone());
            }
        }

        self.nodes.insert(tx_hash, ctx);
    }

    /// Check if two transactions conflict
    fn has_conflict(&self, ctx1: &ExecutionContext, ctx2: &ExecutionContext) -> bool {
        // Write-write conflict
        if !ctx1.write_set.is_disjoint(&ctx2.write_set) {
            return true;
        }

        // Read-write conflict
        if !ctx1.read_set.is_disjoint(&ctx2.write_set) ||
           !ctx2.read_set.is_disjoint(&ctx1.write_set) {
            return true;
        }

        false
    }

    /// Get transactions that can be executed in parallel
    pub fn get_parallel_batch(&self, max_batch_size: usize) -> Vec<Hash> {
        let mut batch = Vec::new();
        let mut used_accounts = HashSet::new();

        // Simple greedy algorithm for conflict-free batch
        for (tx_hash, ctx) in &self.nodes {
            if self.committed.contains(tx_hash) || self.aborted.contains(tx_hash) {
                continue;
            }

            // Check if this transaction conflicts with batch
            let tx_accounts: HashSet<_> = ctx.read_set.union(&ctx.write_set).collect();
            if used_accounts.is_disjoint(&tx_accounts) {
                batch.push(tx_hash.clone());
                used_accounts.extend(tx_accounts);

                if batch.len() >= max_batch_size {
                    break;
                }
            }
        }

        batch
    }

    /// Mark transaction as committed
    pub fn commit_transaction(&mut self, tx_hash: &Hash) {
        self.committed.insert(tx_hash.clone());
        // Remove from conflict edges
        self.edges.remove(tx_hash);
        for edges in self.edges.values_mut() {
            edges.remove(tx_hash);
        }
    }

    /// Mark transaction as aborted
    pub fn abort_transaction(&mut self, tx_hash: &Hash) {
        self.aborted.insert(tx_hash.clone());
        self.nodes.remove(tx_hash);
        self.edges.remove(tx_hash);
        for edges in self.edges.values_mut() {
            edges.remove(tx_hash);
        }
    }

    /// Clean up committed/aborted transactions
    pub fn cleanup(&mut self) {
        // Remove committed and aborted transactions from nodes
        self.nodes.retain(|hash, _| {
            !self.committed.contains(hash) && !self.aborted.contains(hash)
        });
    }
}

/// Efficient execution engine
pub struct EfficientExecutionEngine {
    state: Arc<RwLock<State>>,
    conflict_graph: Arc<RwLock<ConflictGraph>>,
    max_parallel_batch: usize,
    max_memory_mb: usize,
}

impl EfficientExecutionEngine {
    pub fn new(initial_state: State, max_parallel_batch: usize, max_memory_mb: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(initial_state)),
            conflict_graph: Arc::new(RwLock::new(ConflictGraph::new())),
            max_parallel_batch,
            max_memory_mb,
        }
    }

    /// Execute a batch of transactions in parallel
    pub async fn execute_batch(&self, transactions: Vec<Transaction>) -> Result<Vec<ExecutionResult>, Box<dyn std::error::Error>> {
        let mut contexts = Vec::new();

        // Analyze read/write sets for each transaction
        for tx in transactions {
            let ctx = self.analyze_transaction(&tx).await?;
            contexts.push(ctx);
        }

        // Add to conflict graph
        {
            let mut graph = self.conflict_graph.write().await;
            for ctx in &contexts {
                graph.add_transaction(ctx.clone());
            }
        }

        // Execute non-conflicting batches
        let mut results = vec![ExecutionResult::Pending; contexts.len()];
        let mut executed_count = 0;

        while executed_count < contexts.len() {
            let batch = {
                let graph = self.conflict_graph.read().await;
                graph.get_parallel_batch(self.max_parallel_batch)
            };

            if batch.is_empty() {
                break; // No more transactions can be executed
            }

            // Execute batch in parallel
            let batch_results = self.execute_parallel_batch(&batch, &contexts).await?;

            // Update results and conflict graph
            {
                let mut graph = self.conflict_graph.write().await;
                for (i, tx_hash) in batch.iter().enumerate() {
                    if let ExecutionResult::Success { .. } = &batch_results[i] {
                        graph.commit_transaction(tx_hash);
                        executed_count += 1;
                    } else {
                        graph.abort_transaction(tx_hash);
                    }
                }
            }

            // Store results
            for (i, tx_hash) in batch.iter().enumerate() {
                if let Some(pos) = contexts.iter().position(|ctx| ctx.tx.id == *tx_hash) {
                    results[pos] = batch_results[i].clone();
                }
            }
        }

        // Cleanup conflict graph periodically
        {
            let mut graph = self.conflict_graph.write().await;
            graph.cleanup();
        }

        Ok(results)
    }

    /// Analyze transaction to determine read/write sets
    async fn analyze_transaction(&self, tx: &Transaction) -> Result<ExecutionContext, Box<dyn std::error::Error>> {
        // For simplicity, assume all transactions read sender and write both sender and receiver
        // In a real implementation, this would analyze the transaction's smart contract or operations
        let mut read_set = HashSet::new();
        let mut write_set = HashSet::new();

        read_set.insert(tx.sender.clone());
        write_set.insert(tx.sender.clone());
        write_set.insert(tx.receiver.clone());

        Ok(ExecutionContext {
            tx: tx.clone(),
            read_set,
            write_set,
            result: None,
        })
    }

    /// Execute a batch of transactions in parallel
    async fn execute_parallel_batch(&self, batch: &[Hash], contexts: &[ExecutionContext]) -> Result<Vec<ExecutionResult>, Box<dyn std::error::Error>> {
        let mut tasks = Vec::new();

        for tx_hash in batch {
            if let Some(ctx) = contexts.iter().find(|c| c.tx.id == *tx_hash) {
                let state = Arc::clone(&self.state);
                let tx = ctx.tx.clone();

                let task = tokio::spawn(async move {
                    Self::execute_single_transaction(state, tx).await
                });
                tasks.push(task);
            }
        }

        // Wait for all tasks to complete
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(ExecutionResult::Failed {
                    error: format!("Task join error: {}", e)
                }),
            }
        }

        Ok(results)
    }

    /// Execute single transaction
    async fn execute_single_transaction(state: Arc<RwLock<State>>, tx: Transaction) -> ExecutionResult {
        let mut state_write = state.write().await;

        // Check sender balance
        let sender_balance = state_write.accounts.get(&tx.sender).unwrap_or(&0);
        if *sender_balance < tx.amount {
            return ExecutionResult::Failed {
                error: "Insufficient balance".to_string()
            };
        }

        // Execute transaction
        *state_write.accounts.entry(tx.sender.clone()).or_insert(0) -= tx.amount;
        *state_write.accounts.entry(tx.receiver.clone()).or_insert(0) += tx.amount;

        ExecutionResult::Success { gas_used: 21000 } // Standard gas for simple transfer
    }

    /// Get execution statistics
    pub async fn get_stats(&self) -> ExecutionStats {
        let graph = self.conflict_graph.read().await;
        let state = self.state.read().await;

        ExecutionStats {
            active_transactions: graph.nodes.len(),
            committed_transactions: graph.committed.len(),
            aborted_transactions: graph.aborted.len(),
            total_accounts: state.accounts.len(),
            memory_usage: self.estimate_memory_usage().await,
        }
    }

    /// Estimate memory usage
    async fn estimate_memory_usage(&self) -> usize {
        let graph = self.conflict_graph.read().await;
        let state = self.state.read().await;

        // Rough memory estimation
        let graph_memory = graph.nodes.len() * 256; // ~256 bytes per transaction context
        let state_memory = state.accounts.len() * 64; // ~64 bytes per account

        graph_memory + state_memory
    }
}

/// Execution statistics
#[derive(Debug, Clone)]
pub struct ExecutionStats {
    pub active_transactions: usize,
    pub committed_transactions: usize,
    pub aborted_transactions: usize,
    pub total_accounts: usize,
    pub memory_usage: usize,
}

/// Transaction executor trait for integration
#[async_trait]
pub trait TransactionExecutor {
    async fn execute_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>>;
    async fn validate_transaction(&self, tx: &Transaction) -> Result<bool, Box<dyn std::error::Error>>;
    async fn get_execution_stats(&self) -> Result<ExecutionStats, Box<dyn std::error::Error>>;
}

#[async_trait]
impl TransactionExecutor for EfficientExecutionEngine {
    async fn execute_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let results = self.execute_batch(block.transactions.clone()).await?;

        // Check if all transactions succeeded
        let failed_count = results.iter().filter(|r| matches!(r, ExecutionResult::Failed { .. })).count();
        if failed_count > 0 {
            return Err(format!("{} transactions failed in block", failed_count).into());
        }

        Ok(())
    }

    async fn validate_transaction(&self, tx: &Transaction) -> Result<bool, Box<dyn std::error::Error>> {
        // Basic validation
        if tx.amount == 0 {
            return Ok(false);
        }

        let state = self.state.read().await;
        let sender_balance = state.accounts.get(&tx.sender).unwrap_or(&0);
        Ok(*sender_balance >= tx.amount)
    }

    async fn get_execution_stats(&self) -> Result<ExecutionStats, Box<dyn std::error::Error>> {
        Ok(self.get_stats().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::create_genesis_block;

    #[tokio::test]
    async fn test_conflict_graph() {
        let mut graph = ConflictGraph::new();

        // Create two conflicting transactions (same sender)
        let sender = PublicKey(vec![1; 32]);
        let receiver1 = PublicKey(vec![2; 32]);
        let receiver2 = PublicKey(vec![3; 32]);

        let tx1 = Transaction::new(sender.clone(), receiver1, 100, 0);
        let tx2 = Transaction::new(sender.clone(), receiver2, 50, 1);

        let ctx1 = ExecutionContext {
            tx: tx1.clone(),
            read_set: HashSet::from([sender.clone()]),
            write_set: HashSet::from([sender.clone(), receiver1]),
            result: None,
        };

        let ctx2 = ExecutionContext {
            tx: tx2.clone(),
            read_set: HashSet::from([sender.clone()]),
            write_set: HashSet::from([sender.clone(), receiver2]),
            result: None,
        };

        graph.add_transaction(ctx1);
        graph.add_transaction(ctx2);

        // Should detect conflict
        assert!(graph.has_conflict(
            &ExecutionContext {
                tx: tx1,
                read_set: HashSet::from([sender.clone()]),
                write_set: HashSet::from([sender.clone(), receiver1]),
                result: None,
            },
            &ExecutionContext {
                tx: tx2,
                read_set: HashSet::from([sender.clone()]),
                write_set: HashSet::from([sender.clone(), receiver2]),
                result: None,
            }
        ));
    }

    #[tokio::test]
    async fn test_parallel_execution() {
        let genesis = create_genesis_block();
        let mut initial_state = State::new();
        initial_state.apply_block(&genesis).unwrap();

        let engine = EfficientExecutionEngine::new(initial_state, 10, 100);

        // Create non-conflicting transactions
        let transactions = vec![
            Transaction::new(PublicKey(vec![1; 32]), PublicKey(vec![2; 32]), 50, 0),
            Transaction::new(PublicKey(vec![3; 32]), PublicKey(vec![4; 32]), 30, 1),
        ];

        let results = engine.execute_batch(transactions).await.unwrap();
        assert_eq!(results.len(), 2);

        for result in results {
            match result {
                ExecutionResult::Success { .. } => {},
                _ => {
                    log::error!("Unexpected transaction execution failure");
                    return Err("Transaction execution failed unexpectedly".into());
                }
            }
        }
    }
}

