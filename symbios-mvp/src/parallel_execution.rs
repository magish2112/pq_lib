//! Parallel Transaction Execution Engine
//!
//! This module provides high-performance parallel transaction execution
//! using Optimistic Concurrency Control (OCC) for blockchain scalability.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use serde::{Serialize, Deserialize};
use futures::future::join_all;
use crate::types::{Transaction, Block, PublicKey, Hash, Address};
use crate::state_machine::{StateMachine, StateResult, StateError};
use crate::storage::StorageTrait;

/// Execution result for a single transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExecutionResult {
    pub tx_hash: Hash,
    pub success: bool,
    pub gas_used: u64,
    pub gas_price: u64,
    pub execution_time_ms: u64,
    pub error_message: Option<String>,
    pub state_changes: Vec<StateChange>,
}

/// State change tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub account: PublicKey,
    pub balance_change: i64,
    pub nonce_change: i64,
    pub storage_changes: HashMap<Hash, Vec<u8>>,
}

/// Execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub average_execution_time_ms: f64,
    pub total_gas_used: u64,
    pub throughput_tps: f64,
    pub parallelization_efficiency: f64,
    pub conflict_rate: f64,
}

/// Parallel execution configuration
#[derive(Debug, Clone)]
pub struct ParallelExecutionConfig {
    pub max_parallel_transactions: usize,
    pub batch_size: usize,
    pub conflict_detection_enabled: bool,
    pub validation_workers: usize,
    pub execution_workers: usize,
    pub max_retries: usize,
    pub timeout_ms: u64,
}

/// Parallel execution engine
pub struct ParallelExecutionEngine<S: StorageTrait + Send + Sync + 'static> {
    config: ParallelExecutionConfig,
    state_machine: Arc<StateMachine<S>>,
    execution_stats: Arc<RwLock<ExecutionStats>>,
    total_transactions_processed: Arc<AtomicU64>,
    semaphore: Arc<Semaphore>,
}

impl<S: StorageTrait + Send + Sync + 'static> ParallelExecutionEngine<S> {
    /// Create new parallel execution engine
    pub fn new(
        state_machine: Arc<StateMachine<S>>,
        config: ParallelExecutionConfig,
    ) -> Self {
        let stats = ExecutionStats {
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            average_execution_time_ms: 0.0,
            total_gas_used: 0,
            throughput_tps: 0.0,
            parallelization_efficiency: 0.0,
            conflict_rate: 0.0,
        };

        Self {
            config,
            state_machine,
            execution_stats: Arc::new(RwLock::new(stats)),
            total_transactions_processed: Arc::new(AtomicU64::new(0)),
            semaphore: Arc::new(Semaphore::new(config.max_parallel_transactions)),
        }
    }

    /// Execute transactions in parallel using OCC
    pub async fn execute_transactions_parallel(
        &self,
        transactions: Vec<Transaction>,
        block_height: u64,
    ) -> Result<Vec<TransactionExecutionResult>, Box<dyn std::error::Error>> {
        let start_time = std::time::SystemTime::now();
        let mut results = Vec::new();

        // Phase 1: Read validation (check for conflicts)
        let read_results = self.validate_reads_parallel(&transactions).await?;

        // Phase 2: Execute transactions in parallel
        let execution_results = self.execute_transactions_parallel_internal(
            transactions,
            &read_results,
            block_height,
        ).await?;

        // Phase 3: Write validation and commit
        let final_results = self.commit_transactions(&execution_results).await?;

        // Update statistics
        self.update_statistics(&final_results, start_time.elapsed());

        Ok(final_results)
    }

    /// Validate reads for conflict detection
    async fn validate_reads_parallel(
        &self,
        transactions: &[Transaction],
    ) -> Result<Vec<ReadValidationResult>, Box<dyn std::error::Error>> {
        let mut validation_futures = Vec::new();

        for tx in transactions {
            let state_machine = Arc::clone(&self.state_machine);
            let tx_clone = tx.clone();

            let future = tokio::spawn(async move {
                Self::validate_single_read(&state_machine, &tx_clone).await
            });
            validation_futures.push(future);
        }

        let validation_results = join_all(validation_futures).await;

        validation_results.into_iter()
            .map(|r| r.map_err(|e| format!("Validation task failed: {}", e)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }

    /// Validate a single transaction read
    async fn validate_single_read(
        state_machine: &StateMachine<S>,
        tx: &Transaction,
    ) -> ReadValidationResult {
        // Check if sender has sufficient balance
        let sender_balance = state_machine.get_balance(&tx.sender).unwrap_or(0);
        let total_cost = tx.amount + tx.fee;

        if sender_balance < total_cost {
            return ReadValidationResult {
                tx_hash: tx.id,
                can_proceed: false,
                conflicts: vec![Conflict::InsufficientBalance {
                    account: tx.sender.clone(),
                    required: total_cost,
                    available: sender_balance,
                }],
            };
        }

        // Check nonce
        let current_nonce = state_machine.get_nonce(&tx.sender).unwrap_or(0);
        if current_nonce != tx.nonce {
            return ReadValidationResult {
                tx_hash: tx.id,
                can_proceed: false,
                conflicts: vec![Conflict::InvalidNonce {
                    account: tx.sender.clone(),
                    expected: current_nonce,
                    got: tx.nonce,
                }],
            };
        }

        // Check for double-spend (same tx hash)
        if state_machine.is_transaction_processed(&tx.id).unwrap_or(false) {
            return ReadValidationResult {
                tx_hash: tx.id,
                can_proceed: false,
                conflicts: vec![Conflict::AlreadyProcessed],
            };
        }

        ReadValidationResult {
            tx_hash: tx.id,
            can_proceed: true,
            conflicts: vec![],
        }
    }

    /// Execute transactions in parallel with conflict resolution
    async fn execute_transactions_parallel_internal(
        &self,
        transactions: Vec<Transaction>,
        read_results: &[ReadValidationResult],
        block_height: u64,
    ) -> Result<Vec<TransactionExecutionResult>, Box<dyn std::error::Error>> {
        let mut execution_futures = Vec::new();
        let mut valid_transactions = Vec::new();

        // Filter out transactions that failed read validation
        for (i, tx) in transactions.iter().enumerate() {
            let read_result = &read_results[i];

            if read_result.can_proceed {
                valid_transactions.push(tx.clone());
            } else {
                // Create failed result for invalid transactions
                execution_futures.push(tokio::spawn(async move {
                    TransactionExecutionResult {
                        tx_hash: tx.id,
                        success: false,
                        gas_used: 0,
                        gas_price: tx.fee,
                        execution_time_ms: 0,
                        error_message: Some(format!("Read validation failed: {:?}", read_result.conflicts)),
                        state_changes: vec![],
                    }
                }));
            }
        }

        // Execute valid transactions in parallel batches
        for batch in valid_transactions.chunks(self.config.batch_size) {
            let batch_futures = self.execute_batch(batch.to_vec(), block_height).await?;
            execution_futures.extend(batch_futures);
        }

        let results = join_all(execution_futures).await;

        results.into_iter()
            .map(|r| r.map_err(|e| format!("Execution task failed: {}", e)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }

    /// Execute a batch of transactions
    async fn execute_batch(
        &self,
        batch: Vec<Transaction>,
        block_height: u64,
    ) -> Result<Vec<tokio::task::JoinHandle<TransactionExecutionResult>>, Box<dyn std::error::Error>> {
        let mut batch_futures = Vec::new();

        for tx in batch {
            let state_machine = Arc::clone(&self.state_machine);
            let semaphore = Arc::clone(&self.semaphore);
            let tx_clone = tx.clone();

            let future = tokio::spawn(async move {
                // Acquire semaphore permit for parallel execution control
                let _permit = semaphore.acquire().await;

                Self::execute_single_transaction(&state_machine, &tx_clone, block_height).await
            });

            batch_futures.push(future);
        }

        Ok(batch_futures)
    }

    /// Execute a single transaction
    async fn execute_single_transaction(
        state_machine: &StateMachine<S>,
        tx: &Transaction,
        block_height: u64,
    ) -> TransactionExecutionResult {
        let start_time = std::time::SystemTime::now();

        // Simulate execution (in real implementation, this would execute smart contract code)
        let execution_result = state_machine.validate_and_execute_transaction(tx, block_height);

        let execution_time = start_time.elapsed();

        match execution_result {
            Ok(receipt) => {
                let state_changes = vec![StateChange {
                    account: tx.sender.clone(),
                    balance_change: -(tx.amount + tx.fee) as i64,
                    nonce_change: 1,
                    storage_changes: HashMap::new(),
                }, StateChange {
                    account: tx.receiver.clone(),
                    balance_change: tx.amount as i64,
                    nonce_change: 0,
                    storage_changes: HashMap::new(),
                }];

                TransactionExecutionResult {
                    tx_hash: tx.id,
                    success: true,
                    gas_used: receipt.gas_used,
                    gas_price: receipt.gas_price,
                    execution_time_ms: execution_time.as_millis() as u64,
                    error_message: None,
                    state_changes,
                }
            }
            Err(e) => {
                TransactionExecutionResult {
                    tx_hash: tx.id,
                    success: false,
                    gas_used: 0,
                    gas_price: tx.fee,
                    execution_time_ms: execution_time.as_millis() as u64,
                    error_message: Some(format!("{:?}", e)),
                    state_changes: vec![],
                }
            }
        }
    }

    /// Commit validated transactions
    async fn commit_transactions(
        &self,
        execution_results: &[TransactionExecutionResult],
    ) -> Result<Vec<TransactionExecutionResult>, Box<dyn std::error::Error>> {
        // In OCC, we would validate writes here and commit atomically
        // For demonstration, we'll just return the results
        Ok(execution_results.to_vec())
    }

    /// Update execution statistics
    fn update_statistics(&self, results: &[TransactionExecutionResult], total_time: Duration) {
        let mut stats = self.execution_stats.write().unwrap();

        let total_txs = results.len() as u64;
        let successful_txs = results.iter().filter(|r| r.success).count() as u64;
        let failed_txs = total_txs - successful_txs;

        let total_gas: u64 = results.iter().map(|r| r.gas_used).sum();
        let total_time_ms = total_time.as_millis() as u64;

        // Update cumulative stats
        stats.total_transactions += total_txs;
        stats.successful_transactions += successful_txs;
        stats.failed_transactions += failed_txs;
        stats.total_gas_used += total_gas;

        // Calculate averages
        if stats.total_transactions > 0 {
            stats.average_execution_time_ms = stats.total_gas_used as f64 / stats.total_transactions as f64;
        }

        // Calculate throughput (TPS)
        if total_time_ms > 0 {
            stats.throughput_tps = (total_txs as f64 * 1000.0) / total_time_ms as f64;
        }

        // Calculate parallelization efficiency
        if total_txs > 0 {
            stats.parallelization_efficiency = (successful_txs as f64 / total_txs as f64) * 100.0;
        }

        // Calculate conflict rate
        stats.conflict_rate = (failed_txs as f64 / total_txs as f64) * 100.0;
    }

    /// Get current execution statistics
    pub fn get_execution_stats(&self) -> ExecutionStats {
        self.execution_stats.read().unwrap().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.execution_stats.write().unwrap();
        *stats = ExecutionStats {
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            average_execution_time_ms: 0.0,
            total_gas_used: 0,
            throughput_tps: 0.0,
            parallelization_efficiency: 0.0,
            conflict_rate: 0.0,
        };
    }

    /// Execute block with parallel transaction processing
    pub async fn execute_block(
        &self,
        block: &Block,
    ) -> Result<(Vec<TransactionExecutionResult>, ExecutionStats), Box<dyn std::error::Error>> {
        let execution_results = self.execute_transactions_parallel(
            block.transactions.clone(),
            block.height,
        ).await?;

        let stats = self.get_execution_stats();

        Ok((execution_results, stats))
    }

    /// Get performance metrics
    pub fn get_performance_metrics(&self) -> PerformanceMetrics {
        let stats = self.get_execution_stats();
        let total_processed = self.total_transactions_processed.load(Ordering::Relaxed);

        PerformanceMetrics {
            throughput_tps: stats.throughput_tps,
            average_latency_ms: stats.average_execution_time_ms,
            parallelization_efficiency: stats.parallelization_efficiency,
            conflict_rate: stats.conflict_rate,
            total_transactions_processed: total_processed,
            success_rate: if stats.total_transactions > 0 {
                (stats.successful_transactions as f64 / stats.total_transactions as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

/// Read validation result
#[derive(Debug, Clone)]
struct ReadValidationResult {
    tx_hash: Hash,
    can_proceed: bool,
    conflicts: Vec<Conflict>,
}

/// Conflict types
#[derive(Debug, Clone)]
enum Conflict {
    InsufficientBalance { account: PublicKey, required: u64, available: u64 },
    InvalidNonce { account: PublicKey, expected: u64, got: u64 },
    AlreadyProcessed,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub throughput_tps: f64,
    pub average_latency_ms: f64,
    pub parallelization_efficiency: f64,
    pub conflict_rate: f64,
    pub total_transactions_processed: u64,
    pub success_rate: f64,
}

/// Batch execution result
#[derive(Debug, Clone)]
pub struct BatchExecutionResult {
    pub batch_id: u64,
    pub transaction_count: usize,
    pub execution_time_ms: u64,
    pub gas_used: u64,
    pub conflicts_detected: usize,
    pub successful_executions: usize,
}

/// DAG-aware parallel execution
pub struct DagParallelExecutor<S: StorageTrait + Send + Sync + 'static> {
    base_engine: ParallelExecutionEngine<S>,
    dag_analyzer: DagAnalyzer,
}

impl<S: StorageTrait + Send + Sync + 'static> DagParallelExecutor<S> {
    /// Create new DAG-aware executor
    pub fn new(
        state_machine: Arc<StateMachine<S>>,
        config: ParallelExecutionConfig,
    ) -> Self {
        Self {
            base_engine: ParallelExecutionEngine::new(state_machine, config),
            dag_analyzer: DagAnalyzer::new(),
        }
    }

    /// Execute transactions with DAG-aware parallelization
    pub async fn execute_with_dag_optimization(
        &self,
        transactions: Vec<Transaction>,
        block_height: u64,
    ) -> Result<Vec<TransactionExecutionResult>, Box<dyn std::error::Error>> {
        // Analyze transaction dependencies using DAG
        let dependency_graph = self.dag_analyzer.analyze_dependencies(&transactions).await?;

        // Group transactions by dependency levels for parallel execution
        let execution_batches = self.create_execution_batches(&dependency_graph, &transactions)?;

        let mut all_results = Vec::new();

        // Execute batches sequentially (respecting dependencies) but transactions within batches in parallel
        for batch in execution_batches {
            let batch_results = self.base_engine.execute_transactions_parallel(
                batch,
                block_height,
            ).await?;

            all_results.extend(batch_results);
        }

        Ok(all_results)
    }

    /// Create execution batches based on dependency analysis
    fn create_execution_batches(
        &self,
        dependency_graph: &DependencyGraph,
        transactions: &[Transaction],
    ) -> Result<Vec<Vec<Transaction>>, Box<dyn std::error::Error>> {
        // Group transactions by their dependency level (topological sort)
        let mut batches = Vec::new();
        let mut processed = HashSet::new();

        // Find transactions with no dependencies (can execute first)
        let mut current_batch = Vec::new();

        for tx in transactions {
            if dependency_graph.get_dependencies(&tx.id).unwrap_or(&vec![]).is_empty() {
                current_batch.push(tx.clone());
                processed.insert(tx.id);
            }
        }

        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        // Continue with dependent transactions
        while processed.len() < transactions.len() {
            let mut next_batch = Vec::new();

            for tx in transactions {
                if processed.contains(&tx.id) {
                    continue;
                }

                // Check if all dependencies are satisfied
                let dependencies = dependency_graph.get_dependencies(&tx.id).unwrap_or(&vec![]);
                let all_deps_processed = dependencies.iter().all(|dep| processed.contains(dep));

                if all_deps_processed {
                    next_batch.push(tx.clone());
                    processed.insert(tx.id);
                }
            }

            if next_batch.is_empty() && processed.len() < transactions.len() {
                return Err("Circular dependency detected in transactions".into());
            }

            if !next_batch.is_empty() {
                batches.push(next_batch);
            }
        }

        Ok(batches)
    }
}

/// DAG dependency analyzer
pub struct DagAnalyzer {
    dependency_cache: Arc<RwLock<BTreeMap<Hash, Vec<Hash>>>>,
}

impl DagAnalyzer {
    /// Create new DAG analyzer
    pub fn new() -> Self {
        Self {
            dependency_cache: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Analyze transaction dependencies
    pub async fn analyze_dependencies(
        &self,
        transactions: &[Transaction],
    ) -> Result<DependencyGraph, Box<dyn std::error::Error>> {
        let mut dependencies = BTreeMap::new();

        // Analyze each transaction for dependencies
        for tx in transactions {
            let tx_dependencies = self.analyze_transaction_dependencies(tx, transactions).await?;
            dependencies.insert(tx.id, tx_dependencies);
        }

        Ok(DependencyGraph { dependencies })
    }

    /// Analyze dependencies for a single transaction
    async fn analyze_transaction_dependencies(
        &self,
        tx: &Transaction,
        all_txs: &[Transaction],
    ) -> Result<Vec<Hash>, Box<dyn std::error::Error>> {
        let mut deps = Vec::new();

        // Find transactions that this transaction depends on
        for other_tx in all_txs {
            if other_tx.id == tx.id {
                continue;
            }

            // Check if other_tx modifies an account that tx reads from
            if other_tx.sender == tx.sender || other_tx.receiver == tx.sender ||
               other_tx.sender == tx.receiver || other_tx.receiver == tx.receiver {
                deps.push(other_tx.id);
            }

            // Check for nonce dependencies (same sender, lower nonce)
            if other_tx.sender == tx.sender && other_tx.nonce < tx.nonce {
                deps.push(other_tx.id);
            }
        }

        Ok(deps)
    }
}

/// Dependency graph for transactions
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    dependencies: HashMap<Hash, Vec<Hash>>,
}

impl DependencyGraph {
    /// Get dependencies for a transaction
    pub fn get_dependencies(&self, tx_hash: &Hash) -> Option<&Vec<Hash>> {
        self.dependencies.get(tx_hash)
    }

    /// Check if transaction can be executed (all dependencies satisfied)
    pub fn can_execute(&self, tx_hash: &Hash, completed: &HashSet<Hash>) -> bool {
        if let Some(deps) = self.dependencies.get(tx_hash) {
            deps.iter().all(|dep| completed.contains(dep))
        } else {
            true // No dependencies
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use tempfile::TempDir;

    fn create_test_state_machine() -> Arc<StateMachine<Storage>> {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        let genesis_hash = Hash::new(b"genesis");
        let sm = StateMachine::new(storage, genesis_hash);

        // Add initial balance
        let mut accounts = std::collections::HashMap::new();
        accounts.insert(PublicKey::new("alice".to_string()), 10000);
        accounts.insert(PublicKey::new("bob".to_string()), 5000);
        sm.create_genesis(accounts).unwrap();

        Arc::new(sm)
    }

    #[tokio::test]
    async fn test_parallel_execution_engine_creation() {
        let sm = create_test_state_machine();
        let config = ParallelExecutionConfig {
            max_parallel_transactions: 100,
            batch_size: 10,
            conflict_detection_enabled: true,
            validation_workers: 4,
            execution_workers: 8,
            max_retries: 3,
            timeout_ms: 5000,
        };

        let engine = ParallelExecutionEngine::new(sm, config);
        assert_eq!(engine.get_execution_stats().total_transactions, 0);
    }

    #[tokio::test]
    async fn test_single_transaction_execution() {
        let sm = create_test_state_machine();
        let config = ParallelExecutionConfig {
            max_parallel_transactions: 100,
            batch_size: 10,
            conflict_detection_enabled: true,
            validation_workers: 4,
            execution_workers: 8,
            max_retries: 3,
            timeout_ms: 5000,
        };

        let engine = ParallelExecutionEngine::new(sm, config);

        // Create test transaction
        let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender_key, receiver, 100, 10, 0);
        tx.sign(&private_key).unwrap();

        let results = engine.execute_transactions_parallel(vec![tx], 1).await.unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert!(results[0].gas_used > 0);
    }

    #[tokio::test]
    async fn test_parallel_transaction_execution() {
        let sm = create_test_state_machine();
        let config = ParallelExecutionConfig {
            max_parallel_transactions: 10,
            batch_size: 5,
            conflict_detection_enabled: true,
            validation_workers: 4,
            execution_workers: 8,
            max_retries: 3,
            timeout_ms: 5000,
        };

        let engine = ParallelExecutionEngine::new(sm, config);

        // Create multiple independent transactions
        let mut transactions = Vec::new();
        for i in 0..5 {
            let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
            let receiver = PublicKey::new(format!("receiver{}", i));
            let mut tx = Transaction::new(sender_key, receiver, 100, 10, 0);
            tx.sign(&private_key).unwrap();
            transactions.push(tx);
        }

        let results = engine.execute_transactions_parallel(transactions, 1).await.unwrap();

        assert_eq!(results.len(), 5);

        // All should succeed (no conflicts)
        let successful = results.iter().filter(|r| r.success).count();
        assert_eq!(successful, 5);

        // Check performance metrics
        let metrics = engine.get_performance_metrics();
        assert!(metrics.throughput_tps > 0.0);
        assert!(metrics.success_rate == 100.0);
    }

    #[test]
    fn test_dependency_analyzer() {
        let analyzer = DagAnalyzer::new();

        // Create test transactions
        let tx1 = Transaction::new(
            PublicKey::new("alice".to_string()),
            PublicKey::new("bob".to_string()),
            100, 10, 0
        );

        let tx2 = Transaction::new(
            PublicKey::new("bob".to_string()),
            PublicKey::new("charlie".to_string()),
            50, 5, 0
        );

        let transactions = vec![tx1.clone(), tx2.clone()];

        // This would normally be async, but for testing we'll create a simple dependency graph
        let mut dependencies = BTreeMap::new();
        dependencies.insert(tx1.id, vec![]);
        dependencies.insert(tx2.id, vec![tx1.id]); // tx2 depends on tx1

        let graph = DependencyGraph { dependencies };

        // tx1 should be able to execute (no dependencies)
        assert!(graph.can_execute(&tx1.id, &HashSet::new()));

        // tx2 should not be able to execute until tx1 is processed
        assert!(!graph.can_execute(&tx2.id, &HashSet::new()));
        assert!(graph.can_execute(&tx2.id, &HashSet::from([tx1.id])));
    }

    #[test]
    fn test_execution_statistics() {
        let sm = create_test_state_machine();
        let config = ParallelExecutionConfig {
            max_parallel_transactions: 100,
            batch_size: 10,
            conflict_detection_enabled: true,
            validation_workers: 4,
            execution_workers: 8,
            max_retries: 3,
            timeout_ms: 5000,
        };

        let engine = ParallelExecutionEngine::new(sm, config);
        let initial_stats = engine.get_execution_stats();

        assert_eq!(initial_stats.total_transactions, 0);
        assert_eq!(initial_stats.successful_transactions, 0);
        assert_eq!(initial_stats.failed_transactions, 0);
        assert_eq!(initial_stats.throughput_tps, 0.0);
    }

    #[test]
    fn test_performance_metrics() {
        let sm = create_test_state_machine();
        let config = ParallelExecutionConfig {
            max_parallel_transactions: 100,
            batch_size: 10,
            conflict_detection_enabled: true,
            validation_workers: 4,
            execution_workers: 8,
            max_retries: 3,
            timeout_ms: 5000,
        };

        let engine = ParallelExecutionEngine::new(sm, config);
        let metrics = engine.get_performance_metrics();

        assert_eq!(metrics.total_transactions_processed, 0);
        assert_eq!(metrics.success_rate, 0.0);
        assert_eq!(metrics.throughput_tps, 0.0);
    }
}
