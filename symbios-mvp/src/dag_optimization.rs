//! DAG Mempool Optimization Engine
//!
//! This module provides advanced DAG-based mempool optimization
//! for maximum transaction throughput and minimal latency.

use std::collections::{HashMap, HashSet, BinaryHeap, VecDeque};
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};
use std::time::{Instant, Duration};
use serde::{Serialize, Deserialize};
use crate::types::{Transaction, Block, PublicKey, Hash};
use crate::dag_mempool::{SmartDagMempool, DagVertex, MempoolBlock, Certificate};
use crate::parallel_execution::{ParallelExecutionEngine, ParallelExecutionConfig};

/// DAG optimization configuration
#[derive(Debug, Clone)]
pub struct DagOptimizationConfig {
    pub max_parallel_batches: usize,
    pub batch_size: usize,
    pub conflict_window_size: usize,
    pub certificate_threshold: usize,
    pub optimization_interval_ms: u64,
    pub adaptive_batching_enabled: bool,
    pub priority_queue_size: usize,
}

/// Optimized DAG mempool with advanced features
pub struct OptimizedDagMempool {
    config: DagOptimizationConfig,
    base_mempool: SmartDagMempool,
    optimization_stats: Arc<RwLock<OptimizationStats>>,
    priority_queue: Arc<RwLock<BinaryHeap<TransactionPriority>>>,
    conflict_detector: ConflictDetector,
    adaptive_optimizer: AdaptiveOptimizer,
}

impl OptimizedDagMempool {
    /// Create new optimized DAG mempool
    pub fn new(
        validators: Vec<PublicKey>,
        config: DagOptimizationConfig,
    ) -> Self {
        let base_config = SmartDagMempool::default_config();
        let base_mempool = SmartDagMempool::new(validators, base_config.min_certificates_required);

        Self {
            config,
            base_mempool,
            optimization_stats: Arc::new(RwLock::new(OptimizationStats::new())),
            priority_queue: Arc::new(RwLock::new(BinaryHeap::new())),
            conflict_detector: ConflictDetector::new(),
            adaptive_optimizer: AdaptiveOptimizer::new(),
        }
    }

    /// Add transaction with optimization
    pub async fn add_transaction_optimized(
        &self,
        mut tx: Transaction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Calculate priority score
        let priority = self.calculate_transaction_priority(&tx).await?;

        // Add to priority queue
        self.priority_queue.write().unwrap().push(TransactionPriority {
            tx_hash: tx.id,
            priority_score: priority,
            timestamp: tx.timestamp,
        });

        // Detect conflicts
        let conflicts = self.conflict_detector.detect_conflicts(&tx).await?;

        if conflicts.is_empty() {
            // No conflicts - add to DAG
            self.base_mempool.add_transaction(tx).await?;
        } else {
            // Handle conflicts
            self.handle_conflicts(&tx, &conflicts).await?;
        }

        // Update statistics
        self.update_optimization_stats().await;

        Ok(())
    }

    /// Calculate transaction priority score
    async fn calculate_transaction_priority(&self, tx: &Transaction) -> Result<f64, Box<dyn std::error::Error>> {
        let mut priority = 0.0;

        // Fee-based priority (higher fees = higher priority)
        priority += tx.fee as f64 * 0.4;

        // Age-based priority (older transactions get slight boost)
        let age_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64 - tx.timestamp;

        if age_ms > 1000 {
            priority += (age_ms / 1000) as f64 * 0.1;
        }

        // Size-based priority (smaller transactions get slight boost)
        let tx_size = bincode::serialize(tx)?.len();
        priority += (1000 - tx_size) as f64 * 0.01;

        // Account-based priority (frequent users get slight boost)
        let account_activity = self.get_account_activity_score(&tx.sender).await?;
        priority += account_activity * 0.05;

        Ok(priority)
    }

    /// Get account activity score
    async fn get_account_activity_score(&self, account: &PublicKey) -> Result<f64, Box<dyn std::error::Error>> {
        // In production, this would query historical activity
        // For demonstration, return a mock score
        Ok(0.5)
    }

    /// Handle transaction conflicts
    async fn handle_conflicts(
        &self,
        tx: &Transaction,
        conflicts: &[TransactionConflict],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for conflict in conflicts {
            match conflict {
                TransactionConflict::DoubleSpend { conflicting_tx } => {
                    // Resolve double-spend by comparing fees and timestamps
                    if tx.fee > conflicting_tx.fee ||
                       (tx.fee == conflicting_tx.fee && tx.timestamp < conflicting_tx.timestamp) {
                        // Our transaction has higher priority - replace the conflicting one
                        self.base_mempool.remove_transaction(&conflicting_tx.id).await?;
                        self.base_mempool.add_transaction(tx.clone()).await?;
                    }
                }
                TransactionConflict::NonceGap { expected_nonce, got_nonce } => {
                    // Handle nonce gaps by adjusting transaction
                    // In production, this might involve reordering or dropping
                    println!("Nonce gap detected: expected {}, got {}", expected_nonce, got_nonce);
                }
                TransactionConflict::InsufficientBalance { required, available } => {
                    // Transaction cannot be executed - drop or queue for later
                    println!("Insufficient balance: required {}, available {}", required, available);
                }
            }
        }

        Ok(())
    }

    /// Create optimized mempool blocks
    pub async fn create_optimized_mempool_blocks(
        &self,
        count: usize,
    ) -> Result<Vec<OptimizedMempoolBlock>, Box<dyn std::error::Error>> {
        let mut optimized_blocks = Vec::new();

        // Get high-priority transactions from queue
        let priority_txs = self.get_high_priority_transactions().await?;

        // Group transactions into optimized batches
        let batches = self.create_optimized_batches(&priority_txs).await?;

        for (i, batch) in batches.iter().enumerate().take(count) {
            let block = self.create_optimized_block(batch.clone(), i as u64).await?;
            optimized_blocks.push(block);
        }

        Ok(optimized_blocks)
    }

    /// Get high-priority transactions from queue
    async fn get_high_priority_transactions(&self) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        let mut priority_txs = Vec::new();
        let mut processed_hashes = HashSet::new();

        let priority_queue = self.priority_queue.read().unwrap();

        for _ in 0..self.config.priority_queue_size {
            if let Some(priority_tx) = priority_queue.peek() {
                // Check if transaction is still valid and not processed
                if !processed_hashes.contains(&priority_tx.tx_hash) {
                    if let Some(tx) = self.base_mempool.get_transaction(&priority_tx.tx_hash).await? {
                        priority_txs.push(tx);
                        processed_hashes.insert(priority_tx.tx_hash);
                    }
                }
            } else {
                break;
            }
        }

        Ok(priority_txs)
    }

    /// Create optimized transaction batches
    async fn create_optimized_batches(
        &self,
        transactions: &[Transaction],
    ) -> Result<Vec<Vec<Transaction>>, Box<dyn std::error::Error>> {
        let mut batches = Vec::new();
        let mut remaining_txs = transactions.to_vec();
        let mut current_batch = Vec::new();

        while !remaining_txs.is_empty() && batches.len() < self.config.max_parallel_batches {
            // Find transactions that can be executed in parallel
            let (parallel_txs, remaining) = self.find_parallel_executable(&remaining_txs).await?;

            current_batch.extend(parallel_txs);

            if current_batch.len() >= self.config.batch_size {
                batches.push(current_batch);
                current_batch = Vec::new();
            }

            remaining_txs = remaining;
        }

        // Add remaining transactions to final batch
        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        Ok(batches)
    }

    /// Find transactions that can be executed in parallel
    async fn find_parallel_executable(
        &self,
        transactions: &[Transaction],
    ) -> Result<(Vec<Transaction>, Vec<Transaction>), Box<dyn std::error::Error>> {
        let mut parallel_txs = Vec::new();
        let mut remaining_txs = Vec::new();

        for tx in transactions {
            let conflicts = self.conflict_detector.detect_conflicts(tx).await?;

            if conflicts.is_empty() {
                parallel_txs.push(tx.clone());
            } else {
                remaining_txs.push(tx.clone());
            }
        }

        Ok((parallel_txs, remaining_txs))
    }

    /// Create optimized mempool block
    async fn create_optimized_block(
        &self,
        transactions: Vec<Transaction>,
        block_id: u64,
    ) -> Result<OptimizedMempoolBlock, Box<dyn std::error::Error>> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let block = OptimizedMempoolBlock {
            id: Hash::new(&block_id.to_be_bytes()),
            transactions,
            timestamp,
            batch_size: transactions.len(),
            optimization_metadata: OptimizationMetadata {
                priority_score: self.calculate_batch_priority(&transactions).await?,
                conflict_free: true,
                execution_order: self.determine_execution_order(&transactions).await?,
            },
        };

        Ok(block)
    }

    /// Calculate batch priority score
    async fn calculate_batch_priority(&self, transactions: &[Transaction]) -> Result<f64, Box<dyn std::error::Error>> {
        let mut total_priority = 0.0;
        let mut count = 0;

        for tx in transactions {
            let priority = self.calculate_transaction_priority(tx).await?;
            total_priority += priority;
            count += 1;
        }

        Ok(if count > 0 { total_priority / count as f64 } else { 0.0 })
    }

    /// Determine optimal execution order for batch
    async fn determine_execution_order(
        &self,
        transactions: &[Transaction],
    ) -> Result<Vec<Hash>, Box<dyn std::error::Error>> {
        // Use topological sort based on dependencies
        let mut order = Vec::new();

        // For simplicity, use fee-based ordering (highest fee first)
        let mut txs_with_fees: Vec<_> = transactions.iter()
            .map(|tx| (tx, tx.fee))
            .collect();

        txs_with_fees.sort_by(|a, b| b.1.cmp(&a.1));

        for (tx, _) in txs_with_fees {
            order.push(tx.id);
        }

        Ok(order)
    }

    /// Update optimization statistics
    async fn update_optimization_stats(&self) {
        let mut stats = self.optimization_stats.write().unwrap();

        // Update counters
        stats.total_transactions_processed += 1;

        // Update priority queue size
        stats.priority_queue_size = self.priority_queue.read().unwrap().len();

        // Update average batch size
        // (This would be calculated from actual batch creation)
        stats.average_batch_size = 10.0; // Mock value

        // Update conflict rate
        // (This would be calculated from conflict detection results)
        stats.conflict_rate = 0.05; // Mock value
    }

    /// Get optimization statistics
    pub fn get_optimization_stats(&self) -> OptimizationStats {
        self.optimization_stats.read().unwrap().clone()
    }

    /// Perform adaptive optimization
    pub async fn perform_adaptive_optimization(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.adaptive_batching_enabled {
            return Ok(());
        }

        // Analyze current performance
        let current_stats = self.get_optimization_stats();

        // Adjust configuration based on performance metrics
        let optimization_result = self.adaptive_optimizer.optimize_config(
            &self.config,
            &current_stats,
        ).await?;

        if let Some(new_config) = optimization_result {
            self.config = new_config;
            println!("Adaptive optimization: Updated configuration");
        }

        Ok(())
    }
}

/// Transaction priority for ordering
#[derive(Debug, Clone)]
struct TransactionPriority {
    tx_hash: Hash,
    priority_score: f64,
    timestamp: u64,
}

impl Ord for TransactionPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority_score.partial_cmp(&other.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| other.timestamp.cmp(&self.timestamp)) // Earlier timestamp wins when priority equal
    }
}

impl PartialOrd for TransactionPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for TransactionPriority {}
impl PartialEq for TransactionPriority {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash == other.tx_hash
    }
}

/// Transaction conflict types
#[derive(Debug, Clone)]
enum TransactionConflict {
    DoubleSpend { conflicting_tx: Transaction },
    NonceGap { expected_nonce: u64, got_nonce: u64 },
    InsufficientBalance { required: u64, available: u64 },
}

/// Conflict detector
struct ConflictDetector {
    conflict_cache: Arc<RwLock<HashMap<Hash, Vec<TransactionConflict>>>>,
}

impl ConflictDetector {
    /// Create new conflict detector
    fn new() -> Self {
        Self {
            conflict_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Detect conflicts for a transaction
    async fn detect_conflicts(&self, tx: &Transaction) -> Result<Vec<TransactionConflict>, Box<dyn std::error::Error>> {
        let mut conflicts = Vec::new();

        // Check for double-spend (same sender/receiver with different nonce)
        // Check for nonce gaps
        // Check for insufficient balance

        // In production, this would query the state machine and mempool
        // For demonstration, return empty conflicts

        Ok(conflicts)
    }
}

/// Adaptive optimizer for configuration tuning
struct AdaptiveOptimizer {
    optimization_history: VecDeque<OptimizationResult>,
}

impl AdaptiveOptimizer {
    /// Create new adaptive optimizer
    fn new() -> Self {
        Self {
            optimization_history: VecDeque::new(),
        }
    }

    /// Optimize configuration based on performance
    async fn optimize_config(
        &mut self,
        current_config: &DagOptimizationConfig,
        stats: &OptimizationStats,
    ) -> Result<Option<DagOptimizationConfig>, Box<dyn std::error::Error>> {
        // Analyze performance metrics and suggest configuration changes
        let mut new_config = current_config.clone();

        // Adjust batch size based on conflict rate
        if stats.conflict_rate > 0.1 {
            new_config.batch_size = (new_config.batch_size as f64 * 0.8) as usize;
            new_config.batch_size = new_config.batch_size.max(1);
        } else if stats.conflict_rate < 0.02 {
            new_config.batch_size = (new_config.batch_size as f64 * 1.2) as usize;
            new_config.batch_size = new_config.batch_size.min(100);
        }

        // Adjust parallel batches based on throughput
        if stats.average_batch_size > 0.0 {
            let efficiency = stats.average_batch_size / current_config.batch_size as f64;
            if efficiency < 0.5 {
                new_config.max_parallel_batches = (new_config.max_parallel_batches as f64 * 0.8) as usize;
            } else if efficiency > 0.8 {
                new_config.max_parallel_batches = (new_config.max_parallel_batches as f64 * 1.2) as usize;
            }
        }

        // Record optimization result
        let result = OptimizationResult {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            config_changes: vec![
                format!("batch_size: {} -> {}", current_config.batch_size, new_config.batch_size),
                format!("max_parallel_batches: {} -> {}", current_config.max_parallel_batches, new_config.max_parallel_batches),
            ],
            performance_improvement: 0.0, // Would calculate actual improvement
        };

        self.optimization_history.push_back(result);

        // Keep only last 10 optimizations
        if self.optimization_history.len() > 10 {
            self.optimization_history.pop_front();
        }

        // Return new config if changes were made
        if new_config != *current_config {
            Ok(Some(new_config))
        } else {
            Ok(None)
        }
    }
}

/// Optimization result
#[derive(Debug, Clone)]
struct OptimizationResult {
    timestamp: u64,
    config_changes: Vec<String>,
    performance_improvement: f64,
}

/// Optimization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationStats {
    pub total_transactions_processed: u64,
    pub priority_queue_size: usize,
    pub average_batch_size: f64,
    pub conflict_rate: f64,
    pub optimization_cycles: u64,
    pub last_optimization: u64,
}

impl OptimizationStats {
    /// Create new optimization stats
    fn new() -> Self {
        Self {
            total_transactions_processed: 0,
            priority_queue_size: 0,
            average_batch_size: 0.0,
            conflict_rate: 0.0,
            optimization_cycles: 0,
            last_optimization: 0,
        }
    }
}

/// Optimized mempool block with metadata
#[derive(Debug, Clone)]
pub struct OptimizedMempoolBlock {
    pub id: Hash,
    pub transactions: Vec<Transaction>,
    pub timestamp: u64,
    pub batch_size: usize,
    pub optimization_metadata: OptimizationMetadata,
}

/// Optimization metadata for blocks
#[derive(Debug, Clone)]
pub struct OptimizationMetadata {
    pub priority_score: f64,
    pub conflict_free: bool,
    pub execution_order: Vec<Hash>,
}

/// DAG optimization engine for performance tuning
pub struct DagOptimizationEngine {
    config: DagOptimizationConfig,
    optimization_stats: OptimizationStats,
    performance_monitor: PerformanceMonitor,
}

impl DagOptimizationEngine {
    /// Create new optimization engine
    pub fn new(config: DagOptimizationConfig) -> Self {
        Self {
            config,
            optimization_stats: OptimizationStats::new(),
            performance_monitor: PerformanceMonitor::new(),
        }
    }

    /// Optimize DAG structure for better performance
    pub async fn optimize_dag_structure(
        &mut self,
        dag: &mut SmartDagMempool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Analyze current DAG structure
        let analysis = self.analyze_dag_structure(dag).await?;

        // Optimize based on analysis
        if analysis.requires_optimization {
            self.apply_optimizations(dag, &analysis).await?;
            self.optimization_stats.optimization_cycles += 1;
            self.optimization_stats.last_optimization = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
        }

        Ok(())
    }

    /// Analyze DAG structure for optimization opportunities
    async fn analyze_dag_structure(
        &self,
        dag: &SmartDagMempool,
    ) -> Result<DagAnalysis, Box<dyn std::error::Error>> {
        let vertices = dag.get_vertices();
        let total_vertices = vertices.len();

        // Calculate depth and width metrics
        let max_depth = self.calculate_max_depth(&vertices);
        let avg_width = self.calculate_average_width(&vertices);

        // Detect bottlenecks
        let bottlenecks = self.detect_bottlenecks(&vertices).await?;

        // Calculate fragmentation
        let fragmentation = self.calculate_fragmentation(&vertices);

        Ok(DagAnalysis {
            total_vertices,
            max_depth,
            avg_width,
            bottlenecks,
            fragmentation,
            requires_optimization: max_depth > 10 || fragmentation > 0.3 || !bottlenecks.is_empty(),
        })
    }

    /// Calculate maximum depth of DAG
    fn calculate_max_depth(&self, vertices: &[DagVertex]) -> usize {
        // Simple depth calculation (in production, would use proper topological analysis)
        vertices.len().min(10) // Mock implementation
    }

    /// Calculate average width of DAG
    fn calculate_average_width(&self, vertices: &[DagVertex]) -> f64 {
        if vertices.is_empty() {
            0.0
        } else {
            vertices.len() as f64 / self.calculate_max_depth(vertices) as f64
        }
    }

    /// Detect performance bottlenecks in DAG
    async fn detect_bottlenecks(&self, vertices: &[DagVertex]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut bottlenecks = Vec::new();

        // Check for high-degree vertices (too many dependencies)
        for vertex in vertices {
            if vertex.parents.len() > 5 || vertex.children.len() > 5 {
                bottlenecks.push(format!("High degree vertex: {:?}", vertex.mempool_block_hash));
            }
        }

        Ok(bottlenecks)
    }

    /// Calculate DAG fragmentation (how spread out the graph is)
    fn calculate_fragmentation(&self, vertices: &[DagVertex]) -> f64 {
        // Simple fragmentation calculation
        if vertices.is_empty() {
            0.0
        } else {
            0.1 // Mock value
        }
    }

    /// Apply optimizations to DAG
    async fn apply_optimizations(
        &self,
        dag: &mut SmartDagMempool,
        analysis: &DagAnalysis,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Rebalance DAG structure
        if analysis.max_depth > 10 {
            self.rebalance_dag_depth(dag).await?;
        }

        // Reduce fragmentation
        if analysis.fragmentation > 0.3 {
            self.defragment_dag(dag).await?;
        }

        // Resolve bottlenecks
        for bottleneck in &analysis.bottlenecks {
            self.resolve_bottleneck(dag, bottleneck).await?;
        }

        Ok(())
    }

    /// Rebalance DAG depth for better parallelization
    async fn rebalance_dag_depth(&self, dag: &mut SmartDagMempool) -> Result<(), Box<dyn std::error::Error>> {
        // In production, this would reorganize the DAG structure
        println!("Rebalancing DAG depth...");
        Ok(())
    }

    /// Defragment DAG for better locality
    async fn defragment_dag(&self, dag: &mut SmartDagMempool) -> Result<(), Box<dyn std::error::Error>> {
        // In production, this would reorganize transactions for better locality
        println!("Defragmenting DAG...");
        Ok(())
    }

    /// Resolve specific bottleneck
    async fn resolve_bottleneck(
        &self,
        dag: &mut SmartDagMempool,
        bottleneck: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Resolving bottleneck: {}", bottleneck);
        Ok(())
    }

    /// Get optimization statistics
    pub fn get_optimization_stats(&self) -> &OptimizationStats {
        &self.optimization_stats
    }
}

/// DAG analysis result
#[derive(Debug, Clone)]
struct DagAnalysis {
    total_vertices: usize,
    max_depth: usize,
    avg_width: f64,
    bottlenecks: Vec<String>,
    fragmentation: f64,
    requires_optimization: bool,
}

/// Performance monitor for optimization decisions
struct PerformanceMonitor {
    metrics_history: VecDeque<PerformanceSnapshot>,
}

impl PerformanceMonitor {
    /// Create new performance monitor
    fn new() -> Self {
        Self {
            metrics_history: VecDeque::new(),
        }
    }

    /// Record performance snapshot
    fn record_snapshot(&mut self, snapshot: PerformanceSnapshot) {
        self.metrics_history.push_back(snapshot);

        // Keep only last 100 snapshots
        if self.metrics_history.len() > 100 {
            self.metrics_history.pop_front();
        }
    }

    /// Get performance trend
    fn get_performance_trend(&self) -> PerformanceTrend {
        if self.metrics_history.len() < 2 {
            return PerformanceTrend::Stable;
        }

        let recent = &self.metrics_history[self.metrics_history.len() - 5..];
        let older = &self.metrics_history[..self.metrics_history.len() - 5];

        let recent_avg = recent.iter().map(|s| s.throughput_tps).sum::<f64>() / recent.len() as f64;
        let older_avg = older.iter().map(|s| s.throughput_tps).sum::<f64>() / older.len() as f64;

        if recent_avg > older_avg * 1.1 {
            PerformanceTrend::Improving
        } else if recent_avg < older_avg * 0.9 {
            PerformanceTrend::Degrading
        } else {
            PerformanceTrend::Stable
        }
    }
}

/// Performance snapshot
#[derive(Debug, Clone)]
struct PerformanceSnapshot {
    timestamp: u64,
    throughput_tps: f64,
    latency_ms: f64,
    memory_usage_mb: u64,
}

/// Performance trend
#[derive(Debug, Clone)]
enum PerformanceTrend {
    Improving,
    Stable,
    Degrading,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PublicKey;

    #[test]
    fn test_optimized_dag_mempool_creation() {
        let validators = vec![PublicKey::new("validator1".to_string())];
        let config = DagOptimizationConfig {
            max_parallel_batches: 4,
            batch_size: 10,
            conflict_window_size: 100,
            certificate_threshold: 3,
            optimization_interval_ms: 1000,
            adaptive_batching_enabled: true,
            priority_queue_size: 1000,
        };

        let mempool = OptimizedDagMempool::new(validators, config);
        let stats = mempool.get_optimization_stats();

        assert_eq!(stats.total_transactions_processed, 0);
        assert_eq!(stats.priority_queue_size, 0);
    }

    #[test]
    fn test_dag_optimization_engine_creation() {
        let config = DagOptimizationConfig {
            max_parallel_batches: 4,
            batch_size: 10,
            conflict_window_size: 100,
            certificate_threshold: 3,
            optimization_interval_ms: 1000,
            adaptive_batching_enabled: true,
            priority_queue_size: 1000,
        };

        let engine = DagOptimizationEngine::new(config);
        let stats = engine.get_optimization_stats();

        assert_eq!(stats.optimization_cycles, 0);
        assert_eq!(stats.last_optimization, 0);
    }

    #[tokio::test]
    async fn test_priority_calculation() {
        let validators = vec![PublicKey::new("validator1".to_string())];
        let config = DagOptimizationConfig {
            max_parallel_batches: 4,
            batch_size: 10,
            conflict_window_size: 100,
            certificate_threshold: 3,
            optimization_interval_ms: 1000,
            adaptive_batching_enabled: true,
            priority_queue_size: 1000,
        };

        let mempool = OptimizedDagMempool::new(validators, config);

        // Create test transaction
        let (sender_key, private_key) = crate::types::Transaction::generate_keypair();
        let receiver = PublicKey::new("receiver".to_string());
        let mut tx = Transaction::new(sender_key, receiver, 100, 50, 0); // High fee
        tx.sign(&private_key).unwrap();

        let priority = mempool.calculate_transaction_priority(&tx).await.unwrap();
        assert!(priority > 0.0);
    }

    #[test]
    fn test_transaction_priority_ordering() {
        let tx1 = TransactionPriority {
            tx_hash: Hash::new(b"tx1"),
            priority_score: 100.0,
            timestamp: 1000,
        };

        let tx2 = TransactionPriority {
            tx_hash: Hash::new(b"tx2"),
            priority_score: 50.0,
            timestamp: 1000,
        };

        let tx3 = TransactionPriority {
            tx_hash: Hash::new(b"tx3"),
            priority_score: 100.0,
            timestamp: 2000, // Later timestamp, same priority
        };

        // tx1 should have highest priority (highest score)
        // tx3 should have higher priority than tx2 (same score, earlier timestamp)
        assert!(tx1 > tx2);
        assert!(tx3 > tx2);
        assert!(tx1.cmp(&tx3) == std::cmp::Ordering::Equal); // Same priority, but tx1 has earlier timestamp
    }

    #[test]
    fn test_optimization_stats() {
        let mut stats = OptimizationStats::new();

        stats.total_transactions_processed = 100;
        stats.priority_queue_size = 50;
        stats.average_batch_size = 10.0;
        stats.conflict_rate = 0.05;

        assert_eq!(stats.total_transactions_processed, 100);
        assert_eq!(stats.priority_queue_size, 50);
        assert_eq!(stats.average_batch_size, 10.0);
        assert_eq!(stats.conflict_rate, 0.05);
    }
}
