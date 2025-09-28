//! Production-Ready Symbios Node
//!
//! This module implements a highly optimized blockchain node designed to run
//! efficiently on minimal hardware while providing high performance and reliability.

use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;
use crate::types::{Transaction, Block, State, PublicKey, PrivateKey, create_genesis_block};
use crate::lightweight_consensus::{LightweightConsensus, ConsensusStats};
use crate::efficient_execution::{EfficientExecutionEngine, ExecutionStats};
use crate::minimal_storage::{MinimalStorage, StorageStats};
use crate::dag_mempool::{SmartDagMempool, CertificateGenerator};
use crate::storage::StorageTrait;
use crate::consensus::ConsensusTrait;

/// Production node configuration
#[derive(Debug, Clone)]
pub struct ProductionConfig {
    pub node_id: String,
    pub data_dir: String,
    pub consensus_round_duration: u64,
    pub max_memory_mb: usize,
    pub max_storage_mb: usize,
    pub max_parallel_batch: usize,
    pub metrics_port: u16,
}

impl Default for ProductionConfig {
    fn default() -> Self {
        Self {
            node_id: "production-node".to_string(),
            data_dir: "./data".to_string(),
            consensus_round_duration: 3, // 3 seconds for fast consensus
            max_memory_mb: 256, // 256MB memory limit
            max_storage_mb: 1024, // 1GB storage limit
            max_parallel_batch: 50, // 50 parallel transactions
            metrics_port: 9101,
        }
    }
}

/// Production blockchain node
pub struct ProductionNode {
    config: ProductionConfig,
    storage: Arc<MinimalStorage>,
    consensus: Arc<RwLock<LightweightConsensus>>,
    execution_engine: Arc<EfficientExecutionEngine>,
    dag_mempool: Arc<RwLock<SmartDagMempool>>,
    node_id: PublicKey,
    private_key: PrivateKey,
    validators: Vec<PublicKey>,
    stats: Arc<RwLock<NodeStats>>,
}

#[derive(Debug, Clone)]
pub struct NodeStats {
    pub uptime_seconds: u64,
    pub blocks_processed: u64,
    pub transactions_processed: u64,
    pub consensus_rounds: u64,
    pub memory_usage_mb: usize,
    pub storage_usage_mb: usize,
    pub tps_average: f64,
}

impl ProductionNode {
    pub async fn new(config: ProductionConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Create data directory
        std::fs::create_dir_all(&config.data_dir)?;

        // Initialize storage
        let storage_path = format!("{}/{}.db", config.data_dir, config.node_id);
        let storage = Arc::new(MinimalStorage::new(storage_path, config.max_storage_mb)?);

        // Create node keys (in production, load from secure storage)
        let node_id = PublicKey(format!("validator_{}", config.node_id).into_bytes());
        let private_key = PrivateKey(format!("private_key_{}", config.node_id).into_bytes());

        // Create validator set (in production, load from network)
        let validators = vec![
            PublicKey("validator_validator-1".to_string().into_bytes()),
            PublicKey("validator_validator-2".to_string().into_bytes()),
            PublicKey("validator_validator-3".to_string().into_bytes()),
            PublicKey("validator_validator-4".to_string().into_bytes()),
        ];

        // Initialize consensus
        let consensus = Arc::new(RwLock::new(LightweightConsensus::new(
            node_id.clone(),
            private_key.clone(),
            validators.clone(),
            config.consensus_round_duration,
            config.max_memory_mb,
        )));

        // Initialize execution engine
        let initial_state = storage.get_state().await.unwrap_or_else(|_| State::new());
        let execution_engine = Arc::new(EfficientExecutionEngine::new(
            initial_state,
            config.max_parallel_batch,
            config.max_memory_mb,
        ));

        // Initialize Smart DAG mempool
        let dag_mempool = Arc::new(RwLock::new(SmartDagMempool::new(validators.clone(), config.max_parallel_batch)));

        // Initialize genesis block if needed
        Self::ensure_genesis_block(&storage).await?;

        let stats = Arc::new(RwLock::new(NodeStats {
            uptime_seconds: 0,
            blocks_processed: 0,
            transactions_processed: 0,
            consensus_rounds: 0,
            memory_usage_mb: 0,
            storage_usage_mb: 0,
            tps_average: 0.0,
        }));

        Ok(Self {
            config,
            storage,
            consensus,
            execution_engine,
            dag_mempool,
            node_id,
            private_key,
            validators,
            stats,
        })
    }

    /// Ensure genesis block exists
    async fn ensure_genesis_block(storage: &MinimalStorage) -> Result<(), Box<dyn std::error::Error>> {
        if storage.get_block_by_height(0).await?.is_none() {
            log::info!("Creating genesis block...");
            let genesis = create_genesis_block();
            storage.store_block(&genesis).await?;

            let mut state = State::new();
            state.apply_block(&genesis)?;
            storage.store_state(&state).await?;
        }
        Ok(())
    }

    /// Start the production node
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🚀 Starting Symbios Production Node: {}", self.config.node_id);
        log::info!("📊 Configuration:");
        log::info!("   Memory limit: {} MB", self.config.max_memory_mb);
        log::info!("   Storage limit: {} MB", self.config.max_storage_mb);
        log::info!("   Consensus round: {}s", self.config.consensus_round_duration);
        log::info!("   Max parallel batch: {}", self.config.max_parallel_batch);

        // Start background tasks
        let node = Arc::new(self.clone());
        tokio::spawn(Self::consensus_loop(Arc::clone(&node)));
        tokio::spawn(Self::execution_loop(Arc::clone(&node)));
        tokio::spawn(Self::maintenance_loop(Arc::clone(&node)));

        log::info!("✅ Production node started successfully");
        Ok(())
    }

    /// Consensus loop - handles block proposal and validation
    async fn consensus_loop(node: Arc<ProductionNode>) {
        let mut round_start = std::time::Instant::now();

        loop {
            // Check if round timed out
            if node.consensus.read().await.round_timed_out() {
                let mut consensus = node.consensus.write().await;
                consensus.advance_round();

                // Update stats
                {
                    let mut stats = node.stats.write().await;
                    stats.consensus_rounds += 1;
                }

                round_start = std::time::Instant::now();
                log::debug!("Advanced to consensus round {}", consensus.state.current_round);
            }

            // Check if we're the leader and have transactions to propose
            if node.consensus.read().await.is_leader() {
                let pending_count = node.dag_mempool.read().await.pending_transactions_count();
                if pending_count >= 10 { // Minimum batch size
                    if let Err(e) = node.propose_block().await {
                        log::error!("Failed to propose block: {}", e);
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Execution loop - processes pending transactions
    async fn execution_loop(node: Arc<ProductionNode>) {
        loop {
            // Process pending transactions in parallel
            let pending_txs = {
                let dag_mempool = node.dag_mempool.read().await;
                dag_mempool.get_pending_transactions(100).await.unwrap_or_default()
            };

            if !pending_txs.is_empty() {
                if let Err(e) = node.execution_engine.execute_batch(pending_txs.clone()).await {
                    log::warn!("Batch execution failed: {}", e);
                } else {
                    // Update transaction count
                    let mut stats = node.stats.write().await;
                    stats.transactions_processed += pending_txs.len() as u64;

                    log::debug!("Executed {} transactions in parallel", pending_txs.len());
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    /// Maintenance loop - cleanup and statistics
    async fn maintenance_loop(node: Arc<ProductionNode>) {
        let mut last_cleanup = std::time::Instant::now();
        let mut last_stats_update = std::time::Instant::now();

        loop {
            let now = std::time::Instant::now();

            // Periodic cleanup (every 60 seconds)
            if now.duration_since(last_cleanup).as_secs() >= 60 {
                node.perform_maintenance().await;
                last_cleanup = now;
            }

            // Statistics update (every 10 seconds)
            if now.duration_since(last_stats_update).as_secs() >= 10 {
                node.update_statistics().await;
                last_stats_update = now;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    /// Propose a new block
    async fn propose_block(&self) -> Result<(), Box<dyn std::error::Error>> {
        let transactions = self.dag_mempool.read().await.get_pending_transactions(50).await?;
        if transactions.is_empty() {
            return Ok(());
        }

        let state = self.storage.get_state().await?;
        let height = state.height + 1;

        // Create block
        let mut block = Block::new(
            state.last_block_hash,
            height,
            transactions.clone(),
            self.node_id.clone()
        );

        // Execute transactions first
        self.execution_engine.execute_batch(transactions).await?;

        // Propose block via consensus
        {
            let mut consensus = self.consensus.write().await;
            consensus.propose_block(vec![], &*self.dag_mempool.read().await, &*self.storage).await?;
        }

        // Create DAG certificate
        let certificate = CertificateGenerator::generate_certificate(
            block.hash(),
            self.node_id.clone(),
            self.consensus.read().await.state.current_round,
            vec![],
        )?;

        // Add to DAG mempool
        self.dag_mempool.write().await.add_certificate(certificate).await?;

        // Finalize block
        {
            let mut consensus = self.consensus.write().await;
            consensus.finalize_block(block, &*self.storage).await?;
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.blocks_processed += 1;
        }

        log::info!("Proposed and finalized block at height {}", height);
        Ok(())
    }

    /// Perform maintenance tasks
    async fn perform_maintenance(&self) {
        // Clean up consensus state
        {
            let mut consensus = self.consensus.write().await;
            consensus.state.cleanup_old_data();
        }

        // Clean up DAG mempool
        {
            let mut dag = self.dag_mempool.write().await;
            dag.cleanup();
        }

        // Log current stats
        let stats = self.stats.read().await;
        log::info!("Maintenance completed - Blocks: {}, TXs: {}, TPS: {:.1f}",
            stats.blocks_processed, stats.transactions_processed, stats.tps_average);
    }

    /// Update node statistics
    async fn update_statistics(&self) {
        let mut stats = self.stats.write().await;

        // Update uptime
        stats.uptime_seconds += 10;

        // Calculate TPS
        if stats.uptime_seconds > 0 {
            stats.tps_average = stats.transactions_processed as f64 / stats.uptime_seconds as f64;
        }

        // Update memory usage (simplified)
        stats.memory_usage_mb = self.consensus.read().await.memory_usage() / (1024 * 1024);

        // Update storage usage
        let storage_stats = self.storage.get_stats().await;
        stats.storage_usage_mb = (storage_stats.file_size / (1024 * 1024)) as usize;
    }

    /// Get current node statistics
    pub async fn get_stats(&self) -> NodeStats {
        self.stats.read().await.clone()
    }

    /// Submit transaction to the node
    pub async fn submit_transaction(&self, tx: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        // Validate transaction
        if !self.execution_engine.validate_transaction(&tx).await? {
            return Err("Transaction validation failed".into());
        }

        // Add to mempool
        let mut dag_mempool = self.dag_mempool.write().await;
        dag_mempool.add_transaction(tx).await?;

        Ok(())
    }

    /// Get current blockchain state
    pub async fn get_blockchain_state(&self) -> Result<State, Box<dyn std::error::Error>> {
        self.storage.get_state().await
    }

    /// Get consensus statistics
    pub async fn get_consensus_stats(&self) -> ConsensusStats {
        self.consensus.read().await.get_stats()
    }

    /// Get execution statistics
    pub async fn get_execution_stats(&self) -> Result<ExecutionStats, Box<dyn std::error::error::Error>> {
        self.execution_engine.get_execution_stats().await
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> StorageStats {
        self.storage.get_stats().await
    }
}

impl Clone for ProductionNode {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            storage: Arc::clone(&self.storage),
            consensus: Arc::clone(&self.consensus),
            execution_engine: Arc::clone(&self.execution_engine),
            dag_mempool: Arc::clone(&self.dag_mempool),
            node_id: self.node_id.clone(),
            private_key: self.private_key.clone(),
            validators: self.validators.clone(),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Node factory for creating production nodes
pub struct ProductionNodeFactory;

impl ProductionNodeFactory {
    pub async fn create_node(config: ProductionConfig) -> Result<ProductionNode, Box<dyn std::error::Error>> {
        ProductionNode::new(config).await
    }

    pub fn create_default_config() -> ProductionConfig {
        ProductionConfig::default()
    }

    pub fn create_minimal_config() -> ProductionConfig {
        ProductionConfig {
            node_id: "minimal-node".to_string(),
            data_dir: "./data".to_string(),
            consensus_round_duration: 5, // Longer rounds for minimal resources
            max_memory_mb: 64, // 64MB for very constrained environments
            max_storage_mb: 256, // 256MB storage
            max_parallel_batch: 10, // Smaller batches
            metrics_port: 9101,
        }
    }

    pub fn create_high_performance_config() -> ProductionConfig {
        ProductionConfig {
            node_id: "high-perf-node".to_string(),
            data_dir: "./data".to_string(),
            consensus_round_duration: 2, // Faster consensus
            max_memory_mb: 1024, // 1GB memory
            max_storage_mb: 10240, // 10GB storage
            max_parallel_batch: 200, // Larger batches
            metrics_port: 9101,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_production_config() {
        let config = ProductionConfig::default();
        assert_eq!(config.max_memory_mb, 256);
        assert_eq!(config.consensus_round_duration, 3);
        assert_eq!(config.max_parallel_batch, 50);
    }

    #[tokio::test]
    async fn test_minimal_config() {
        let config = ProductionNodeFactory::create_minimal_config();
        assert_eq!(config.max_memory_mb, 64);
        assert_eq!(config.consensus_round_duration, 5);
        assert_eq!(config.max_parallel_batch, 10);
    }

    #[tokio::test]
    async fn test_node_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ProductionConfig::default();
        config.data_dir = temp_dir.path().to_string_lossy().to_string();

        let node = ProductionNode::new(config).await;
        assert!(node.is_ok());
    }

    #[tokio::test]
    async fn test_node_stats() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ProductionConfig::default();
        config.data_dir = temp_dir.path().to_string_lossy().to_string();

        let node = ProductionNode::new(config).await.unwrap();
        let stats = node.get_stats().await;

        assert_eq!(stats.uptime_seconds, 0);
        assert_eq!(stats.blocks_processed, 0);
        assert_eq!(stats.transactions_processed, 0);
    }
}

