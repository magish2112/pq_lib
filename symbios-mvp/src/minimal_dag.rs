//! Minimal DAG Mempool Implementation
//!
//! This module provides a simplified DAG-based mempool focused on
//! transaction storage, dependency checking, and ordering queue.

use std::collections::{HashMap, HashSet, BinaryHeap};
use serde::{Serialize, Deserialize};
use crate::types::{Transaction, Hash, PublicKey};

/// Minimal DAG mempool configuration
#[derive(Debug, Clone)]
pub struct MinimalDagConfig {
    pub max_pending_transactions: usize,
    pub max_dag_depth: usize,
    pub batch_size: usize,
}

/// Simplified DAG vertex for transaction dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagVertex {
    pub tx_hash: Hash,
    pub dependencies: Vec<Hash>,
    pub dependents: Vec<Hash>,
    pub timestamp: u64,
    pub priority: f64,
}

/// Minimal DAG mempool implementation
pub struct MinimalDagMempool {
    config: MinimalDagConfig,
    vertices: HashMap<Hash, DagVertex>,
    pending_transactions: BinaryHeap<TransactionPriority>,
    processed_transactions: HashSet<Hash>,
    transaction_storage: HashMap<Hash, Transaction>,
}

impl MinimalDagMempool {
    /// Create new minimal DAG mempool
    pub fn new(config: MinimalDagConfig) -> Self {
        Self {
            config,
            vertices: HashMap::new(),
            pending_transactions: BinaryHeap::new(),
            processed_transactions: HashSet::new(),
            transaction_storage: HashMap::new(),
        }
    }

    /// Add transaction to DAG mempool
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        // Check if transaction already processed
        if self.processed_transactions.contains(&tx.id) {
            return Err("Transaction already processed".to_string());
        }

        // Check if transaction already in mempool
        if self.transaction_storage.contains_key(&tx.id) {
            return Err("Transaction already in mempool".to_string());
        }

        // Validate transaction dependencies
        self.validate_dependencies(&tx)?;

        // Calculate priority (fee + timestamp based)
        let priority = self.calculate_priority(&tx);

        // Create DAG vertex
        let vertex = DagVertex {
            tx_hash: tx.id,
            dependencies: self.find_dependencies(&tx),
            dependents: Vec::new(),
            timestamp: tx.timestamp,
            priority,
        };

        // Store transaction and vertex
        self.transaction_storage.insert(tx.id, tx.clone());
        self.vertices.insert(tx.id, vertex);

        // Add to priority queue
        self.pending_transactions.push(TransactionPriority {
            tx_hash: tx.id,
            priority,
            timestamp: tx.timestamp,
        });

        // Update dependent relationships
        self.update_dependencies(&tx.id);

        // Trim mempool if too large
        self.trim_mempool();

        Ok(())
    }

    /// Validate transaction dependencies
    fn validate_dependencies(&self, tx: &Transaction) -> Result<(), String> {
        // Check if all dependencies exist and are valid
        for dep_hash in &self.find_dependencies(tx) {
            if !self.transaction_storage.contains_key(dep_hash) {
                return Err(format!("Missing dependency: {:?}", dep_hash));
            }

            // Check for cycles (simplified check)
            if self.would_create_cycle(&tx.id, dep_hash) {
                return Err("Transaction would create cycle".to_string());
            }
        }

        Ok(())
    }

    /// Find transaction dependencies
    fn find_dependencies(&self, tx: &Transaction) -> Vec<Hash> {
        let mut dependencies = Vec::new();

        // Find transactions that modify accounts this tx depends on
        for (other_hash, other_tx) in &self.transaction_storage {
            // Check if other_tx modifies an account that tx reads/writes
            if (other_tx.sender == tx.sender && other_tx.nonce < tx.nonce) ||
               (other_tx.receiver == tx.sender) ||
               (other_tx.sender == tx.receiver) {
                dependencies.push(*other_hash);
            }
        }

        dependencies
    }

    /// Check if adding tx would create a cycle
    fn would_create_cycle(&self, new_tx: &Hash, dependency: &Hash) -> bool {
        // Simple cycle detection - check if dependency depends on new_tx
        if let Some(dep_vertex) = self.vertices.get(dependency) {
            dep_vertex.dependencies.contains(new_tx)
        } else {
            false
        }
    }

    /// Update dependent relationships when adding new transaction
    fn update_dependencies(&mut self, new_tx_hash: &Hash) {
        // Update dependents of dependencies
        if let Some(new_vertex) = self.vertices.get(new_tx_hash) {
            for dep_hash in &new_vertex.dependencies {
                if let Some(dep_vertex) = self.vertices.get_mut(dep_hash) {
                    if !dep_vertex.dependents.contains(new_tx_hash) {
                        dep_vertex.dependents.push(*new_tx_hash);
                    }
                }
            }
        }
    }

    /// Calculate transaction priority (fee + age based)
    fn calculate_priority(&self, tx: &Transaction) -> f64 {
        let fee_priority = tx.fee as f64 * 0.8;

        // Age bonus (older transactions get slight priority boost)
        let age_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 - tx.timestamp;

        let age_priority = if age_ms > 1000 {
            (age_ms / 1000) as f64 * 0.1
        } else {
            0.0
        };

        fee_priority + age_priority
    }

    /// Get transactions ready for execution (no pending dependencies)
    pub fn get_executable_transactions(&self, max_count: usize) -> Vec<Transaction> {
        let mut executable = Vec::new();

        // Find transactions with no unprocessed dependencies
        for (tx_hash, vertex) in &self.vertices {
            if self.processed_transactions.contains(tx_hash) {
                continue;
            }

            let all_deps_processed = vertex.dependencies.iter()
                .all(|dep| self.processed_transactions.contains(dep));

            if all_deps_processed {
                if let Some(tx) = self.transaction_storage.get(tx_hash) {
                    executable.push(tx.clone());

                    if executable.len() >= max_count {
                        break;
                    }
                }
            }
        }

        // Sort by priority (highest first)
        executable.sort_by(|a, b| {
            let a_priority = self.calculate_priority(a);
            let b_priority = self.calculate_priority(b);
            b_priority.partial_cmp(&a_priority).unwrap_or(std::cmp::Ordering::Equal)
        });

        executable
    }

    /// Mark transactions as processed
    pub fn mark_processed(&mut self, tx_hashes: &[Hash]) {
        for hash in tx_hashes {
            self.processed_transactions.insert(*hash);
        }
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.transaction_storage.len() - self.processed_transactions.len()
    }

    /// Get DAG depth (maximum dependency chain length)
    pub fn dag_depth(&self) -> usize {
        // Simplified depth calculation
        let mut max_depth = 0;

        for vertex in self.vertices.values() {
            let depth = self.calculate_vertex_depth(vertex);
            max_depth = max_depth.max(depth);
        }

        max_depth
    }

    /// Calculate depth for a single vertex
    fn calculate_vertex_depth(&self, vertex: &DagVertex) -> usize {
        if vertex.dependencies.is_empty() {
            1
        } else {
            let mut max_dep_depth = 0;
            for dep_hash in &vertex.dependencies {
                if let Some(dep_vertex) = self.vertices.get(dep_hash) {
                    max_dep_depth = max_dep_depth.max(self.calculate_vertex_depth(dep_vertex));
                }
            }
            max_dep_depth + 1
        }
    }

    /// Trim mempool to prevent memory bloat
    fn trim_mempool(&mut self) {
        while self.transaction_storage.len() > self.config.max_pending_transactions {
            if let Some(lowest_priority) = self.pending_transactions.pop() {
                self.transaction_storage.remove(&lowest_priority.tx_hash);
                self.vertices.remove(&lowest_priority.tx_hash);
            } else {
                break;
            }
        }
    }

    /// Get mempool statistics
    pub fn get_stats(&self) -> DagMempoolStats {
        DagMempoolStats {
            total_transactions: self.transaction_storage.len(),
            pending_transactions: self.pending_count(),
            processed_transactions: self.processed_transactions.len(),
            dag_depth: self.dag_depth(),
            priority_queue_size: self.pending_transactions.len(),
        }
    }
}

/// Transaction priority for ordering
#[derive(Debug, Clone)]
struct TransactionPriority {
    tx_hash: Hash,
    priority: f64,
    timestamp: u64,
}

impl Ord for TransactionPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.partial_cmp(&other.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| other.timestamp.cmp(&self.timestamp)) // Earlier timestamp wins
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

/// DAG mempool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagMempoolStats {
    pub total_transactions: usize,
    pub pending_transactions: usize,
    pub processed_transactions: usize,
    pub dag_depth: usize,
    pub priority_queue_size: usize,
}

/// Ordering queue for consensus
pub struct OrderingQueue {
    pending_blocks: VecDeque<BlockProposal>,
    max_queue_size: usize,
}

impl OrderingQueue {
    /// Create new ordering queue
    pub fn new(max_size: usize) -> Self {
        Self {
            pending_blocks: VecDeque::new(),
            max_queue_size: max_size,
        }
    }

    /// Add block proposal to queue
    pub fn enqueue_block(&mut self, proposal: BlockProposal) {
        if self.pending_blocks.len() < self.max_queue_size {
            self.pending_blocks.push_back(proposal);
        }
    }

    /// Get next block for consensus
    pub fn dequeue_block(&mut self) -> Option<BlockProposal> {
        self.pending_blocks.pop_front()
    }

    /// Get queue length
    pub fn len(&self) -> usize {
        self.pending_blocks.len()
    }
}

/// Block proposal for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    pub block_hash: Hash,
    pub transactions: Vec<Transaction>,
    pub proposer: PublicKey,
    pub timestamp: u64,
    pub priority: f64,
}

/// Minimal gossip implementation for transaction relay
pub struct MinimalGossip {
    known_transactions: HashSet<Hash>,
    message_queue: VecDeque<NetworkMessage>,
}

impl MinimalGossip {
    /// Create new gossip instance
    pub fn new() -> Self {
        Self {
            known_transactions: HashSet::new(),
            message_queue: VecDeque::new(),
        }
    }

    /// Broadcast transaction to network
    pub fn broadcast_transaction(&mut self, tx: Transaction) {
        if !self.known_transactions.contains(&tx.id) {
            self.known_transactions.insert(tx.id);
            self.message_queue.push_back(NetworkMessage::Transaction(tx));
        }
    }

    /// Get pending messages to send
    pub fn get_pending_messages(&mut self) -> Vec<NetworkMessage> {
        self.message_queue.drain(..).collect()
    }

    /// Receive transaction from network
    pub fn receive_transaction(&mut self, tx: Transaction) {
        if !self.known_transactions.contains(&tx.id) {
            self.known_transactions.insert(tx.id);
            // In real implementation, this would trigger further gossip
        }
    }
}

/// Network message types for minimal protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(BlockProposal),
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PublicKey;

    #[test]
    fn test_minimal_dag_creation() {
        let config = MinimalDagConfig {
            max_pending_transactions: 1000,
            max_dag_depth: 10,
            batch_size: 10,
        };

        let mempool = MinimalDagMempool::new(config);
        let stats = mempool.get_stats();

        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.pending_transactions, 0);
        assert_eq!(stats.dag_depth, 0);
    }

    #[test]
    fn test_transaction_priority_ordering() {
        let tx1 = TransactionPriority {
            tx_hash: Hash::new(b"tx1"),
            priority: 100.0,
            timestamp: 1000,
        };

        let tx2 = TransactionPriority {
            tx_hash: Hash::new(b"tx2"),
            priority: 50.0,
            timestamp: 1000,
        };

        let tx3 = TransactionPriority {
            tx_hash: Hash::new(b"tx3"),
            priority: 100.0,
            timestamp: 2000, // Later timestamp
        };

        // tx1 should have highest priority
        assert!(tx1 > tx2);

        // tx3 should have higher priority than tx2 (same priority, earlier timestamp)
        assert!(tx3 > tx2);

        // tx1 and tx3 should be equal (same priority, different timestamps)
        assert_eq!(tx1.cmp(&tx3), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_ordering_queue() {
        let mut queue = OrderingQueue::new(10);

        assert_eq!(queue.len(), 0);

        let proposal1 = BlockProposal {
            block_hash: Hash::new(b"block1"),
            transactions: vec![],
            proposer: PublicKey::new("proposer1"),
            timestamp: 1000,
            priority: 100.0,
        };

        let proposal2 = BlockProposal {
            block_hash: Hash::new(b"block2"),
            transactions: vec![],
            proposer: PublicKey::new("proposer2"),
            timestamp: 2000,
            priority: 200.0,
        };

        queue.enqueue_block(proposal1);
        queue.enqueue_block(proposal2);

        assert_eq!(queue.len(), 2);

        let dequeued = queue.dequeue_block().unwrap();
        assert_eq!(dequeued.block_hash, Hash::new(b"block1"));

        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_minimal_gossip() {
        let mut gossip = MinimalGossip::new();

        let tx = Transaction::new(
            PublicKey::new("sender"),
            PublicKey::new("receiver"),
            100,
            10,
            0,
        );

        // Broadcast transaction
        gossip.broadcast_transaction(tx.clone());

        let messages = gossip.get_pending_messages();
        assert_eq!(messages.len(), 1);

        if let NetworkMessage::Transaction(received_tx) = &messages[0] {
            assert_eq!(received_tx.id, tx.id);
        } else {
            panic!("Expected transaction message");
        }
    }

    #[test]
    fn test_dag_stats() {
        let config = MinimalDagConfig {
            max_pending_transactions: 1000,
            max_dag_depth: 10,
            batch_size: 10,
        };

        let mempool = MinimalDagMempool::new(config);
        let stats = mempool.get_stats();

        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.pending_transactions, 0);
        assert_eq!(stats.processed_transactions, 0);
        assert_eq!(stats.dag_depth, 0);
        assert_eq!(stats.priority_queue_size, 0);
    }
}
