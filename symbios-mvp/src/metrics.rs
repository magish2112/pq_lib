use prometheus::{Encoder, TextEncoder, register_gauge, register_counter, register_histogram};
use prometheus::{Gauge, Counter, Histogram};
use lazy_static::lazy_static;

lazy_static! {
    // Block metrics
    pub static ref BLOCK_HEIGHT: Gauge = register_gauge!("symbios_block_height", "Current block height").unwrap();
    pub static ref BLOCK_FINALIZATION_TIME: Histogram = register_histogram!("symbios_block_finalization_time", "Time to finalize a block").unwrap();

    // Transaction metrics
    pub static ref TRANSACTIONS_TOTAL: Counter = register_counter!("symbios_transactions_total", "Total number of transactions").unwrap();
    pub static ref TRANSACTIONS_PER_SECOND: Gauge = register_gauge!("symbios_transactions_per_second", "Current TPS rate").unwrap();

    // Mempool metrics
    pub static ref MEMPOOL_SIZE: Gauge = register_gauge!("symbios_mempool_size", "Current mempool size").unwrap();
    pub static ref MEMPOOL_TRANSACTIONS_ADDED: Counter = register_counter!("symbios_mempool_transactions_added", "Transactions added to mempool").unwrap();
    pub static ref MEMPOOL_TRANSACTIONS_REMOVED: Counter = register_counter!("symbios_mempool_transactions_removed", "Transactions removed from mempool").unwrap();

    // Consensus metrics
    pub static ref CONSENSUS_ROUND: Gauge = register_gauge!("symbios_consensus_round", "Current consensus round").unwrap();
    pub static ref CONSENSUS_PROPOSALS: Counter = register_counter!("symbios_consensus_proposals", "Number of block proposals").unwrap();
    pub static ref CONSENSUS_VOTES: Counter = register_counter!("symbios_consensus_votes", "Number of consensus votes").unwrap();

    // Network metrics
    pub static ref PEERS_CONNECTED: Gauge = register_gauge!("symbios_peers_connected", "Number of connected peers").unwrap();
    pub static ref NETWORK_MESSAGES_SENT: Counter = register_counter!("symbios_network_messages_sent", "Network messages sent").unwrap();
    pub static ref NETWORK_MESSAGES_RECEIVED: Counter = register_counter!("symbios_network_messages_received", "Network messages received").unwrap();

    // Storage metrics
    pub static ref STORAGE_SIZE_BYTES: Gauge = register_gauge!("symbios_storage_size_bytes", "Storage size in bytes").unwrap();
    pub static ref STORAGE_OPERATIONS: Counter = register_counter!("symbios_storage_operations", "Storage operations performed").unwrap();

    // DAG Mempool metrics
    pub static ref DAG_VERTICES_TOTAL: Gauge = register_gauge!("symbios_dag_vertices_total", "Total vertices in DAG").unwrap();
    pub static ref DAG_CERTIFICATES_TOTAL: Gauge = register_gauge!("symbios_dag_certificates_total", "Total certificates in DAG").unwrap();
    pub static ref DAG_CURRENT_ROUND: Gauge = register_gauge!("symbios_dag_current_round", "Current DAG round").unwrap();
    pub static ref DAG_BLOCKS_PER_SECOND: Gauge = register_gauge!("symbios_dag_blocks_per_second", "DAG blocks created per second").unwrap();
    pub static ref DAG_CERTIFICATES_CREATED: Counter = register_counter!("symbios_dag_certificates_created", "Certificates created in DAG").unwrap();

    // Production Node metrics
    pub static ref NODE_UPTIME_SECONDS: Gauge = register_gauge!("symbios_node_uptime_seconds", "Node uptime in seconds").unwrap();
    pub static ref NODE_BLOCKS_PROCESSED: Counter = register_counter!("symbios_node_blocks_processed", "Total blocks processed").unwrap();
    pub static ref NODE_TRANSACTIONS_PROCESSED: Counter = register_counter!("symbios_node_transactions_processed", "Total transactions processed").unwrap();
    pub static ref NODE_MEMORY_USAGE_MB: Gauge = register_gauge!("symbios_node_memory_usage_mb", "Current memory usage in MB").unwrap();
    pub static ref NODE_STORAGE_USAGE_MB: Gauge = register_gauge!("symbios_node_storage_usage_mb", "Current storage usage in MB").unwrap();
    pub static ref NODE_TPS_AVERAGE: Gauge = register_gauge!("symbios_node_tps_average", "Average transactions per second").unwrap();

    // Execution Engine metrics
    pub static ref EXECUTION_ACTIVE_TRANSACTIONS: Gauge = register_gauge!("symbios_execution_active_transactions", "Currently executing transactions").unwrap();
    pub static ref EXECUTION_COMMITTED_TRANSACTIONS: Counter = register_counter!("symbios_execution_committed_transactions", "Successfully committed transactions").unwrap();
    pub static ref EXECUTION_ABORTED_TRANSACTIONS: Counter = register_counter!("symbios_execution_aborted_transactions", "Aborted transactions").unwrap();
    pub static ref EXECUTION_MEMORY_USAGE: Gauge = register_gauge!("symbios_execution_memory_usage", "Execution engine memory usage").unwrap();

    // Lightweight Consensus metrics
    pub static ref CONSENSUS_ACTIVE_PROPOSALS: Gauge = register_gauge!("symbios_consensus_active_proposals", "Active block proposals").unwrap();
    pub static ref CONSENSUS_TOTAL_VOTES: Counter = register_counter!("symbios_consensus_total_votes", "Total consensus votes").unwrap();
    pub static ref CONSENSUS_MEMORY_USAGE: Gauge = register_gauge!("symbios_consensus_memory_usage", "Consensus memory usage").unwrap();

    // Minimal Storage metrics
    pub static ref STORAGE_TOTAL_ENTRIES: Gauge = register_gauge!("symbios_storage_total_entries", "Total entries in storage").unwrap();
    pub static ref STORAGE_FILE_SIZE: Gauge = register_gauge!("symbios_storage_file_size", "Storage file size in bytes").unwrap();
    pub static ref STORAGE_FRAGMENTATION_RATIO: Gauge = register_gauge!("symbios_storage_fragmentation_ratio", "Storage fragmentation ratio").unwrap();
}

/// Metrics server for exposing Prometheus metrics
pub struct MetricsServer {
    port: u16,
}

impl MetricsServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        use warp::Filter;

        let metrics_route = warp::path!("metrics")
            .map(|| {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                String::from_utf8(buffer).unwrap()
            });

        log::info!("Starting metrics server on port {}", self.port);
        warp::serve(metrics_route)
            .run(([0, 0, 0, 0], self.port))
            .await;

        Ok(())
    }
}

/// Initialize all metrics with default values
pub fn init_metrics() {
    // Set initial values
    BLOCK_HEIGHT.set(0.0);
    MEMPOOL_SIZE.set(0.0);
    PEERS_CONNECTED.set(0.0);
    CONSENSUS_ROUND.set(0.0);
    TRANSACTIONS_PER_SECOND.set(0.0);
    STORAGE_SIZE_BYTES.set(0.0);
}

/// Update metrics based on current state
pub fn update_metrics(block_height: u64, mempool_size: usize, peers_count: usize, consensus_round: u64) {
    BLOCK_HEIGHT.set(block_height as f64);
    MEMPOOL_SIZE.set(mempool_size as f64);
    PEERS_CONNECTED.set(peers_count as f64);
    CONSENSUS_ROUND.set(consensus_round as f64);
}

/// Update DAG-specific metrics
pub fn update_dag_metrics(vertices_total: usize, certificates_total: usize, current_round: u64) {
    DAG_VERTICES_TOTAL.set(vertices_total as f64);
    DAG_CERTIFICATES_TOTAL.set(certificates_total as f64);
    DAG_CURRENT_ROUND.set(current_round as f64);
}

/// Update production node metrics
pub fn update_node_metrics(uptime_seconds: u64, blocks_processed: u64, transactions_processed: u64, memory_usage_mb: usize, storage_usage_mb: usize, tps_average: f64) {
    NODE_UPTIME_SECONDS.set(uptime_seconds as f64);
    NODE_BLOCKS_PROCESSED.inc_by(blocks_processed);
    NODE_TRANSACTIONS_PROCESSED.inc_by(transactions_processed);
    NODE_MEMORY_USAGE_MB.set(memory_usage_mb as f64);
    NODE_STORAGE_USAGE_MB.set(storage_usage_mb as f64);
    NODE_TPS_AVERAGE.set(tps_average);
}

/// Update execution engine metrics
pub fn update_execution_metrics(active_transactions: usize, committed: u64, aborted: u64, memory_usage: usize) {
    EXECUTION_ACTIVE_TRANSACTIONS.set(active_transactions as f64);
    EXECUTION_COMMITTED_TRANSACTIONS.inc_by(committed);
    EXECUTION_ABORTED_TRANSACTIONS.inc_by(aborted);
    EXECUTION_MEMORY_USAGE.set(memory_usage as f64);
}

/// Update consensus metrics
pub fn update_consensus_metrics(active_proposals: usize, total_votes: usize, memory_usage: usize) {
    CONSENSUS_ACTIVE_PROPOSALS.set(active_proposals as f64);
    CONSENSUS_TOTAL_VOTES.inc_by(total_votes as u64);
    CONSENSUS_MEMORY_USAGE.set(memory_usage as f64);
}

/// Update storage metrics
pub fn update_storage_metrics(total_entries: usize, file_size: u64, fragmentation_ratio: f64) {
    STORAGE_TOTAL_ENTRIES.set(total_entries as f64);
    STORAGE_FILE_SIZE.set(file_size as f64);
    STORAGE_FRAGMENTATION_RATIO.set(fragmentation_ratio);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        init_metrics();
        assert_eq!(BLOCK_HEIGHT.get(), 0.0);
        assert_eq!(MEMPOOL_SIZE.get(), 0.0);
    }
}
