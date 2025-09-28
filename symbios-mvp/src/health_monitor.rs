//! Health Monitoring Module for Symbios Network Nodes
//!
//! This module provides comprehensive health checking and monitoring capabilities
//! for blockchain nodes, including performance metrics, connectivity checks,
//! and system health indicators.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// Node health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub node_id: String,
    pub status: HealthStatus,
    pub uptime_seconds: u64,
    pub last_check: u64,
    pub checks: HashMap<String, HealthCheck>,
    pub metrics: NodeMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub last_run: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub disk_usage_gb: f64,
    pub network_connections: u32,
    pub active_peers: u32,
    pub pending_transactions: u64,
    pub processed_blocks: u64,
    pub tps_average: f64,
    pub latency_ms: u64,
    pub sync_progress_percent: f64,
}

/// Health monitor for node monitoring
pub struct HealthMonitor {
    node_id: String,
    start_time: Instant,
    checks: HashMap<String, Box<dyn HealthCheckTrait + Send + Sync>>,
    health_history: Vec<NodeHealth>,
    metrics_history: Vec<NodeMetrics>,
    check_interval: Duration,
}

impl HealthMonitor {
    pub fn new(node_id: String) -> Self {
        let mut monitor = Self {
            node_id,
            start_time: Instant::now(),
            checks: HashMap::new(),
            health_history: Vec::new(),
            metrics_history: Vec::new(),
            check_interval: Duration::from_secs(30),
        };

        // Register default health checks
        monitor.register_check(Box::new(MemoryHealthCheck::new()));
        monitor.register_check(Box::new(DiskHealthCheck::new()));
        monitor.register_check(Box::new(NetworkHealthCheck::new()));
        monitor.register_check(Box::new(ConsensusHealthCheck::new()));

        monitor
    }

    /// Register a health check
    pub fn register_check(&mut self, check: Box<dyn HealthCheckTrait + Send + Sync>) {
        self.checks.insert(check.name().to_string(), check);
    }

    /// Run all health checks
    pub async fn run_health_checks(&mut self) -> NodeHealth {
        let start_time = Instant::now();
        let mut checks = HashMap::new();
        let mut overall_status = HealthStatus::Healthy;

        for (name, check) in &mut self.checks {
            let check_start = Instant::now();
            let result = check.execute().await;
            let duration = check_start.elapsed().as_millis() as u64;

            let check_result = HealthCheck {
                name: name.clone(),
                status: result.status,
                message: result.message,
                last_run: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                duration_ms: duration,
            };

            checks.insert(name.clone(), check_result.clone());

            // Update overall status based on check result
            if matches!(result.status, HealthStatus::Critical) {
                overall_status = HealthStatus::Critical;
            } else if matches!(result.status, HealthStatus::Unhealthy) && !matches!(overall_status, HealthStatus::Critical) {
                overall_status = HealthStatus::Unhealthy;
            } else if matches!(result.status, HealthStatus::Degraded) && matches!(overall_status, HealthStatus::Healthy) {
                overall_status = HealthStatus::Degraded;
            }
        }

        let uptime = self.start_time.elapsed().as_secs();

        let health = NodeHealth {
            node_id: self.node_id.clone(),
            status: overall_status,
            uptime_seconds: uptime,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            checks,
            metrics: self.collect_metrics().await,
        };

        self.health_history.push(health.clone());
        health
    }

    /// Collect current node metrics
    async fn collect_metrics(&mut self) -> NodeMetrics {
        // Collect system metrics (simplified for MVP)
        let cpu_usage = self.get_cpu_usage().await;
        let memory_usage = self.get_memory_usage().await;
        let disk_usage = self.get_disk_usage().await;

        // Network metrics (placeholder)
        let network_connections = 10; // TODO: Get from network layer
        let active_peers = 5; // TODO: Get from network layer

        // Blockchain metrics (placeholder)
        let pending_transactions = 100; // TODO: Get from mempool
        let processed_blocks = 1000; // TODO: Get from storage
        let tps_average = 50.0; // TODO: Calculate TPS
        let latency_ms = 100; // TODO: Measure latency
        let sync_progress_percent = 95.0; // TODO: Get from sync manager

        let metrics = NodeMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_usage,
            disk_usage_gb: disk_usage,
            network_connections,
            active_peers,
            pending_transactions,
            processed_blocks,
            tps_average,
            latency_ms,
            sync_progress_percent,
        };

        self.metrics_history.push(metrics.clone());
        metrics
    }

    async fn get_cpu_usage(&self) -> f64 {
        // Simplified CPU usage (in real implementation, use system monitoring)
        45.0 + (rand::random::<f64>() * 20.0 - 10.0) // Random variation around 45%
    }

    async fn get_memory_usage(&self) -> f64 {
        // Simplified memory usage
        512.0 + (rand::random::<f64>() * 100.0 - 50.0) // Random variation around 512MB
    }

    async fn get_disk_usage(&self) -> f64 {
        // Simplified disk usage
        50.0 + (rand::random::<f64>() * 10.0 - 5.0) // Random variation around 50GB
    }

    /// Get current health status
    pub async fn get_current_health(&self) -> Option<&NodeHealth> {
        self.health_history.last()
    }

    /// Get health history
    pub fn get_health_history(&self) -> &[NodeHealth] {
        &self.health_history
    }

    /// Get metrics history
    pub fn get_metrics_history(&self) -> &[NodeMetrics] {
        &self.metrics_history
    }

    /// Generate health report
    pub fn generate_health_report(&self) -> String {
        let mut report = String::new();
        report.push_str("# Node Health Report - Symbios Network\n\n");

        if let Some(latest_health) = self.health_history.last() {
            report.push_str(&format!("## Node: {}\n\n", latest_health.node_id));
            report.push_str(&format!("**Status:** {:?}\n", latest_health.status));
            report.push_str(&format!("**Uptime:** {} seconds\n", latest_health.uptime_seconds));
            report.push_str(&format!("**Last Check:** {}\n\n", latest_health.last_check));

            report.push_str("## Health Checks\n\n");
            for check in latest_health.checks.values() {
                report.push_str(&format!("### {}\n", check.name));
                report.push_str(&format!("**Status:** {:?}\n", check.status));
                report.push_str(&format!("**Message:** {}\n", check.message));
                report.push_str(&format!("**Duration:** {}ms\n\n", check.duration_ms));
            }

            report.push_str("## Performance Metrics\n\n");
            let metrics = &latest_health.metrics;
            report.push_str(&format!("- CPU Usage: {:.1}%\n", metrics.cpu_usage_percent));
            report.push_str(&format!("- Memory Usage: {:.1} MB\n", metrics.memory_usage_mb));
            report.push_str(&format!("- Disk Usage: {:.1} GB\n", metrics.disk_usage_gb));
            report.push_str(&format!("- Network Connections: {}\n", metrics.network_connections));
            report.push_str(&format!("- Active Peers: {}\n", metrics.active_peers));
            report.push_str(&format!("- Pending Transactions: {}\n", metrics.pending_transactions));
            report.push_str(&format!("- Processed Blocks: {}\n", metrics.processed_blocks));
            report.push_str(&format!("- Average TPS: {:.1}\n", metrics.tps_average));
            report.push_str(&format!("- Network Latency: {}ms\n", metrics.latency_ms));
            report.push_str(&format!("- Sync Progress: {:.1}%\n", metrics.sync_progress_percent));
        }

        report
    }

    /// Check if node is healthy
    pub fn is_healthy(&self) -> bool {
        if let Some(health) = self.health_history.last() {
            matches!(health.status, HealthStatus::Healthy)
        } else {
            false
        }
    }

    /// Get health score (0.0 to 1.0, where 1.0 is perfect health)
    pub fn get_health_score(&self) -> f64 {
        if let Some(health) = self.health_history.last() {
            let checks_total = health.checks.len() as f64;
            let healthy_checks = health.checks.values()
                .filter(|c| matches!(c.status, HealthStatus::Healthy))
                .count() as f64;

            if checks_total > 0.0 {
                healthy_checks / checks_total
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub message: String,
}

/// Trait for health checks
#[async_trait::async_trait]
pub trait HealthCheckTrait {
    fn name(&self) -> &str;
    async fn execute(&mut self) -> HealthCheckResult;
}

/// Memory health check
pub struct MemoryHealthCheck {
    threshold_mb: f64,
}

impl MemoryHealthCheck {
    pub fn new() -> Self {
        Self { threshold_mb: 1024.0 } // 1GB threshold
    }
}

#[async_trait::async_trait]
impl HealthCheckTrait for MemoryHealthCheck {
    fn name(&self) -> &str {
        "Memory Usage"
    }

    async fn execute(&mut self) -> HealthCheckResult {
        // In real implementation, get actual memory usage
        let memory_usage = 512.0 + (rand::random::<f64>() * 200.0 - 100.0);

        if memory_usage > self.threshold_mb {
            HealthCheckResult {
                status: HealthStatus::Critical,
                message: format!("Memory usage too high: {:.1} MB", memory_usage),
            }
        } else if memory_usage > self.threshold_mb * 0.8 {
            HealthCheckResult {
                status: HealthStatus::Degraded,
                message: format!("Memory usage high: {:.1} MB", memory_usage),
            }
        } else {
            HealthCheckResult {
                status: HealthStatus::Healthy,
                message: format!("Memory usage normal: {:.1} MB", memory_usage),
            }
        }
    }
}

/// Disk health check
pub struct DiskHealthCheck {
    threshold_gb: f64,
}

impl DiskHealthCheck {
    pub fn new() -> Self {
        Self { threshold_gb: 100.0 } // 100GB threshold
    }
}

#[async_trait::async_trait]
impl HealthCheckTrait for DiskHealthCheck {
    fn name(&self) -> &str {
        "Disk Usage"
    }

    async fn execute(&mut self) -> HealthCheckResult {
        // In real implementation, get actual disk usage
        let disk_usage = 50.0 + (rand::random::<f64>() * 20.0 - 10.0);

        if disk_usage > self.threshold_gb {
            HealthCheckResult {
                status: HealthStatus::Critical,
                message: format!("Disk usage too high: {:.1} GB", disk_usage),
            }
        } else if disk_usage > self.threshold_gb * 0.9 {
            HealthCheckResult {
                status: HealthStatus::Degraded,
                message: format!("Disk usage high: {:.1} GB", disk_usage),
            }
        } else {
            HealthCheckResult {
                status: HealthStatus::Healthy,
                message: format!("Disk usage normal: {:.1} GB", disk_usage),
            }
        }
    }
}

/// Network health check
pub struct NetworkHealthCheck {
    min_peers: u32,
}

impl NetworkHealthCheck {
    pub fn new() -> Self {
        Self { min_peers: 3 }
    }
}

#[async_trait::async_trait]
impl HealthCheckTrait for NetworkHealthCheck {
    fn name(&self) -> &str {
        "Network Connectivity"
    }

    async fn execute(&mut self) -> HealthCheckResult {
        // In real implementation, check actual network connectivity
        let active_peers = 5 + (rand::random::<i32>() % 4 - 2); // Random between 3-7

        if active_peers < 0 {
            HealthCheckResult {
                status: HealthStatus::Critical,
                message: "No network connectivity".to_string(),
            }
        } else if (active_peers as u32) < self.min_peers {
            HealthCheckResult {
                status: HealthStatus::Degraded,
                message: format!("Low peer count: {} (minimum: {})", active_peers, self.min_peers),
            }
        } else {
            HealthCheckResult {
                status: HealthStatus::Healthy,
                message: format!("Good connectivity: {} active peers", active_peers),
            }
        }
    }
}

/// Consensus health check
pub struct ConsensusHealthCheck {
    max_behind_blocks: u64,
}

impl ConsensusHealthCheck {
    pub fn new() -> Self {
        Self { max_behind_blocks: 10 }
    }
}

#[async_trait::async_trait]
impl HealthCheckTrait for ConsensusHealthCheck {
    fn name(&self) -> &str {
        "Consensus Health"
    }

    async fn execute(&mut self) -> HealthCheckResult {
        // In real implementation, check consensus health
        let blocks_behind = (rand::random::<u64>() % 20); // Random between 0-19

        if blocks_behind > self.max_behind_blocks {
            HealthCheckResult {
                status: HealthStatus::Critical,
                message: format!("Too far behind: {} blocks", blocks_behind),
            }
        } else if blocks_behind > self.max_behind_blocks / 2 {
            HealthCheckResult {
                status: HealthStatus::Degraded,
                message: format!("Falling behind: {} blocks", blocks_behind),
            }
        } else {
            HealthCheckResult {
                status: HealthStatus::Healthy,
                message: format!("Consensus healthy: {} blocks behind", blocks_behind),
            }
        }
    }
}

/// Cluster health monitor for monitoring multiple nodes
pub struct ClusterHealthMonitor {
    nodes: HashMap<String, Arc<RwLock<HealthMonitor>>>,
}

impl ClusterHealthMonitor {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node_id: String, monitor: HealthMonitor) {
        self.nodes.insert(node_id, Arc::new(RwLock::new(monitor)));
    }

    pub async fn get_cluster_health(&self) -> ClusterHealth {
        let mut node_healths = Vec::new();
        let mut healthy_count = 0;
        let mut total_nodes = 0;

        for (node_id, monitor) in &self.nodes {
            total_nodes += 1;
            let health_monitor = monitor.read().await;
            if let Some(health) = health_monitor.get_current_health() {
                node_healths.push(health.clone());
                if matches!(health.status, HealthStatus::Healthy) {
                    healthy_count += 1;
                }
            }
        }

        let cluster_status = if healthy_count == total_nodes && total_nodes > 0 {
            HealthStatus::Healthy
        } else if healthy_count >= total_nodes / 2 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Critical
        };

        ClusterHealth {
            status: cluster_status,
            total_nodes,
            healthy_nodes: healthy_count,
            node_healths,
            last_update: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClusterHealth {
    pub status: HealthStatus,
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub node_healths: Vec<NodeHealth>,
    pub last_update: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_monitor_creation() {
        let monitor = HealthMonitor::new("test-node".to_string());
        assert_eq!(monitor.node_id, "test-node");
        assert!(!monitor.checks.is_empty()); // Should have default checks
    }

    #[tokio::test]
    async fn test_memory_health_check() {
        let mut check = MemoryHealthCheck::new();
        let result = check.execute().await;
        // Should return some status
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn test_disk_health_check() {
        let mut check = DiskHealthCheck::new();
        let result = check.execute().await;
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn test_network_health_check() {
        let mut check = NetworkHealthCheck::new();
        let result = check.execute().await;
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn test_consensus_health_check() {
        let mut check = ConsensusHealthCheck::new();
        let result = check.execute().await;
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn test_cluster_health_monitor() {
        let mut cluster_monitor = ClusterHealthMonitor::new();

        let monitor1 = HealthMonitor::new("node-1".to_string());
        let monitor2 = HealthMonitor::new("node-2".to_string());

        cluster_monitor.add_node("node-1".to_string(), monitor1);
        cluster_monitor.add_node("node-2".to_string(), monitor2);

        let cluster_health = cluster_monitor.get_cluster_health().await;
        assert_eq!(cluster_health.total_nodes, 2);
    }
}
