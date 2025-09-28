//! Symbios MVP - Smart DAG Mempool Blockchain
//! 
//! A high-performance blockchain implementation with smart DAG-based mempool
//! for optimal transaction ordering and parallel processing.

pub mod types;
pub mod mempool;
pub mod dag_mempool;
pub mod storage;
pub mod consensus;
pub mod lightweight_consensus;
pub mod efficient_execution;
pub mod minimal_storage;
pub mod network;
pub mod state_sync;
pub mod security_audit;
pub mod health_monitor;
pub mod formal_verification;
pub mod economics;
pub mod pqcrypto;
pub mod metrics;
pub mod production_node;
pub mod simple_node;
pub mod proptests;

// Re-export network types for convenience
pub use network::{
    Network, NetworkTrait, NetworkEvent, NetworkConfig, NetworkManager,
    NetworkRequest, NetworkResponse, NodeInfo, StateDiff, StateChange,
    StateSyncData, SyncStatus
};

pub use types::*;
pub use storage::{Storage, StorageTrait};
pub use state_sync::{StateSyncManager, SyncStats};
pub use security_audit::{SecurityAuditor, SecurityAuditResult, RiskLevel, Vulnerability};
pub use health_monitor::{HealthMonitor, ClusterHealthMonitor, NodeHealth, HealthStatus, NodeMetrics};
pub use formal_verification::{ConsensusVerifier, ByzantineFaultInjector, VerificationStatus};
pub use economics::{TokenomicsEngine, GovernanceSystem, SYMToken, EconomicParameters, StakingPool, ValidatorMetrics};
pub use pqcrypto::{PQCrypto, PQKeyPair, PQPublicKey, PQPrivateKey, PQSignature, MLKEM, MLDSA, SLHDSA};
pub use dag_mempool::SmartDagMempool;
pub use production_node::{ProductionNode, ProductionConfig};
pub use metrics::MetricsServer;
