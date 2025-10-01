//! Symbios Network - DAG-based Blockchain Protocol
//!
//! High-performance blockchain with DAG-mempool for optimal transaction ordering.
//! Focus: Parallel execution, DAG structure, leader-based consensus.

/// Core Protocol Modules
pub mod types;           // Type definitions and core data structures
pub mod dag_mempool;     // DAG-based transaction mempool
pub mod minimal_dag;     // Minimal DAG implementation for protocol
pub mod consensus;       // Proto-BFT consensus implementation
pub mod hotstuff_consensus; // Production HotStuff BFT consensus
// pub mod network;         // P2P networking (disabled for compilation)
pub mod state_machine;   // State management and execution
pub mod storage;         // Persistent storage layer

/// Advanced Features (Optional)
// pub mod parallel_execution; // Parallel transaction execution (disabled)
// pub mod dag_optimization;   // DAG structure optimization (disabled)
// pub mod production_consensus; // Production BFT consensus (disabled)
// pub mod crypto_audit;     // Cryptographic security auditing (disabled)
// pub mod hsm;             // Hardware Security Module integration (disabled)
// pub mod kms;             // Key Management Service for validators (disabled)

/// Supporting Infrastructure
// pub mod metrics;         // Performance monitoring and metrics (disabled)
// pub mod health_monitor;  // Node and network health monitoring (disabled)

/// Legacy/Experimental Modules
pub mod mempool;         // Legacy mempool (deprecated)
pub mod lightweight_consensus; // Simplified consensus (deprecated)
pub mod efficient_execution;   // Legacy execution (deprecated)
pub mod minimal_storage;       // Legacy storage (deprecated)
// pub mod state_sync;            // State synchronization (disabled)
// pub mod security_audit;        // Legacy security audit (disabled)
// pub mod formal_verification;   // Formal verification (disabled)
// pub mod economics;             // Economics (disabled)
// pub mod production_node;       // Production node (disabled)
// pub mod simple_node;           // Simple node (disabled)
// pub mod proptests;             // Property-based tests (disabled)

/// Future/Experimental Modules (actively developed)
pub mod pqcrypto;              // Post-quantum crypto (mock implementation)
// pub mod adaptive_crypto;       // Adaptive cryptography (disabled)
// pub mod ai_dos_protection;     // AI-powered DoS protection (disabled)
// pub mod advanced_consensus;    // Advanced consensus (disabled)
// pub mod hybrid_crypto;         // Hybrid Ed25519 + PQ cryptography (disabled)

// Core Protocol Exports
pub use types::*;
pub use dag_mempool::{SmartDagMempool, DagVertex, MempoolBlock, Certificate};
pub use minimal_dag::{MinimalDagMempool, MinimalDagConfig, DagVertex as MinimalDagVertex, OrderingQueue, MinimalGossip, NetworkMessage as MinimalNetworkMessage, DagMempoolStats};
pub use consensus::{ConsensusTrait, SimpleConsensus};
// pub use network::{Network, NetworkTrait, NetworkMessage}; // Disabled
pub use state_machine::{StateMachine, StateError, StateResult, AccountState};
pub use storage::{Storage, StorageTrait};

// Advanced Feature Exports (Optional) - All disabled for compilation
// pub use parallel_execution::{ParallelExecutionEngine, ParallelExecutionConfig};
// pub use dag_optimization::{OptimizedDagMempool, DagOptimizationConfig};
// pub use production_consensus::{BftConsensus, BftConfig, ConsensusPhase, ConsensusMessage};
// pub use crypto_audit::{CryptoAuditor, CryptoAuditResult};
// pub use hsm::{HardwareSecurityModule, ProductionHsm, HsmConfig};
// pub use kms::{ValidatorKms, ValidatorConfig};
// pub use metrics::MetricsServer;
// pub use health_monitor::{HealthMonitor, NodeHealth, HealthStatus};
