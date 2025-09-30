//! Symbios Network - DAG-based Blockchain Protocol
//!
//! High-performance blockchain with DAG-mempool for optimal transaction ordering.
//! Focus: Parallel execution, DAG structure, leader-based consensus.

/// Core Protocol Modules
pub mod types;           // Type definitions and core data structures
pub mod dag_mempool;     // DAG-based transaction mempool
pub mod minimal_dag;     // Minimal DAG implementation for protocol
pub mod consensus;       // Proto-BFT consensus implementation
pub mod network;         // P2P networking (libp2p-based)
pub mod state_machine;   // State management and execution
pub mod storage;         // Persistent storage layer

/// Advanced Features (Optional)
pub mod parallel_execution; // Parallel transaction execution
pub mod dag_optimization;   // DAG structure optimization
pub mod production_consensus; // Production BFT consensus
pub mod crypto_audit;     // Cryptographic security auditing
pub mod hsm;             // Hardware Security Module integration
pub mod kms;             // Key Management Service for validators

/// Supporting Infrastructure
pub mod metrics;         // Performance monitoring and metrics
pub mod health_monitor;  // Node and network health monitoring

/// Legacy/Experimental Modules
pub mod mempool;         // Legacy mempool (deprecated)
pub mod lightweight_consensus; // Simplified consensus (deprecated)
pub mod efficient_execution;   // Legacy execution (deprecated)
pub mod minimal_storage;       // Legacy storage (deprecated)
pub mod state_sync;            // State synchronization (deprecated)
pub mod security_audit;        // Legacy security audit (deprecated)
pub mod formal_verification;   // Formal verification (deprecated)
pub mod economics;             // Economics (deprecated)
pub mod production_node;       // Production node (deprecated)
pub mod simple_node;           // Simple node (deprecated)
pub mod proptests;             // Property-based tests (deprecated)

/// Future/Experimental Modules (actively developed)
pub mod pqcrypto;              // Post-quantum crypto (actively used in types.rs)
pub mod adaptive_crypto;       // Adaptive cryptography with algorithm rotation
pub mod ai_dos_protection;     // AI-powered DoS protection and traffic analysis
pub mod advanced_consensus;    // Advanced consensus with attack resistance

// Core Protocol Exports
pub use types::*;
pub use dag_mempool::{SmartDagMempool, DagVertex, MempoolBlock, Certificate};
pub use minimal_dag::{MinimalDagMempool, MinimalDagConfig, DagVertex as MinimalDagVertex, OrderingQueue, MinimalGossip, NetworkMessage as MinimalNetworkMessage, DagMempoolStats};
pub use consensus::{ConsensusTrait, SimpleConsensus};
pub use network::{Network, NetworkTrait, NetworkMessage};
pub use state_machine::{StateMachine, StateError, StateResult, AccountState};
pub use storage::{Storage, StorageTrait};

// Advanced Feature Exports (Optional)
pub use parallel_execution::{ParallelExecutionEngine, ParallelExecutionConfig};
pub use dag_optimization::{OptimizedDagMempool, DagOptimizationConfig};
pub use production_consensus::{BftConsensus, BftConfig, ConsensusPhase, ConsensusMessage};
pub use crypto_audit::{CryptoAuditor, CryptoAuditResult};
pub use hsm::{HardwareSecurityModule, ProductionHsm, HsmConfig};
pub use kms::{ValidatorKms, ValidatorConfig};
pub use metrics::MetricsServer;
pub use health_monitor::{HealthMonitor, NodeHealth, HealthStatus};
