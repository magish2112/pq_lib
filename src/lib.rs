//! # pq_lib - Post-Quantum Cryptography for Blockchains
//!
//! **WORK IN PROGRESS** - MVP implementation in development
//!
//! A production-grade Rust library providing hybrid cryptographic primitives
//! specifically designed for blockchain applications. Combines classical
//! Ed25519 signatures with post-quantum algorithms for forward-compatibility.
//!
//! ## Current Status
//!
//! - ✅ Basic project structure
//! - ✅ Core types (AlgorithmId, Keys, Signature)
//! - ✅ Unit tests
//! - ✅ CI/CD setup
//! - ✅ MVP crypto implementation
//! - ✅ Domain separation
//! - ✅ Error handling
//! - ✅ Benchmarks
//! - ✅ Property-based tests
//! - ✅ Documentation examples
//! - ✅ Blockchain integration
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pq_lib::{HybridSigner, AlgorithmId, ValidationPolicy, DomainSeparator, KeyGenerator, Signer, Verifier};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate hybrid keypair
//!     let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await?;
//!
//!     // Sign transaction data with domain separation
//!     let signature = HybridSigner::sign_with_domain(
//!         b"transaction_data",
//!         &keypair.private_key,
//!         DomainSeparator::Transaction
//!     ).await?;
//!
//!     // Verify with hybrid policy
//!     let is_valid = HybridSigner::verify_with_policy(
//!         b"transaction_data",
//!         &signature,
//!         &keypair.public_key,
//!         ValidationPolicy::HybridPreferred
//!     ).await?;
//!
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Algorithm identifiers and properties
pub mod algorithm;
/// Fluent builder APIs for elegant configuration
pub mod builders;
/// Backward compatibility layer for smooth migration
pub mod compat;
/// Domain separators for cryptographic operations
pub mod domain;
/// Cryptographic error types
pub mod error;
/// Hybrid cryptographic keypair types
pub mod keypair;
/// Declarative macros for elegant code generation
#[macro_use]
pub mod macros;
/// Validation policies for signature verification
pub mod policy;
/// Post-quantum cryptography operations
pub mod pqc;
/// Stable serialization utilities for cryptographic types
#[cfg(feature = "serde-support")]
pub mod serialization;
/// Hybrid cryptographic signature types
pub mod signature;
/// Production-ready hybrid signer implementation
pub mod signer;
/// Cryptographic trait definitions
pub mod traits;
/// Type-level cryptography primitives for zero-cost abstractions
pub mod typed;
/// Type-state pattern for safe migration management
pub mod typestate;

// Re-export main types
pub use algorithm::AlgorithmId;
pub use domain::DomainSeparator;
pub use error::CryptoError;
pub use keypair::{HybridKeypair, HybridPrivateKey, HybridPublicKey};
pub use policy::{MigrationConfig, PolicyConfig, ValidationPolicy};
pub use signature::HybridSignature;
pub use signer::HybridSigner;
pub use traits::{
    BatchSigner, BatchVerifier, KemProvider, KeyDerivation, KeyGenerator, Signer, Verifier,
};

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Version information for the pq_lib crate
///
/// Provides compile-time version information and compatibility checks.
pub mod version {
    /// Current crate version as specified in Cargo.toml
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Supported algorithm versions for compatibility checking
    ///
    /// Currently supports version "v1" of the cryptographic protocol.
    pub const ALGORITHM_VERSIONS: &[&str] = &["v1"];

    /// Minimum supported Rust version for this crate
    ///
    /// The crate requires Rust 1.70.0 or later for full functionality.
    pub const RUST_VERSION: &str = "1.70";
}
