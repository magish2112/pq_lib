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
//! - 🔄 Core types (AlgorithmId, Keys, Signature)
//! - 🔄 Unit tests
//! - 🔄 CI/CD setup
//! - 🔄 MVP crypto implementation
//! - 🔄 Domain separation
//! - 🔄 Error handling
//! - 🔄 Benchmarks
//! - 🔄 Property-based tests
//! - 🔄 Documentation examples
//! - 🔄 Blockchain integration
//!
//! ## Quick Start (Future API)
//!
//! ```rust,ignore
//! use pq_lib::{HybridSigner, AlgorithmId, ValidationPolicy, DomainSeparator};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate hybrid keypair
//!     let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;
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
//!         ValidationPolicy::HybridRequired
//!     ).await?;
//!
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

/// Core cryptographic error types
pub mod error;
/// Algorithm identifiers and properties
pub mod algorithm;
/// Keypair types
pub mod keypair;
/// Signature types
pub mod signature;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, error::CryptoError>;

/// Version information
pub mod version {
    /// Current crate version
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Supported algorithm versions
    pub const ALGORITHM_VERSIONS: &[&str] = &["v1"];

    /// Minimum supported Rust version
    pub const RUST_VERSION: &str = "1.70";
}

/// Re-exported for convenience
pub use async_trait::async_trait;
pub use error::CryptoError;
pub use algorithm::AlgorithmId;
pub use keypair::{HybridKeypair, HybridPublicKey, HybridPrivateKey};
pub use signature::HybridSignature;