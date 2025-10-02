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

use core::fmt;

#[cfg(feature = "std")]
extern crate std;

/// Algorithm identifiers and properties
pub mod algorithm;
/// Post-quantum cryptography operations
pub mod pqc;

/// Result type for cryptographic operations
///
/// This is a type alias for `Result<T, &'static str>` for basic error handling.
pub type CryptoResult<T> = Result<T, &'static str>;

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

/// Algorithm identifiers for supported cryptographic schemes
pub use algorithm::AlgorithmId;