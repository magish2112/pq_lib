//! # Symbios PQC - Post-Quantum Cryptography for Blockchains
//!
//! A production-grade Rust library providing hybrid cryptographic primitives
//! specifically designed for blockchain applications. Combines classical
//! Ed25519 signatures with post-quantum algorithms (ML-DSA, SLH-DSA) for
//! forward-compatibility and optimal security-performance balance.
//!
//! ## Key Features
//!
//! - **Hybrid Signatures**: Ed25519 + ML-DSA/SLH-DSA with domain separation
//! - **Migration Paths**: Seamless transition from classical to post-quantum crypto
//! - **Policy-based Validation**: Flexible signature verification policies
//! - **Zeroization**: Automatic secure cleanup of secret keys
//! - **Stable Serialization**: CBOR-based format with versioning
//! - **No_std Support**: Optional core functionality without std
//!
//! ## Architecture
//!
//! The library implements a **Strangler Fig pattern** for gradual migration:
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐
//! │   Ed25519 Only  │ -> │  Hybrid Ed25519  │
//! │   (Legacy)      │    │  + ML-DSA/SLH   │
//! └─────────────────┘    └──────────────────┘
//!                              |
//!                              v
//!                       ┌──────────────────┐
//!                       │   PQ Only        │
//!                       │   (Future)       │
//!                       └──────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust
//! use symbios_pqc::{HybridSigner, AlgorithmId, ValidationPolicy, DomainSeparator};
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
//!
//! ## Security Considerations
//!
//! - **Domain Separation**: Prevents cross-protocol signature reuse attacks
//! - **Key Zeroization**: Secret keys are automatically zeroized on drop
//! - **Algorithm Agility**: Support for multiple PQ algorithms with versioning
//! - **Migration Safety**: Backward compatibility during transition periods
//!
//! ## Performance
//!
//! | Algorithm | Signing | Verification | Key Size | Sig Size |
//! |-----------|---------|--------------|----------|----------|
//! | Ed25519   | ~50μs   | ~150μs       | 64B      | 64B      |
//! | ML-DSA-65 | ~150μs  | ~200μs       | ~4KB     | ~4KB     |
//! | SLH-DSA   | ~500μs  | ~100μs       | ~32B     | ~8KB     |
//!
//! ## Feature Flags
//!
//! - `std`: Enable standard library (default)
//! - `no_std`: Core functionality without std
//! - `ed25519`: Enable Ed25519 support (default)
//! - `ml-dsa`: Enable ML-DSA support (default)
//! - `ml-kem`: Enable ML-KEM support (default)
//! - `slh-dsa`: Enable SLH-DSA support (default)
//! - `serde-support`: Enable serialization support

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

mod error;
mod keypair;
mod signature;
mod algorithm;
mod domain;
mod policy;
mod traits;
mod signer;
#[cfg(feature = "serde-support")]
mod serialization;

pub use error::CryptoError;
pub use keypair::{HybridKeypair, HybridPublicKey, HybridPrivateKey};
pub use signature::HybridSignature;
pub use algorithm::AlgorithmId;
pub use domain::DomainSeparator;
pub use policy::ValidationPolicy;
pub use traits::{KeyGenerator, Signer, Verifier, KemProvider};
pub use signer::HybridSigner;

#[cfg(feature = "serde-support")]
pub use serialization;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

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

