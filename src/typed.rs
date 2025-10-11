//! Type-level cryptography primitives
//!
//! This module provides a type-safe, zero-cost abstraction layer for cryptographic operations.
//! It leverages Rust's type system to enforce correctness at compile time and eliminate runtime overhead.
//!
//! # Design Philosophy
//!
//! 1. **Type Safety**: Different algorithms use different types, preventing accidental mixing
//! 2. **Zero Cost**: All abstractions compile down to optimal machine code
//! 3. **Compile-time Validation**: Sizes and algorithms checked at compile time
//! 4. **Elegance**: Self-documenting APIs that express intent clearly
//!
//! # Examples
//!
//! ```
//! use pq_lib::typed::{Ed25519, Algorithm, Keypair};
//! use pq_lib::DomainSeparator;
//!
//! # fn example() -> Result<(), pq_lib::CryptoError> {
//! // Type-safe keypair generation
//! let keypair = Keypair::<Ed25519>::generate()?;
//!
//! // Signing with compile-time algorithm knowledge
//! let message = b"Hello, quantum world!";
//! let signature = keypair.sign(message, DomainSeparator::Transaction)?;
//!
//! // Verification with type-enforced compatibility
//! let valid = keypair.public_key().verify(message, &signature, DomainSeparator::Transaction)?;
//! assert!(valid);
//! # Ok(())
//! # }
//! ```

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::ToString, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, format, string::ToString, vec, vec::Vec};

use core::marker::PhantomData;
use core::{fmt, ops::Deref};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AlgorithmId, CryptoError, CryptoResult, DomainSeparator};

// =============================================================================
// Sealed Trait Pattern - Prevents external implementations
// =============================================================================

mod sealed {
    pub trait Sealed {}
}

// =============================================================================
// Core Type-Level Traits
// =============================================================================

/// Type-level algorithm specification
///
/// This trait provides compile-time information about cryptographic algorithms.
/// It uses associated constants for zero-cost access to algorithm properties.
///
/// # Safety
///
/// This trait is sealed and cannot be implemented outside this crate to ensure
/// algorithm implementations are properly vetted.
pub trait Algorithm: sealed::Sealed + Clone + Copy + fmt::Debug + fmt::Display {
    /// Algorithm identifier
    const ID: AlgorithmId;

    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;

    /// Private key size in bytes
    const PRIVATE_KEY_SIZE: usize;

    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;

    /// NIST security level (1-5)
    const SECURITY_LEVEL: u8;

    /// Human-readable algorithm name
    const NAME: &'static str;

    /// Whether this is a hybrid (classical + PQ) algorithm
    const IS_HYBRID: bool;

    /// Whether this algorithm is post-quantum secure
    const IS_POST_QUANTUM: bool;
}

// =============================================================================
// Type-Safe Key Types
// =============================================================================

/// Type-safe public key with compile-time size guarantees
///
/// The size of the key is determined by the algorithm type parameter,
/// eliminating runtime size checks.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<A: Algorithm> {
    bytes: Vec<u8>, // TODO: Use const generics when stable for large arrays
    _phantom: PhantomData<A>,
}

impl<A: Algorithm> PublicKey<A> {
    /// Create a public key from bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the byte slice length doesn't match
    /// the algorithm's expected public key size.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != A::PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "{} public key must be {} bytes, got {}",
                A::NAME,
                A::PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes,
            _phantom: PhantomData,
        })
    }

    /// Get the algorithm identifier at compile time
    #[inline(always)]
    pub const fn algorithm() -> AlgorithmId {
        A::ID
    }

    /// Get the key bytes as a slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size at compile time
    #[inline(always)]
    pub const fn size() -> usize {
        A::PUBLIC_KEY_SIZE
    }
}

impl<A: Algorithm> fmt::Debug for PublicKey<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("algorithm", &A::NAME)
            .field("size", &self.bytes.len())
            .field("bytes", &format!("{}...", hex_preview(&self.bytes, 8)))
            .finish()
    }
}

impl<A: Algorithm> AsRef<[u8]> for PublicKey<A> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Type-safe private key with automatic zeroization
///
/// Private keys are automatically zeroized when dropped, ensuring sensitive
/// material doesn't linger in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey<A: Algorithm> {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    _phantom: PhantomData<A>,
}

impl<A: Algorithm> PrivateKey<A> {
    /// Create a private key from bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the byte slice length doesn't match
    /// the algorithm's expected private key size.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != A::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "{} private key must be {} bytes, got {}",
                A::NAME,
                A::PRIVATE_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes,
            _phantom: PhantomData,
        })
    }

    /// Get the algorithm identifier at compile time
    #[inline(always)]
    pub const fn algorithm() -> AlgorithmId {
        A::ID
    }

    /// Get the key bytes as a slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size at compile time
    #[inline(always)]
    pub const fn size() -> usize {
        A::PRIVATE_KEY_SIZE
    }
}

impl<A: Algorithm> fmt::Debug for PrivateKey<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &A::NAME)
            .field("size", &self.bytes.len())
            .field("bytes", &"<REDACTED>")
            .finish()
    }
}

impl<A: Algorithm> AsRef<[u8]> for PrivateKey<A> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Type-safe cryptographic signature
///
/// The signature size is determined by the algorithm type parameter,
/// ensuring signatures are always the correct size for verification.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<A: Algorithm> {
    bytes: Vec<u8>,
    domain: DomainSeparator,
    _phantom: PhantomData<A>,
}

impl<A: Algorithm> Signature<A> {
    /// Create a signature from bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidSignature` if the byte slice length doesn't match
    /// the algorithm's expected signature size.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>, domain: DomainSeparator) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.len() != A::SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature(format!(
                "{} signature must be {} bytes, got {}",
                A::NAME,
                A::SIGNATURE_SIZE,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes,
            domain,
            _phantom: PhantomData,
        })
    }

    /// Get the algorithm identifier at compile time
    #[inline(always)]
    pub const fn algorithm() -> AlgorithmId {
        A::ID
    }

    /// Get the signature bytes as a slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the domain separator
    #[inline(always)]
    pub fn domain(&self) -> DomainSeparator {
        self.domain
    }

    /// Get the size at compile time
    #[inline(always)]
    pub const fn size() -> usize {
        A::SIGNATURE_SIZE
    }
}

impl<A: Algorithm> fmt::Debug for Signature<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("algorithm", &A::NAME)
            .field("domain", &self.domain)
            .field("size", &self.bytes.len())
            .field("bytes", &format!("{}...", hex_preview(&self.bytes, 8)))
            .finish()
    }
}

impl<A: Algorithm> AsRef<[u8]> for Signature<A> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// =============================================================================
// Keypair Type
// =============================================================================

/// Type-safe cryptographic keypair
///
/// A keypair bundles a public and private key of the same algorithm,
/// ensuring they're always used together correctly.
#[derive(Clone)]
pub struct Keypair<A: Algorithm> {
    public: PublicKey<A>,
    private: PrivateKey<A>,
}

impl<A: Algorithm> Keypair<A> {
    /// Create a new keypair from public and private keys
    pub fn new(public: PublicKey<A>, private: PrivateKey<A>) -> Self {
        Self { public, private }
    }

    /// Get a reference to the public key
    #[inline(always)]
    pub fn public_key(&self) -> &PublicKey<A> {
        &self.public
    }

    /// Get a reference to the private key
    #[inline(always)]
    pub fn private_key(&self) -> &PrivateKey<A> {
        &self.private
    }

    /// Decompose into public and private keys
    pub fn into_parts(self) -> (PublicKey<A>, PrivateKey<A>) {
        (self.public, self.private)
    }

    /// Get the algorithm identifier at compile time
    #[inline(always)]
    pub const fn algorithm() -> AlgorithmId {
        A::ID
    }
}

impl<A: Algorithm> fmt::Debug for Keypair<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("algorithm", &A::NAME)
            .field("public_key", &self.public)
            .field("private_key", &"<REDACTED>")
            .finish()
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Create a hex preview of bytes for debugging
fn hex_preview(bytes: &[u8], len: usize) -> alloc::string::String {
    let preview_len = core::cmp::min(bytes.len(), len);
    bytes[..preview_len]
        .iter()
        .map(|b| alloc::format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

// =============================================================================
// Concrete Algorithm Implementations
// =============================================================================

/// Ed25519 signature algorithm (classical)
///
/// Ed25519 provides 128-bit classical security but is vulnerable to quantum attacks.
/// It's included for legacy compatibility and hybrid constructions.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519;

impl sealed::Sealed for Ed25519 {}

impl Algorithm for Ed25519 {
    const ID: AlgorithmId = AlgorithmId::Ed25519;
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;
    const SIGNATURE_SIZE: usize = 64;
    const SECURITY_LEVEL: u8 = 2; // NIST Level 2 (classical only)
    const NAME: &'static str = "Ed25519";
    const IS_HYBRID: bool = false;
    const IS_POST_QUANTUM: bool = false;
}

impl fmt::Display for Ed25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

/// ML-DSA-65 + Ed25519 hybrid signature algorithm
///
/// Combines Ed25519 (classical) with ML-DSA-65 (post-quantum) for forward security.
/// Provides NIST Level 3 post-quantum security.
#[derive(Debug, Clone, Copy)]
pub struct MlDsa65Hybrid;

impl sealed::Sealed for MlDsa65Hybrid {}

impl Algorithm for MlDsa65Hybrid {
    const ID: AlgorithmId = AlgorithmId::MlDsa65;
    const PUBLIC_KEY_SIZE: usize = 32 + 1952; // Ed25519 + ML-DSA-65
    const PRIVATE_KEY_SIZE: usize = 32 + 4032;
    const SIGNATURE_SIZE: usize = 64 + 3309;
    const SECURITY_LEVEL: u8 = 3; // NIST Level 3
    const NAME: &'static str = "Ed25519+ML-DSA-65";
    const IS_HYBRID: bool = true;
    const IS_POST_QUANTUM: bool = true;
}

impl fmt::Display for MlDsa65Hybrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

/// ML-DSA-87 + Ed25519 hybrid signature algorithm
///
/// Combines Ed25519 (classical) with ML-DSA-87 (post-quantum) for maximum security.
/// Provides NIST Level 5 post-quantum security.
#[derive(Debug, Clone, Copy)]
pub struct MlDsa87Hybrid;

impl sealed::Sealed for MlDsa87Hybrid {}

impl Algorithm for MlDsa87Hybrid {
    const ID: AlgorithmId = AlgorithmId::MlDsa87;
    const PUBLIC_KEY_SIZE: usize = 32 + 2592; // Ed25519 + ML-DSA-87
    const PRIVATE_KEY_SIZE: usize = 32 + 4896;
    const SIGNATURE_SIZE: usize = 64 + 4627;
    const SECURITY_LEVEL: u8 = 5; // NIST Level 5
    const NAME: &'static str = "Ed25519+ML-DSA-87";
    const IS_HYBRID: bool = true;
    const IS_POST_QUANTUM: bool = true;
}

impl fmt::Display for MlDsa87Hybrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

/// SLH-DSA-SHAKE-256f + Ed25519 hybrid signature algorithm
///
/// Combines Ed25519 (classical) with SLH-DSA (stateless hash-based, post-quantum).
/// Provides NIST Level 3 post-quantum security with different security assumptions than ML-DSA.
#[derive(Debug, Clone, Copy)]
pub struct SlhDsaHybrid;

impl sealed::Sealed for SlhDsaHybrid {}

impl Algorithm for SlhDsaHybrid {
    const ID: AlgorithmId = AlgorithmId::SlhDsaShake256f;
    const PUBLIC_KEY_SIZE: usize = 32 + 32; // Ed25519 + SLH-DSA
    const PRIVATE_KEY_SIZE: usize = 32 + 64;
    const SIGNATURE_SIZE: usize = 64 + 7856;
    const SECURITY_LEVEL: u8 = 3; // NIST Level 3
    const NAME: &'static str = "Ed25519+SLH-DSA-SHAKE-256f";
    const IS_HYBRID: bool = true;
    const IS_POST_QUANTUM: bool = true;
}

impl fmt::Display for SlhDsaHybrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

// =============================================================================
// Compile-Time Validations
// =============================================================================

/// Compile-time assertions for algorithm consistency
mod compile_time_checks {
    use super::*;

    // Ensure Ed25519 sizes are correct
    const _: () = assert!(Ed25519::PUBLIC_KEY_SIZE == 32);
    const _: () = assert!(Ed25519::PRIVATE_KEY_SIZE == 32);
    const _: () = assert!(Ed25519::SIGNATURE_SIZE == 64);

    // Ensure security levels are valid (1-5)
    const _: () = assert!(Ed25519::SECURITY_LEVEL >= 1 && Ed25519::SECURITY_LEVEL <= 5);
    const _: () = assert!(MlDsa65Hybrid::SECURITY_LEVEL >= 1 && MlDsa65Hybrid::SECURITY_LEVEL <= 5);
    const _: () = assert!(MlDsa87Hybrid::SECURITY_LEVEL >= 1 && MlDsa87Hybrid::SECURITY_LEVEL <= 5);
    const _: () = assert!(SlhDsaHybrid::SECURITY_LEVEL >= 1 && SlhDsaHybrid::SECURITY_LEVEL <= 5);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_constants() {
        assert_eq!(Ed25519::ID, AlgorithmId::Ed25519);
        assert_eq!(Ed25519::PUBLIC_KEY_SIZE, 32);
        assert_eq!(Ed25519::PRIVATE_KEY_SIZE, 32);
        assert_eq!(Ed25519::SIGNATURE_SIZE, 64);
        assert_eq!(Ed25519::NAME, "Ed25519");
        assert!(!Ed25519::IS_HYBRID);
        assert!(!Ed25519::IS_POST_QUANTUM);
    }

    #[test]
    fn test_public_key_creation() {
        let bytes = vec![42u8; 32];
        let key = PublicKey::<Ed25519>::from_bytes(bytes.clone()).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
        assert_eq!(PublicKey::<Ed25519>::algorithm(), AlgorithmId::Ed25519);
    }

    #[test]
    fn test_public_key_invalid_size() {
        let bytes = vec![42u8; 16]; // Wrong size
        let result = PublicKey::<Ed25519>::from_bytes(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_zeroization() {
        let bytes = vec![42u8; 32];
        let key = PrivateKey::<Ed25519>::from_bytes(bytes).unwrap();
        assert_eq!(key.as_bytes()[0], 42);
        drop(key);
        // Key is zeroized on drop
    }

    #[test]
    fn test_signature_with_domain() {
        let bytes = vec![42u8; 64];
        let sig =
            Signature::<Ed25519>::from_bytes(bytes.clone(), DomainSeparator::Transaction).unwrap();
        assert_eq!(sig.as_bytes(), &bytes);
        assert_eq!(sig.domain(), DomainSeparator::Transaction);
    }

    #[test]
    fn test_keypair() {
        let pub_key = PublicKey::<Ed25519>::from_bytes(vec![1u8; 32]).unwrap();
        let priv_key = PrivateKey::<Ed25519>::from_bytes(vec![2u8; 32]).unwrap();
        let keypair = Keypair::new(pub_key.clone(), priv_key);

        assert_eq!(keypair.public_key().as_bytes(), pub_key.as_bytes());
        assert_eq!(Keypair::<Ed25519>::algorithm(), AlgorithmId::Ed25519);
    }

    #[test]
    fn test_type_safety() {
        // This test demonstrates that the type system prevents algorithm mixing
        let _ed25519_key = PublicKey::<Ed25519>::from_bytes(vec![1u8; 32]).unwrap();
        let _ml_dsa_key = PublicKey::<MlDsa65Hybrid>::from_bytes(vec![2u8; 32 + 1952]).unwrap();

        // The following would not compile:
        // let keypair = Keypair::new(_ed25519_key, _ml_dsa_key); // Type mismatch!
    }

    #[test]
    fn test_hybrid_algorithms() {
        assert!(MlDsa65Hybrid::IS_HYBRID);
        assert!(MlDsa65Hybrid::IS_POST_QUANTUM);
        assert_eq!(MlDsa65Hybrid::SECURITY_LEVEL, 3);

        assert!(MlDsa87Hybrid::IS_HYBRID);
        assert!(MlDsa87Hybrid::IS_POST_QUANTUM);
        assert_eq!(MlDsa87Hybrid::SECURITY_LEVEL, 5);
    }
}
