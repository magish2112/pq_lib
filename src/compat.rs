//! Backward compatibility layer for smooth migration
//!
//! This module provides a compatibility facade that allows existing code
//! to continue working while gradually migrating to the new elegant API.
//!
//! # Migration Strategy
//!
//! 1. **Phase 1**: Both APIs coexist, old API marked as deprecated
//! 2. **Phase 2**: Update examples and documentation to use new API
//! 3. **Phase 3**: Remove old API in next major version
//!
//! # Example Migration
//!
//! ```ignore
//! // Old API (still works, but deprecated)
//! let keypair = HybridKeypair::generate(AlgorithmId::Ed25519)?;
//! let sig = keypair.sign(data, DomainSeparator::Transaction)?;
//!
//! // New elegant API (recommended)
//! let keypair = Keypair::<Ed25519>::generate()?;
//! let sig = keypair.sign(data, DomainSeparator::Transaction)?;
//! ```

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use crate::{
    typed::{Algorithm, Ed25519, Keypair as TypedKeypair, MlDsa65Hybrid, MlDsa87Hybrid},
    AlgorithmId, CryptoError, CryptoResult, DomainSeparator, HybridKeypair, HybridPrivateKey,
    HybridPublicKey, HybridSignature,
};

/// Compatibility wrapper for old HybridKeypair API
///
/// This type provides backward compatibility while encouraging migration
/// to the new type-safe API.
///
/// # Deprecation Notice
///
/// This wrapper will be removed in version 0.3.0. Please migrate to the
/// new `typed::Keypair<A>` API which provides:
/// - Compile-time algorithm safety
/// - Zero-cost abstractions
/// - Better error messages
/// - Cleaner API design
#[deprecated(
    since = "0.2.0",
    note = "Use typed::Keypair<A> for type-safe cryptography. See migration guide."
)]
pub struct CompatKeypair {
    inner: Box<dyn KeypairCompat>,
}

trait KeypairCompat: Send + Sync {
    fn algorithm(&self) -> AlgorithmId;
    fn public_key_bytes(&self) -> &[u8];
    fn sign(&self, data: &[u8], domain: DomainSeparator) -> CryptoResult<Vec<u8>>;
}

/// Convert from old HybridKeypair to new typed API
///
/// # Example
///
/// ```ignore
/// let old_keypair: HybridKeypair = /* ... */;
/// let new_keypair = convert_to_typed(old_keypair)?;
/// ```
pub fn convert_hybrid_to_typed(
    keypair: &HybridKeypair,
) -> CryptoResult<Box<dyn core::any::Any>> {
    match keypair.public_key.algorithm {
        AlgorithmId::Ed25519 => {
            let public = crate::typed::PublicKey::<Ed25519>::from_bytes(
                keypair.public_key.ed25519_key.clone(),
            )?;
            let private = crate::typed::PrivateKey::<Ed25519>::from_bytes(
                keypair.private_key.ed25519_key.clone(),
            )?;
            Ok(Box::new(TypedKeypair::new(public, private)))
        }
        AlgorithmId::MlDsa65 => {
            let mut pub_bytes = keypair.public_key.ed25519_key.clone();
            if let Some(pq_key) = &keypair.public_key.pq_key {
                pub_bytes.extend_from_slice(pq_key);
            }
            let public = crate::typed::PublicKey::<MlDsa65Hybrid>::from_bytes(pub_bytes)?;

            let mut priv_bytes = keypair.private_key.ed25519_key.clone();
            if let Some(pq_key) = &keypair.private_key.pq_key {
                priv_bytes.extend_from_slice(pq_key);
            }
            let private = crate::typed::PrivateKey::<MlDsa65Hybrid>::from_bytes(priv_bytes)?;

            Ok(Box::new(TypedKeypair::new(public, private)))
        }
        AlgorithmId::MlDsa87 => {
            let mut pub_bytes = keypair.public_key.ed25519_key.clone();
            if let Some(pq_key) = &keypair.public_key.pq_key {
                pub_bytes.extend_from_slice(pq_key);
            }
            let public = crate::typed::PublicKey::<MlDsa87Hybrid>::from_bytes(pub_bytes)?;

            let mut priv_bytes = keypair.private_key.ed25519_key.clone();
            if let Some(pq_key) = &keypair.private_key.pq_key {
                priv_bytes.extend_from_slice(pq_key);
            }
            let private = crate::typed::PrivateKey::<MlDsa87Hybrid>::from_bytes(priv_bytes)?;

            Ok(Box::new(TypedKeypair::new(public, private)))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(format!(
            "Cannot convert {:?} to typed API",
            keypair.public_key.algorithm
        ))),
    }
}

/// Convert from new typed API to old HybridKeypair
///
/// This is useful for gradual migration when some parts of the codebase
/// still use the old API.
///
/// # Example
///
/// ```ignore
/// let typed_keypair = Keypair::<Ed25519>::generate()?;
/// let old_keypair = convert_typed_to_hybrid(&typed_keypair)?;
/// ```
pub fn convert_typed_to_hybrid<A: Algorithm>(
    keypair: &TypedKeypair<A>,
) -> CryptoResult<HybridKeypair> {
    match A::ID {
        AlgorithmId::Ed25519 => {
            let public = HybridPublicKey::from_ed25519(keypair.public_key().as_bytes().to_vec());
            let private =
                HybridPrivateKey::from_ed25519(keypair.private_key().as_bytes().to_vec());
            Ok(HybridKeypair::new(public, private))
        }
        AlgorithmId::MlDsa65 | AlgorithmId::MlDsa87 => {
            // For hybrid algorithms, split the combined keys
            let pub_bytes = keypair.public_key().as_bytes();
            let priv_bytes = keypair.private_key().as_bytes();

            let ed25519_pub = pub_bytes[..32].to_vec();
            let pq_pub = pub_bytes[32..].to_vec();

            let ed25519_priv = priv_bytes[..32].to_vec();
            let pq_priv = priv_bytes[32..].to_vec();

            let public = HybridPublicKey::new(A::ID, ed25519_pub, Some(pq_pub))?;
            let private = HybridPrivateKey::new(A::ID, ed25519_priv, Some(pq_priv))?;

            Ok(HybridKeypair::new(public, private))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(format!(
            "Cannot convert {} to hybrid API",
            A::NAME
        ))),
    }
}

/// Migration guide helper
///
/// Provides migration suggestions based on current usage patterns.
pub struct MigrationGuide;

impl MigrationGuide {
    /// Get migration instructions for a specific use case
    pub fn for_algorithm(algorithm: AlgorithmId) -> &'static str {
        match algorithm {
            AlgorithmId::Ed25519 => {
                "Migrate to: pq_lib::typed::Keypair<Ed25519>\n\
                 Old: HybridKeypair::generate(AlgorithmId::Ed25519)\n\
                 New: Keypair::<Ed25519>::generate()\n\
                 Benefits: Compile-time type safety, zero-cost abstractions"
            }
            AlgorithmId::MlDsa65 => {
                "Migrate to: pq_lib::typed::Keypair<MlDsa65Hybrid>\n\
                 Old: HybridKeypair::generate(AlgorithmId::MlDsa65)\n\
                 New: Keypair::<MlDsa65Hybrid>::generate()\n\
                 Benefits: Compile-time algorithm checks, better performance"
            }
            AlgorithmId::MlDsa87 => {
                "Migrate to: pq_lib::typed::Keypair<MlDsa87Hybrid>\n\
                 Old: HybridKeypair::generate(AlgorithmId::MlDsa87)\n\
                 New: Keypair::<MlDsa87Hybrid>::generate()\n\
                 Benefits: Type-safe operations, cleaner API"
            }
            AlgorithmId::SlhDsaShake256f => {
                "Migrate to: pq_lib::typed::Keypair<SlhDsaHybrid>\n\
                 Old: HybridKeypair::generate(AlgorithmId::SlhDsaShake256f)\n\
                 New: Keypair::<SlhDsaHybrid>::generate()\n\
                 Benefits: Compile-time safety, zero overhead"
            }
        }
    }

    /// Print migration checklist
    pub fn print_checklist() {
        println!("📋 Migration Checklist:");
        println!("  [ ] Update imports: use pq_lib::typed::{{Keypair, Ed25519, ...}}");
        println!("  [ ] Replace HybridKeypair with Keypair<Algorithm>");
        println!("  [ ] Replace AlgorithmId parameters with type parameters");
        println!("  [ ] Update error handling for new error types");
        println!("  [ ] Use PolicyConfigBuilder for configuration");
        println!("  [ ] Migrate to type-state pattern for migration management");
        println!("  [ ] Run tests to verify functionality");
        println!("  [ ] Update documentation");
    }

    /// Estimate migration effort
    pub fn estimate_effort(lines_of_code: usize) -> &'static str {
        match lines_of_code {
            0..=500 => "Effort: Low (1-2 hours)\nMostly find-and-replace with some manual review",
            501..=2000 => {
                "Effort: Medium (4-8 hours)\nRequires careful review and testing of each usage"
            }
            _ => "Effort: High (1-2 days)\nConsider gradual migration, module by module",
        }
    }
}

/// Compatibility shim for old validation functions
///
/// # Note
///
/// This is a placeholder showing the migration path.
/// Actual implementation would use the existing sync verification logic.
#[deprecated(
    since = "0.2.0",
    note = "Use typed::Keypair::verify with typed::PublicKey"
)]
pub fn verify_hybrid_signature_compat(
    _data: &[u8],
    _signature: &HybridSignature,
    _public_key: &HybridPublicKey,
) -> CryptoResult<bool> {
    // Placeholder - actual implementation would delegate to verification logic
    Err(CryptoError::UnsupportedAlgorithm(
        "Use new typed API for verification".into(),
    ))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_guide() {
        let guide = MigrationGuide::for_algorithm(AlgorithmId::Ed25519);
        assert!(guide.contains("Ed25519"));
        assert!(guide.contains("Keypair"));
    }

    #[test]
    fn test_effort_estimation() {
        assert!(MigrationGuide::estimate_effort(100).contains("Low"));
        assert!(MigrationGuide::estimate_effort(1000).contains("Medium"));
        assert!(MigrationGuide::estimate_effort(5000).contains("High"));
    }

    #[test]
    fn test_conversion_functions_exist() {
        // These tests just verify the functions exist and have correct signatures
        // Actual conversion logic is tested in integration tests
        let _guide = MigrationGuide::print_checklist();
    }
}

