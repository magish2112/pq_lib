//! Fluent builder APIs for elegant configuration
//!
//! This module provides builder patterns for creating complex configurations
//! with a clean, self-documenting API.
//!
//! # Design Principles
//!
//! 1. **Fluency**: Method chaining for readable configuration
//! 2. **Type Safety**: Builder types enforce valid state transitions
//! 3. **Ergonomics**: Sensible defaults with optional overrides
//! 4. **Documentation**: Method names self-document their purpose
//!
//! # Examples
//!
//! ```
//! use pq_lib::builders::PolicyConfigBuilder;
//! use pq_lib::ValidationPolicy;
//!
//! let config = PolicyConfigBuilder::new()
//!     .transaction(ValidationPolicy::HybridPreferred)
//!     .block(ValidationPolicy::HybridRequired)
//!     .consensus(ValidationPolicy::HybridRequired)
//!     .migration_deadline_days(180)
//!     .build();
//! ```

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use crate::{MigrationConfig, PolicyConfig, ValidationPolicy};

// =============================================================================
// Policy Configuration Builder
// =============================================================================

/// Fluent builder for policy configuration
///
/// Provides an elegant API for constructing validation policies across
/// different blockchain domains.
///
/// # Example
///
/// ```
/// use pq_lib::builders::PolicyConfigBuilder;
/// use pq_lib::ValidationPolicy;
///
/// // Conservative production configuration
/// let config = PolicyConfigBuilder::conservative()
///     .transaction(ValidationPolicy::HybridRequired)
///     .build();
///
/// // Progressive migration configuration
/// let config = PolicyConfigBuilder::progressive()
///     .migration_deadline_days(365)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct PolicyConfigBuilder {
    transaction_policy: Option<ValidationPolicy>,
    block_policy: Option<ValidationPolicy>,
    consensus_policy: Option<ValidationPolicy>,
    migration: Option<MigrationConfig>,
}

impl PolicyConfigBuilder {
    /// Create a new builder with no defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a conservative configuration (hybrid required everywhere)
    ///
    /// This is recommended for production systems that need maximum security.
    pub fn conservative() -> Self {
        Self {
            transaction_policy: Some(ValidationPolicy::HybridRequired),
            block_policy: Some(ValidationPolicy::HybridRequired),
            consensus_policy: Some(ValidationPolicy::HybridRequired),
            migration: Some(MigrationConfig::default()),
        }
    }

    /// Create a progressive configuration (hybrid preferred, gradual migration)
    ///
    /// This is recommended for systems transitioning from classical to post-quantum.
    pub fn progressive() -> Self {
        Self {
            transaction_policy: Some(ValidationPolicy::HybridPreferred),
            block_policy: Some(ValidationPolicy::HybridPreferred),
            consensus_policy: Some(ValidationPolicy::HybridRequired),
            migration: Some(MigrationConfig::default()),
        }
    }

    /// Create a legacy configuration (classical only)
    ///
    /// This is for systems that need backward compatibility.
    /// ⚠️  Not recommended for new deployments.
    pub fn legacy() -> Self {
        Self {
            transaction_policy: Some(ValidationPolicy::ClassicOnly),
            block_policy: Some(ValidationPolicy::ClassicOnly),
            consensus_policy: Some(ValidationPolicy::ClassicOnly),
            migration: None,
        }
    }

    /// Create a post-quantum only configuration
    ///
    /// This is for systems that have completed migration and want
    /// maximum quantum resistance.
    pub fn post_quantum() -> Self {
        Self {
            transaction_policy: Some(ValidationPolicy::PqOnly),
            block_policy: Some(ValidationPolicy::PqOnly),
            consensus_policy: Some(ValidationPolicy::PqOnly),
            migration: None,
        }
    }

    /// Set the validation policy for transactions
    ///
    /// Transactions are user-initiated actions that modify state.
    pub fn transaction(mut self, policy: ValidationPolicy) -> Self {
        self.transaction_policy = Some(policy);
        self
    }

    /// Set the validation policy for blocks
    ///
    /// Blocks are collections of transactions produced by validators.
    pub fn block(mut self, policy: ValidationPolicy) -> Self {
        self.block_policy = Some(policy);
        self
    }

    /// Set the validation policy for consensus messages
    ///
    /// Consensus messages coordinate validators and finalize blocks.
    pub fn consensus(mut self, policy: ValidationPolicy) -> Self {
        self.consensus_policy = Some(policy);
        self
    }

    /// Set custom migration configuration
    pub fn migration(mut self, config: MigrationConfig) -> Self {
        self.migration = Some(config);
        self
    }

    /// Set migration deadline in days from now
    ///
    /// After this deadline, the system will enforce stricter policies.
    #[cfg(feature = "std")]
    pub fn migration_deadline_days(mut self, days: u64) -> Self {
        use std::time::{Duration, SystemTime};

        let deadline = SystemTime::now() + Duration::from_secs(days * 24 * 60 * 60);
        let migration = self.migration.get_or_insert_with(MigrationConfig::default);
        // TODO: Add deadline field to MigrationConfig
        // migration.deadline = Some(deadline);
        self
    }

    /// Enable gradual migration mode
    ///
    /// In gradual mode, the system accepts both old and new signature formats
    /// during the transition period.
    pub fn enable_gradual_migration(mut self) -> Self {
        self.migration = Some(MigrationConfig::gradual());
        self
    }

    /// Build the final configuration
    ///
    /// Uses sensible defaults for any unspecified policies:
    /// - Transaction: HybridPreferred
    /// - Block: HybridPreferred
    /// - Consensus: HybridRequired
    /// - Migration: Default configuration
    pub fn build(self) -> PolicyConfig {
        PolicyConfig {
            transaction_policy: self
                .transaction_policy
                .unwrap_or(ValidationPolicy::HybridPreferred),
            block_policy: self
                .block_policy
                .unwrap_or(ValidationPolicy::HybridPreferred),
            consensus_policy: self
                .consensus_policy
                .unwrap_or(ValidationPolicy::HybridRequired),
            migration: self.migration.unwrap_or_default(),
        }
    }
}

// =============================================================================
// Keypair Generation Builder
// =============================================================================

/// Fluent builder for keypair generation
///
/// Provides fine-grained control over keypair generation parameters.
///
/// # Example
///
/// ```no_run
/// use pq_lib::builders::KeypairBuilder;
/// use pq_lib::typed::Ed25519;
/// use rand::rngs::OsRng;
///
/// # fn example() -> Result<(), pq_lib::CryptoError> {
/// let keypair = KeypairBuilder::<Ed25519>::new()
///     .with_rng(OsRng)
///     .generate()?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "std")]
pub struct KeypairBuilder<A: crate::typed::Algorithm> {
    algorithm: core::marker::PhantomData<A>,
    rng: Option<Box<dyn rand::RngCore>>,
}

#[cfg(feature = "std")]
impl<A: crate::typed::Algorithm> KeypairBuilder<A> {
    /// Create a new keypair builder
    pub fn new() -> Self {
        Self {
            algorithm: core::marker::PhantomData,
            rng: None,
        }
    }

    /// Specify a custom random number generator
    ///
    /// If not specified, the builder will use a cryptographically secure
    /// default RNG.
    pub fn with_rng<R: rand::RngCore + 'static>(mut self, rng: R) -> Self {
        self.rng = Some(Box::new(rng));
        self
    }

    /// Generate the keypair
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key generation fails.
    pub fn generate(self) -> crate::CryptoResult<crate::typed::Keypair<A>> {
        // TODO: Implement actual key generation
        // For now, this is a placeholder that shows the API design
        Err(crate::CryptoError::UnsupportedAlgorithm(
            "Key generation not yet implemented".into(),
        ))
    }
}

#[cfg(feature = "std")]
impl<A: crate::typed::Algorithm> Default for KeypairBuilder<A> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Signature Builder (for complex signing scenarios)
// =============================================================================

/// Fluent builder for signature creation with advanced options
///
/// Useful for complex signing scenarios with custom parameters.
///
/// # Example
///
/// ```no_run
/// use pq_lib::builders::SignatureBuilder;
/// use pq_lib::DomainSeparator;
/// use pq_lib::typed::{Ed25519, PrivateKey};
///
/// # fn example(private_key: &PrivateKey<Ed25519>) -> Result<(), pq_lib::CryptoError> {
/// let signature = SignatureBuilder::new()
///     .message(b"Important message")
///     .domain(DomainSeparator::Consensus)
///     .private_key(private_key)
///     .sign()?;
/// # Ok(())
/// # }
/// ```
pub struct SignatureBuilder<'a, A: crate::typed::Algorithm> {
    message: Option<&'a [u8]>,
    domain: Option<crate::DomainSeparator>,
    private_key: Option<&'a crate::typed::PrivateKey<A>>,
    _phantom: core::marker::PhantomData<A>,
}

impl<'a, A: crate::typed::Algorithm> SignatureBuilder<'a, A> {
    /// Create a new signature builder
    pub fn new() -> Self {
        Self {
            message: None,
            domain: None,
            private_key: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Set the message to sign
    pub fn message(mut self, message: &'a [u8]) -> Self {
        self.message = Some(message);
        self
    }

    /// Set the domain separator
    pub fn domain(mut self, domain: crate::DomainSeparator) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the private key for signing
    pub fn private_key(mut self, key: &'a crate::typed::PrivateKey<A>) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Generate the signature
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if:
    /// - Message, domain, or private key not set
    /// - Signing operation fails
    pub fn sign(self) -> crate::CryptoResult<crate::typed::Signature<A>> {
        let message = self
            .message
            .ok_or_else(|| crate::CryptoError::InvalidSignature("Message not set".into()))?;
        let domain = self
            .domain
            .ok_or_else(|| crate::CryptoError::InvalidSignature("Domain not set".into()))?;
        let _private_key = self
            .private_key
            .ok_or_else(|| crate::CryptoError::InvalidKey("Private key not set".into()))?;

        // TODO: Implement actual signing
        Err(crate::CryptoError::UnsupportedAlgorithm(
            "Signing not yet implemented".into(),
        ))
    }
}

impl<'a, A: crate::typed::Algorithm> Default for SignatureBuilder<'a, A> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_builder_default() {
        let config = PolicyConfigBuilder::new().build();
        assert_eq!(config.transaction_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
    }

    #[test]
    fn test_policy_builder_conservative() {
        let config = PolicyConfigBuilder::conservative().build();
        assert_eq!(config.transaction_policy, ValidationPolicy::HybridRequired);
        assert_eq!(config.block_policy, ValidationPolicy::HybridRequired);
        assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
    }

    #[test]
    fn test_policy_builder_progressive() {
        let config = PolicyConfigBuilder::progressive().build();
        assert_eq!(config.transaction_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
    }

    #[test]
    fn test_policy_builder_legacy() {
        let config = PolicyConfigBuilder::legacy().build();
        assert_eq!(config.transaction_policy, ValidationPolicy::ClassicOnly);
        assert_eq!(config.block_policy, ValidationPolicy::ClassicOnly);
        assert_eq!(config.consensus_policy, ValidationPolicy::ClassicOnly);
    }

    #[test]
    fn test_policy_builder_post_quantum() {
        let config = PolicyConfigBuilder::post_quantum().build();
        assert_eq!(config.transaction_policy, ValidationPolicy::PqOnly);
        assert_eq!(config.block_policy, ValidationPolicy::PqOnly);
        assert_eq!(config.consensus_policy, ValidationPolicy::PqOnly);
    }

    #[test]
    fn test_policy_builder_fluent() {
        let config = PolicyConfigBuilder::new()
            .transaction(ValidationPolicy::ClassicOnly)
            .block(ValidationPolicy::HybridPreferred)
            .consensus(ValidationPolicy::HybridRequired)
            .build();

        assert_eq!(config.transaction_policy, ValidationPolicy::ClassicOnly);
        assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);
    }

    #[test]
    fn test_policy_builder_override_conservative() {
        let config = PolicyConfigBuilder::conservative()
            .transaction(ValidationPolicy::ClassicOnly)
            .build();

        assert_eq!(config.transaction_policy, ValidationPolicy::ClassicOnly);
        assert_eq!(config.block_policy, ValidationPolicy::HybridRequired); // Still conservative
    }
}
