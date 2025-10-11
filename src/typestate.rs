//! Type-state pattern for safe migration management
//!
//! This module implements a type-state machine that uses Rust's type system
//! to enforce valid state transitions during cryptographic migration.
//!
//! # Design Philosophy
//!
//! 1. **Compile-Time Safety**: Invalid transitions are impossible to express
//! 2. **Self-Documenting**: State transitions are explicit in the type signature
//! 3. **Zero Runtime Cost**: All state information erased at compile time
//! 4. **Elegant API**: Method availability guides the developer
//!
//! # State Machine
//!
//! ```text
//! ┌─────────┐ begin_migration  ┌────────────┐ complete_migration  ┌─────────┐
//! │ Legacy  │─────────────────>│ Transition │────────────────────>│ Modern  │
//! └─────────┘                   └────────────┘                     └─────────┘
//!      │                              │                                 │
//!      │ rollback_migration           │ rollback_migration              │
//!      │<─────────────────────────────┘                                 │
//!      │<───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Examples
//!
//! ```
//! use pq_lib::typestate::{MigrationContext, LegacyState};
//! use pq_lib::PolicyConfig;
//!
//! # fn example() -> Result<(), pq_lib::CryptoError> {
//! // Start in legacy state (classical-only signatures)
//! let context = MigrationContext::<LegacyState>::new(PolicyConfig::default());
//!
//! // Begin migration (compile-time state change)
//! let context = context.begin_migration()?;
//!
//! // ... migration period ...
//!
//! // Complete migration when ready
//! let context = context.complete_migration()?;
//!
//! // Now in modern state - only hybrid/PQ signatures accepted
//! # Ok(())
//! # }
//! ```

#[cfg(not(feature = "std"))]
use alloc::{format, string::ToString};

#[cfg(feature = "std")]
use std::{format, string::ToString};

use core::marker::PhantomData;

#[cfg(feature = "std")]
use std::time::SystemTime;

use crate::{CryptoError, CryptoResult, PolicyConfig, ValidationPolicy};

// =============================================================================
// State Marker Types
// =============================================================================

/// Legacy state: Classical-only cryptography
///
/// In this state, the system accepts only classical Ed25519 signatures.
/// This is the starting point for systems migrating to post-quantum crypto.
#[derive(Debug, Clone, Copy)]
pub struct LegacyState;

/// Transition state: Hybrid operation during migration
///
/// In this state, the system accepts both classical and hybrid signatures,
/// providing a safe migration path without disrupting operations.
#[derive(Debug, Clone, Copy)]
pub struct TransitionState;

/// Modern state: Post-quantum ready
///
/// In this state, the system requires hybrid or PQ-only signatures,
/// providing quantum resistance.
#[derive(Debug, Clone, Copy)]
pub struct ModernState;

/// Archived state: Historical data only
///
/// This state indicates the system has completed migration and is
/// preserving historical signatures for archival purposes only.
#[derive(Debug, Clone, Copy)]
pub struct ArchivedState;

// =============================================================================
// State Trait
// =============================================================================

/// Marker trait for migration states
pub trait MigrationState: core::fmt::Debug + Clone + Copy {
    /// Human-readable state name
    const NAME: &'static str;

    /// Whether this state accepts classical signatures
    const ACCEPTS_CLASSICAL: bool;

    /// Whether this state accepts hybrid signatures
    const ACCEPTS_HYBRID: bool;

    /// Whether this state accepts PQ-only signatures
    const ACCEPTS_PQ: bool;

    /// Whether this state is transient (requires eventual transition)
    const IS_TRANSIENT: bool;
}

impl MigrationState for LegacyState {
    const NAME: &'static str = "Legacy";
    const ACCEPTS_CLASSICAL: bool = true;
    const ACCEPTS_HYBRID: bool = false;
    const ACCEPTS_PQ: bool = false;
    const IS_TRANSIENT: bool = true; // Should eventually migrate
}

impl MigrationState for TransitionState {
    const NAME: &'static str = "Transition";
    const ACCEPTS_CLASSICAL: bool = true;
    const ACCEPTS_HYBRID: bool = true;
    const ACCEPTS_PQ: bool = true;
    const IS_TRANSIENT: bool = true; // Should eventually complete or rollback
}

impl MigrationState for ModernState {
    const NAME: &'static str = "Modern";
    const ACCEPTS_CLASSICAL: bool = false;
    const ACCEPTS_HYBRID: bool = true;
    const ACCEPTS_PQ: bool = true;
    const IS_TRANSIENT: bool = false; // Stable end state
}

impl MigrationState for ArchivedState {
    const NAME: &'static str = "Archived";
    const ACCEPTS_CLASSICAL: bool = true; // For historical verification only
    const ACCEPTS_HYBRID: bool = true;
    const ACCEPTS_PQ: bool = true;
    const IS_TRANSIENT: bool = false; // Stable end state
}

// =============================================================================
// Migration Context
// =============================================================================

/// Type-safe migration context
///
/// The state parameter `S` determines which operations are available.
/// Invalid state transitions are prevented at compile time.
///
/// # Type Parameter
///
/// - `S`: Current migration state (LegacyState, TransitionState, or ModernState)
#[derive(Debug, Clone)]
pub struct MigrationContext<S: MigrationState> {
    /// Policy configuration for this state
    config: PolicyConfig,

    /// Optional migration deadline
    #[cfg(feature = "std")]
    deadline: Option<SystemTime>,

    /// Migration metadata
    metadata: MigrationMetadata,

    /// Type-level state marker (zero-cost)
    _state: PhantomData<S>,
}

/// Migration metadata and metrics
#[derive(Debug, Clone)]
pub struct MigrationMetadata {
    /// Number of classical signatures validated in this state
    pub classical_count: u64,

    /// Number of hybrid signatures validated in this state
    pub hybrid_count: u64,

    /// Number of PQ-only signatures validated in this state
    pub pq_count: u64,

    /// Number of validation failures
    pub failure_count: u64,
}

impl Default for MigrationMetadata {
    fn default() -> Self {
        Self {
            classical_count: 0,
            hybrid_count: 0,
            pq_count: 0,
            failure_count: 0,
        }
    }
}

// =============================================================================
// Common Methods (Available in All States)
// =============================================================================

impl<S: MigrationState> MigrationContext<S> {
    /// Get the current state name
    #[inline(always)]
    pub const fn state_name() -> &'static str {
        S::NAME
    }

    /// Get the current policy configuration
    #[inline(always)]
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Get migration metadata
    #[inline(always)]
    pub fn metadata(&self) -> &MigrationMetadata {
        &self.metadata
    }

    /// Get migration deadline (if set)
    #[cfg(feature = "std")]
    pub fn deadline(&self) -> Option<SystemTime> {
        self.deadline
    }

    /// Check if the deadline has passed
    #[cfg(feature = "std")]
    pub fn is_deadline_passed(&self) -> bool {
        self.deadline
            .map(|d| SystemTime::now() >= d)
            .unwrap_or(false)
    }

    /// Get the percentage of hybrid/PQ signatures vs total
    pub fn migration_progress(&self) -> f64 {
        let total =
            self.metadata.classical_count + self.metadata.hybrid_count + self.metadata.pq_count;
        if total == 0 {
            return 0.0;
        }
        let modern = self.metadata.hybrid_count + self.metadata.pq_count;
        (modern as f64 / total as f64) * 100.0
    }

    /// Record a signature validation
    pub fn record_validation(&mut self, policy: ValidationPolicy) {
        match policy {
            ValidationPolicy::ClassicOnly => self.metadata.classical_count += 1,
            ValidationPolicy::HybridPreferred | ValidationPolicy::HybridRequired => {
                self.metadata.hybrid_count += 1
            }
            ValidationPolicy::PqOnly => self.metadata.pq_count += 1,
        }
    }

    /// Record a validation failure
    pub fn record_failure(&mut self) {
        self.metadata.failure_count += 1;
    }
}

// =============================================================================
// Legacy State Methods
// =============================================================================

impl MigrationContext<LegacyState> {
    /// Create a new migration context in legacy state
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "std")]
            deadline: None,
            metadata: MigrationMetadata::default(),
            _state: PhantomData,
        }
    }

    /// Begin migration to hybrid cryptography
    ///
    /// # Transition
    ///
    /// `LegacyState` → `TransitionState`
    ///
    /// # Parameters
    ///
    /// - `deadline`: Optional deadline for completing migration
    ///
    /// # Returns
    ///
    /// A new `MigrationContext` in `TransitionState`
    #[cfg(feature = "std")]
    pub fn begin_migration(
        self,
        deadline: Option<SystemTime>,
    ) -> CryptoResult<MigrationContext<TransitionState>> {
        // Validate the system is ready for migration
        if self.metadata.failure_count > 0 {
            return Err(CryptoError::PolicyViolation(
                "Cannot begin migration with validation failures".into(),
            ));
        }

        Ok(MigrationContext {
            config: self.config.transition_to_hybrid(),
            deadline,
            metadata: self.metadata,
            _state: PhantomData,
        })
    }

    /// Begin migration (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn begin_migration(self) -> CryptoResult<MigrationContext<TransitionState>> {
        Ok(MigrationContext {
            config: self.config.transition_to_hybrid(),
            metadata: self.metadata,
            _state: PhantomData,
        })
    }
}

// =============================================================================
// Transition State Methods
// =============================================================================

impl MigrationContext<TransitionState> {
    /// Check if the system is ready to complete migration
    ///
    /// Ready when:
    /// 1. Deadline has passed (if set), OR
    /// 2. Migration progress >= threshold
    pub fn is_ready_to_complete(&self, threshold_percent: f64) -> bool {
        #[cfg(feature = "std")]
        {
            if self.is_deadline_passed() {
                return true;
            }
        }

        self.migration_progress() >= threshold_percent
    }

    /// Complete migration to modern state
    ///
    /// # Transition
    ///
    /// `TransitionState` → `ModernState`
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Migration not ready (use `is_ready_to_complete` first)
    /// - Validation failures exceed threshold
    pub fn complete_migration(self) -> CryptoResult<MigrationContext<ModernState>> {
        // Validate readiness
        if !self.is_ready_to_complete(90.0) {
            return Err(CryptoError::PolicyViolation(
                "Migration not ready: insufficient hybrid/PQ adoption".into(),
            ));
        }

        // Check failure rate
        let total_validations =
            self.metadata.classical_count + self.metadata.hybrid_count + self.metadata.pq_count;
        if total_validations > 0 {
            let failure_rate =
                (self.metadata.failure_count as f64 / total_validations as f64) * 100.0;
            if failure_rate > 5.0 {
                return Err(CryptoError::PolicyViolation(format!(
                    "Failure rate too high: {:.2}%",
                    failure_rate
                )));
            }
        }

        Ok(MigrationContext {
            config: self.config.complete_migration(),
            #[cfg(feature = "std")]
            deadline: None,
            metadata: self.metadata,
            _state: PhantomData,
        })
    }

    /// Rollback migration to legacy state
    ///
    /// # Transition
    ///
    /// `TransitionState` → `LegacyState`
    ///
    /// Use this if migration encounters critical issues.
    pub fn rollback_migration(self) -> MigrationContext<LegacyState> {
        MigrationContext {
            config: self.config.rollback_to_classical(),
            #[cfg(feature = "std")]
            deadline: None,
            metadata: self.metadata,
            _state: PhantomData,
        }
    }

    /// Extend the migration deadline
    #[cfg(feature = "std")]
    pub fn extend_deadline(&mut self, new_deadline: SystemTime) -> CryptoResult<()> {
        if let Some(current) = self.deadline {
            if new_deadline <= current {
                return Err(CryptoError::PolicyViolation(
                    "New deadline must be after current deadline".into(),
                ));
            }
        }
        self.deadline = Some(new_deadline);
        Ok(())
    }
}

// =============================================================================
// Modern State Methods
// =============================================================================

impl MigrationContext<ModernState> {
    /// Archive the system state for historical records
    ///
    /// # Transition
    ///
    /// `ModernState` → `ArchivedState`
    ///
    /// Use this when moving to a new cryptographic standard.
    pub fn archive(self) -> MigrationContext<ArchivedState> {
        MigrationContext {
            config: self.config,
            #[cfg(feature = "std")]
            deadline: None,
            metadata: self.metadata,
            _state: PhantomData,
        }
    }

    /// Rollback to transition state (emergency only)
    ///
    /// # Transition
    ///
    /// `ModernState` → `TransitionState`
    ///
    /// ⚠️  **WARNING**: This should only be used in emergencies if a critical
    /// vulnerability is discovered in post-quantum algorithms.
    pub fn emergency_rollback(self) -> MigrationContext<TransitionState> {
        MigrationContext {
            config: self.config.transition_to_hybrid(),
            #[cfg(feature = "std")]
            deadline: None,
            metadata: self.metadata,
            _state: PhantomData,
        }
    }
}

// =============================================================================
// Helper Trait Implementations for PolicyConfig
// =============================================================================

trait PolicyConfigTransitions {
    fn transition_to_hybrid(self) -> Self;
    fn complete_migration(self) -> Self;
    fn rollback_to_classical(self) -> Self;
}

impl PolicyConfigTransitions for PolicyConfig {
    fn transition_to_hybrid(mut self) -> Self {
        self.transaction_policy = ValidationPolicy::HybridPreferred;
        self.block_policy = ValidationPolicy::HybridPreferred;
        self.consensus_policy = ValidationPolicy::HybridRequired;
        self
    }

    fn complete_migration(mut self) -> Self {
        self.transaction_policy = ValidationPolicy::HybridRequired;
        self.block_policy = ValidationPolicy::HybridRequired;
        self.consensus_policy = ValidationPolicy::HybridRequired;
        self
    }

    fn rollback_to_classical(mut self) -> Self {
        self.transaction_policy = ValidationPolicy::ClassicOnly;
        self.block_policy = ValidationPolicy::ClassicOnly;
        self.consensus_policy = ValidationPolicy::ClassicOnly;
        self
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_constants() {
        assert_eq!(LegacyState::NAME, "Legacy");
        assert!(LegacyState::ACCEPTS_CLASSICAL);
        assert!(!LegacyState::ACCEPTS_HYBRID);

        assert_eq!(TransitionState::NAME, "Transition");
        assert!(TransitionState::ACCEPTS_CLASSICAL);
        assert!(TransitionState::ACCEPTS_HYBRID);

        assert_eq!(ModernState::NAME, "Modern");
        assert!(!ModernState::ACCEPTS_CLASSICAL);
        assert!(ModernState::ACCEPTS_HYBRID);
    }

    #[test]
    fn test_migration_flow() {
        let config = PolicyConfig::default();
        let context = MigrationContext::<LegacyState>::new(config);

        assert_eq!(MigrationContext::<LegacyState>::state_name(), "Legacy");

        // Begin migration
        #[cfg(feature = "std")]
        let context = context.begin_migration(None).unwrap();
        #[cfg(not(feature = "std"))]
        let context = context.begin_migration().unwrap();

        assert_eq!(
            MigrationContext::<TransitionState>::state_name(),
            "Transition"
        );
    }

    #[test]
    fn test_migration_progress() {
        let mut context = MigrationContext::<TransitionState> {
            config: PolicyConfig::default(),
            #[cfg(feature = "std")]
            deadline: None,
            metadata: MigrationMetadata {
                classical_count: 100,
                hybrid_count: 900,
                pq_count: 0,
                failure_count: 0,
            },
            _state: PhantomData,
        };

        assert_eq!(context.migration_progress(), 90.0);

        context.record_validation(ValidationPolicy::HybridRequired);
        assert!(context.migration_progress() > 90.0);
    }

    #[test]
    fn test_type_safety() {
        // This test demonstrates that invalid transitions don't compile

        let config = PolicyConfig::default();
        let context = MigrationContext::<LegacyState>::new(config);

        // The following would not compile (no complete_migration method on LegacyState):
        // let _modern = context.complete_migration(); // ERROR!

        // Must go through transition state:
        #[cfg(feature = "std")]
        let transition = context.begin_migration(None).unwrap();
        #[cfg(not(feature = "std"))]
        let transition = context.begin_migration().unwrap();

        // Now complete_migration is available
        // let _modern = transition.complete_migration(); // Would work (if ready)
    }

    #[test]
    fn test_rollback() {
        let config = PolicyConfig::default();
        let legacy = MigrationContext::<LegacyState>::new(config);

        #[cfg(feature = "std")]
        let transition = legacy.begin_migration(None).unwrap();
        #[cfg(not(feature = "std"))]
        let transition = legacy.begin_migration().unwrap();

        let rolled_back = transition.rollback_migration();
        assert_eq!(
            MigrationContext::<LegacyState>::state_name(),
            rolled_back.state_name()
        );
    }
}
