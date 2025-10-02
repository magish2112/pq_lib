//! Validation policies for signature verification

use core::fmt;

/// Validation policy for signature verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub enum ValidationPolicy {
    /// Accept only classical signatures (Ed25519)
    ClassicOnly,
    /// Prefer hybrid signatures but accept classical
    HybridPreferred,
    /// Require both classical and PQ signatures
    HybridRequired,
    /// Accept only post-quantum signatures
    PqOnly,
}

impl ValidationPolicy {
    /// Check if policy allows classical-only signatures
    pub const fn allows_classic_only(self) -> bool {
        matches!(self, ValidationPolicy::ClassicOnly | ValidationPolicy::HybridPreferred)
    }

    /// Check if policy allows post-quantum signatures
    pub const fn allows_pq(self) -> bool {
        matches!(
            self,
            ValidationPolicy::HybridPreferred | ValidationPolicy::HybridRequired | ValidationPolicy::PqOnly
        )
    }

    /// Check if policy requires both signature types
    pub const fn requires_hybrid(self) -> bool {
        matches!(self, ValidationPolicy::HybridRequired)
    }

    /// Get policy name for display
    pub const fn name(self) -> &'static str {
        match self {
            ValidationPolicy::ClassicOnly => "Classic Only",
            ValidationPolicy::HybridPreferred => "Hybrid Preferred",
            ValidationPolicy::HybridRequired => "Hybrid Required",
            ValidationPolicy::PqOnly => "PQ Only",
        }
    }

    /// Get security level of policy (higher = more secure)
    pub const fn security_level(self) -> u8 {
        match self {
            ValidationPolicy::ClassicOnly => 1,
            ValidationPolicy::HybridPreferred => 3,
            ValidationPolicy::HybridRequired => 5,
            ValidationPolicy::PqOnly => 5,
        }
    }
}

impl fmt::Display for ValidationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        ValidationPolicy::HybridPreferred
    }
}

/// Migration path configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct MigrationConfig {
    /// Current validation policy
    pub current_policy: ValidationPolicy,
    /// Target policy for migration
    pub target_policy: ValidationPolicy,
    /// Whether migration is active
    pub migration_active: bool,
    /// Migration deadline (Unix timestamp)
    pub deadline: Option<u64>,
}

impl MigrationConfig {
    /// Create new migration config
    pub const fn new(current_policy: ValidationPolicy, target_policy: ValidationPolicy) -> Self {
        Self {
            current_policy,
            target_policy,
            migration_active: true,
            deadline: None,
        }
    }

    /// Check if migration should be enforced
    ///
    /// In std environments, uses system time. In no_std environments,
    /// requires external time source via `current_time` parameter.
    pub fn should_enforce_target(&self) -> bool {
        self.should_enforce_target_with_time(None)
    }

    /// Check if migration should be enforced with custom time source
    ///
    /// # Arguments
    ///
    /// * `current_time` - Optional current Unix timestamp. If None, uses system time in std environments.
    pub fn should_enforce_target_with_time(&self, current_time: Option<u64>) -> bool {
        if !self.migration_active {
            return false;
        }

        if let Some(deadline) = self.deadline {
            let now = current_time.unwrap_or_else(|| {
                #[cfg(feature = "std")]
                {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                }
                #[cfg(not(feature = "std"))]
                {
                    // In no_std, we can't get current time without external source
                    // Return false to maintain conservative behavior
                    return false;
                }
            });

            now >= deadline
        } else {
            false
        }
    }

    /// Get effective policy based on migration status
    ///
    /// # Arguments
    ///
    /// * `current_time` - Optional current Unix timestamp for time-based migration checks
    pub fn effective_policy(&self) -> ValidationPolicy {
        self.effective_policy_with_time(None)
    }

    /// Get effective policy based on migration status with custom time source
    ///
    /// # Arguments
    ///
    /// * `current_time` - Optional current Unix timestamp. If None, uses system time in std environments.
    pub fn effective_policy_with_time(&self, current_time: Option<u64>) -> ValidationPolicy {
        if self.should_enforce_target_with_time(current_time) {
            self.target_policy
        } else {
            self.current_policy
        }
    }
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            current_policy: ValidationPolicy::HybridPreferred,
            target_policy: ValidationPolicy::HybridRequired,
            migration_active: false,
            deadline: None,
        }
    }
}

/// Policy configuration for different contexts
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyConfig {
    /// Policy for transaction signatures
    pub transaction_policy: ValidationPolicy,
    /// Policy for block signatures
    pub block_policy: ValidationPolicy,
    /// Policy for consensus messages
    pub consensus_policy: ValidationPolicy,
    /// Migration configuration
    pub migration: MigrationConfig,
}

impl PolicyConfig {
    /// Create conservative policy config (allows gradual migration)
    pub fn conservative() -> Self {
        Self {
            transaction_policy: ValidationPolicy::HybridPreferred,
            block_policy: ValidationPolicy::HybridPreferred,
            consensus_policy: ValidationPolicy::HybridRequired,
            migration: MigrationConfig::default(),
        }
    }

    /// Create strict policy config (requires PQ signatures)
    pub fn strict() -> Self {
        Self {
            transaction_policy: ValidationPolicy::HybridRequired,
            block_policy: ValidationPolicy::HybridRequired,
            consensus_policy: ValidationPolicy::HybridRequired,
            migration: MigrationConfig {
                current_policy: ValidationPolicy::HybridRequired,
                target_policy: ValidationPolicy::PqOnly,
                migration_active: false,
                deadline: None,
            },
        }
    }

    /// Get policy for specific domain
    pub fn policy_for_domain(&self, domain: crate::DomainSeparator) -> ValidationPolicy {
        match domain {
            crate::DomainSeparator::Transaction => self.transaction_policy,
            crate::DomainSeparator::Block => self.block_policy,
            crate::DomainSeparator::Consensus => self.consensus_policy,
            _ => self.transaction_policy, // Default to transaction policy
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self::conservative()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_policies() {
        assert!(ValidationPolicy::ClassicOnly.allows_classic_only());
        assert!(!ValidationPolicy::ClassicOnly.allows_pq());
        assert!(!ValidationPolicy::ClassicOnly.requires_hybrid());

        assert!(ValidationPolicy::HybridPreferred.allows_classic_only());
        assert!(ValidationPolicy::HybridPreferred.allows_pq());
        assert!(!ValidationPolicy::HybridPreferred.requires_hybrid());

        assert!(!ValidationPolicy::HybridRequired.allows_classic_only());
        assert!(ValidationPolicy::HybridRequired.allows_pq());
        assert!(ValidationPolicy::HybridRequired.requires_hybrid());

        assert!(!ValidationPolicy::PqOnly.allows_classic_only());
        assert!(ValidationPolicy::PqOnly.allows_pq());
        assert!(!ValidationPolicy::PqOnly.requires_hybrid());
    }

    #[test]
    fn test_policy_config() {
        let config = PolicyConfig::conservative();
        assert_eq!(config.transaction_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.block_policy, ValidationPolicy::HybridPreferred);
        assert_eq!(config.consensus_policy, ValidationPolicy::HybridRequired);

        let strict = PolicyConfig::strict();
        assert_eq!(strict.transaction_policy, ValidationPolicy::HybridRequired);
        assert_eq!(strict.consensus_policy, ValidationPolicy::HybridRequired);
    }

    #[test]
    fn test_policy_for_domain() {
        let config = PolicyConfig::conservative();
        assert_eq!(
            config.policy_for_domain(crate::DomainSeparator::Transaction),
            ValidationPolicy::HybridPreferred
        );
        assert_eq!(
            config.policy_for_domain(crate::DomainSeparator::Consensus),
            ValidationPolicy::HybridRequired
        );
    }

    #[test]
    fn test_migration_config() {
        let mut config = MigrationConfig::new(
            ValidationPolicy::HybridPreferred,
            ValidationPolicy::HybridRequired,
        );

        assert_eq!(config.effective_policy(), ValidationPolicy::HybridPreferred);

        // Simulate deadline passed
        config.deadline = Some(0); // Unix epoch
        // Note: should_enforce_target() would return true in std environment with current time > 0
        // But we can't test time-dependent logic easily in no_std
    }
}

