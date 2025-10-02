//! Algorithm identifiers and properties

use core::fmt;

/// Algorithm identifiers for hybrid cryptography
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum AlgorithmId {
    /// Ed25519 only (backward compatibility)
    Ed25519 = 0,
    /// ML-DSA-65 + Ed25519 hybrid
    MlDsa65 = 1,
    /// ML-DSA-87 + Ed25519 hybrid (stronger security)
    MlDsa87 = 2,
    /// SLH-DSA + Ed25519 hybrid (maximum long-term security)
    SlhDsaShake256f = 3,
}

impl AlgorithmId {
    /// Get human-readable name
    pub const fn name(self) -> &'static str {
        match self {
            AlgorithmId::Ed25519 => "Ed25519",
            AlgorithmId::MlDsa65 => "ML-DSA-65 + Ed25519",
            AlgorithmId::MlDsa87 => "ML-DSA-87 + Ed25519",
            AlgorithmId::SlhDsaShake256f => "SLH-DSA + Ed25519",
        }
    }

    /// Check if algorithm uses post-quantum components
    pub const fn is_post_quantum(self) -> bool {
        !matches!(self, AlgorithmId::Ed25519)
    }

    /// Get expected signature size in bytes
    pub const fn signature_size(self) -> usize {
        match self {
            AlgorithmId::Ed25519 => 64,
            AlgorithmId::MlDsa65 => 64 + 3302, // Ed25519 + ML-DSA-65
            AlgorithmId::MlDsa87 => 64 + 4627, // Ed25519 + ML-DSA-87
            AlgorithmId::SlhDsaShake256f => 64 + 7856, // Ed25519 + SLH-DSA
        }
    }

    /// Get expected public key size in bytes
    pub const fn public_key_size(self) -> usize {
        match self {
            AlgorithmId::Ed25519 => 32,
            AlgorithmId::MlDsa65 => 32 + 1952, // Ed25519 + ML-DSA-65
            AlgorithmId::MlDsa87 => 32 + 2592, // Ed25519 + ML-DSA-87
            AlgorithmId::SlhDsaShake256f => 32 + 32, // Ed25519 + SLH-DSA
        }
    }

    /// Get security level estimate (NIST categories)
    pub const fn security_level(self) -> u8 {
        match self {
            AlgorithmId::Ed25519 => 2, // ~128-bit security
            AlgorithmId::MlDsa65 => 3, // Category 3 (192-bit)
            AlgorithmId::MlDsa87 => 5, // Category 5 (256-bit)
            AlgorithmId::SlhDsaShake256f => 5, // Category 5 (256-bit)
        }
    }

    /// Check if algorithm is available with current feature flags
    pub const fn is_available(self) -> bool {
        match self {
            AlgorithmId::Ed25519 => cfg!(feature = "ed25519"),
            AlgorithmId::MlDsa65 => cfg!(feature = "ml-dsa"),
            AlgorithmId::MlDsa87 => cfg!(feature = "ml-dsa"),
            AlgorithmId::SlhDsaShake256f => cfg!(feature = "slh-dsa"),
        }
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Iterator over all available algorithms
pub struct AlgorithmIter {
    current: usize,
}

impl AlgorithmIter {
    /// Create new iterator
    pub const fn new() -> Self {
        Self { current: 0 }
    }
}

impl Iterator for AlgorithmIter {
    type Item = AlgorithmId;

    fn next(&mut self) -> Option<Self::Item> {
        let algorithms = [
            AlgorithmId::Ed25519,
            AlgorithmId::MlDsa65,
            AlgorithmId::MlDsa87,
            AlgorithmId::SlhDsaShake256f,
        ];

        if self.current < algorithms.len() {
            let algo = algorithms[self.current];
            self.current += 1;
            if algo.is_available() {
                Some(algo)
            } else {
                self.next() // Skip unavailable algorithms
            }
        } else {
            None
        }
    }
}

/// Get all available algorithms
pub fn available_algorithms() -> AlgorithmIter {
    AlgorithmIter::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        assert!(!AlgorithmId::Ed25519.is_post_quantum());
        assert!(AlgorithmId::MlDsa65.is_post_quantum());

        assert_eq!(AlgorithmId::Ed25519.signature_size(), 64);
        assert_eq!(AlgorithmId::MlDsa65.signature_size(), 64 + 3302);

        assert_eq!(AlgorithmId::Ed25519.public_key_size(), 32);
        assert_eq!(AlgorithmId::MlDsa65.public_key_size(), 32 + 1952);
    }

    #[test]
    fn test_algorithm_iterator() {
        let mut iter = available_algorithms();
        let first = iter.next();
        assert!(first.is_some());
        // Should at least have Ed25519 if std is enabled
        #[cfg(feature = "ed25519")]
        assert_eq!(first, Some(AlgorithmId::Ed25519));
    }
}

