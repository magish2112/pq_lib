//! Domain separators for cryptographic operations

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use core::fmt;

/// Domain separators for cryptographic operations to prevent cross-protocol attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DomainSeparator {
    /// Transaction signing
    Transaction = 0x01,
    /// Block header signing
    Block = 0x02,
    /// Consensus message signing
    Consensus = 0x03,
    /// Validator key certification
    ValidatorCert = 0x04,
    /// State commitment signing
    StateCommitment = 0x05,
    /// Custom domain (for extensibility)
    Custom(u8),
}

impl DomainSeparator {
    /// Get domain tag as bytes for cryptographic operations
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            DomainSeparator::Transaction => b"Symbios-PQC-TX-v1",
            DomainSeparator::Block => b"Symbios-PQC-BLOCK-v1",
            DomainSeparator::Consensus => b"Symbios-PQC-CONSENSUS-v1",
            DomainSeparator::ValidatorCert => b"Symbios-PQC-VALIDATOR-v1",
            DomainSeparator::StateCommitment => b"Symbios-PQC-STATE-v1",
            DomainSeparator::Custom(_) => b"Symbios-PQC-CUSTOM-v1",
        }
    }

    /// Get domain name for display
    pub const fn name(self) -> &'static str {
        match self {
            DomainSeparator::Transaction => "Transaction",
            DomainSeparator::Block => "Block",
            DomainSeparator::Consensus => "Consensus",
            DomainSeparator::ValidatorCert => "Validator Certificate",
            DomainSeparator::StateCommitment => "State Commitment",
            DomainSeparator::Custom(id) => "Custom",
        }
    }

    /// Check if domain separator is blockchain-specific
    pub const fn is_blockchain_domain(self) -> bool {
        matches!(
            self,
            DomainSeparator::Transaction
                | DomainSeparator::Block
                | DomainSeparator::Consensus
                | DomainSeparator::ValidatorCert
                | DomainSeparator::StateCommitment
        )
    }
}

impl From<u8> for DomainSeparator {
    fn from(value: u8) -> Self {
        match value {
            0x01 => DomainSeparator::Transaction,
            0x02 => DomainSeparator::Block,
            0x03 => DomainSeparator::Consensus,
            0x04 => DomainSeparator::ValidatorCert,
            0x05 => DomainSeparator::StateCommitment,
            custom => DomainSeparator::Custom(custom),
        }
    }
}

impl From<DomainSeparator> for u8 {
    fn from(domain: DomainSeparator) -> Self {
        match domain {
            DomainSeparator::Transaction => 0x01,
            DomainSeparator::Block => 0x02,
            DomainSeparator::Consensus => 0x03,
            DomainSeparator::ValidatorCert => 0x04,
            DomainSeparator::StateCommitment => 0x05,
            DomainSeparator::Custom(id) => id,
        }
    }
}

impl fmt::Display for DomainSeparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Create domain-separated message by prepending domain tag
pub fn create_domain_separated_message(domain: DomainSeparator, message: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.as_bytes().len() + message.len());
    result.extend_from_slice(domain.as_bytes());
    result.extend_from_slice(message);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separators() {
        assert_eq!(DomainSeparator::Transaction.as_bytes(), b"Symbios-PQC-TX-v1");
        assert_eq!(DomainSeparator::Block.as_bytes(), b"Symbios-PQC-BLOCK-v1");
        assert!(DomainSeparator::Transaction.is_blockchain_domain());
        assert!(DomainSeparator::Custom(0xFF).is_blockchain_domain()); // Custom is not blockchain-specific
    }

    #[test]
    fn test_domain_conversion() {
        let tx: u8 = DomainSeparator::Transaction.into();
        assert_eq!(tx, 0x01);

        let domain: DomainSeparator = 0x01.into();
        assert_eq!(domain, DomainSeparator::Transaction);
    }

    #[test]
    fn test_domain_separated_message() {
        let message = b"Hello, World!";
        let domain_msg = create_domain_separated_message(DomainSeparator::Transaction, message);

        assert!(domain_msg.starts_with(DomainSeparator::Transaction.as_bytes()));
        assert!(domain_msg.ends_with(message));
    }
}

