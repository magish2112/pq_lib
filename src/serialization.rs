//! Stable serialization utilities for cryptographic types

use crate::{HybridSignature, HybridPublicKey, CryptoResult};

/// Serialize signature to CBOR bytes
pub fn serialize_signature(signature: &HybridSignature) -> CryptoResult<Vec<u8>> {
    serde_cbor::to_vec(signature)
        .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
}

/// Deserialize signature from CBOR bytes
pub fn deserialize_signature(bytes: &[u8]) -> CryptoResult<HybridSignature> {
    serde_cbor::from_slice(bytes)
        .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
}

/// Serialize public key to CBOR bytes
pub fn serialize_public_key(key: &HybridPublicKey) -> CryptoResult<Vec<u8>> {
    serde_cbor::to_vec(key)
        .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
}

/// Deserialize public key from CBOR bytes
pub fn deserialize_public_key(bytes: &[u8]) -> CryptoResult<HybridPublicKey> {
    serde_cbor::from_slice(bytes)
        .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HybridSigner, AlgorithmId, DomainSeparator};

    #[tokio::test]
    async fn test_signature_serialization() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap();
        let data = b"Serialization test";

        let signature = HybridSigner::sign_with_domain(
            data,
            &keypair.private_key,
            DomainSeparator::Transaction,
        ).await.unwrap();

        // Serialize and deserialize signature
        let serialized = serialize_signature(&signature).unwrap();
        let deserialized = deserialize_signature(&serialized).unwrap();

        assert_eq!(signature, deserialized);

        // Should still verify
        assert!(HybridSigner::verify(data, &deserialized, &keypair.public_key).await.unwrap());
    }

    #[tokio::test]
    async fn test_public_key_serialization() {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap();

        // Serialize and deserialize public key
        let serialized = serialize_public_key(&keypair.public_key).unwrap();
        let deserialized = deserialize_public_key(&serialized).unwrap();

        assert_eq!(keypair.public_key, deserialized);
    }

    #[test]
    fn test_serialization_stability() {
        // Test that the same data always serializes to the same bytes
        let sig1 = crate::HybridSignature::ed25519_only(vec![1; 64], DomainSeparator::Transaction);
        let sig2 = crate::HybridSignature::ed25519_only(vec![1; 64], DomainSeparator::Transaction);

        let serialized1 = serialize_signature(&sig1).unwrap();
        let serialized2 = serialize_signature(&sig2).unwrap();

        assert_eq!(serialized1, serialized2);
    }
}

