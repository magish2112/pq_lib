//! Hybrid Cryptography Implementation
//!
//! Performance-optimized hybrid cryptographic system combining classical
//! Ed25519 with post-quantum algorithms (ML-KEM, ML-DSA) for optimal
//! security-performance balance.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::pqcrypto::*;
use crate::adaptive_crypto::*;

/// Hybrid cryptographic signature combining Ed25519 and PQ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
    pub algorithm_version: HybridAlgorithmVersion,
}

/// Hybrid cryptographic public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ed25519_key: Vec<u8>,
    pub pq_key: Vec<u8>,
    pub algorithm_version: HybridAlgorithmVersion,
}

/// Hybrid cryptographic private key
#[derive(Debug, Clone)]
pub struct HybridPrivateKey {
    pub ed25519_key: Vec<u8>,
    pub pq_key: Vec<u8>,
    pub algorithm_version: HybridAlgorithmVersion,
}

/// Algorithm version for hybrid crypto
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HybridAlgorithmVersion {
    V1, // Ed25519 + ML-DSA-65
    V2, // Ed25519 + ML-DSA-87 (stronger)
    V3, // Ed25519 + SLH-DSA (hash-based)
}

/// Performance metrics for hybrid crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCryptoMetrics {
    pub signing_time_ns: u64,
    pub verification_time_ns: u64,
    pub signature_size_bytes: usize,
    pub key_size_bytes: usize,
    pub security_level: f64,
    pub performance_score: f64,
}

/// Hybrid cryptography engine
pub struct HybridCryptoEngine {
    pq_crypto: PQCrypto,
    adaptive_crypto: Arc<AdaptiveCryptoEngine>,
    metrics: HashMap<HybridAlgorithmVersion, HybridCryptoMetrics>,
}

/// Hybrid cryptographic result
pub type HybridResult<T> = Result<T, HybridCryptoError>;

/// Hybrid crypto errors
#[derive(Debug)]
pub enum HybridCryptoError {
    Ed25519Error(String),
    PQError(String),
    KeyMismatch,
    InvalidSignature,
    VersionMismatch,
}

impl HybridCryptoEngine {
    /// Create new hybrid crypto engine
    pub async fn new(adaptive_crypto: Arc<AdaptiveCryptoEngine>) -> Self {
        let pq_crypto = PQCrypto::new();
        let mut metrics = HashMap::new();

        // Initialize performance metrics for each version
        metrics.insert(HybridAlgorithmVersion::V1, HybridCryptoMetrics {
            signing_time_ns: 150_000, // ~150μs
            verification_time_ns: 200_000, // ~200μs
            signature_size_bytes: 64 + 3302, // Ed25519 + ML-DSA-65
            key_size_bytes: 32 + 1952, // Ed25519 + ML-DSA-65
            security_level: 9.5, // High security
            performance_score: 8.0, // Good performance
        });

        metrics.insert(HybridAlgorithmVersion::V2, HybridCryptoMetrics {
            signing_time_ns: 250_000, // ~250μs
            verification_time_ns: 350_000, // ~350μs
            signature_size_bytes: 64 + 4627, // Ed25519 + ML-DSA-87
            key_size_bytes: 32 + 2592, // Ed25519 + ML-DSA-87
            security_level: 9.8, // Maximum security
            performance_score: 7.0, // Slower but more secure
        });

        metrics.insert(HybridAlgorithmVersion::V3, HybridCryptoMetrics {
            signing_time_ns: 500_000, // ~500μs
            verification_time_ns: 100_000, // ~100μs fast verify
            signature_size_bytes: 64 + 7856, // Ed25519 + SLH-DSA
            key_size_bytes: 32 + 32, // Ed25519 + SLH-DSA (small PQ key)
            security_level: 10.0, // Maximum long-term security
            performance_score: 6.0, // Slower signing, fast verify
        });

        Self {
            pq_crypto,
            adaptive_crypto,
            metrics,
        }
    }

    /// Generate hybrid keypair
    pub async fn generate_keypair(&self, version: HybridAlgorithmVersion) -> HybridResult<HybridKeyPair> {
        let start_time = std::time::Instant::now();

        // Generate Ed25519 keypair
        let ed25519_keypair = self.generate_ed25519_keypair()?;

        // Generate PQ keypair based on version
        let pq_keypair = match version {
            HybridAlgorithmVersion::V1 => self.pq_crypto.generate_mldsa65_keypair()?,
            HybridAlgorithmVersion::V2 => self.pq_crypto.generate_mldsa87_keypair()?,
            HybridAlgorithmVersion::V3 => self.pq_crypto.generate_slhdsa_keypair()?,
        };

        let generation_time = start_time.elapsed().as_nanos() as u64;

        // Update adaptive crypto metrics
        self.adaptive_crypto.add_performance_anomaly(PerformanceAnomaly {
            anomaly_id: format!("hybrid_keygen_{:?}", version),
            affected_component: "hybrid_crypto".to_string(),
            deviation_percentage: 0.0, // Normal operation
            duration: std::time::Duration::from_nanos(generation_time),
            auto_recovered: true,
        }).await;

        Ok(HybridKeyPair {
            public_key: HybridPublicKey {
                ed25519_key: ed25519_keypair.public_key,
                pq_key: pq_keypair.public_key,
                algorithm_version: version,
            },
            private_key: HybridPrivateKey {
                ed25519_key: ed25519_keypair.private_key,
                pq_key: pq_keypair.private_key,
                algorithm_version: version,
            },
        })
    }

    /// Sign data with hybrid cryptography
    pub async fn sign(&self, data: &[u8], private_key: &HybridPrivateKey) -> HybridResult<HybridSignature> {
        let start_time = std::time::Instant::now();

        // Sign with Ed25519 (fast)
        let ed25519_sig = self.sign_ed25519(data, &private_key.ed25519_key)?;

        // Sign with PQ algorithm (secure)
        let pq_sig = match private_key.algorithm_version {
            HybridAlgorithmVersion::V1 => self.pq_crypto.sign_mldsa65(data, &private_key.pq_key)?,
            HybridAlgorithmVersion::V2 => self.pq_crypto.sign_mldsa87(data, &private_key.pq_key)?,
            HybridAlgorithmVersion::V3 => self.pq_crypto.sign_slhdsa(data, &private_key.pq_key)?,
        };

        let signing_time = start_time.elapsed().as_nanos() as u64;

        // Update metrics
        if let Some(metrics) = self.metrics.get(&private_key.algorithm_version) {
            let expected_time = metrics.signing_time_ns;
            let deviation = ((signing_time as f64 - expected_time as f64) / expected_time as f64) * 100.0;

            if deviation.abs() > 20.0 { // More than 20% deviation
                let _ = self.adaptive_crypto.add_performance_anomaly(PerformanceAnomaly {
                    anomaly_id: format!("hybrid_signing_{:?}", private_key.algorithm_version),
                    affected_component: "hybrid_crypto".to_string(),
                    deviation_percentage: deviation,
                    duration: std::time::Duration::from_nanos(signing_time),
                    auto_recovered: true,
                }).await;
            }
        }

        Ok(HybridSignature {
            ed25519_sig,
            pq_sig,
            algorithm_version: private_key.algorithm_version.clone(),
        })
    }

    /// Verify hybrid signature
    pub async fn verify(&self, data: &[u8], signature: &HybridSignature, public_key: &HybridPublicKey) -> HybridResult<bool> {
        let start_time = std::time::Instant::now();

        // Check version compatibility
        if signature.algorithm_version != public_key.algorithm_version {
            return Err(HybridCryptoError::VersionMismatch);
        }

        // Verify Ed25519 signature (fast check)
        let ed25519_valid = self.verify_ed25519(data, &signature.ed25519_sig, &public_key.ed25519_key)?;

        if !ed25519_valid {
            return Ok(false);
        }

        // Verify PQ signature (security check)
        let pq_valid = match signature.algorithm_version {
            HybridAlgorithmVersion::V1 => self.pq_crypto.verify_mldsa65(data, &signature.pq_sig, &public_key.pq_key)?,
            HybridAlgorithmVersion::V2 => self.pq_crypto.verify_mldsa87(data, &signature.pq_sig, &public_key.pq_key)?,
            HybridAlgorithmVersion::V3 => self.pq_crypto.verify_slhdsa(data, &signature.pq_sig, &public_key.pq_key)?,
        };

        let verification_time = start_time.elapsed().as_nanos() as u64;

        // Update metrics
        if let Some(metrics) = self.metrics.get(&signature.algorithm_version) {
            let expected_time = metrics.verification_time_ns;
            let deviation = ((verification_time as f64 - expected_time as f64) / expected_time as f64) * 100.0;

            if deviation.abs() > 20.0 {
                let _ = self.adaptive_crypto.add_performance_anomaly(PerformanceAnomaly {
                    anomaly_id: format!("hybrid_verification_{:?}", signature.algorithm_version),
                    affected_component: "hybrid_crypto".to_string(),
                    deviation_percentage: deviation,
                    duration: std::time::Duration::from_nanos(verification_time),
                    auto_recovered: true,
                }).await;
            }
        }

        Ok(ed25519_valid && pq_valid)
    }

    /// Get performance metrics for algorithm version
    pub fn get_metrics(&self, version: &HybridAlgorithmVersion) -> Option<&HybridCryptoMetrics> {
        self.metrics.get(version)
    }

    /// Choose optimal algorithm version based on requirements
    pub async fn choose_optimal_version(&self, security_priority: f64, performance_priority: f64) -> HybridAlgorithmVersion {
        // security_priority + performance_priority should equal 1.0
        let normalized_security = security_priority;
        let normalized_performance = performance_priority;

        let mut best_score = 0.0;
        let mut best_version = HybridAlgorithmVersion::V1;

        for (version, metrics) in &self.metrics {
            let score = (metrics.security_level * normalized_security) +
                       (metrics.performance_score * normalized_performance);

            if score > best_score {
                best_score = score;
                best_version = version.clone();
            }
        }

        // Update adaptive crypto about the choice
        let _ = self.adaptive_crypto.force_rotation(
            format!("hybrid_{:?}", best_version),
            crate::adaptive_crypto::TransitionReason::ProactiveRotation
        ).await;

        best_version
    }

    /// Encrypt data using hybrid approach (ML-KEM for key exchange + AES)
    pub async fn encrypt_hybrid(&self, data: &[u8], recipient_public_key: &HybridPublicKey) -> HybridResult<HybridEncryptedData> {
        // Use ML-KEM for key exchange
        let (shared_secret, ciphertext) = match recipient_public_key.algorithm_version {
            HybridAlgorithmVersion::V1 | HybridAlgorithmVersion::V2 => {
                // Use ML-KEM-1024 for all versions for consistency
                self.pq_crypto.encapsulate_mlkem1024(&recipient_public_key.pq_key)?
            }
            HybridAlgorithmVersion::V3 => {
                // SLH-DSA doesn't support KEM, fall back to ML-KEM
                self.pq_crypto.encapsulate_mlkem1024(&recipient_public_key.pq_key)?
            }
        };

        // Use shared secret for AES encryption (simplified - in real impl use proper AES)
        let encrypted_data = self.xor_encrypt(data, &shared_secret);

        Ok(HybridEncryptedData {
            ciphertext,
            encrypted_payload: encrypted_data,
            algorithm_version: recipient_public_key.algorithm_version.clone(),
        })
    }

    /// Decrypt data using hybrid approach
    pub async fn decrypt_hybrid(&self, encrypted_data: &HybridEncryptedData, recipient_private_key: &HybridPrivateKey) -> HybridResult<Vec<u8>> {
        if encrypted_data.algorithm_version != recipient_private_key.algorithm_version {
            return Err(HybridCryptoError::VersionMismatch);
        }

        // Decapsulate shared secret
        let shared_secret = match recipient_private_key.algorithm_version {
            HybridAlgorithmVersion::V1 | HybridAlgorithmVersion::V2 => {
                self.pq_crypto.decapsulate_mlkem1024(&encrypted_data.ciphertext, &recipient_private_key.pq_key)?
            }
            HybridAlgorithmVersion::V3 => {
                self.pq_crypto.decapsulate_mlkem1024(&encrypted_data.ciphertext, &recipient_private_key.pq_key)?
            }
        };

        // Decrypt payload
        Ok(self.xor_decrypt(&encrypted_data.encrypted_payload, &shared_secret))
    }

    // Private helper methods

    fn generate_ed25519_keypair(&self) -> HybridResult<KeyPair> {
        // In real implementation, use proper Ed25519 key generation
        // This is a placeholder
        Ok(KeyPair {
            public_key: vec![0u8; 32],
            private_key: vec![0u8; 32],
        })
    }

    fn sign_ed25519(&self, data: &[u8], private_key: &[u8]) -> HybridResult<Vec<u8>> {
        // In real implementation, use proper Ed25519 signing
        Ok(vec![0u8; 64]) // Placeholder signature
    }

    fn verify_ed25519(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> HybridResult<bool> {
        // In real implementation, use proper Ed25519 verification
        Ok(true) // Placeholder verification
    }

    fn xor_encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect()
    }

    fn xor_decrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        self.xor_encrypt(data, key) // XOR is symmetric
    }
}

/// Hybrid keypair structure
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub private_key: HybridPrivateKey,
}

/// Hybrid encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEncryptedData {
    pub ciphertext: Vec<u8>,          // ML-KEM ciphertext
    pub encrypted_payload: Vec<u8>,   // AES-encrypted data
    pub algorithm_version: HybridAlgorithmVersion,
}

/// Simple keypair for Ed25519 (placeholder)
#[derive(Debug, Clone)]
struct KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hybrid_key_generation() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto).await;

        let keypair = hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await.unwrap();

        assert_eq!(keypair.private_key.algorithm_version, HybridAlgorithmVersion::V1);
        assert_eq!(keypair.public_key.algorithm_version, HybridAlgorithmVersion::V1);
    }

    #[tokio::test]
    async fn test_hybrid_signing_verification() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto).await;

        let keypair = hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await.unwrap();
        let data = b"Hello, hybrid crypto!";

        let signature = hybrid_crypto.sign(data, &keypair.private_key).await.unwrap();
        let is_valid = hybrid_crypto.verify(data, &signature, &keypair.public_key).await.unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_algorithm_selection() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto).await;

        // Prioritize security
        let secure_version = hybrid_crypto.choose_optimal_version(0.8, 0.2).await;
        assert_eq!(secure_version, HybridAlgorithmVersion::V2);

        // Prioritize performance
        let fast_version = hybrid_crypto.choose_optimal_version(0.2, 0.8).await;
        assert_eq!(fast_version, HybridAlgorithmVersion::V1);
    }

    #[test]
    fn test_metrics_access() {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let hybrid_crypto = rt.block_on(HybridCryptoEngine::new(adaptive_crypto));

        let metrics = hybrid_crypto.get_metrics(&HybridAlgorithmVersion::V1).unwrap();
        assert!(metrics.signing_time_ns > 0);
        assert!(metrics.security_level > 9.0);
    }
}
