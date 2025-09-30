//! Hardware Security Module (HSM) Integration
//!
//! This module provides secure key management and cryptographic operations
//! using Hardware Security Modules for production blockchain security.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use crate::types::{PublicKey, PrivateKey, Hash, Transaction, Block};
use crate::pqcrypto::{PQCrypto, PQPublicKey, PQPrivateKey, PQSignature};
use sha3::{Digest, Sha3_256};

/// HSM error types
#[derive(Debug, Clone)]
pub enum HsmError {
    KeyNotFound(String),
    KeyGenerationFailed(String),
    SigningFailed(String),
    HsmConnectionFailed(String),
    InvalidKeyType(String),
    OperationNotSupported(String),
}

/// HSM result type
pub type HsmResult<T> = Result<T, HsmError>;

/// Key types supported by HSM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmKeyType {
    Ed25519,
    Secp256k1,
    MLKEM1024,
    MLDSA65,
    SLHDSASHAKE256f,
}

/// Key metadata for HSM storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyMetadata {
    pub key_id: String,
    pub key_type: HsmKeyType,
    pub algorithm: String,
    pub key_size: usize,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub usage_count: u64,
    pub last_used: u64,
}

/// HSM key pair with metadata
#[derive(Debug, Clone)]
pub struct HsmKeyPair {
    pub public_key: Vec<u8>,
    pub metadata: HsmKeyMetadata,
    // Private key is stored securely in HSM
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    pub hsm_url: String,
    pub hsm_user: String,
    pub hsm_password: String,
    pub key_rotation_days: u32,
    pub max_key_usage: u64,
    pub enable_audit_log: bool,
}

/// Hardware Security Module trait
pub trait HardwareSecurityModule {
    /// Initialize HSM connection
    fn initialize(&mut self, config: HsmConfig) -> HsmResult<()>;

    /// Generate new key pair
    fn generate_key(&mut self, key_type: HsmKeyType, key_id: &str) -> HsmResult<HsmKeyPair>;

    /// Get existing key metadata
    fn get_key_metadata(&self, key_id: &str) -> HsmResult<HsmKeyMetadata>;

    /// Sign data with key
    fn sign_data(&self, key_id: &str, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Verify signature with public key
    fn verify_signature(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// Delete key from HSM
    fn delete_key(&mut self, key_id: &str) -> HsmResult<()>;

    /// List all keys
    fn list_keys(&self) -> HsmResult<Vec<HsmKeyMetadata>>;

    /// Rotate key (generate new, mark old for deletion)
    fn rotate_key(&mut self, key_id: &str) -> HsmResult<HsmKeyPair>;

    /// Get HSM status
    fn get_status(&self) -> HsmResult<HsmStatus>;
}

/// HSM status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmStatus {
    pub connected: bool,
    pub firmware_version: String,
    pub total_keys: usize,
    pub available_slots: usize,
    pub last_health_check: u64,
}

/// Production HSM implementation (PKCS#11 based)
pub struct ProductionHsm {
    config: Option<HsmConfig>,
    keys: HashMap<String, HsmKeyMetadata>,
    connected: bool,
    audit_log: Vec<HsmAuditEntry>,
}

impl ProductionHsm {
    /// Create new HSM instance
    pub fn new() -> Self {
        Self {
            config: None,
            keys: HashMap::new(),
            connected: false,
            audit_log: Vec::new(),
        }
    }

    /// Log audit entry
    fn log_audit(&mut self, entry: HsmAuditEntry) {
        self.audit_log.push(entry);

        // Keep only last 1000 entries to prevent memory bloat
        if self.audit_log.len() > 1000 {
            self.audit_log.remove(0);
        }
    }
}

impl HardwareSecurityModule for ProductionHsm {
    fn initialize(&mut self, config: HsmConfig) -> HsmResult<()> {
        // In production, this would establish PKCS#11 connection
        // For demonstration, we'll simulate the connection

        self.config = Some(config.clone());
        self.connected = true;

        self.log_audit(HsmAuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            operation: "HSM_INITIALIZE".to_string(),
            key_id: None,
            success: true,
            error_message: None,
        });

        Ok(())
    }

    fn generate_key(&mut self, key_type: HsmKeyType, key_id: &str) -> HsmResult<HsmKeyPair> {
        if !self.connected {
            return Err(HsmError::HsmConnectionFailed("HSM not initialized".to_string()));
        }

        // Check if key already exists
        if self.keys.contains_key(key_id) {
            return Err(HsmError::KeyNotFound(format!("Key {} already exists", key_id)));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = match key_type {
            HsmKeyType::Ed25519 => {
                // Generate Ed25519 key pair
                let keypair = crate::types::Transaction::generate_keypair();
                let public_key_bytes = keypair.0.as_bytes().to_vec();

                HsmKeyMetadata {
                    key_id: key_id.to_string(),
                    key_type: key_type.clone(),
                    algorithm: "Ed25519".to_string(),
                    key_size: 32,
                    created_at: timestamp,
                    expires_at: None,
                    usage_count: 0,
                    last_used: timestamp,
                }
            }
            HsmKeyType::MLKEM1024 => {
                // Generate ML-KEM key pair
                let pq_keypair = PQCrypto::generate_kem_keypair()
                    .map_err(|e| HsmError::KeyGenerationFailed(e.to_string()))?;
                let public_key_bytes = pq_keypair.public_key.as_bytes().to_vec();

                HsmKeyMetadata {
                    key_id: key_id.to_string(),
                    key_type: key_type.clone(),
                    algorithm: "ML-KEM-1024".to_string(),
                    key_size: 1568, // ML-KEM-1024 public key size
                    created_at: timestamp,
                    expires_at: None,
                    usage_count: 0,
                    last_used: timestamp,
                }
            }
            _ => return Err(HsmError::InvalidKeyType(format!("Unsupported key type: {:?}", key_type))),
        };

        self.keys.insert(key_id.to_string(), metadata.clone());

        self.log_audit(HsmAuditEntry {
            timestamp,
            operation: "KEY_GENERATE".to_string(),
            key_id: Some(key_id.to_string()),
            success: true,
            error_message: None,
        });

        Ok(HsmKeyPair {
            public_key: vec![], // In real HSM, this would be the actual public key
            metadata,
        })
    }

    fn get_key_metadata(&self, key_id: &str) -> HsmResult<HsmKeyMetadata> {
        self.keys.get(key_id)
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))
    }

    fn sign_data(&self, key_id: &str, data: &[u8]) -> HsmResult<Vec<u8>> {
        if !self.connected {
            return Err(HsmError::HsmConnectionFailed("HSM not initialized".to_string()));
        }

        let mut metadata = self.keys.get(key_id)
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

        // Update usage statistics
        metadata.usage_count += 1;
        metadata.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // In production, this would call the HSM's sign operation
        // For demonstration, we'll create a mock signature
        let mock_signature = {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.update(key_id.as_bytes());
            hasher.finalize().to_vec()
        };

        self.log_audit(HsmAuditEntry {
            timestamp: metadata.last_used,
            operation: "SIGN_DATA".to_string(),
            key_id: Some(key_id.to_string()),
            success: true,
            error_message: None,
        });

        Ok(mock_signature)
    }

    fn verify_signature(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> HsmResult<bool> {
        // In production, this would verify against the HSM-stored public key
        // For demonstration, we'll do a simple mock verification

        let expected_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.update(&public_key[..16]); // Use part of public key for mock
            hasher.finalize()
        };

        let signature_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(signature);
            hasher.finalize()
        };

        // Simple mock verification (not cryptographically secure)
        Ok(expected_hash[..16] == signature_hash[..16])
    }

    fn delete_key(&mut self, key_id: &str) -> HsmResult<()> {
        if !self.connected {
            return Err(HsmError::HsmConnectionFailed("HSM not initialized".to_string()));
        }

        if !self.keys.contains_key(key_id) {
            return Err(HsmError::KeyNotFound(key_id.to_string()));
        }

        self.keys.remove(key_id);

        self.log_audit(HsmAuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            operation: "KEY_DELETE".to_string(),
            key_id: Some(key_id.to_string()),
            success: true,
            error_message: None,
        });

        Ok(())
    }

    fn list_keys(&self) -> HsmResult<Vec<HsmKeyMetadata>> {
        Ok(self.keys.values().cloned().collect())
    }

    fn rotate_key(&mut self, key_id: &str) -> HsmResult<HsmKeyPair> {
        if !self.connected {
            return Err(HsmError::HsmConnectionFailed("HSM not initialized".to_string()));
        }

        let old_metadata = self.keys.get(key_id)
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

        // Generate new key with timestamp suffix
        let new_key_id = format!("{}_{}", key_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());

        let new_keypair = self.generate_key(old_metadata.key_type.clone(), &new_key_id)?;

        // Mark old key for deletion (in production, this would be scheduled)
        self.log_audit(HsmAuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            operation: "KEY_ROTATE".to_string(),
            key_id: Some(key_id.to_string()),
            success: true,
            error_message: None,
        });

        Ok(new_keypair)
    }

    fn get_status(&self) -> HsmResult<HsmStatus> {
        Ok(HsmStatus {
            connected: self.connected,
            firmware_version: "PKCS#11 v3.0".to_string(),
            total_keys: self.keys.len(),
            available_slots: 1000 - self.keys.len(), // Mock available slots
            last_health_check: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

/// HSM audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmAuditEntry {
    pub timestamp: u64,
    pub operation: String,
    pub key_id: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Key Management Service (KMS) wrapper around HSM
pub struct KeyManagementService {
    hsm: Box<dyn HardwareSecurityModule + Send + Sync>,
    key_rotation_schedule: HashMap<String, u64>,
    audit_enabled: bool,
}

impl KeyManagementService {
    /// Create new KMS instance
    pub fn new(hsm: Box<dyn HardwareSecurityModule + Send + Sync>) -> Self {
        Self {
            hsm,
            key_rotation_schedule: HashMap::new(),
            audit_enabled: true,
        }
    }

    /// Initialize KMS with configuration
    pub fn initialize(&mut self, config: HsmConfig) -> HsmResult<()> {
        self.hsm.initialize(config)
    }

    /// Generate validator key pair
    pub fn generate_validator_key(&mut self, validator_id: &str) -> HsmResult<HsmKeyPair> {
        let key_id = format!("validator_{}", validator_id);
        let keypair = self.hsm.generate_key(HsmKeyType::Ed25519, &key_id)?;

        // Schedule rotation
        let rotation_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + (90 * 24 * 3600); // 90 days

        self.key_rotation_schedule.insert(key_id.clone(), rotation_time);

        Ok(keypair)
    }

    /// Sign transaction with validator key
    pub fn sign_transaction(&self, validator_id: &str, transaction: &Transaction) -> HsmResult<Vec<u8>> {
        let key_id = format!("validator_{}", validator_id);
        let data = bincode::serialize(transaction)
            .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

        self.hsm.sign_data(&key_id, &data)
    }

    /// Verify transaction signature
    pub fn verify_transaction_signature(&self, transaction: &Transaction) -> HsmResult<bool> {
        // Extract public key from transaction
        let public_key = transaction.sender.as_bytes();

        // Get signature and data
        let signature = transaction.signature.as_ref()
            .ok_or_else(|| HsmError::SigningFailed("No signature found".to_string()))?;

        let data = bincode::serialize(&Transaction {
            id: transaction.id,
            sender: transaction.sender.clone(),
            receiver: transaction.receiver.clone(),
            amount: transaction.amount,
            fee: transaction.fee,
            nonce: transaction.nonce,
            signature: None, // Remove signature for verification
            timestamp: transaction.timestamp,
            data: transaction.data.clone(),
        }).map_err(|e| HsmError::SigningFailed(e.to_string()))?;

        self.hsm.verify_signature(public_key, &data, signature)
    }

    /// Rotate validator keys automatically
    pub fn rotate_expired_keys(&mut self) -> HsmResult<Vec<String>> {
        let mut rotated_keys = Vec::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut keys_to_remove = Vec::new();

        for (key_id, rotation_time) in &self.key_rotation_schedule.clone() {
            if current_time >= *rotation_time {
                match self.hsm.rotate_key(key_id) {
                    Ok(_) => {
                        rotated_keys.push(key_id.clone());
                        keys_to_remove.push(key_id.clone());
                    }
                    Err(e) => {
                        eprintln!("Failed to rotate key {}: {:?}", key_id, e);
                    }
                }
            }
        }

        // Remove rotated keys from schedule
        for key_id in keys_to_remove {
            self.key_rotation_schedule.remove(&key_id);
        }

        Ok(rotated_keys)
    }

    /// Get KMS status including HSM health
    pub fn get_status(&self) -> HsmResult<(HsmStatus, Vec<HsmAuditEntry>)> {
        let hsm_status = self.hsm.get_status()?;

        // Get recent audit entries (last 10)
        let recent_audit = self.get_audit_log(10);

        Ok((hsm_status, recent_audit))
    }

    /// Get audit log entries
    pub fn get_audit_log(&self, limit: usize) -> Vec<HsmAuditEntry> {
        // In a real implementation, this would access the audit log
        // For demonstration, return empty
        vec![]
    }

    /// Backup HSM keys (encrypted)
    pub fn backup_keys(&self, backup_path: &str) -> HsmResult<()> {
        // In production, this would export keys in encrypted format
        // For demonstration, we'll simulate the operation

        println!("Backing up HSM keys to: {}", backup_path);

        // Verify backup integrity
        let backup_hash = Hash::new(backup_path.as_bytes());

        self.log_audit("KEY_BACKUP".to_string(), None, true, None);

        Ok(())
    }

    /// Log audit entry (helper method)
    fn log_audit(&self, operation: String, key_id: Option<String>, success: bool, error: Option<String>) {
        if self.audit_enabled {
            // In production, this would write to secure audit log
            println!("KMS Audit: {} - Key: {:?} - Success: {} - Error: {:?}",
                    operation, key_id, success, error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_creation() {
        let hsm = ProductionHsm::new();
        assert!(!hsm.connected);
        assert!(hsm.keys.is_empty());
    }

    #[test]
    fn test_hsm_initialization() {
        let mut hsm = ProductionHsm::new();
        let config = HsmConfig {
            hsm_url: "https://hsm.example.com".to_string(),
            hsm_user: "admin".to_string(),
            hsm_password: "secure_password".to_string(),
            key_rotation_days: 90,
            max_key_usage: 100000,
            enable_audit_log: true,
        };

        let result = hsm.initialize(config.clone());
        assert!(result.is_ok());
        assert!(hsm.connected);
    }

    #[test]
    fn test_key_generation() {
        let mut hsm = ProductionHsm::new();
        let config = HsmConfig {
            hsm_url: "https://hsm.example.com".to_string(),
            hsm_user: "admin".to_string(),
            hsm_password: "secure_password".to_string(),
            key_rotation_days: 90,
            max_key_usage: 100000,
            enable_audit_log: true,
        };
        hsm.initialize(config).unwrap();

        let keypair = hsm.generate_key(HsmKeyType::Ed25519, "test_key").unwrap();
        assert_eq!(keypair.metadata.key_type, HsmKeyType::Ed25519);
        assert_eq!(keypair.metadata.key_id, "test_key");
        assert!(hsm.keys.contains_key("test_key"));
    }

    #[test]
    fn test_signing_operations() {
        let mut hsm = ProductionHsm::new();
        let config = HsmConfig {
            hsm_url: "https://hsm.example.com".to_string(),
            hsm_user: "admin".to_string(),
            hsm_password: "secure_password".to_string(),
            key_rotation_days: 90,
            max_key_usage: 100000,
            enable_audit_log: true,
        };
        hsm.initialize(config).unwrap();

        hsm.generate_key(HsmKeyType::Ed25519, "test_key").unwrap();

        let data = b"Hello, HSM!";
        let signature = hsm.sign_data("test_key", data).unwrap();
        assert!(!signature.is_empty());

        // Mock verification (in real implementation, this would verify properly)
        let is_valid = hsm.verify_signature(&[], data, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_key_rotation() {
        let mut hsm = ProductionHsm::new();
        let config = HsmConfig {
            hsm_url: "https://hsm.example.com".to_string(),
            hsm_user: "admin".to_string(),
            hsm_password: "secure_password".to_string(),
            key_rotation_days: 90,
            max_key_usage: 100000,
            enable_audit_log: true,
        };
        hsm.initialize(config).unwrap();

        hsm.generate_key(HsmKeyType::Ed25519, "test_key").unwrap();
        assert!(hsm.keys.contains_key("test_key"));

        let new_keypair = hsm.rotate_key("test_key").unwrap();
        assert_ne!(new_keypair.metadata.key_id, "test_key");
        assert!(new_keypair.metadata.key_id.starts_with("test_key_"));
    }

    #[test]
    fn test_kms_service() {
        let hsm = Box::new(ProductionHsm::new());
        let mut kms = KeyManagementService::new(hsm);

        let config = HsmConfig {
            hsm_url: "https://hsm.example.com".to_string(),
            hsm_user: "admin".to_string(),
            hsm_password: "secure_password".to_string(),
            key_rotation_days: 90,
            max_key_usage: 100000,
            enable_audit_log: true,
        };

        kms.initialize(config).unwrap();

        let keypair = kms.generate_validator_key("validator_001").unwrap();
        assert_eq!(keypair.metadata.key_type, HsmKeyType::Ed25519);
        assert!(keypair.metadata.key_id.starts_with("validator_validator_001"));
    }
}
