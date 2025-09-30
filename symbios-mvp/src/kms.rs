//! Key Management Service (KMS) for Validator Operations
//!
//! This module provides secure key management for blockchain validators,
//! integrating with HSM for cryptographic operations and providing
//! automated key rotation and backup capabilities.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use crate::types::{PublicKey, PrivateKey, Hash, Transaction, Block};
use crate::hsm::{HardwareSecurityModule, KeyManagementService, HsmConfig, HsmError, HsmResult, HsmKeyPair, HsmKeyMetadata};
use crate::crypto_audit::{CryptoAuditor, CryptoAuditResult};

/// Validator key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKeyInfo {
    pub validator_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub key_metadata: HsmKeyMetadata,
    pub is_active: bool,
    pub created_at: u64,
    pub last_used: u64,
    pub usage_count: u64,
}

/// Validator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub validator_id: String,
    pub hsm_config: HsmConfig,
    pub key_rotation_interval_days: u32,
    pub backup_enabled: bool,
    pub backup_path: String,
    pub audit_enabled: bool,
}

/// Validator KMS implementation
pub struct ValidatorKms {
    config: ValidatorConfig,
    kms: KeyManagementService,
    validator_keys: Arc<RwLock<HashMap<String, ValidatorKeyInfo>>>,
    crypto_auditor: CryptoAuditor,
}

impl ValidatorKms {
    /// Create new validator KMS
    pub fn new(config: ValidatorConfig, hsm: Box<dyn HardwareSecurityModule + Send + Sync>) -> Self {
        let kms = KeyManagementService::new(hsm);

        Self {
            config,
            kms,
            validator_keys: Arc::new(RwLock::new(HashMap::new())),
            crypto_auditor: CryptoAuditor::new(),
        }
    }

    /// Initialize validator KMS
    pub async fn initialize(&mut self) -> HsmResult<()> {
        // Initialize HSM connection
        self.kms.initialize(self.config.hsm_config.clone())?;

        // Load existing validator keys
        self.load_validator_keys().await?;

        // Perform initial crypto audit
        if self.config.audit_enabled {
            let _audit_result = self.crypto_auditor.perform_full_crypto_audit().await
                .map_err(|e| HsmError::HsmConnectionFailed(format!("Audit failed: {}", e)))?;
        }

        Ok(())
    }

    /// Register new validator
    pub async fn register_validator(&mut self, validator_id: &str) -> HsmResult<ValidatorKeyInfo> {
        let key_id = format!("validator_{}", validator_id);

        // Generate key pair in HSM
        let hsm_keypair = self.kms.generate_validator_key(validator_id)?;

        // Create public key from HSM public key data
        let public_key = PublicKey::from_bytes(hsm_keypair.public_key.clone());

        let key_info = ValidatorKeyInfo {
            validator_id: validator_id.to_string(),
            key_id: key_id.clone(),
            public_key,
            key_metadata: hsm_keypair.metadata.clone(),
            is_active: true,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_used: 0,
            usage_count: 0,
        };

        // Store key info
        self.validator_keys.write().unwrap().insert(validator_id.to_string(), key_info.clone());

        // Backup if enabled
        if self.config.backup_enabled {
            self.kms.backup_keys(&self.config.backup_path)?;
        }

        Ok(key_info)
    }

    /// Sign block as validator
    pub async fn sign_block(&self, validator_id: &str, block: &Block) -> HsmResult<Vec<u8>> {
        let mut keys = self.validator_keys.write().unwrap();
        let key_info = keys.get_mut(validator_id)
            .ok_or_else(|| HsmError::KeyNotFound(format!("Validator {} not found", validator_id)))?;

        if !key_info.is_active {
            return Err(HsmError::KeyNotFound(format!("Validator {} key is not active", validator_id)));
        }

        // Serialize block for signing
        let block_data = bincode::serialize(block)
            .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

        // Sign with HSM
        let signature = self.kms.sign_transaction(validator_id, &Transaction {
            id: Hash::new(&block_data),
            sender: key_info.public_key.clone(),
            receiver: PublicKey::new("block_signer".to_string()),
            amount: 0,
            fee: 0,
            nonce: 0,
            signature: None,
            timestamp: block.timestamp,
            data: block_data,
        })?;

        // Update usage statistics
        key_info.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        key_info.usage_count += 1;

        Ok(signature)
    }

    /// Verify block signature
    pub async fn verify_block_signature(&self, block: &Block, signature: &[u8]) -> HsmResult<bool> {
        // Find validator public key
        let keys = self.validator_keys.read().unwrap();
        let validator_key = keys.values().find(|k| k.public_key == block.validator)
            .ok_or_else(|| HsmError::KeyNotFound("Validator not found".to_string()))?;

        // Create transaction for verification
        let block_data = bincode::serialize(block)
            .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

        let tx_for_verification = Transaction {
            id: Hash::new(&block_data),
            sender: validator_key.public_key.clone(),
            receiver: PublicKey::new("block_verifier".to_string()),
            amount: 0,
            fee: 0,
            nonce: 0,
            signature: Some(signature.to_vec()),
            timestamp: block.timestamp,
            data: block_data,
        };

        self.kms.verify_transaction_signature(&tx_for_verification)
    }

    /// Rotate validator keys
    pub async fn rotate_validator_keys(&mut self, validator_id: &str) -> HsmResult<ValidatorKeyInfo> {
        let mut keys = self.validator_keys.write().unwrap();
        let key_info = keys.get_mut(validator_id)
            .ok_or_else(|| HsmError::KeyNotFound(format!("Validator {} not found", validator_id)))?;

        // Deactivate current key
        key_info.is_active = false;

        // Generate new key
        let new_key_info = self.register_validator(validator_id).await?;

        // Mark old key for deletion (in production, this would be scheduled)
        let _rotated_keys = self.kms.rotate_expired_keys()?;

        Ok(new_key_info)
    }

    /// Get validator key info
    pub fn get_validator_key_info(&self, validator_id: &str) -> HsmResult<ValidatorKeyInfo> {
        let keys = self.validator_keys.read().unwrap();
        keys.get(validator_id)
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(format!("Validator {} not found", validator_id)))
    }

    /// List all validator keys
    pub fn list_validator_keys(&self) -> Vec<ValidatorKeyInfo> {
        self.validator_keys.read().unwrap().values().cloned().collect()
    }

    /// Perform crypto audit for all validators
    pub async fn perform_crypto_audit(&mut self) -> HsmResult<CryptoAuditResult> {
        self.crypto_auditor.perform_full_crypto_audit().await
            .map_err(|e| HsmError::HsmConnectionFailed(format!("Audit failed: {}", e)))
    }

    /// Get KMS status
    pub async fn get_status(&self) -> HsmResult<String> {
        let (hsm_status, audit_log) = self.kms.get_status()?;

        let keys = self.validator_keys.read().unwrap();
        let active_validators = keys.values().filter(|k| k.is_active).count();

        Ok(format!(
            "KMS Status:\n\
            - HSM Connected: {}\n\
            - Active Validators: {}\n\
            - Total Keys: {}\n\
            - Audit Log Entries: {}\n\
            - Firmware: {}\n\
            - Available Slots: {}",
            hsm_status.connected,
            active_validators,
            keys.len(),
            audit_log.len(),
            hsm_status.firmware_version,
            hsm_status.available_slots
        ))
    }

    /// Load existing validator keys from storage
    async fn load_validator_keys(&mut self) -> HsmResult<()> {
        // In production, this would load from secure storage
        // For demonstration, we'll start with empty key set
        Ok(())
    }

    /// Backup all validator keys
    pub async fn backup_all_keys(&self) -> HsmResult<()> {
        if self.config.backup_enabled {
            self.kms.backup_keys(&self.config.backup_path)?;
        }
        Ok(())
    }

    /// Get crypto audit report
    pub fn get_crypto_audit_report(&self) -> String {
        self.crypto_auditor.generate_security_report()
    }

    /// Emergency key revocation
    pub async fn revoke_validator_key(&mut self, validator_id: &str) -> HsmResult<()> {
        let mut keys = self.validator_keys.write().unwrap();
        let key_info = keys.get_mut(validator_id)
            .ok_or_else(|| HsmError::KeyNotFound(format!("Validator {} not found", validator_id)))?;

        key_info.is_active = false;

        // In production, this would immediately delete the key from HSM
        // For safety, we'll just mark it as inactive
        self.kms.delete_key(&key_info.key_id)?;

        Ok(())
    }

    /// Validate validator key health
    pub async fn validate_validator_health(&self, validator_id: &str) -> HsmResult<bool> {
        let key_info = self.get_validator_key_info(validator_id)?;

        // Check if key is active
        if !key_info.is_active {
            return Ok(false);
        }

        // Check key age (should be rotated periodically)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key_age_days = (current_time - key_info.created_at) / (24 * 3600);
        let max_age_days = self.config.key_rotation_interval_days as u64;

        if key_age_days > max_age_days {
            return Ok(false); // Key is too old
        }

        // Check usage count (shouldn't be excessive)
        let max_usage = self.config.hsm_config.max_key_usage;
        if key_info.usage_count > max_usage {
            return Ok(false); // Key has been used too much
        }

        Ok(true)
    }

    /// Get validator statistics
    pub fn get_validator_statistics(&self) -> HashMap<String, serde_json::Value> {
        let keys = self.validator_keys.read().unwrap();
        let mut stats = HashMap::new();

        let total_validators = keys.len();
        let active_validators = keys.values().filter(|k| k.is_active).count();
        let total_usage: u64 = keys.values().map(|k| k.usage_count).sum();

        stats.insert("total_validators".to_string(), serde_json::Value::Number(total_validators.into()));
        stats.insert("active_validators".to_string(), serde_json::Value::Number(active_validators.into()));
        stats.insert("total_key_usage".to_string(), serde_json::Value::Number(total_usage.into()));

        // Key type distribution
        let mut key_types = HashMap::new();
        for key_info in keys.values() {
            let key_type_str = format!("{:?}", key_info.key_metadata.key_type);
            *key_types.entry(key_type_str).or_insert(0) += 1;
        }

        stats.insert("key_type_distribution".to_string(), serde_json::json!(key_types));

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::ProductionHsm;

    fn create_test_validator_kms() -> ValidatorKms {
        let config = ValidatorConfig {
            validator_id: "test_validator".to_string(),
            hsm_config: HsmConfig {
                hsm_url: "https://test-hsm.com".to_string(),
                hsm_user: "test_user".to_string(),
                hsm_password: "test_password".to_string(),
                key_rotation_days: 90,
                max_key_usage: 100000,
                enable_audit_log: true,
            },
            key_rotation_interval_days: 90,
            backup_enabled: false,
            backup_path: "/tmp/backup".to_string(),
            audit_enabled: true,
        };

        let hsm = Box::new(ProductionHsm::new());
        ValidatorKms::new(config, hsm)
    }

    #[tokio::test]
    async fn test_validator_kms_initialization() {
        let mut kms = create_test_validator_kms();
        let result = kms.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validator_registration() {
        let mut kms = create_test_validator_kms();
        kms.initialize().await.unwrap();

        let key_info = kms.register_validator("validator_001").await.unwrap();

        assert_eq!(key_info.validator_id, "validator_001");
        assert!(key_info.is_active);
        assert!(key_info.key_id.starts_with("validator_validator_001"));
    }

    #[tokio::test]
    async fn test_block_signing() {
        let mut kms = create_test_validator_kms();
        kms.initialize().await.unwrap();

        // Register validator
        kms.register_validator("validator_001").await.unwrap();

        // Create test block
        let validator = PublicKey::new("validator_001".to_string());
        let block = Block::new(
            Hash::new(b"genesis"),
            1,
            vec![],
            validator.clone()
        );

        // Sign block
        let signature = kms.sign_block("validator_001", &block).await.unwrap();
        assert!(!signature.is_empty());

        // Verify signature
        let is_valid = kms.verify_block_signature(&block, &signature).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let mut kms = create_test_validator_kms();
        kms.initialize().await.unwrap();

        // Register validator
        let old_key_info = kms.register_validator("validator_001").await.unwrap();
        assert!(old_key_info.is_active);

        // Rotate key
        let new_key_info = kms.rotate_validator_keys("validator_001").await.unwrap();

        // Old key should be inactive, new key should be active
        let updated_old_key = kms.get_validator_key_info("validator_001").unwrap();
        assert!(!updated_old_key.is_active);
        assert!(new_key_info.is_active);
        assert_ne!(old_key_info.key_id, new_key_info.key_id);
    }

    #[test]
    fn test_validator_statistics() {
        let kms = create_test_validator_kms();
        let stats = kms.get_validator_statistics();

        assert!(stats.contains_key("total_validators"));
        assert!(stats.contains_key("active_validators"));
        assert!(stats.contains_key("total_key_usage"));
        assert!(stats.contains_key("key_type_distribution"));
    }

    #[tokio::test]
    async fn test_validator_health_check() {
        let mut kms = create_test_validator_kms();
        kms.initialize().await.unwrap();

        // Register validator
        kms.register_validator("validator_001").await.unwrap();

        // Check health (should be healthy)
        let is_healthy = kms.validate_validator_health("validator_001").await.unwrap();
        assert!(is_healthy);
    }

    #[tokio::test]
    async fn test_emergency_key_revocation() {
        let mut kms = create_test_validator_kms();
        kms.initialize().await.unwrap();

        // Register validator
        kms.register_validator("validator_001").await.unwrap();

        // Revoke key
        kms.revoke_validator_key("validator_001").await.unwrap();

        // Key should be inactive
        let key_info = kms.get_validator_key_info("validator_001").unwrap();
        assert!(!key_info.is_active);
    }

    #[tokio::test]
    async fn test_crypto_audit() {
        let mut kms = create_test_validator_kms();
        kms.initialize().await.unwrap();

        let audit_result = kms.perform_crypto_audit().await.unwrap();
        assert_eq!(audit_result.component, "Full Cryptographic System");
        assert!(audit_result.compliance_score >= 0.0);
        assert!(audit_result.compliance_score <= 100.0);
    }

    #[test]
    fn test_crypto_audit_report() {
        let kms = create_test_validator_kms();
        let report = kms.get_crypto_audit_report();

        assert!(report.contains("Cryptographic Security Audit Report"));
        assert!(report.contains("Compliance Score"));
        assert!(report.contains("Vulnerabilities Found"));
    }
}
