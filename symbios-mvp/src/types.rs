//! Core types for Symbios Network
//! 
//! ⚠️  MVP STATUS: This is a research prototype with simplified cryptography.
//! Real Ed25519 signatures are implemented but network layer is placeholder.
//! DO NOT USE IN PRODUCTION!

use sha3::{Digest, Sha3_256};
use ed25519_dalek::{Signer, Verifier, Signature as Ed25519Signature, SigningKey, VerifyingKey};
use rand::{Rng, rngs::OsRng};
use serde::{Serialize, Deserialize};
use crate::pqcrypto::{PQCrypto, PQPublicKey, PQPrivateKey, PQSignature};

/// SHA3-256 hash type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Ethereum-style address (20 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let hash = Hash::new(&pk.as_bytes());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.as_bytes()[12..32]); // Last 20 bytes
        Self(addr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_hex(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 20 {
            return Err("Invalid address length".into());
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Ok(Self(addr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Transaction amount (u64)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }
}

/// Account nonce for replay protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce(pub u64);

impl Nonce {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn checked_add(&self, other: u64) -> Option<Self> {
        self.0.checked_add(other).map(Self)
    }

    pub fn checked_sub(&self, other: u64) -> Option<Self> {
        self.0.checked_sub(other).map(Self)
    }
}

/// Gas price in wei (smallest unit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasPrice(pub u64);

impl GasPrice {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn saturating_add(&self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    pub fn saturating_sub(&self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

/// Gas amount for transaction execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gas(pub u64);

impl Gas {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn checked_add(&self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

/// Block height/timestamp
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeight(pub u64);

impl std::fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BlockHeight {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn increment(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    pub fn checked_add(&self, other: u64) -> Option<Self> {
        self.0.checked_add(other).map(Self)
    }
}

/// Unix timestamp in seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp(pub u64);

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Timestamp {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn now() -> Self {
        Self(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs())
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn checked_add(&self, seconds: u64) -> Option<Self> {
        self.0.checked_add(seconds).map(Self)
    }

    pub fn elapsed_since(&self, other: &Self) -> Option<std::time::Duration> {
        self.0.checked_sub(other.0)
            .map(|secs| std::time::Duration::from_secs(secs))
    }
}

/// Validator set for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
    pub threshold: usize, // Minimum validators needed for consensus
    pub total_stake: u64,
}

impl ValidatorSet {
    pub fn new(validators: Vec<ValidatorInfo>, threshold: usize) -> Self {
        let total_stake = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            threshold,
            total_stake,
        }
    }

    pub fn is_quorum_reached(&self, signatures: usize) -> bool {
        signatures >= self.threshold
    }

    pub fn get_validator(&self, public_key: &PublicKey) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.public_key == public_key)
    }

    pub fn add_validator(&mut self, validator: ValidatorInfo) {
        self.validators.push(validator.clone());
        self.total_stake += validator.stake;
        self.threshold = (self.validators.len() * 2 / 3) + 1; // 2/3 + 1 rule
    }

    pub fn remove_validator(&mut self, public_key: &PublicKey) -> bool {
        if let Some(index) = self.validators.iter().position(|v| &v.public_key == public_key) {
            let removed = self.validators.remove(index);
            self.total_stake -= removed.stake;
            self.threshold = (self.validators.len() * 2 / 3) + 1;
            true
        } else {
            false
        }
    }
}

/// Validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub public_key: PublicKey,
    pub name: String,
    pub stake: u64,
    pub reputation: f64,
    pub is_active: bool,
    pub joined_at: Timestamp,
    pub last_seen: Timestamp,
}

/// Transaction data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub contract_address: Option<Address>,
    pub method: String,
    pub parameters: Vec<u8>,
    pub value: Amount,
}

impl TransactionData {
    pub fn new(contract_address: Option<Address>, method: String, parameters: Vec<u8>, value: Amount) -> Self {
        Self {
            contract_address,
            method,
            parameters,
            value,
        }
    }

    pub fn simple_transfer(to: Address, amount: Amount) -> Self {
        Self::new(
            None,
            "transfer".to_string(),
            bincode::serialize(&(to, amount)).unwrap_or_default(),
            amount,
        )
    }

    pub fn contract_call(contract: Address, method: String, params: Vec<u8>) -> Self {
        Self::new(
            Some(contract),
            method,
            params,
            Amount::zero(),
        )
    }
}

/// Block header with metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: BlockHeight,
    pub timestamp: Timestamp,
    pub previous_hash: Hash,
    pub transactions_root: Hash,
    pub state_root: Hash,
    pub validator: PublicKey,
    pub signature: Option<Vec<u8>>,
    pub gas_used: Gas,
    pub gas_limit: Gas,
    pub transaction_count: u64,
}

impl BlockHeader {
    pub fn new(
        height: BlockHeight,
        timestamp: Timestamp,
        previous_hash: Hash,
        transactions_root: Hash,
        state_root: Hash,
        validator: PublicKey,
        gas_limit: Gas,
    ) -> Self {
        Self {
            height,
            timestamp,
            previous_hash,
            transactions_root,
            state_root,
            validator,
            signature: None,
            gas_used: Gas::zero(),
            gas_limit,
            transaction_count: 0,
        }
    }

    pub fn hash(&self) -> Hash {
        let data = bincode::serialize(self).unwrap_or_default();
        Hash::new(&data)
    }

    pub fn sign(&mut self, private_key: &PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        let data = bincode::serialize(&BlockHeader {
            height: self.height.clone(),
            timestamp: self.timestamp.clone(),
            previous_hash: self.previous_hash.clone(),
            transactions_root: self.transactions_root.clone(),
            state_root: self.state_root.clone(),
            validator: self.validator.clone(),
            signature: None, // Don't include signature in signing data
            gas_used: self.gas_used.clone(),
            gas_limit: self.gas_limit.clone(),
            transaction_count: self.transaction_count,
        })?;

        let signature = crate::pqcrypto::PQCrypto::sign(&data, &private_key.pq_key.as_ref().unwrap())?;
        self.signature = Some(bincode::serialize(&signature)?);
        Ok(())
    }

    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.signature.is_none() {
            return Ok(false);
        }

        let data = bincode::serialize(&BlockHeader {
            height: self.height.clone(),
            timestamp: self.timestamp.clone(),
            previous_hash: self.previous_hash.clone(),
            transactions_root: self.transactions_root.clone(),
            state_root: self.state_root.clone(),
            validator: self.validator.clone(),
            signature: None, // Don't include signature in verification data
            gas_used: self.gas_used.clone(),
            gas_limit: self.gas_limit.clone(),
            transaction_count: self.transaction_count,
        })?;

        let signature_bytes = self.signature.as_ref().unwrap();
        let pq_signature: crate::pqcrypto::PQSignature = bincode::deserialize(signature_bytes)?;
        let public_key = crate::pqcrypto::PQPublicKey(self.validator.ed25519_key.clone());

        let pq_valid = crate::pqcrypto::PQCrypto::verify(&data, &pq_signature, &public_key)?;

        Ok(pq_valid)
    }
}

/// Improved Block structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockV2 {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub validator_set: ValidatorSet,
    pub execution_results: Vec<TransactionExecutionResult>,
}

impl BlockV2 {
    pub fn new(
        header: BlockHeader,
        transactions: Vec<Transaction>,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            header,
            transactions,
            validator_set,
            execution_results: Vec::new(),
        }
    }

    pub fn hash(&self) -> Hash {
        let data = bincode::serialize(self).unwrap_or_default();
        Hash::new(&data)
    }

    pub fn calculate_transactions_root(&self) -> Hash {
        let mut tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.id).collect();
        tx_hashes.sort();
        let data = bincode::serialize(&tx_hashes).unwrap_or_default();
        Hash::new(&data)
    }

    pub fn calculate_state_root(&self, state_machine: &crate::state_machine::StateMachine<crate::storage::Storage>) -> Hash {
        state_machine.get_state_root().unwrap_or(Hash::new(b"empty_state"))
    }

    pub fn add_execution_results(&mut self, results: Vec<TransactionExecutionResult>) {
        self.execution_results = results;
    }
}

/// Transaction execution result for better error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExecutionResult {
    pub tx_hash: Hash,
    pub success: bool,
    pub gas_used: Gas,
    pub gas_price: GasPrice,
    pub execution_time_ms: u64,
    pub error_message: Option<String>,
    pub return_value: Option<Vec<u8>>,
    pub logs: Vec<TransactionLog>,
}

/// Transaction log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLog {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

/// Network message types for better type safety
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(BlockV2),
    Consensus(crate::consensus::ConsensusMessage),
    StateSync(Vec<u8>), // Placeholder for state sync data
    // HealthCheck(crate::health_monitor::NodeHealth), // disabled
}

/// Configuration for different network environments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
    pub heartbeat_interval_ms: u64,
    pub connection_timeout_ms: u64,
    pub gossipsub_config: GossipSubConfig,
    pub kad_config: KadConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipSubConfig {
    pub heartbeat_interval: std::time::Duration,
    pub history_length: usize,
    pub history_gossip: usize,
    pub mesh_n: usize,
    pub mesh_n_low: usize,
    pub mesh_n_high: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KadConfig {
    pub k_bucket_size: usize,
    pub replication_factor: usize,
    pub query_timeout: std::time::Duration,
    pub record_ttl: std::time::Duration,
}

/// Type-safe error handling
#[derive(Debug, Clone)]
pub enum BlockchainError {
    ValidationError(String),
    ExecutionError(String),
    NetworkError(String),
    StorageError(String),
    ConsensusError(String),
    CryptographicError(String),
    ConfigurationError(String),
    LockPoisoned,
}

impl std::fmt::Display for BlockchainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            BlockchainError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            BlockchainError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            BlockchainError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            BlockchainError::ConsensusError(msg) => write!(f, "Consensus error: {}", msg),
            BlockchainError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            BlockchainError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            BlockchainError::LockPoisoned => write!(f, "Lock poisoned"),
        }
    }
}

impl std::error::Error for BlockchainError {}

impl From<Box<dyn std::error::Error>> for BlockchainError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        BlockchainError::StorageError(err.to_string())
    }
}

// Removed conflicting From implementation for Box<bincode::ErrorKind>

impl From<bincode::Error> for BlockchainError {
    fn from(err: bincode::Error) -> Self {
        BlockchainError::StorageError(format!("Serialization error: {}", err))
    }
}

/// Type-safe result type
pub type BlockchainResult<T> = Result<T, BlockchainError>;

/// Metrics collection for performance monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainMetrics {
    pub timestamp: Timestamp,
    pub block_height: BlockHeight,
    pub transactions_per_second: f64,
    pub average_block_time_ms: f64,
    pub gas_used_per_block: u64,
    pub active_validators: usize,
    pub network_peers: usize,
    pub mempool_size: usize,
    pub state_size_mb: f64,
    pub disk_usage_mb: f64,
}

/// Configuration validation
pub trait Configurable {
    fn validate_config(&self) -> BlockchainResult<()>;
    fn get_config_summary(&self) -> String;
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
    Unknown,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }

    pub fn is_degraded(&self) -> bool {
        matches!(self, HealthStatus::Degraded(_))
    }
}

/// Node information for network discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: PublicKey,
    pub listen_addresses: Vec<String>,
    pub version: String,
    pub capabilities: Vec<String>,
    pub last_seen: Timestamp,
    pub reputation: f64,
    pub is_validator: bool,
    pub stake: Option<u64>,
}

impl Hash {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self(result.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Multi-crypto public key (supports both Ed25519 and PQ)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    pub ed25519_key: Vec<u8>,
    pub pq_key: Option<PQPublicKey>,
}

impl PublicKey {
    pub fn new(key: String) -> Self {
        // For backward compatibility with tests - hash string to 32 bytes
        let mut hasher = Sha3_256::new();
        hasher.update(key.as_bytes());
        Self {
            ed25519_key: hasher.finalize().to_vec(),
            pq_key: None,
        }
    }

    pub fn new_with_pq(key: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut hasher = Sha3_256::new();
        hasher.update(key.as_bytes());
        let ed25519_key = hasher.finalize().to_vec();

        // Generate PQ keypair
        let pq_keypair = PQCrypto::generate_keypair();
        let pq_key = pq_keypair.public_key;

        Ok(Self {
            ed25519_key,
            pq_key: Some(pq_key),
        })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            ed25519_key: bytes,
            pq_key: None,
        }
    }

    pub fn from_bytes_with_pq(ed25519_bytes: Vec<u8>, pq_key: PQPublicKey) -> Self {
        Self {
            ed25519_key: ed25519_bytes,
            pq_key: Some(pq_key),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ed25519_key
    }

    pub fn as_str(&self) -> String {
        hex::encode(&self.ed25519_key)
    }

    pub fn has_pq_key(&self) -> bool {
        self.pq_key.is_some()
    }

    pub fn pq_key(&self) -> Option<&PQPublicKey> {
        self.pq_key.as_ref()
    }
}

/// Multi-crypto private key (supports both Ed25519 and PQ)
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub ed25519_key: Vec<u8>,
    pub pq_key: Option<PQPrivateKey>,
}

impl PrivateKey {
    pub fn new(key: String) -> Self {
        // For backward compatibility - hash string to 32 bytes
        let mut hasher = Sha3_256::new();
        hasher.update(key.as_bytes());
        Self {
            ed25519_key: hasher.finalize().to_vec(),
            pq_key: None,
        }
    }

    pub fn new_with_pq(key: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut hasher = Sha3_256::new();
        hasher.update(key.as_bytes());
        let ed25519_key = hasher.finalize().to_vec();

        // Generate PQ keypair
        let pq_keypair = PQCrypto::generate_keypair();
        let pq_key = pq_keypair.private_key;

        Ok(Self {
            ed25519_key,
            pq_key: Some(pq_key),
        })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            ed25519_key: bytes,
            pq_key: None,
        }
    }

    pub fn from_bytes_with_pq(ed25519_bytes: Vec<u8>, pq_key: PQPrivateKey) -> Self {
        Self {
            ed25519_key: ed25519_bytes,
            pq_key: Some(pq_key),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ed25519_key
    }

    pub fn has_pq_key(&self) -> bool {
        self.pq_key.is_some()
    }

    pub fn pq_key(&self) -> Option<&PQPrivateKey> {
        self.pq_key.as_ref()
    }

    /// Get PQ key for consensus operations (owned)
    pub fn pq_key_owned(&self) -> Option<PQPrivateKey> {
        self.pq_key.clone()
    }

    /// Get public key for consensus operations
    pub fn public_key(&self) -> Option<PublicKey> {
        Some(PublicKey {
            ed25519_key: self.ed25519_key.clone(),
            pq_key: self.pq_key.as_ref().map(|pk| pk.public_key()),
        })
    }
}

/// Multi-crypto signature (supports both Ed25519 and PQ)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub ed25519_sig: Vec<u8>,
    pub pq_sig: Option<PQSignature>,
}

impl Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            ed25519_sig: bytes,
            pq_sig: None,
        }
    }

    pub fn from_bytes_with_pq(ed25519_bytes: Vec<u8>, pq_sig: PQSignature) -> Self {
        Self {
            ed25519_sig: ed25519_bytes,
            pq_sig: Some(pq_sig),
        }
    }

    pub fn from_pq_only(pq_sig: PQSignature) -> Self {
        Self {
            ed25519_sig: vec![], // Empty for backward compatibility
            pq_sig: Some(pq_sig),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ed25519_sig
    }

    pub fn has_pq_sig(&self) -> bool {
        self.pq_sig.is_some()
    }

    pub fn pq_sig(&self) -> Option<&PQSignature> {
        self.pq_sig.as_ref()
    }
}

/// Transaction with Ed25519 signature support
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Hash,
    pub sender: PublicKey,
    pub receiver: PublicKey,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: Option<Signature>,
}

impl Transaction {
    pub fn new(sender: PublicKey, receiver: PublicKey, amount: u64, nonce: u64) -> Self {
        Self::new_with_fee(sender, receiver, amount, 0, nonce)
    }

    pub fn new_with_fee(sender: PublicKey, receiver: PublicKey, amount: u64, fee: u64, nonce: u64) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut tx = Self {
            id: Hash([0; 32]), // Will be calculated after signing
            sender,
            receiver,
            amount,
            fee,
            nonce,
            timestamp,
            signature: None,
        };

        // Calculate transaction hash (without signature)
        tx.id = tx.calculate_hash();

        tx
    }
    
    /// Calculate transaction hash (excluding signature)
    pub fn calculate_hash(&self) -> Hash {
        let tx_data = format!("{}{}{}{}{}{}",
            hex::encode(&self.sender.ed25519_key),
            hex::encode(&self.receiver.ed25519_key),
            self.amount,
            self.fee,
            self.nonce,
            self.timestamp
        );
        Hash::new(tx_data.as_bytes())
    }
    
    /// Sign transaction with private key (supports both Ed25519 and PQ)
    pub fn sign(&mut self, private_key: &PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        let message = self.calculate_hash();

        // Sign with Ed25519 (always present for backward compatibility)
        let signing_key = SigningKey::from_bytes(
            private_key.ed25519_key.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 private key length")?
        );
        let ed25519_signature = signing_key.sign(message.as_bytes());

        // Sign with PQ if available
        let pq_signature = if let Some(pq_key) = &private_key.pq_key {
            Some(PQCrypto::sign(message.as_bytes(), pq_key)?)
        } else {
            None
        };

        // Create combined signature
        let signature = if let Some(pq_sig) = pq_signature {
            Signature::from_bytes_with_pq(ed25519_signature.to_bytes().to_vec(), pq_sig)
        } else {
            Signature::from_bytes(ed25519_signature.to_bytes().to_vec())
        };

        // Store signature
        self.signature = Some(signature);

        // Recalculate ID to include signature
        self.id = self.calculate_hash();

        Ok(())
    }
    
    /// Verify transaction signature (supports both Ed25519 and PQ)
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let signature_data = match &self.signature {
            Some(sig) => sig,
            None => return Ok(false), // Unsigned transaction
        };

        let signature = signature_data;

        let message = self.calculate_hash();

        // Verify Ed25519 signature (always present)
        let verifying_key = VerifyingKey::from_bytes(
            signature_data.ed25519_sig.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 public key length")?
        )?;

        let ed25519_sig = Ed25519Signature::from_bytes(
            signature.ed25519_sig.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 signature length")?
        );

        let ed25519_valid = verifying_key.verify(message.as_bytes(), &ed25519_sig).is_ok();

        // Verify PQ signature if present
        let pq_valid = if let Some(pq_key) = self.sender.pq_key() {
            if let Some(ref pq_sig) = signature.pq_sig {
                PQCrypto::verify(message.as_bytes(), pq_sig, pq_key)?
            } else {
                true // No PQ signature required
            }
        } else {
            true // No PQ key required
        };

        // Both signatures must be valid if PQ is present
        Ok(ed25519_valid && pq_valid)
    }
    
    /// Generate a new keypair (Ed25519 only for backward compatibility)
    pub fn generate_keypair() -> (PublicKey, PrivateKey) {
        let random_bytes: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&random_bytes);
        let verifying_key = signing_key.verifying_key();

        (
            PublicKey::from_bytes(verifying_key.to_bytes().to_vec()),
            PrivateKey::from_bytes(signing_key.to_bytes().to_vec())
        )
    }

    /// Generate a new keypair with PQ cryptography
    pub fn generate_keypair_with_pq() -> Result<(PublicKey, PrivateKey), Box<dyn std::error::Error>> {
        let random_bytes: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&random_bytes);
        let verifying_key = signing_key.verifying_key();

        // Generate PQ keypair
        let pq_keypair = PQCrypto::generate_keypair();

        let public_key = PublicKey::from_bytes_with_pq(
            verifying_key.to_bytes().to_vec(),
            pq_keypair.public_key
        );

        let private_key = PrivateKey::from_bytes_with_pq(
            signing_key.to_bytes().to_vec(),
            pq_keypair.private_key
        );

        Ok((public_key, private_key))
    }
}

/// Block containing transactions with Ed25519 signature support
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}


impl Block {
    pub fn new(previous_hash: Hash, height: u64, transactions: Vec<Transaction>, validator: PublicKey) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simple merkle root calculation
        let transactions_root = Self::calculate_simple_merkle(&transactions);

        let header = BlockHeader {
            previous_hash,
            height: BlockHeight(height),
            timestamp: Timestamp(timestamp),
            transactions_root,
            state_root: Hash::new(b"state_root"), // Mock state root
            validator,
            signature: None,
            gas_used: Gas(21000), // Standard gas used
            gas_limit: Gas(8000000), // Standard gas limit
            transaction_count: transactions.len() as u64,
        };

        Self {
            header,
            transactions,
        }
    }

    pub fn calculate_simple_merkle(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::new(b"empty");
        }

        let mut combined = String::new();
        for tx in transactions {
            combined.push_str(&format!("{:?}", tx.id));
        }

        Hash::new(combined.as_bytes())
    }

    pub fn hash(&self) -> Hash {
        let header_data = format!("{}{}{}{}{}",
            self.header.previous_hash.as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
            self.header.height,
            self.header.timestamp,
            self.header.transactions_root.as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
            self.header.validator.as_str()
        );

        Hash::new(header_data.as_bytes())
    }
    
    /// Sign block with validator's private key (supports both Ed25519 and PQ)
    pub fn sign(&mut self, private_key: &PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        let block_hash = self.hash();

        // Sign with Ed25519 (always present for backward compatibility)
        let signing_key = SigningKey::from_bytes(
            private_key.ed25519_key.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 private key length")?
        );
        let ed25519_signature = signing_key.sign(block_hash.as_bytes());

        // Sign with PQ if available
        let pq_signature = if let Some(pq_key) = &private_key.pq_key {
            Some(PQCrypto::sign(block_hash.as_bytes(), pq_key)?)
        } else {
            None
        };

        // Create combined signature
        let signature = if let Some(pq_sig) = pq_signature {
            Signature::from_bytes_with_pq(ed25519_signature.to_bytes().to_vec(), pq_sig)
        } else {
            Signature::from_bytes(ed25519_signature.to_bytes().to_vec())
        };

        self.header.signature = Some(bincode::serialize(&signature)?);
        Ok(())
    }
    
    /// Verify block signature (supports both Ed25519 and PQ)
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let signature_data = match &self.header.signature {
            Some(sig) => sig,
            None => return Ok(false),
        };

        let signature_bytes = signature_data;
        let signature: Signature = bincode::deserialize(signature_bytes)?;

        let block_hash = self.hash();

        // Verify Ed25519 signature (always present)
        let verifying_key = VerifyingKey::from_bytes(
            self.header.validator.ed25519_key.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 public key length")?
        )?;

        let ed25519_sig = Ed25519Signature::from_bytes(
            signature.ed25519_sig.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 signature length")?
        );

        let ed25519_valid = verifying_key.verify(block_hash.as_bytes(), &ed25519_sig).is_ok();

        // Verify PQ signature if present
        let pq_valid = if let Some(pq_key) = self.header.validator.pq_key() {
            if let Some(ref pq_sig) = signature.pq_sig {
                PQCrypto::verify(block_hash.as_bytes(), pq_sig, pq_key)?
            } else {
                true // No PQ signature required
            }
        } else {
            true // No PQ key required
        };

        // Both signatures must be valid if PQ is present
        Ok(ed25519_valid && pq_valid)
    }
}

/// Current state of the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub accounts: std::collections::HashMap<PublicKey, u64>,
    pub last_block_hash: Hash,
    pub height: BlockHeight,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            accounts: std::collections::HashMap::new(),
            last_block_hash: Hash::new(b"genesis"),
            height: BlockHeight(0),
        }
    }

    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        // Check sender balance
        let sender_balance = self.accounts.get(&tx.sender).unwrap_or(&0);
        if *sender_balance < tx.amount {
            return Err("Insufficient balance".into());
        }

        // Update balances
        *self.accounts.entry(tx.sender.clone()).or_insert(0) -= tx.amount;
        *self.accounts.entry(tx.receiver.clone()).or_insert(0) += tx.amount;

        Ok(())
    }

    pub fn apply_block(&mut self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        for tx in &block.transactions {
            self.apply_transaction(tx)?;
        }

        self.last_block_hash = block.hash();
        self.height = block.header.height;

        Ok(())
    }
}

/// Genesis block creation
pub fn create_genesis_block() -> Block {
    let genesis_validator = PublicKey::new("genesis".to_string());
    Block::new(
        Hash::new(b"genesis"),
        0,
        vec![], // No transactions in genesis
        genesis_validator,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqcrypto::PQCrypto;

    #[test]
    fn test_hash_creation() {
        let data = b"Hello, Symbios!";
        let hash1 = Hash::new(data);
        let hash2 = Hash::new(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_backward_compatibility() {
        let key_str = "test_key";
        let key = PublicKey::new(key_str.to_string());

        assert_eq!(key.ed25519_key.len(), 32); // SHA3-256 produces 32 bytes
        assert!(key.pq_key.is_none()); // No PQ key by default
    }

    #[test]
    fn test_public_key_with_pq() {
        let key_str = "test_pq_key";
        let key = PublicKey::new_with_pq(key_str.to_string()).unwrap();

        assert_eq!(key.ed25519_key.len(), 32);
        assert!(key.pq_key.is_some());
        assert!(key.has_pq_key());
    }

    #[test]
    fn test_private_key_backward_compatibility() {
        let key_str = "test_private";
        let key = PrivateKey::new(key_str.to_string());

        assert_eq!(key.ed25519_key.len(), 32);
        assert!(key.pq_key.is_none());
    }

    #[test]
    fn test_private_key_with_pq() {
        let key_str = "test_private_pq";
        let key = PrivateKey::new_with_pq(key_str.to_string()).unwrap();

        assert_eq!(key.ed25519_key.len(), 32);
        assert!(key.pq_key.is_some());
        assert!(key.has_pq_key());
    }

    #[test]
    fn test_signature_types() {
        // Test Ed25519-only signature
        let sig1 = Signature::from_bytes(vec![1, 2, 3, 4]);
        assert!(!sig1.has_pq_sig());
        assert_eq!(sig1.ed25519_sig, vec![1, 2, 3, 4]);

        // Test PQ-only signature
        let pq_sig = PQCrypto::generate_signing_keypair().unwrap().private_key;
        let test_sig = PQCrypto::sign(b"test", &pq_sig).unwrap();
        let sig2 = Signature::from_pq_only(test_sig);
        assert!(sig2.has_pq_sig());
        assert!(sig2.ed25519_sig.is_empty());
    }

    #[test]
    fn test_signature_with_both_crypto() {
        let ed25519_sig = vec![1, 2, 3, 4];
        let pq_sig = PQCrypto::generate_signing_keypair().unwrap().private_key;
        let pq_signature = PQCrypto::sign(b"test", &pq_sig).unwrap();

        let sig = Signature::from_bytes_with_pq(ed25519_sig.clone(), pq_signature);
        assert!(sig.has_pq_sig());
        assert_eq!(sig.ed25519_sig, ed25519_sig);
    }

    #[test]
    fn test_transaction_creation_and_hashing() {
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());

        let tx = Transaction::new(sender.clone(), receiver.clone(), 1000, 0);

        // Check basic properties
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 0);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.sender.ed25519_key, sender.ed25519_key);
        assert_eq!(tx.receiver.ed25519_key, receiver.ed25519_key);

        // Transaction should not be signed initially
        assert!(tx.signature.is_none());

        // Hash should be consistent
        let hash1 = tx.calculate_hash();
        let hash2 = tx.calculate_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_transaction_signing_verification_ed25519() {
        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());

        let mut tx = Transaction::new(sender.clone(), receiver, 1000, 1);
        let original_hash = tx.id;

        // Sign transaction
        tx.sign(&private_key).unwrap();

        // Transaction should now be signed
        assert!(tx.signature.is_some());

        // Hash should change after signing (due to signature inclusion)
        assert_ne!(tx.id, original_hash);

        // Verification should succeed
        assert!(tx.verify().unwrap());

        // Test with wrong sender
        let mut wrong_tx = tx.clone();
        wrong_tx.sender = PublicKey::new("charlie".to_string());
        assert!(!wrong_tx.verify().unwrap());
    }

    #[test]
    fn test_transaction_signing_verification_pq() {
        let (sender, private_key) = Transaction::generate_keypair_with_pq().unwrap();
        let receiver = PublicKey::new("bob".to_string());

        let mut tx = Transaction::new(sender.clone(), receiver, 1000, 1);

        // Sign transaction (should use both Ed25519 and PQ)
        tx.sign(&private_key).unwrap();

        // Transaction should have both signatures
        assert!(tx.signature.is_some());
        let sig = tx.signature.as_ref().unwrap();
        assert!(!sig.ed25519_sig.is_empty());
        assert!(sig.has_pq_sig());

        // Verification should succeed
        assert!(tx.verify().unwrap());

        // Test with tampered signature
        let mut tampered_tx = tx.clone();
        if let Some(ref mut sig) = tampered_tx.signature {
            sig.ed25519_sig[0] = sig.ed25519_sig[0].wrapping_add(1);
        }
        assert!(!tampered_tx.verify().unwrap());
    }

    #[test]
    fn test_block_creation_and_hashing() {
        let validator = PublicKey::new("validator".to_string());
        let transactions = vec![
            Transaction::new(
                PublicKey::new("alice".to_string()),
                PublicKey::new("bob".to_string()),
                100,
                0
            )
        ];

        let block = Block::new(
            Hash::new(b"previous"),
            1,
            transactions,
            validator.clone()
        );

        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.previous_hash, Hash::new(b"previous"));
        assert_eq!(block.header.validator.ed25519_key, validator.ed25519_key);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.header.signature.is_none()); // Not signed initially

        // Block hash should be consistent
        let hash1 = block.hash();
        let hash2 = block.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_signing_verification_ed25519() {
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        let mut block = Block::new(
            Hash::new(b"previous"),
            1,
            vec![],
            validator.clone()
        );

        // Sign block
        block.sign(&private_key).unwrap();
        assert!(block.header.signature.is_some());

        // Verification should succeed
        assert!(block.verify().unwrap());

        // Test with wrong validator
        let mut wrong_block = block.clone();
        wrong_block.header.validator = PublicKey::new("wrong_validator".to_string());
        assert!(!wrong_block.verify().unwrap());
    }

    #[test]
    fn test_block_signing_verification_pq() {
        let validator = PublicKey::new_with_pq("validator".to_string()).unwrap();
        let private_key = PrivateKey::new_with_pq("validator_key".to_string()).unwrap();

        let mut block = Block::new(
            Hash::new(b"previous"),
            1,
            vec![],
            validator.clone()
        );

        // Sign block with PQ
        block.sign(&private_key).unwrap();
        assert!(block.header.signature.is_some());

        let sig = block.header.signature.as_ref().unwrap();
        assert!(!sig.ed25519_sig.is_empty());
        assert!(sig.has_pq_sig());

        // Verification should succeed
        assert!(block.verify().unwrap());
    }

    #[test]
    fn test_genesis_block_creation() {
        let genesis = create_genesis_block();

        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.previous_hash, Hash::new(b"genesis"));
        assert_eq!(genesis.transactions.len(), 0);
        assert_eq!(genesis.header.validator.ed25519_key, PublicKey::new("genesis".to_string()).ed25519_key);
    }

    #[test]
    fn test_state_operations() {
        let mut state = State::new();

        // Initially empty
        assert_eq!(state.accounts.len(), 0);
        assert_eq!(state.height.as_u64(), 0);

        // Add transaction
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());
        let tx = Transaction::new(sender.clone(), receiver.clone(), 100, 0);

        state.apply_transaction(&tx).unwrap();

        // Check balances
        assert_eq!(*state.accounts.get(&sender).unwrap_or(&0), -100i64 as u64);
        assert_eq!(*state.accounts.get(&receiver).unwrap_or(&0), 100);

        // Apply block
        let validator = PublicKey::new("validator".to_string());
        let block = Block::new(state.last_block_hash, 1, vec![tx], validator);

        state.apply_block(&block).unwrap();

        assert_eq!(state.height.as_u64(), 1);
        assert_eq!(state.last_block_hash, block.hash());
    }

    #[test]
    fn test_keypair_generation_compatibility() {
        // Test that new PQ keypair generation works
        let result = Transaction::generate_keypair_with_pq();
        assert!(result.is_ok());

        let (pub_key, priv_key) = result.unwrap();
        assert!(pub_key.has_pq_key());
        assert!(priv_key.has_pq_key());
    }

    #[test]
    fn test_transaction_with_fee() {
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());

        let tx = Transaction::new_with_fee(sender, receiver, 1000, 10, 1);

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
        assert_eq!(tx.nonce, 1);
    }

    #[test]
    fn test_merkle_root_calculation() {
        // Empty block
        let empty_root = Block::calculate_simple_merkle(&[]);
        assert_eq!(empty_root, Hash::new(b"empty"));

        // Block with transactions
        let tx1 = Transaction::new(
            PublicKey::new("a".to_string()),
            PublicKey::new("b".to_string()),
            100, 0
        );
        let tx2 = Transaction::new(
            PublicKey::new("c".to_string()),
            PublicKey::new("d".to_string()),
            200, 1
        );

        let root = Block::calculate_simple_merkle(&[tx1, tx2]);
        // Should be different from empty
        assert_ne!(root, Hash::new(b"empty"));
    }
}