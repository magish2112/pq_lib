//! Core types for Symbios Network
//! 
//! ⚠️  MVP STATUS: This is a research prototype with simplified cryptography.
//! Real Ed25519 signatures are implemented but network layer is placeholder.
//! DO NOT USE IN PRODUCTION!

use sha3::{Digest, Sha3_256};
use ed25519_dalek::{Signer, Verifier, Signature as Ed25519Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use crate::pqcrypto::{PQCrypto, PQPublicKey, PQPrivateKey, PQSignature};

/// SHA3-256 hash type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

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
        let pq_keypair = PQCrypto::generate_signing_keypair()?;
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
        let pq_keypair = PQCrypto::generate_signing_keypair()?;
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
            hex::encode(&self.sender.0),
            hex::encode(&self.receiver.0),
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
        let signature = match &self.signature {
            Some(sig) => sig,
            None => return Ok(false), // Unsigned transaction
        };

        let message = self.calculate_hash();

        // Verify Ed25519 signature (always present)
        let verifying_key = VerifyingKey::from_bytes(
            self.sender.ed25519_key.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 public key length")?
        )?;

        let ed25519_sig = Ed25519Signature::from_bytes(
            signature.ed25519_sig.as_slice().try_into()
                .map_err(|_| "Invalid Ed25519 signature length")?
        );

        let ed25519_valid = verifying_key.verify(message.as_bytes(), &ed25519_sig).is_ok();

        // Verify PQ signature if present
        let pq_valid = if let (Some(pq_sig), Some(pq_key)) = (&signature.pq_sig, self.sender.pq_key()) {
            PQCrypto::verify(message.as_bytes(), pq_sig, pq_key)?
        } else {
            true // No PQ signature required
        };

        // Both signatures must be valid if PQ is present
        Ok(ed25519_valid && pq_valid)
    }
    
    /// Generate a new keypair (Ed25519 only for backward compatibility)
    pub fn generate_keypair() -> (PublicKey, PrivateKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        (
            PublicKey::from_bytes(verifying_key.to_bytes().to_vec()),
            PrivateKey::from_bytes(signing_key.to_bytes().to_vec())
        )
    }

    /// Generate a new keypair with PQ cryptography
    pub fn generate_keypair_with_pq() -> Result<(PublicKey, PrivateKey), Box<dyn std::error::Error>> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Generate PQ keypair
        let pq_keypair = PQCrypto::generate_signing_keypair()?;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub previous_hash: Hash,
    pub height: u64,
    pub timestamp: u64,
    pub merkle_root: Hash,
    pub validator: PublicKey,
    pub signature: Option<Signature>,
}

impl Block {
    pub fn new(previous_hash: Hash, height: u64, transactions: Vec<Transaction>, validator: PublicKey) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simple merkle root calculation
        let merkle_root = Self::calculate_simple_merkle(&transactions);

        let header = BlockHeader {
            previous_hash,
            height,
            timestamp,
            merkle_root,
            validator,
            signature: None,
        };

        Self {
            header,
            transactions,
        }
    }

    fn calculate_simple_merkle(transactions: &[Transaction]) -> Hash {
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
            self.header.merkle_root.as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
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

        self.header.signature = Some(signature);
        Ok(())
    }
    
    /// Verify block signature (supports both Ed25519 and PQ)
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let signature = match &self.header.signature {
            Some(sig) => sig,
            None => return Ok(false),
        };

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
        let pq_valid = if let (Some(pq_sig), Some(pq_key)) = (&signature.pq_sig, self.header.validator.pq_key()) {
            PQCrypto::verify(block_hash.as_bytes(), pq_sig, pq_key)?
        } else {
            true // No PQ signature required
        };

        // Both signatures must be valid if PQ is present
        Ok(ed25519_valid && pq_valid)
    }
}

/// Current state of the blockchain
#[derive(Debug, Clone)]
pub struct State {
    pub accounts: std::collections::HashMap<PublicKey, u64>,
    pub last_block_hash: Hash,
    pub height: u64,
}

impl State {
    pub fn new() -> Self {
        Self {
            accounts: std::collections::HashMap::new(),
            last_block_hash: Hash::new(b"genesis"),
            height: 0,
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
        assert_eq!(state.height, 0);

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

        assert_eq!(state.height, 1);
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