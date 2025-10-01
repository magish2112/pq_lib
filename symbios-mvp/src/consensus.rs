use std::collections::HashMap;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use crate::types::{Block, Transaction, Hash, State, PublicKey, PrivateKey};
use crate::mempool::MempoolTrait;
use crate::storage::StorageTrait;

/// Consensus trait for block validation and creation
#[async_trait]
pub trait ConsensusTrait {
    async fn propose_block(&mut self, transactions: Vec<Transaction>, mempool: &mut dyn MempoolTrait, storage: &dyn StorageTrait) -> Result<Block, Box<dyn std::error::Error>>;
    async fn validate_block(&self, block: &Block, state: &State) -> Result<bool, Box<dyn std::error::Error>>;
    async fn finalize_block(&mut self, block: Block, storage: &dyn StorageTrait) -> Result<(), Box<dyn std::error::Error>>;
}

/// Simple leader-based consensus for MVP
/// In production, this would be replaced with proper BFT consensus
pub struct SimpleConsensus {
    validator_id: PublicKey,
    private_key: PrivateKey,
    validators: Vec<PublicKey>,
    current_leader: usize,
    round: u64,
}

impl SimpleConsensus {
    pub fn new(validator_id: PublicKey, private_key: PrivateKey, validators: Vec<PublicKey>) -> Self {
        Self {
            validator_id,
            private_key,
            validators,
            current_leader: 0,
            round: 0,
        }
    }

    /// Check if current validator is the leader for this round
    pub fn is_leader(&self) -> bool {
        self.validator_id == self.validators[self.current_leader]
    }

    /// Get next leader (simple round-robin for MVP)
    fn next_leader(&mut self) {
        self.current_leader = (self.current_leader + 1) % self.validators.len();
        self.round += 1;
    }

    /// Simple leader selection - in production would use VRF or other mechanisms
    fn select_leader(&self, round: u64) -> &PublicKey {
        let leader_index = (round as usize) % self.validators.len();
        &self.validators[leader_index]
    }
}

#[async_trait]
impl ConsensusTrait for SimpleConsensus {
    async fn propose_block(&mut self, transactions: Vec<Transaction>, _mempool: &mut dyn MempoolTrait, storage: &dyn StorageTrait) -> Result<Block, Box<dyn std::error::Error>> {
        // Only leader can propose blocks
        if !self.is_leader() {
            return Err("Not a leader for this round".into());
        }

        // Get current state to determine block height
        let state = storage.get_state().await?;
        let previous_hash = state.last_block_hash;
        let height = state.height.as_u64() + 1;

        // Create new block
        let mut block = Block::new(previous_hash, height, transactions, self.validator_id.clone());

        // Sign the block
        block.sign(&self.private_key)?;

        // Move to next round
        self.next_leader();

        Ok(block)
    }

    async fn validate_block(&self, block: &Block, state: &State) -> Result<bool, Box<dyn std::error::Error>> {
        // Basic validation checks

        // 1. Check block height
        if block.header.height.as_u64() != state.height.as_u64() + 1 {
            log::warn!("Invalid block height: expected {}, got {}", state.height.as_u64() + 1, block.header.height.as_u64());
            return Ok(false);
        }

        // 2. Check previous hash
        if block.header.previous_hash != state.last_block_hash {
            log::warn!("Invalid previous hash");
            return Ok(false);
        }

        // 3. Verify block Ed25519 signature
        if !block.verify()? {
            log::warn!("Invalid block signature");
            return Ok(false);
        }

        // 4. Check if proposer is a valid validator
        if !self.validators.contains(&block.header.validator) {
            log::warn!("Invalid block proposer");
            return Ok(false);
        }

        // 5. Verify Merkle root
        let calculated_merkle_root = Block::calculate_simple_merkle(&block.transactions);
        if calculated_merkle_root != block.header.transactions_root {
            log::warn!("Invalid Merkle root");
            return Ok(false);
        }

        // 6. Validate transactions
        for tx in &block.transactions {
            if !tx.verify()? {
                log::warn!("Invalid transaction signature in block");
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn finalize_block(&mut self, block: Block, storage: &dyn StorageTrait) -> Result<(), Box<dyn std::error::Error>> {
        // Store the block
        storage.store_block(&block).await?;

        // Update state (in production, this would involve state transition)
        let mut state = storage.get_state().await?;
        state.apply_block(&block)?;
        storage.store_state(&state).await?;

        log::info!("Block {} finalized at height {}", block.hash().as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(), block.header.height);

        Ok(())
    }
}

/// Consensus factory for creating consensus instances
pub struct ConsensusFactory;

impl ConsensusFactory {
    pub fn create_simple_consensus(validator_id: PublicKey, private_key: PrivateKey, validators: Vec<PublicKey>) -> Box<dyn ConsensusTrait> {
        Box::new(SimpleConsensus::new(validator_id, private_key, validators))
    }
}

/// Vote structure for consensus messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub block_hash: Hash,
    pub validator: PublicKey,
    pub signature: Vec<u8>,
    pub vote_type: VoteType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Prepare,
    PreCommit,
    Commit,
}

/// Consensus messages for communication between validators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    Proposal(Block),
    Vote(Vote),
    NewView(u64), // Round number
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::create_genesis_block;
    use crate::storage::Storage;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_block_validation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();

        // Create genesis block and initial state
        let genesis = create_genesis_block();
        storage.store_block(&genesis).await.unwrap();

        let mut state = State::new();
        state.apply_block(&genesis).unwrap();
        storage.store_state(&state).await.unwrap();

        // Create consensus instance
        let validator = PublicKey(vec![1; 32]);
        let private_key = PrivateKey(vec![2; 32]);
        let validators = vec![validator.clone()];
        let consensus = SimpleConsensus::new(validator.clone(), private_key, validators);

        // Create a valid transaction
        let sender = PublicKey(vec![3; 32]);
        let receiver = PublicKey(vec![4; 32]);
        let mut tx = Transaction::new(sender, receiver, 100, 0);
        tx.sign(&PrivateKey(vec![5; 32])).unwrap();

        // Create a valid block
        let mut valid_block = Block::new(state.last_block_hash, 1, vec![tx], validator.clone());
        valid_block.sign(&PrivateKey(vec![2; 32])).unwrap();

        // Validate the block
        let is_valid = consensus.validate_block(&valid_block, &state).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_invalid_block_height() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();

        // Create genesis block and initial state
        let genesis = create_genesis_block();
        storage.store_block(&genesis).await.unwrap();

        let mut state = State::new();
        state.apply_block(&genesis).unwrap();
        storage.store_state(&state).await.unwrap();

        // Create consensus instance
        let validator = PublicKey(vec![1; 32]);
        let private_key = PrivateKey(vec![2; 32]);
        let validators = vec![validator.clone()];
        let consensus = SimpleConsensus::new(validator, private_key, validators);

        // Create block with wrong height
        let invalid_block = Block::new(state.last_block_hash, 5, vec![], PublicKey(vec![1; 32]));

        // Validate the block - should fail
        let is_valid = consensus.validate_block(&invalid_block, &state).await.unwrap();
        assert!(!is_valid);
    }
}

