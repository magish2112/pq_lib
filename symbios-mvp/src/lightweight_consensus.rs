//! Lightweight BFT Consensus for Resource-Constrained Environments
//!
//! This module implements an optimized BFT consensus protocol designed to run
//! efficiently on minimal hardware while maintaining high throughput and security.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use crate::types::{Block, Transaction, Hash, PublicKey, PrivateKey};
use crate::mempool::MempoolTrait;
use crate::storage::StorageTrait;

/// Lightweight consensus message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConsensusMessage {
    Proposal { block: Block, round: u64 },
    Vote { block_hash: Hash, round: u64, voter: PublicKey },
    Commit { block_hash: Hash, round: u64 },
}

/// Vote structure optimized for memory efficiency
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightweightVote {
    pub block_hash: Hash,
    pub round: u64,
    pub voter: PublicKey,
    pub timestamp: u64,
}

/// Consensus state optimized for memory usage
#[derive(Debug)]
pub struct ConsensusState {
    pub current_round: u64,
    pub last_committed_round: u64,
    pub votes: HashMap<Hash, Vec<LightweightVote>>, // Block hash -> votes
    pub proposals: HashMap<u64, Block>, // Round -> proposed block
    pub committed_blocks: HashMap<u64, Hash>, // Round -> committed block hash
    pub validators: Vec<PublicKey>,
    pub f_tolerance: usize, // Maximum faulty nodes we can tolerate
}

impl ConsensusState {
    pub fn new(validators: Vec<PublicKey>) -> Self {
        let n = validators.len();
        let f = (n - 1) / 3; // Classic BFT fault tolerance

        Self {
            current_round: 0,
            last_committed_round: 0,
            votes: HashMap::new(),
            proposals: HashMap::new(),
            committed_blocks: HashMap::new(),
            validators,
            f_tolerance: f,
        }
    }

    /// Clean up old data to save memory
    pub fn cleanup_old_data(&mut self) {
        let cutoff_round = self.current_round.saturating_sub(10); // Keep last 10 rounds

        // Remove old proposals
        self.proposals.retain(|&round, _| round >= cutoff_round);

        // Remove old committed blocks (keep more history for state validation)
        let committed_cutoff = self.last_committed_round.saturating_sub(100);
        self.committed_blocks.retain(|&round, _| round >= committed_cutoff);

        // Remove old votes
        self.votes.retain(|_, votes| {
            votes.retain(|vote| vote.round >= cutoff_round);
            !votes.is_empty()
        });
    }

    /// Check if we have enough votes for a block
    pub fn has_quorum(&self, block_hash: &Hash) -> bool {
        if let Some(votes) = self.votes.get(block_hash) {
            votes.len() >= 2 * self.f_tolerance + 1 // 2f + 1 for BFT quorum
        } else {
            false
        }
    }
}

/// Lightweight BFT Consensus implementation
pub struct LightweightConsensus {
    node_id: PublicKey,
    private_key: PrivateKey,
    state: ConsensusState,
    last_leader_rotation: Instant,
    round_duration: Duration,
    memory_limit: usize, // Memory limit in bytes
}

impl LightweightConsensus {
    pub fn new(
        node_id: PublicKey,
        private_key: PrivateKey,
        validators: Vec<PublicKey>,
        round_duration_secs: u64,
        memory_limit_mb: usize,
    ) -> Self {
        Self {
            node_id,
            private_key,
            state: ConsensusState::new(validators),
            last_leader_rotation: Instant::now(),
            round_duration: Duration::from_secs(round_duration_secs),
            memory_limit: memory_limit_mb * 1024 * 1024, // Convert MB to bytes
        }
    }

    /// Get current leader based on round-robin with time-based rotation
    pub fn get_leader(&self) -> &PublicKey {
        let leader_index = (self.state.current_round % self.state.validators.len() as u64) as usize;
        &self.state.validators[leader_index]
    }

    /// Check if this node is the current leader
    pub fn is_leader(&self) -> bool {
        self.get_leader() == &self.node_id
    }

    /// Advance to next round
    pub fn advance_round(&mut self) {
        self.state.current_round += 1;
        self.last_leader_rotation = Instant::now();

        // Periodic cleanup to save memory
        if self.state.current_round % 5 == 0 {
            self.state.cleanup_old_data();
        }
    }

    /// Check if round has timed out
    pub fn round_timed_out(&self) -> bool {
        self.last_leader_rotation.elapsed() > self.round_duration
    }

    /// Handle incoming consensus message
    pub async fn handle_message(&mut self, message: ConsensusMessage) -> Result<(), Box<dyn std::error::Error>> {
        match message {
            ConsensusMessage::Proposal { block, round } => {
                self.handle_proposal(block, round).await
            }
            ConsensusMessage::Vote { block_hash, round, voter } => {
                self.handle_vote(block_hash, round, voter).await
            }
            ConsensusMessage::Commit { block_hash, round } => {
                self.handle_commit(block_hash, round).await
            }
        }
    }

    async fn handle_proposal(&mut self, block: Block, round: u64) -> Result<(), Box<dyn std::error::Error>> {
        // Validate proposal
        if round != self.state.current_round {
            return Ok(()); // Ignore old rounds
        }

        if !self.state.validators.contains(&block.header.validator) {
            return Err("Invalid proposer".into());
        }

        // Store proposal
        self.state.proposals.insert(round, block.clone());

        // Vote for the proposal if we're not the proposer
        if !self.is_leader() {
            // Create and send vote (would be sent to network)
            let vote = LightweightVote {
                block_hash: block.hash(),
                round,
                voter: self.node_id.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            self.state.votes.entry(block.hash())
                .or_insert_with(Vec::new)
                .push(vote);
        }

        Ok(())
    }

    async fn handle_vote(&mut self, block_hash: Hash, round: u64, voter: PublicKey) -> Result<(), Box<dyn std::error::Error>> {
        // Validate vote
        if round != self.state.current_round {
            return Ok(()); // Ignore old rounds
        }

        if !self.state.validators.contains(&voter) {
            return Err("Invalid voter".into());
        }

        // Store vote
        let vote = LightweightVote {
            block_hash: block_hash.clone(),
            round,
            voter,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.state.votes.entry(block_hash.clone())
            .or_insert_with(Vec::new)
            .push(vote);

        // Check for quorum
        if self.state.has_quorum(&block_hash) {
            // Send commit message (would be sent to network)
            let commit_msg = ConsensusMessage::Commit { block_hash, round };
            self.handle_commit(block_hash, round).await?;
        }

        Ok(())
    }

    async fn handle_commit(&mut self, block_hash: Hash, round: u64) -> Result<(), Box<dyn std::error::Error>> {
        if round > self.state.last_committed_round {
            self.state.committed_blocks.insert(round, block_hash);
            self.state.last_committed_round = round;
        }

        Ok(())
    }

    /// Get consensus statistics for monitoring
    pub fn get_stats(&self) -> ConsensusStats {
        ConsensusStats {
            current_round: self.state.current_round,
            last_committed_round: self.state.last_committed_round,
            active_proposals: self.state.proposals.len(),
            total_votes: self.state.votes.values().map(|v| v.len()).sum(),
            is_leader: self.is_leader(),
            validators_count: self.state.validators.len(),
        }
    }

    /// Check memory usage (simplified)
    pub fn memory_usage(&self) -> usize {
        // Rough estimate of memory usage
        let votes_size = self.state.votes.values()
            .map(|votes| votes.len() * std::mem::size_of::<LightweightVote>())
            .sum::<usize>();

        let proposals_size = self.state.proposals.len() * 1024; // Rough estimate per block

        votes_size + proposals_size
    }
}

/// Consensus statistics for monitoring
#[derive(Debug, Clone)]
pub struct ConsensusStats {
    pub current_round: u64,
    pub last_committed_round: u64,
    pub active_proposals: usize,
    pub total_votes: usize,
    pub is_leader: bool,
    pub validators_count: usize,
}

#[async_trait]
impl crate::consensus::ConsensusTrait for LightweightConsensus {
    async fn propose_block(
        &mut self,
        transactions: Vec<Transaction>,
        mempool: &mut dyn MempoolTrait,
        storage: &dyn StorageTrait
    ) -> Result<Block, Box<dyn std::error::Error>> {
        if !self.is_leader() {
            return Err("Not a leader".into());
        }

        // Get current state
        let state = storage.get_state().await?;
        let height = state.height.as_u64() + 1;

        // Create block
        let mut block = Block::new(
            state.last_block_hash,
            height,
            transactions,
            self.node_id.clone()
        );

        // Sign block (simplified)
        // Sign block with validator's private key
        block.sign(&self.private_key)?;

        // Store proposal
        self.state.proposals.insert(self.state.current_round, block.clone());

        Ok(block)
    }

    async fn validate_block(&self, block: &Block, state: &crate::types::State) -> Result<bool, Box<dyn std::error::Error>> {
        // Basic validation
        if block.header.height.as_u64() != state.height.as_u64() + 1 {
            return Ok(false);
        }

        if block.header.previous_hash != state.last_block_hash {
            return Ok(false);
        }

        Ok(true)
    }

    async fn finalize_block(&mut self, block: Block, storage: &dyn StorageTrait) -> Result<(), Box<dyn std::error::Error>> {
        // Store block
        storage.store_block(&block).await?;

        // Update state
        let mut state = storage.get_state().await?;
        state.apply_block(&block)?;
        storage.store_state(&state).await?;

        // Mark as committed
        let round = self.state.current_round;
        self.state.committed_blocks.insert(round, block.hash());
        self.state.last_committed_round = round;

        log::info!("Block {} finalized at height {}", block.hash().as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(), block.header.height.as_u64());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_lightweight_consensus_creation() {
        let validators = vec![
            PublicKey(vec![1; 32]),
            PublicKey(vec![2; 32]),
            PublicKey(vec![3; 32]),
            PublicKey(vec![4; 32]),
        ];

        let consensus = LightweightConsensus::new(
            validators[0].clone(),
            PrivateKey(vec![1; 32]),
            validators,
            5, // 5 second rounds
            50, // 50MB memory limit
        );

        assert_eq!(consensus.state.current_round, 0);
        assert_eq!(consensus.state.validators.len(), 4);
    }

    #[tokio::test]
    async fn test_leader_rotation() {
        let validators = vec![
            PublicKey(vec![1; 32]),
            PublicKey(vec![2; 32]),
            PublicKey(vec![3; 32]),
        ];

        let mut consensus = LightweightConsensus::new(
            validators[0].clone(),
            PrivateKey(vec![1; 32]),
            validators.clone(),
            5,
            50,
        );

        // Initially first validator is leader
        assert_eq!(consensus.get_leader(), &validators[0]);

        consensus.advance_round();
        assert_eq!(consensus.get_leader(), &validators[1]);

        consensus.advance_round();
        assert_eq!(consensus.get_leader(), &validators[2]);

        consensus.advance_round();
        assert_eq!(consensus.get_leader(), &validators[0]);
    }
}

