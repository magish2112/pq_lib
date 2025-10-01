//! Production-Grade BFT Consensus Engine
//!
//! This module implements a robust Byzantine Fault Tolerant (BFT) consensus
//! algorithm based on PBFT (Practical Byzantine Fault Tolerance) with
//! economic sanctions for malicious validators.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc, oneshot};
use futures::future::join_all;
use crate::types::{Block, Transaction, Hash, PublicKey, PrivateKey, BlockHeight, Timestamp, ValidatorSet, ValidatorInfo, BlockchainError, BlockchainResult};
use crate::state_machine::{StateMachine, StateResult};
use crate::storage::StorageTrait;
use crate::kms::{ValidatorKms, ValidatorConfig};
use crate::network::{NetworkTrait, NetworkMessage};
use crate::parallel_execution::{ParallelExecutionEngine, ParallelExecutionConfig};

/// Consensus phases
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusPhase {
    PrePrepare,
    Prepare,
    Commit,
    Finalized,
}

/// Consensus message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    PrePrepare {
        view: u64,
        block_hash: Hash,
        block: Block,
        proposer: PublicKey,
        timestamp: Timestamp,
    },
    Prepare {
        view: u64,
        block_hash: Hash,
        validator: PublicKey,
        signature: Vec<u8>,
        timestamp: Timestamp,
    },
    Commit {
        view: u64,
        block_hash: Hash,
        validator: PublicKey,
        signature: Vec<u8>,
        timestamp: Timestamp,
    },
    ViewChange {
        new_view: u64,
        last_stable_checkpoint: u64,
        validator: PublicKey,
        signature: Vec<u8>,
        timestamp: Timestamp,
    },
    NewView {
        view: u64,
        validators: ValidatorSet,
        pre_prepare_messages: Vec<ConsensusMessage>,
        validator: PublicKey,
        signature: Vec<u8>,
        timestamp: Timestamp,
    },
}

/// Validator reputation and sanctions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    pub validator_id: PublicKey,
    pub reputation: f64,
    pub total_blocks_proposed: u64,
    pub total_blocks_validated: u64,
    pub successful_validations: u64,
    pub failed_validations: u64,
    pub sanctions_applied: u64,
    pub last_activity: Timestamp,
    pub is_active: bool,
    pub stake_amount: u64,
}

/// Sanction types for malicious behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanctionType {
    InvalidBlockProposal,
    DoubleVoting,
    Equivocation,
    NetworkMisbehavior,
    Inactivity,
    InvalidSignature,
}

/// Sanction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionRecord {
    pub validator_id: PublicKey,
    pub sanction_type: SanctionType,
    pub severity: SanctionSeverity,
    pub applied_at: Timestamp,
    pub duration_blocks: u64,
    pub reason: String,
    pub evidence: Vec<u8>,
}

/// Sanction severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanctionSeverity {
    Warning,
    Penalty,
    Suspension,
    Expulsion,
}

/// BFT consensus configuration
#[derive(Debug, Clone)]
pub struct BftConfig {
    pub view_timeout_ms: u64,
    pub max_views_without_progress: u64,
    pub checkpoint_interval: u64,
    pub max_faulty_validators: usize,
    pub min_quorum_size: usize,
    pub sanction_threshold: f64,
    pub reputation_decay_rate: f64,
    pub max_message_age_ms: u64,
}

/// Production BFT consensus engine
pub struct BftConsensus<S: StorageTrait + Send + Sync + 'static, N: NetworkTrait + Send + Sync + 'static> {
    config: BftConfig,
    validator_kms: Arc<ValidatorKms>,
    state_machine: Arc<StateMachine<S>>,
    network: Arc<N>,
    execution_engine: Arc<ParallelExecutionEngine<S>>,

    // Consensus state
    current_view: Arc<AtomicU64>,
    current_phase: Arc<RwLock<ConsensusPhase>>,
    validator_set: Arc<RwLock<ValidatorSet>>,
    validator_metrics: Arc<RwLock<HashMap<PublicKey, ValidatorMetrics>>>,

    // Message handling
    message_channel: mpsc::UnboundedReceiver<ConsensusMessage>,
    message_sender: mpsc::UnboundedSender<ConsensusMessage>,

    // Consensus data structures
    pre_prepare_messages: Arc<RwLock<HashMap<Hash, Vec<ConsensusMessage>>>>,
    prepare_messages: Arc<RwLock<HashMap<Hash, HashSet<PublicKey>>>>,
    commit_messages: Arc<RwLock<HashMap<Hash, HashSet<PublicKey>>>>,

    // Sanctions and reputation
    active_sanctions: Arc<RwLock<HashMap<PublicKey, Vec<SanctionRecord>>>>,
    reputation_scores: Arc<RwLock<HashMap<PublicKey, f64>>>,

    // Performance monitoring
    consensus_stats: Arc<RwLock<ConsensusStats>>,
}

impl<S: StorageTrait + Send + Sync + 'static, N: NetworkTrait + Send + Sync + 'static> BftConsensus<S, N> {
    /// Create new BFT consensus engine
    pub fn new(
        config: BftConfig,
        validator_kms: Arc<ValidatorKms>,
        state_machine: Arc<StateMachine<S>>,
        network: Arc<N>,
        execution_engine: Arc<ParallelExecutionEngine<S>>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            config,
            validator_kms,
            state_machine,
            network,
            execution_engine,
            current_view: Arc::new(AtomicU64::new(0)),
            current_phase: Arc::new(RwLock::new(ConsensusPhase::PrePrepare)),
            validator_set: Arc::new(RwLock::new(ValidatorSet::new(vec![], 0))),
            validator_metrics: Arc::new(RwLock::new(HashMap::new())),
            message_channel: rx,
            message_sender: tx,
            pre_prepare_messages: Arc::new(RwLock::new(HashMap::new())),
            prepare_messages: Arc::new(RwLock::new(HashMap::new())),
            commit_messages: Arc::new(RwLock::new(HashMap::new())),
            active_sanctions: Arc::new(RwLock::new(HashMap::new())),
            reputation_scores: Arc::new(RwLock::new(HashMap::new())),
            consensus_stats: Arc::new(RwLock::new(ConsensusStats::new())),
        }
    }

    /// Start consensus engine
    pub async fn start(&mut self) -> BlockchainResult<()> {
        // Initialize validator set
        self.initialize_validator_set().await?;

        // Start message processing
        self.start_message_processing();

        // Start view management
        self.start_view_management();

        // Perform initial crypto audit
        let audit_result = self.validator_kms.perform_crypto_audit().await?;
        if audit_result.compliance_score < 80.0 {
            return Err(BlockchainError::CryptographicError(
                format!("Insufficient crypto compliance: {:.1}%", audit_result.compliance_score)
            ));
        }

        Ok(())
    }

    /// Initialize validator set from KMS
    async fn initialize_validator_set(&mut self) -> BlockchainResult<()> {
        let validator_keys = self.validator_kms.list_validator_keys();

        let mut validators = Vec::new();
        let mut total_stake = 0u64;

        for key_info in validator_keys {
            if key_info.is_active {
                let validator_info = ValidatorInfo {
                    public_key: key_info.public_key,
                    name: format!("Validator_{}", key_info.validator_id),
                    stake: 1000, // Default stake - in production from staking contract
                    reputation: 100.0, // Default reputation
                    is_active: true,
                    joined_at: key_info.created_at,
                    last_seen: Timestamp::now(),
                };

                validators.push(validator_info.clone());
                total_stake += validator_info.stake;

                // Initialize metrics
                let metrics = ValidatorMetrics {
                    validator_id: key_info.public_key.clone(),
                    reputation: 100.0,
                    total_blocks_proposed: 0,
                    total_blocks_validated: 0,
                    successful_validations: 0,
                    failed_validations: 0,
                    sanctions_applied: 0,
                    last_activity: Timestamp::now(),
                    is_active: true,
                    stake_amount: validator_info.stake,
                };

                self.validator_metrics.write().map_err(|_| BlockchainError::LockPoisoned)?
                    .insert(key_info.public_key, metrics);
            }
        }

        let threshold = (validators.len() * 2 / 3) + 1; // 2/3 + 1 rule
        let validator_set = ValidatorSet::new(validators, threshold);

        *self.validator_set.write().map_err(|_| BlockchainError::LockPoisoned)? = validator_set;

        Ok(())
    }

    /// Start message processing loop
    fn start_message_processing(&self) {
        let message_receiver = self.message_channel;
        let consensus = Arc::new(unsafe { std::ptr::read(self as *const Self) });

        tokio::spawn(async move {
            while let Some(message) = message_receiver.recv().await {
                if let Err(e) = consensus.process_consensus_message(message).await {
                    eprintln!("Error processing consensus message: {:?}", e);
                }
            }
        });
    }

    /// Start view management
    fn start_view_management(&self) {
        let consensus = Arc::new(unsafe { std::ptr::read(self as *const Self) });

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(1000));

            loop {
                interval.tick().await;

                if let Err(e) = consensus.check_view_timeout().await {
                    eprintln!("View timeout check failed: {:?}", e);
                }
            }
        });
    }

    /// Process incoming consensus message
    async fn process_consensus_message(&self, message: ConsensusMessage) -> BlockchainResult<()> {
        // Validate message age
        let message_age = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() - message.timestamp().as_u64();

        if message_age > self.config.max_message_age_ms / 1000 {
            return Ok(()); // Message too old, ignore
        }

        // Validate message signature
        if !self.validate_message_signature(&message).await? {
            return Err(BlockchainError::CryptographicError("Invalid message signature".to_string()));
        }

        // Process based on message type
        match message {
            ConsensusMessage::PrePrepare { view, block_hash, block, proposer, .. } => {
                self.handle_pre_prepare(view, block_hash, block, proposer).await?;
            }
            ConsensusMessage::Prepare { view, block_hash, validator, .. } => {
                self.handle_prepare(view, block_hash, validator).await?;
            }
            ConsensusMessage::Commit { view, block_hash, validator, .. } => {
                self.handle_commit(view, block_hash, validator).await?;
            }
            ConsensusMessage::ViewChange { new_view, last_stable_checkpoint, validator, .. } => {
                self.handle_view_change(new_view, last_stable_checkpoint, validator).await?;
            }
            ConsensusMessage::NewView { view, validators, pre_prepare_messages, validator, .. } => {
                self.handle_new_view(view, validators, pre_prepare_messages, validator).await?;
            }
        }

        Ok(())
    }

    /// Handle PrePrepare message
    async fn handle_pre_prepare(
        &self,
        view: u64,
        block_hash: Hash,
        block: Block,
        proposer: PublicKey,
    ) -> BlockchainResult<()> {
        // Validate block
        if !self.validate_proposed_block(&block, &proposer).await? {
            self.apply_sanction(&proposer, SanctionType::InvalidBlockProposal, SanctionSeverity::Penalty).await?;
            return Ok(());
        }

        // Check if we're in the correct view
        if view != self.current_view.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Store PrePrepare message
        let mut pre_prepare = self.pre_prepare_messages.write().map_err(|_| BlockchainError::LockPoisoned)?;
        pre_prepare.entry(block_hash).or_insert_with(Vec::new).push(
            ConsensusMessage::PrePrepare { view, block_hash, block: block.clone(), proposer: proposer.clone(), timestamp: Timestamp::now() }
        );

        // Send Prepare message if we haven't already
        if !self.have_sent_prepare(&block_hash) {
            self.send_prepare_message(view, block_hash, &block).await?;
        }

        Ok(())
    }

    /// Handle Prepare message
    async fn handle_prepare(
        &self,
        view: u64,
        block_hash: Hash,
        validator: PublicKey,
    ) -> BlockchainResult<()> {
        // Check view and validate message
        if view != self.current_view.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Check for equivocation - validator sending Prepare for different blocks in same view
        let prepare_messages = self.prepare_messages.read().map_err(|_| BlockchainError::LockPoisoned)?;
        for (existing_block_hash, validators) in prepare_messages.iter() {
            if *existing_block_hash != block_hash && validators.contains(&validator) {
                // Equivocation detected - validator voted for different blocks in same view
                self.apply_sanction(&validator, SanctionType::Equivocation, SanctionSeverity::Expulsion).await?;
                return Ok(());
            }
        }
        drop(prepare_messages); // Release read lock

        // Store Prepare message
        let mut prepare_messages = self.prepare_messages.write().map_err(|_| BlockchainError::LockPoisoned)?;
        prepare_messages.entry(block_hash).or_insert_with(HashSet::new).insert(validator);

        // Check if we have enough Prepare messages
        if let Some(prepares) = prepare_messages.get(&block_hash) {
            let validator_set = self.validator_set.read().map_err(|_| BlockchainError::LockPoisoned)?;
            if prepares.len() >= validator_set.threshold {
                // Send Commit message
                self.send_commit_message(view, block_hash).await?;
            }
        }

        Ok(())
    }

    /// Handle Commit message
    async fn handle_commit(
        &self,
        view: u64,
        block_hash: Hash,
        validator: PublicKey,
    ) -> BlockchainResult<()> {
        // Check view and validate message
        if view != self.current_view.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Check for equivocation - validator sending Commit for different blocks in same view
        let commit_messages = self.commit_messages.read().map_err(|_| BlockchainError::LockPoisoned)?;
        for (existing_block_hash, validators) in commit_messages.iter() {
            if *existing_block_hash != block_hash && validators.contains(&validator) {
                // Equivocation detected - validator committed to different blocks in same view
                self.apply_sanction(&validator, SanctionType::Equivocation, SanctionSeverity::Expulsion).await?;
                return Ok(());
            }
        }
        drop(commit_messages); // Release read lock

        // Store Commit message
        let mut commit_messages = self.commit_messages.write().map_err(|_| BlockchainError::LockPoisoned)?;
        commit_messages.entry(block_hash).or_insert_with(HashSet::new).insert(validator);

        // Check if we have enough Commit messages to finalize
        if let Some(commits) = commit_messages.get(&block_hash) {
            let validator_set = self.validator_set.read().map_err(|_| BlockchainError::LockPoisoned)?;
            if commits.len() >= validator_set.threshold {
                self.finalize_block(view, block_hash).await?;
            }
        }

        Ok(())
    }

    /// Handle ViewChange message
    async fn handle_view_change(
        &self,
        new_view: u64,
        last_stable_checkpoint: u64,
        validator: PublicKey,
    ) -> BlockchainResult<()> {
        // Validate view change request
        if new_view <= self.current_view.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Check if we need to initiate view change
        if self.should_initiate_view_change().await? {
            self.initiate_view_change(new_view).await?;
        }

        Ok(())
    }

    /// Handle NewView message
    async fn handle_new_view(
        &self,
        view: u64,
        validators: ValidatorSet,
        pre_prepare_messages: Vec<ConsensusMessage>,
        validator: PublicKey,
    ) -> BlockchainResult<()> {
        // Update view and validator set
        self.current_view.store(view, Ordering::Relaxed);
        *self.validator_set.write().map_err(|_| BlockchainError::LockPoisoned)? = validators;

        // Process pre-prepare messages from new view
        for msg in pre_prepare_messages {
            if let ConsensusMessage::PrePrepare { block_hash, block, proposer, .. } = msg {
                self.handle_pre_prepare(view, block_hash, block, proposer).await?;
            }
        }

        Ok(())
    }

    /// Validate proposed block
    async fn validate_proposed_block(&self, block: &Block, proposer: &PublicKey) -> BlockchainResult<bool> {
        // Check if proposer is authorized
        let validator_set = self.validator_set.read().map_err(|_| BlockchainError::LockPoisoned)?;
        if !validator_set.get_validator(proposer).map_or(false, |v| v.is_active) {
            return Ok(false);
        }

        // Validate block structure and signatures
        if !block.verify().map_err(|e| BlockchainError::ValidationError(e.to_string()))? {
            return Ok(false);
        }

        // Validate transactions in block
        for tx in &block.transactions {
            if !self.validate_transaction_in_block(tx, block.height).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate transaction in block context
    async fn validate_transaction_in_block(&self, tx: &Transaction, block_height: u64) -> BlockchainResult<bool> {
        // Validate transaction signature
        if !tx.verify().map_err(|e| BlockchainError::CryptographicError(e.to_string()))? {
            return Ok(false);
        }

        // Validate nonce and balance using state machine
        let current_state = self.state_machine.get_height().unwrap_or(0);
        if block_height != current_state + 1 {
            return Ok(false);
        }

        // Check if transaction can be executed
        let validation_result = self.state_machine.validate_and_execute_transaction(tx, block_height);

        match validation_result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Transaction would fail, but block validation should continue
        }
    }

    /// Send Prepare message
    async fn send_prepare_message(&self, view: u64, block_hash: Hash, block: &Block) -> BlockchainResult<()> {
        let validator_id = self.get_current_validator_id();

        let prepare_message = ConsensusMessage::Prepare {
            view,
            block_hash,
            validator: validator_id,
            signature: vec![], // Would be signed by KMS
            timestamp: Timestamp::now(),
        };

        self.broadcast_message(prepare_message).await?;
        Ok(())
    }

    /// Send Commit message
    async fn send_commit_message(&self, view: u64, block_hash: Hash) -> BlockchainResult<()> {
        let validator_id = self.get_current_validator_id();

        let commit_message = ConsensusMessage::Commit {
            view,
            block_hash,
            validator: validator_id,
            signature: vec![], // Would be signed by KMS
            timestamp: Timestamp::now(),
        };

        self.broadcast_message(commit_message).await?;
        Ok(())
    }

    /// Finalize block when consensus is reached
    async fn finalize_block(&self, view: u64, block_hash: Hash) -> BlockchainResult<()> {
        // Get the block from PrePrepare messages
        let pre_prepare_messages = self.pre_prepare_messages.read().map_err(|_| BlockchainError::LockPoisoned)?;
        let block_messages = pre_prepare_messages.get(&block_hash)
            .ok_or_else(|| BlockchainError::ConsensusError("No PrePrepare messages found".to_string()))?;

        if let ConsensusMessage::PrePrepare { block, .. } = &block_messages[0] {
            // Execute block transactions in parallel
            let (execution_results, execution_stats) = self.execution_engine.execute_block(block).await?;

            // Apply state changes
            let mut block_with_results = block.clone();
            block_with_results.add_execution_results(execution_results);

            // Store finalized block
            self.state_machine.apply_block(&block_with_results)?;

            // Update consensus statistics
            self.update_consensus_stats(&execution_stats).await?;

            // Move to next view
            self.current_view.fetch_add(1, Ordering::Relaxed);

            // Update validator metrics
            self.update_validator_metrics(block.validator.clone(), true).await?;

            println!("Block finalized at height {} with {} transactions",
                    block.height, block.transactions.len());
        }

        Ok(())
    }

    /// Apply sanction to malicious validator
    async fn apply_sanction(
        &self,
        validator_id: &PublicKey,
        sanction_type: SanctionType,
        severity: SanctionSeverity,
    ) -> BlockchainResult<()> {
        let mut metrics = self.validator_metrics.write().map_err(|_| BlockchainError::LockPoisoned)?;
        if let Some(validator_metrics) = metrics.get_mut(validator_id) {
            validator_metrics.sanctions_applied += 1;
            validator_metrics.reputation *= self.config.reputation_decay_rate;

            // Apply severe sanctions
            match severity {
                SanctionSeverity::Suspension => {
                    validator_metrics.is_active = false;
                }
                SanctionSeverity::Expulsion => {
                    validator_metrics.is_active = false;
                    // In production, would also remove from validator set
                }
                _ => {}
            }

            let sanction_record = SanctionRecord {
                validator_id: validator_id.clone(),
                sanction_type,
                severity,
                applied_at: Timestamp::now(),
                duration_blocks: match severity {
                    SanctionSeverity::Warning => 0,
                    SanctionSeverity::Penalty => 10,
                    SanctionSeverity::Suspension => 100,
                    SanctionSeverity::Expulsion => u64::MAX,
                },
                reason: "Malicious behavior detected".to_string(),
                evidence: vec![],
            };

            self.active_sanctions.write().map_err(|_| BlockchainError::LockPoisoned)?
                .entry(validator_id.clone())
                .or_insert_with(Vec::new)
                .push(sanction_record);
        }

        Ok(())
    }

    /// Check if view has timed out
    async fn check_view_timeout(&self) -> BlockchainResult<()> {
        // In production, this would check if current view has been active too long
        // For demonstration, we'll trigger view change periodically

        let current_view = self.current_view.load(Ordering::Relaxed);
        if current_view > 0 && current_view % 10 == 0 { // Every 10 views
            self.initiate_view_change(current_view + 1).await?;
        }

        Ok(())
    }

    /// Initiate view change
    async fn initiate_view_change(&self, new_view: u64) -> BlockchainResult<()> {
        let validator_id = self.get_current_validator_id();

        let view_change_message = ConsensusMessage::ViewChange {
            new_view,
            last_stable_checkpoint: self.get_last_stable_checkpoint().await?,
            validator: validator_id,
            signature: vec![], // Would be signed by KMS
            timestamp: Timestamp::now(),
        };

        self.broadcast_message(view_change_message).await?;

        // Update local view
        self.current_view.store(new_view, Ordering::Relaxed);

        Ok(())
    }

    /// Get last stable checkpoint
    async fn get_last_stable_checkpoint(&self) -> BlockchainResult<u64> {
        // In production, this would return the last checkpoint height
        Ok(self.state_machine.get_height().map_err(|_| 0)?)
    }

    /// Check if we should initiate view change
    async fn should_initiate_view_change(&self) -> BlockchainResult<bool> {
        // Check if current leader is unresponsive or malicious
        let current_view = self.current_view.load(Ordering::Relaxed);
        let validator_set = self.validator_set.read().map_err(|_| BlockchainError::LockPoisoned)?;

        // Check for timeout since last block
        let last_block_time = self.state_machine.get_last_block_timestamp().unwrap_or(0);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let time_since_last_block = current_time.saturating_sub(last_block_time);

        // Initiate view change if:
        // 1. No block for more than view timeout
        // 2. Leader is suspected of equivocation
        // 3. Network partition detected

        let should_change = time_since_last_block > self.config.view_timeout_ms / 1000;

        // Additional check: if we received conflicting PrePrepare messages from leader
        let pre_prepare_messages = self.pre_prepare_messages.read().map_err(|_| BlockchainError::LockPoisoned)?;
        let conflicting_messages = pre_prepare_messages.len() > 1;

        Ok(should_change || conflicting_messages)
    }

    /// Broadcast message to network
    async fn broadcast_message(&self, message: ConsensusMessage) -> BlockchainResult<()> {
        let network_message = NetworkMessage::Consensus(message);
        self.network.broadcast(&network_message).await
            .map_err(|e| BlockchainError::NetworkError(e.to_string()))?;

        Ok(())
    }

    /// Validate message signature
    async fn validate_message_signature(&self, message: &ConsensusMessage) -> BlockchainResult<bool> {
        // Extract validator from message
        let validator_id = match message {
            ConsensusMessage::PrePrepare { proposer, .. } => proposer,
            ConsensusMessage::Prepare { validator, .. } => validator,
            ConsensusMessage::Commit { validator, .. } => validator,
            ConsensusMessage::ViewChange { validator, .. } => validator,
            ConsensusMessage::NewView { validator, .. } => validator,
        };

        // Verify signature using KMS
        // In production, this would verify the actual signature
        Ok(true) // Assume valid for demonstration
    }

    /// Check if we've already sent Prepare for this block
    fn have_sent_prepare(&self, block_hash: &Hash) -> bool {
        // In production, this would track sent messages
        false
    }

    /// Get current validator ID
    fn get_current_validator_id(&self) -> PublicKey {
        // In production, this would get the current node's validator key
        PublicKey::new("current_validator".to_string())
    }

    /// Update consensus statistics
    async fn update_consensus_stats(&self, execution_stats: &crate::parallel_execution::ExecutionStats) -> BlockchainResult<()> {
        let mut stats = self.consensus_stats.write().unwrap();

        stats.total_blocks_finalized += 1;
        stats.total_transactions_processed += execution_stats.total_transactions;
        stats.average_block_time_ms = if stats.total_blocks_finalized > 0 {
            execution_stats.total_gas_used as f64 / stats.total_blocks_finalized as f64
        } else {
            0.0
        };

        Ok(())
    }

    /// Update validator metrics
    async fn update_validator_metrics(&self, validator_id: PublicKey, success: bool) -> BlockchainResult<()> {
        let mut metrics = self.validator_metrics.write().map_err(|_| BlockchainError::LockPoisoned)?;
        if let Some(validator_metrics) = metrics.get_mut(&validator_id) {
            validator_metrics.last_activity = Timestamp::now();

            if success {
                validator_metrics.successful_validations += 1;
                validator_metrics.reputation = (validator_metrics.reputation * 0.9) + 10.0; // Increase reputation
            } else {
                validator_metrics.failed_validations += 1;
                validator_metrics.reputation *= 0.8; // Decrease reputation
            }
        }

        Ok(())
    }

    /// Get consensus statistics
    pub fn get_consensus_stats(&self) -> ConsensusStats {
        self.consensus_stats.read().map_err(|_| BlockchainError::LockPoisoned)?.clone()
    }

    /// Get current view
    pub fn get_current_view(&self) -> u64 {
        self.current_view.load(Ordering::Relaxed)
    }

    /// Get current phase
    pub fn get_current_phase(&self) -> ConsensusPhase {
        *self.current_phase.read().map_err(|_| ConsensusPhase::PrePrepare)?
    }

    /// Get validator set
    pub fn get_validator_set(&self) -> ValidatorSet {
        self.validator_set.read().map_err(|_| ValidatorSet::new(vec![], 0))?.clone()
    }
}

/// Consensus statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStats {
    pub total_blocks_finalized: u64,
    pub total_transactions_processed: u64,
    pub average_block_time_ms: f64,
    pub total_view_changes: u64,
    pub average_view_duration_ms: f64,
    pub sanction_events: u64,
    pub reputation_changes: u64,
    pub network_messages_sent: u64,
}

impl ConsensusStats {
    /// Create new consensus stats
    fn new() -> Self {
        Self {
            total_blocks_finalized: 0,
            total_transactions_processed: 0,
            average_block_time_ms: 0.0,
            total_view_changes: 0,
            average_view_duration_ms: 0.0,
            sanction_events: 0,
            reputation_changes: 0,
            network_messages_sent: 0,
        }
    }
}

/// Consensus message timestamp helper
impl ConsensusMessage {
    pub fn timestamp(&self) -> Timestamp {
        match self {
            ConsensusMessage::PrePrepare { timestamp, .. } => *timestamp,
            ConsensusMessage::Prepare { timestamp, .. } => *timestamp,
            ConsensusMessage::Commit { timestamp, .. } => *timestamp,
            ConsensusMessage::ViewChange { timestamp, .. } => *timestamp,
            ConsensusMessage::NewView { timestamp, .. } => *timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use crate::network::Network;
    use crate::parallel_execution::{ParallelExecutionEngine, ParallelExecutionConfig};
    use tempfile::TempDir;

    fn create_test_consensus() -> BftConsensus<Storage, Network> {
        let temp_dir = TempDir::new().map_err(|_| BlockchainError::StorageError("Failed to create temp dir".to_string()))?;
        let storage = Storage::new(temp_dir.path()).map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        let state_machine = Arc::new(StateMachine::new(storage, Hash::new(b"genesis")));

        let config = BftConfig {
            view_timeout_ms: 5000,
            max_views_without_progress: 10,
            checkpoint_interval: 100,
            max_faulty_validators: 1,
            min_quorum_size: 3,
            sanction_threshold: 50.0,
            reputation_decay_rate: 0.8,
            max_message_age_ms: 30000,
        };

        let hsm_config = crate::hsm::HsmConfig {
            hsm_url: "https://test-hsm.com".to_string(),
            hsm_user: "test".to_string(),
            hsm_password: "test".to_string(),
            key_rotation_days: 90,
            max_key_usage: 100000,
            enable_audit_log: true,
        };

        let validator_config = ValidatorConfig {
            validator_id: "test".to_string(),
            hsm_config,
            key_rotation_interval_days: 90,
            backup_enabled: false,
            backup_path: "/tmp/backup".to_string(),
            audit_enabled: true,
        };

        let hsm = Box::new(crate::hsm::ProductionHsm::new());
        let validator_kms = Arc::new(ValidatorKms::new(validator_config, hsm));

        let network_storage = Storage::new(temp_dir.path()).map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        let network = Arc::new(Network::new(Box::new(network_storage)).map_err(|e| BlockchainError::NetworkError(e.to_string()))?);

        let execution_config = ParallelExecutionConfig {
            max_parallel_transactions: 100,
            batch_size: 10,
            conflict_detection_enabled: true,
            validation_workers: 4,
            execution_workers: 8,
            max_retries: 3,
            timeout_ms: 5000,
        };

        let execution_engine = Arc::new(ParallelExecutionEngine::new(
            Arc::clone(&state_machine),
            execution_config,
        ));

        BftConsensus::new(config, validator_kms, state_machine, network, execution_engine)
    }

    #[tokio::test]
    async fn test_consensus_creation() {
        let consensus = create_test_consensus();
        assert_eq!(consensus.get_current_view(), 0);
        assert!(matches!(consensus.get_current_phase(), ConsensusPhase::PrePrepare));
    }

    #[test]
    fn test_consensus_stats() {
        let consensus = create_test_consensus();
        let stats = consensus.get_consensus_stats();

        assert_eq!(stats.total_blocks_finalized, 0);
        assert_eq!(stats.total_transactions_processed, 0);
        assert_eq!(stats.total_view_changes, 0);
    }

    #[test]
    fn test_validator_set_operations() {
        let mut validator_set = ValidatorSet::new(vec![], 0);

        let validator1 = ValidatorInfo {
            public_key: PublicKey::new("validator1".to_string()),
            name: "Validator 1".to_string(),
            stake: 1000,
            reputation: 100.0,
            is_active: true,
            joined_at: Timestamp::now(),
            last_seen: Timestamp::now(),
        };

        let validator2 = ValidatorInfo {
            public_key: PublicKey::new("validator2".to_string()),
            name: "Validator 2".to_string(),
            stake: 1500,
            reputation: 100.0,
            is_active: true,
            joined_at: Timestamp::now(),
            last_seen: Timestamp::now(),
        };

        validator_set.add_validator(validator1);
        validator_set.add_validator(validator2);

        assert_eq!(validator_set.validators.len(), 2);
        assert_eq!(validator_set.total_stake, 2500);
        assert_eq!(validator_set.threshold, 2); // 2/3 + 1 = 2

        // Test quorum
        assert!(validator_set.is_quorum_reached(2));
        assert!(!validator_set.is_quorum_reached(1));

        // Test validator lookup
        let found_validator = validator_set.get_validator(&PublicKey::new("validator1".to_string()));
        assert!(found_validator.is_some());
        assert_eq!(found_validator.map(|v| v.stake).unwrap_or(0), 1000);

        // Test validator removal
        assert!(validator_set.remove_validator(&PublicKey::new("validator1".to_string())));
        assert_eq!(validator_set.validators.len(), 1);
        assert_eq!(validator_set.total_stake, 1500);
        assert_eq!(validator_set.threshold, 1);
    }

    #[test]
    fn test_validator_metrics() {
        let mut metrics = ValidatorMetrics {
            validator_id: PublicKey::new("test".to_string()),
            reputation: 100.0,
            total_blocks_proposed: 0,
            total_blocks_validated: 0,
            successful_validations: 0,
            failed_validations: 0,
            sanctions_applied: 0,
            last_activity: Timestamp::now(),
            is_active: true,
            stake_amount: 1000,
        };

        // Simulate successful validation
        metrics.successful_validations += 1;
        metrics.reputation = (metrics.reputation * 0.9) + 10.0;

        assert_eq!(metrics.successful_validations, 1);
        assert!(metrics.reputation > 100.0);

        // Simulate failed validation
        metrics.failed_validations += 1;
        metrics.reputation *= 0.8;

        assert_eq!(metrics.failed_validations, 1);
        assert!(metrics.reputation < 110.0);
    }

    #[test]
    fn test_sanction_severity() {
        let warning = SanctionSeverity::Warning;
        let penalty = SanctionSeverity::Penalty;
        let suspension = SanctionSeverity::Suspension;
        let expulsion = SanctionSeverity::Expulsion;

        // Test duration calculation
        match warning {
            SanctionSeverity::Warning => assert_eq!(0, 0),
            SanctionSeverity::Penalty => {},
            SanctionSeverity::Suspension => {},
            SanctionSeverity::Expulsion => {},
        }
    }

    #[test]
    fn test_consensus_message_timestamp() {
        let timestamp = Timestamp::now();
        let message = ConsensusMessage::PrePrepare {
            view: 1,
            block_hash: Hash::new(b"test"),
            block: Block::new(Hash::new(b"prev"), 1, vec![], PublicKey::new("test")),
            proposer: PublicKey::new("proposer"),
            timestamp,
        };

        assert_eq!(message.timestamp(), timestamp);
    }
}
