use std::collections::{HashMap, HashSet, BinaryHeap};
use async_trait::async_trait;
use crate::types::{Transaction, Hash};
use crate::mempool::MempoolTrait;

/// Wrapper for prioritizing transactions in BinaryHeap (higher fee first, then earlier timestamp)
#[derive(Debug, Clone, Eq)]
struct PriorityTx(pub Transaction);

impl Ord for PriorityTx {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.fee.cmp(&other.0.fee)
            .then_with(|| other.0.timestamp.cmp(&self.0.timestamp)) // earlier timestamp wins when fee equal
    }
}

impl PartialOrd for PriorityTx {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PriorityTx {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

/// Mempool Block - пакет транзакций для параллельной обработки
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MempoolBlock {
    pub id: Hash,
    pub transactions: Vec<crate::types::Transaction>,
    pub timestamp: u64,
    pub worker_id: crate::types::PublicKey,
    pub batch_size: usize,
}

/// Certificate of Availability - доказательство доступности Mempool Block
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Certificate {
    pub id: Hash,
    pub mempool_block_hash: Hash,
    pub validator: crate::types::PublicKey,
    pub signature: Vec<u8>,
    pub round: u64,
    pub timestamp: u64,
}

/// Sanctions record for Byzantine nodes
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SanctionRecord {
    pub validator: crate::types::PublicKey,
    pub violation_type: ViolationType,
    pub timestamp: u64,
    pub evidence: Vec<u8>,
    pub penalty_score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ViolationType {
    DoubleSpending,
    InvalidTransaction,
    ConsensusViolation,
    NetworkMisbehavior,
    TimeoutViolation,
}

/// DAG Vertex representing a Mempool Block in the DAG structure
#[derive(Debug, Clone)]
pub struct DagVertex {
    pub mempool_block_hash: Hash,
    pub mempool_block: MempoolBlock,
    pub certificates: Vec<Certificate>,
    pub parents: Vec<Hash>,
    pub children: Vec<Hash>,
    pub round: u64,
    pub timestamp: u64,
    pub confidence_score: f64, // 0.0 to 1.0 based on certificate count
}

/// Wave structure for DAG ordering
#[derive(Debug, Clone)]
pub struct Wave {
    pub round: u64,
    pub vertices: Vec<DagVertex>,
}

/// Smart DAG-based mempool with Narwhal-inspired design and sanctions
pub struct SmartDagMempool {
    // Core DAG structure
    vertices: HashMap<Hash, DagVertex>,
    mempool_blocks: HashMap<Hash, MempoolBlock>,

    // Transaction management (priority by fee desc, then timestamp)
    pending_transactions: BinaryHeap<PriorityTx>,
    processed_transactions: HashSet<Hash>,

    // Certificate management
    certificates: HashMap<Hash, Vec<Certificate>>,
    seen_certificates: HashSet<Hash>,

    // Sanctions system
    sanctions: HashMap<crate::types::PublicKey, SanctionRecord>,
    validator_scores: HashMap<crate::types::PublicKey, i64>,

    // Network state
    validators: Vec<crate::types::PublicKey>,
    f_tolerance: usize,

    // Performance tuning
    max_batch_size: usize,
    min_certificates_required: usize,
    round_duration_ms: u64,
    current_round: u64,

    // Statistics
    stats: DagStats,
}

/// Statistics for DAG operations
#[derive(Debug, Clone, Default)]
pub struct DagStats {
    pub total_mempool_blocks: usize,
    pub total_certificates: usize,
    pub total_sanctions: usize,
    pub average_batch_size: f64,
    pub average_latency_ms: f64,
    pub confidence_threshold: f64,
}

impl SmartDagMempool {
    /// Peek top-N pending transactions without removing them
    pub fn peek_pending_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut heap_clone = self.pending_transactions.clone();
        let mut result = Vec::new();
        for _ in 0..limit {
            if let Some(ptx) = heap_clone.pop() {
                result.push(ptx.0);
            } else {
                break;
            }
        }
        result
    }

    /// Pop top-N pending transactions (remove from heap)
    fn pop_pending_transactions(&mut self, limit: usize) -> Vec<Transaction> {
        let mut result = Vec::new();
        for _ in 0..limit {
            if let Some(ptx) = self.pending_transactions.pop() {
                result.push(ptx.0);
            } else {
                break;
            }
        }
        result
    }

    pub fn new(validators: Vec<crate::types::PublicKey>, max_batch_size: usize) -> Self {
        let n = validators.len();
        let f = (n - 1) / 3; // BFT fault tolerance

        Self {
            vertices: HashMap::new(),
            mempool_blocks: HashMap::new(),
            pending_transactions: BinaryHeap::new(),
            processed_transactions: HashSet::new(),
            certificates: HashMap::new(),
            seen_certificates: HashSet::new(),
            sanctions: HashMap::new(),
            validator_scores: validators.iter().map(|v| (v.clone(), 1000)).collect(), // Start with score 1000
            validators,
            f_tolerance: f,
            max_batch_size,
            min_certificates_required: 2 * f + 1, // 2f + 1 for BFT quorum
            round_duration_ms: 1000, // 1 second rounds
            current_round: 0,
            stats: DagStats::default(),
        }
    }

    /// Create a new Mempool Block from pending transactions
    pub async fn create_mempool_block(&mut self, worker_id: &crate::types::PublicKey) -> Result<MempoolBlock, Box<dyn std::error::Error>> {
        // Get batch of transactions
        let batch_size = std::cmp::min(self.max_batch_size, self.pending_transactions.len());
        if batch_size == 0 {
            return Err("No pending transactions".into());
        }

        let mut transactions = Vec::new();
        for _ in 0..batch_size {
            if let Some(priority_tx) = self.pending_transactions.pop() {
                let tx = priority_tx.0;
                if !self.processed_transactions.contains(&tx.id) {
                    transactions.push(tx.clone());
                    self.processed_transactions.insert(tx.id);
                }
            }
        }

        if transactions.is_empty() {
            return Err("No valid transactions".into());
        }

        // Create Mempool Block
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let block_data = format!("{}{}{}", worker_id.as_str(), timestamp, transactions.len());
        let block_hash = Hash::new(block_data.as_bytes());

        let mempool_block = MempoolBlock {
            id: block_hash,
            transactions,
            timestamp,
            worker_id: worker_id.clone(),
            batch_size: transactions.len(),
        };

        // Store Mempool Block
        self.mempool_blocks.insert(block_hash, mempool_block.clone());

        // Update statistics
        self.stats.total_mempool_blocks += 1;
        self.stats.average_batch_size = (self.stats.average_batch_size + batch_size as f64) / 2.0;

        log::info!("Created Mempool Block {} with {} transactions by worker {}",
            block_hash.as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
            batch_size,
            worker_id.as_str()
        );

        Ok(mempool_block)
    }

    /// Add certificate for a Mempool Block
    pub async fn add_certificate(&mut self, certificate: Certificate) -> Result<(), Box<dyn std::error::Error>> {
        // Check if certificate already seen
        if self.seen_certificates.contains(&certificate.id) {
            return Err("Certificate already processed".into());
        }

        // Validate certificate
        self.validate_certificate(&certificate).await?;

        // Check if Mempool Block exists
        if !self.mempool_blocks.contains_key(&certificate.mempool_block_hash) {
            return Err("Mempool Block not found".into());
        }

        // Add certificate
        self.certificates.entry(certificate.mempool_block_hash)
            .or_insert_with(Vec::new)
            .push(certificate.clone());

        self.seen_certificates.insert(certificate.id);
        self.stats.total_certificates += 1;

        // Check if we have enough certificates for consensus
        let cert_count = self.certificates[&certificate.mempool_block_hash].len();
        if cert_count >= self.min_certificates_required {
            self.promote_to_dag_vertex(certificate.mempool_block_hash).await?;
        }

        log::debug!("Added certificate for Mempool Block {}, total certificates: {}",
            certificate.mempool_block_hash.as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
            cert_count
        );

        Ok(())
    }

    /// Promote Mempool Block to DAG vertex when enough certificates collected
    async fn promote_to_dag_vertex(&mut self, mempool_block_hash: Hash) -> Result<(), Box<dyn std::error::Error>> {
        let mempool_block = self.mempool_blocks[&mempool_block_hash].clone();
        let certificates = self.certificates[&mempool_block_hash].clone();

        let confidence_score = certificates.len() as f64 / self.validators.len() as f64;

        let vertex = DagVertex {
            mempool_block_hash: mempool_block_hash.clone(),
            mempool_block,
            certificates,
            parents: self.find_parents_for_vertex(&mempool_block_hash),
            children: vec![],
            round: self.current_round,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            confidence_score,
        };

        // Add to DAG
        self.vertices.insert(mempool_block_hash, vertex);

        log::info!("Promoted Mempool Block to DAG vertex with confidence {:.2f}",
            confidence_score
        );

        Ok(())
    }

    /// Add transaction to pending queue
    pub async fn add_transaction(&mut self, transaction: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        if self.processed_transactions.contains(&transaction.id) {
            return Err("Transaction already processed".into());
        }

        self.pending_transactions.push(PriorityTx(transaction));
        Ok(())
    }

    /// Get pending transactions count
    pub fn pending_transactions_count(&self) -> usize {
        self.pending_transactions.len()
    }

    /// Apply sanction to a validator
    pub async fn apply_sanction(&mut self, validator: &crate::types::PublicKey, violation: ViolationType, evidence: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let penalty_score = match violation {
            ViolationType::DoubleSpending => 500,
            ViolationType::InvalidTransaction => 200,
            ViolationType::ConsensusViolation => 300,
            ViolationType::NetworkMisbehavior => 100,
            ViolationType::TimeoutViolation => 50,
        };

        let sanction = SanctionRecord {
            validator: validator.clone(),
            violation_type: violation,
            timestamp,
            evidence,
            penalty_score,
        };

        // Apply penalty to validator score
        let current_score = self.validator_scores.get(validator).unwrap_or(&1000);
        let new_score = std::cmp::max(0, *current_score - penalty_score as i64);
        self.validator_scores.insert(validator.clone(), new_score);

        // Store sanction record
        self.sanctions.insert(validator.clone(), sanction);
        self.stats.total_sanctions += 1;

        log::warn!("Applied sanction to validator {} for violation {:?}, new score: {}",
            validator.as_str(),
            violation,
            new_score
        );

        Ok(())
    }

    /// Get validator reputation score
    pub fn get_validator_score(&self, validator: &crate::types::PublicKey) -> i64 {
        *self.validator_scores.get(validator).unwrap_or(&1000)
    }

    /// Get vertices ready for consensus ordering
    pub fn get_vertices_for_consensus(&self, round: u64) -> Vec<DagVertex> {
        self.vertices.values()
            .filter(|v| v.round == round)
            .cloned()
            .collect()
    }

    /// Get wave for a specific round
    pub fn get_wave(&self, round: u64) -> Option<Wave> {
        let vertices: Vec<DagVertex> = self.get_vertices_for_consensus(round);

        if vertices.is_empty() {
            None
        } else {
            Some(Wave { round, vertices })
        }
    }

    /// Find parents for a new vertex
    fn find_parents_for_vertex(&self, mempool_block_hash: &Hash) -> Vec<Hash> {
        // Simple parent selection: reference recent high-confidence vertices
        self.vertices.values()
            .filter(|v| v.confidence_score > 0.8 && v.mempool_block_hash != *mempool_block_hash)
            .take(3) // Limit to 3 parents for efficiency
            .map(|v| v.mempool_block_hash.clone())
            .collect()
    }

    /// Validate certificate
    async fn validate_certificate(&self, certificate: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
        // Check if validator is authorized
        if !self.validators.contains(&certificate.validator) {
            self.apply_sanction(&certificate.validator, ViolationType::ConsensusViolation, vec![]).await?;
            return Err("Unauthorized validator".into());
        }

        // Check validator reputation
        let score = self.get_validator_score(&certificate.validator);
        if score < 100 {
            return Err("Validator reputation too low".into());
        }

        // Check round validity
        if certificate.round > self.current_round + 1 {
            return Err("Certificate from future round".into());
        }

        // Basic signature validation (simplified for MVP)
        if certificate.signature.is_empty() {
            return Err("Invalid certificate signature".into());
        }
        
        // TODO: Implement full Ed25519 verification for certificates
        // For MVP, we do basic non-empty check

        Ok(())
    }

    /// Get current DAG state for debugging
    pub fn get_dag_stats(&self) -> DagStats {
        self.stats.clone()
    }

    /// Advance to next round
    pub fn advance_round(&mut self) {
        self.current_round += 1;
    }

    /// Clean up old data to save memory
    pub fn cleanup(&mut self) {
        // Remove old vertices (keep last 10 rounds)
        let cutoff_round = self.current_round.saturating_sub(10);
        self.vertices.retain(|_, v| v.round >= cutoff_round);

        // Remove old certificates
        self.certificates.retain(|hash, _| self.vertices.contains_key(hash));

        // Remove old sanctions (keep last 100)
        if self.sanctions.len() > 100 {
            let mut sanctions_vec: Vec<_> = self.sanctions.iter().collect();
            sanctions_vec.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp));
            sanctions_vec.truncate(100);
            self.sanctions = sanctions_vec.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        }
    }
}

#[async_trait]
impl MempoolTrait for SmartDagMempool {
    async fn add_transaction(&mut self, tx: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        SmartDagMempool::add_transaction(self, tx).await
    }

    async fn get_pending_transactions(&self, limit: usize) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        Ok(self.peek_pending_transactions(limit))
    }

    async fn remove_transaction(&mut self, hash: &Hash) -> Result<(), Box<dyn std::error::Error>> {
        // Rebuild heap without the specified tx
        let mut new_heap: BinaryHeap<PriorityTx> = self.pending_transactions
            .drain()
            .filter(|ptx| &ptx.0.id != hash)
            .collect();
        std::mem::swap(&mut self.pending_transactions, &mut new_heap);
        self.processed_transactions.remove(hash);
        Ok(())
    }

    async fn get_transaction_count(&self) -> usize {
        self.pending_transactions.len()
    }

    async fn clear(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.pending_transactions.clear();
        self.processed_transactions.clear();
        Ok(())
    }
}

/// Statistics about DAG state
#[derive(Debug, Clone)]
pub struct DagStats {
    pub total_vertices: usize,
    pub current_round: u64,
    pub pending_transactions: usize,
    pub seen_certificates: usize,
}

/// Certificate generation (would be done by validators)
pub struct CertificateGenerator;

impl CertificateGenerator {
    pub fn generate_certificate(
        block_hash: Hash,
        validator: crate::types::PublicKey,
        round: u64,
        parents: Vec<Hash>,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        let certificate_data = format!("cert_{}_{}", block_hash.as_bytes().iter().take(8).map(|b| format!("{:02x}", b)).collect::<String>(), round);
        let id = Hash::new(certificate_data.as_bytes());

        // Generate deterministic signature for MVP (not cryptographically secure)
        let signature = format!("cert_sig_{}_{}", 
            mempool_block_hash.as_bytes().iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
            validator.as_str()
        ).into_bytes();

        Ok(Certificate {
            id,
            block_hash,
            validator,
            signature,
            round,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PublicKey;

    #[tokio::test]
    async fn test_smart_dag_mempool_creation() {
        let validators = vec![
            PublicKey::new("validator_1".to_string()),
            PublicKey::new("validator_2".to_string()),
            PublicKey::new("validator_3".to_string()),
            PublicKey::new("validator_4".to_string()),
        ];

        let dag_mempool = SmartDagMempool::new(validators.clone(), 50);

        assert_eq!(dag_mempool.get_dag_stats().total_mempool_blocks, 0);
        assert_eq!(dag_mempool.f_tolerance, 1); // (4-1)/3 = 1
        assert_eq!(dag_mempool.min_certificates_required, 3); // 2*1 + 1 = 3
        assert_eq!(dag_mempool.validators.len(), 4);
    }

    #[tokio::test]
    async fn test_create_mempool_block() {
        let validators = vec![PublicKey::new("validator_1".to_string())];
        let mut dag_mempool = SmartDagMempool::new(validators.clone(), 50);

        // Add some transactions
        let tx1 = Transaction::new(
            PublicKey::new("alice".to_string()),
            PublicKey::new("bob".to_string()),
            100,
            1
        );
        let tx2 = Transaction::new(
            PublicKey::new("charlie".to_string()),
            PublicKey::new("diana".to_string()),
            50,
            2
        );

        dag_mempool.add_transaction(tx1).await.unwrap();
        dag_mempool.add_transaction(tx2).await.unwrap();

        assert_eq!(dag_mempool.pending_transactions_count(), 2);

        // Create Mempool Block
        let worker_id = &validators[0];
        let mempool_block = dag_mempool.create_mempool_block(worker_id).await.unwrap();

        assert_eq!(mempool_block.batch_size, 2);
        assert_eq!(mempool_block.worker_id, *worker_id);
        assert_eq!(dag_mempool.pending_transactions_count(), 0);
        assert_eq!(dag_mempool.get_dag_stats().total_mempool_blocks, 1);
    }

    #[tokio::test]
    async fn test_certificate_validation() {
        let validators = vec![
            PublicKey::new("validator_1".to_string()),
            PublicKey::new("validator_2".to_string()),
        ];
        let mut dag_mempool = SmartDagMempool::new(validators.clone(), 50);

        // Create Mempool Block first
        let worker_id = &validators[0];
        let mempool_block = dag_mempool.create_mempool_block(worker_id).await.unwrap();

        // Generate certificate
        let certificate = CertificateGenerator::generate_certificate(
            mempool_block.id,
            validators[0].clone(),
            0,
        ).unwrap();

        // Add certificate
        let result = dag_mempool.add_certificate(certificate).await;
        assert!(result.is_ok());

        assert_eq!(dag_mempool.get_dag_stats().total_certificates, 1);
    }

    #[tokio::test]
    async fn test_sanctions_system() {
        let validators = vec![
            PublicKey::new("validator_1".to_string()),
            PublicKey::new("validator_2".to_string()),
        ];
        let mut dag_mempool = SmartDagMempool::new(validators.clone(), 50);

        // Initial score
        assert_eq!(dag_mempool.get_validator_score(&validators[0]), 1000);

        // Apply sanction
        dag_mempool.apply_sanction(
            &validators[0],
            ViolationType::DoubleSpending,
            vec![1, 2, 3]
        ).await.unwrap();

        // Check penalty applied
        assert_eq!(dag_mempool.get_validator_score(&validators[0]), 500); // 1000 - 500
        assert_eq!(dag_mempool.get_dag_stats().total_sanctions, 1);
    }

    #[tokio::test]
    async fn test_unauthorized_validator() {
        let validators = vec![PublicKey::new("validator_1".to_string())];
        let mut dag_mempool = SmartDagMempool::new(validators.clone(), 50);

        // Create Mempool Block
        let worker_id = &validators[0];
        let mempool_block = dag_mempool.create_mempool_block(worker_id).await.unwrap();

        // Try to create certificate from unauthorized validator
        let unauthorized_validator = PublicKey::new("bad_validator".to_string());
        let certificate = CertificateGenerator::generate_certificate(
            mempool_block.id,
            unauthorized_validator,
            0,
        ).unwrap();

        // This should fail and apply sanction
        let result = dag_mempool.add_certificate(certificate).await;
        assert!(result.is_err());
    }
}
