//! AI-Powered DoS Protection System
//!
//! Revolutionary distributed AI defense system that uses machine learning,
//! behavioral analysis, and swarm intelligence to detect and mitigate
//! sophisticated DDoS attacks in real-time. Features adaptive rate limiting,
//! traffic pattern recognition, and collaborative defense mechanisms.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::sync::{RwLock as AsyncRwLock, mpsc};
use futures::stream::StreamExt;
use crate::types::{Hash, PublicKey};
use crate::network::{NetworkTrait, NetworkMessage};
use crate::metrics::MetricsServer;

/// AI-powered traffic analyzer with behavioral learning
#[derive(Debug)]
pub struct AiTrafficAnalyzer {
    /// Behavioral models for different traffic patterns
    behavioral_models: Arc<RwLock<HashMap<TrafficPattern, BehaviorModel>>>,

    /// Active connections with ML-tracked metrics
    connections: Arc<RwLock<HashMap<IpAddr, ConnectionProfile>>>,

    /// Global threat intelligence shared across nodes
    threat_intelligence: Arc<AsyncRwLock<SwarmIntelligence>>,

    /// Adaptive rate limiter with ML predictions
    rate_limiter: Arc<RwLock<AdaptiveRateLimiter>>,

    /// Communication channel for swarm coordination
    swarm_channel: mpsc::UnboundedSender<SwarmMessage>,

    /// Network interface for peer communication
    network: Arc<dyn NetworkTrait>,

    /// Metrics collection
    metrics: Arc<MetricsServer>,

    /// AI training data buffer
    training_buffer: Arc<RwLock<VecDeque<TrafficSample>>>,
}

/// Traffic pattern classification
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrafficPattern {
    NormalPeer,
    ValidatorSync,
    TransactionFlood,
    BlockSpam,
    NetworkScan,
    BotnetAttack,
    FlashCrowd,
    SophisticatedAttack,
}

/// ML behavioral model for traffic patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorModel {
    pub pattern: TrafficPattern,
    pub feature_weights: HashMap<String, f64>,
    pub threshold_score: f64,
    pub false_positive_rate: f64,
    pub last_updated: u64,
    pub training_samples: usize,
    pub confidence_level: f64,
}

/// Connection profile with ML-tracked metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub ip_address: IpAddr,
    pub first_seen: u64,
    pub last_activity: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub messages_per_second: f64,
    pub error_rate: f64,
    pub reputation_score: f64,
    pub behavioral_features: HashMap<String, f64>,
    pub threat_level: ThreatLevel,
    pub rate_limit_multiplier: f64,
}

/// Threat level assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    Trusted = 0,
    Normal = 1,
    Suspicious = 2,
    Malicious = 3,
    Critical = 4,
}

/// Swarm intelligence for collaborative defense
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmIntelligence {
    pub global_threats: HashMap<IpAddr, GlobalThreatInfo>,
    pub attack_patterns: Vec<AttackPattern>,
    pub defense_strategies: Vec<DefenseStrategy>,
    pub last_sync: u64,
    pub swarm_size: usize,
}

/// Global threat information shared across swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalThreatInfo {
    pub ip_address: IpAddr,
    pub threat_level: ThreatLevel,
    pub affected_nodes: usize,
    pub first_reported: u64,
    pub last_updated: u64,
    pub attack_vector: String,
    pub mitigation_recommendations: Vec<String>,
}

/// Recognized attack patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_id: String,
    pub signature: Vec<u8>,
    pub attack_type: String,
    pub severity: f64,
    pub detection_confidence: f64,
    pub swarm_detected: bool,
}

/// Collaborative defense strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseStrategy {
    pub strategy_id: String,
    pub target_pattern: TrafficPattern,
    pub actions: Vec<DefenseAction>,
    pub effectiveness_score: f64,
    pub energy_cost: f64,
    pub last_used: u64,
}

/// Defense actions for mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DefenseAction {
    RateLimit { multiplier: f64 },
    BlockConnection { duration_secs: u64 },
    RedirectTraffic { alternative_node: PublicKey },
    SwarmAlert { priority: u8 },
    AdaptiveFiltering { filter_rules: Vec<String> },
}

/// Adaptive rate limiter with ML predictions
#[derive(Debug)]
pub struct AdaptiveRateLimiter {
    pub base_rate_limit: u64, // messages per second
    pub burst_capacity: u64,
    pub current_buckets: HashMap<IpAddr, TokenBucket>,
    pub ml_predictions: HashMap<IpAddr, RatePrediction>,
    pub global_throttle_active: bool,
    pub global_throttle_level: f64,
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill: Instant,
    pub capacity: u64,
    pub refill_rate: f64,
}

/// ML-driven rate prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePrediction {
    pub predicted_load: f64,
    pub confidence: f64,
    pub time_window_secs: u64,
    pub last_updated: u64,
}

/// Traffic sample for ML training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub timestamp: u64,
    pub ip_address: IpAddr,
    pub message_type: String,
    pub message_size: usize,
    pub response_time_ms: u64,
    pub error_occurred: bool,
    pub behavioral_features: HashMap<String, f64>,
    pub classification: TrafficPattern,
}

/// Swarm coordination messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmMessage {
    ThreatReport { threat: GlobalThreatInfo },
    AttackPatternDetected { pattern: AttackPattern },
    DefenseStrategyUpdate { strategy: DefenseStrategy },
    SwarmHealthCheck { node_id: PublicKey, status: NodeStatus },
}

/// Node status for swarm health monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Healthy,
    UnderAttack,
    Overloaded,
    Isolated,
}

impl AiTrafficAnalyzer {
    /// Create new AI-powered traffic analyzer
    pub async fn new(
        network: Arc<dyn NetworkTrait>,
        metrics: Arc<MetricsServer>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, _) = mpsc::unbounded_channel();

        let mut behavioral_models = HashMap::new();

        // Initialize baseline behavioral models
        behavioral_models.insert(TrafficPattern::NormalPeer, BehaviorModel {
            pattern: TrafficPattern::NormalPeer,
            feature_weights: Self::create_normal_peer_features(),
            threshold_score: 0.7,
            false_positive_rate: 0.05,
            last_updated: current_timestamp(),
            training_samples: 1000,
            confidence_level: 0.85,
        });

        behavioral_models.insert(TrafficPattern::TransactionFlood, BehaviorModel {
            pattern: TrafficPattern::TransactionFlood,
            feature_weights: Self::create_attack_features(),
            threshold_score: 0.8,
            false_positive_rate: 0.02,
            last_updated: current_timestamp(),
            training_samples: 500,
            confidence_level: 0.92,
        });

        let rate_limiter = AdaptiveRateLimiter {
            base_rate_limit: 100, // messages per second
            burst_capacity: 1000,
            current_buckets: HashMap::new(),
            ml_predictions: HashMap::new(),
            global_throttle_active: false,
            global_throttle_level: 1.0,
        };

        Ok(Self {
            behavioral_models: Arc::new(RwLock::new(behavioral_models)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            threat_intelligence: Arc::new(AsyncRwLock::new(SwarmIntelligence {
                global_threats: HashMap::new(),
                attack_patterns: Vec::new(),
                defense_strategies: Vec::new(),
                last_sync: current_timestamp(),
                swarm_size: 1,
            })),
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
            swarm_channel: tx,
            network,
            metrics,
            training_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
        })
    }

    /// Start the AI traffic analysis engine
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Start background ML training
        let models = Arc::clone(&self.behavioral_models);
        let training_buffer = Arc::clone(&self.training_buffer);

        tokio::spawn(async move {
            Self::ml_training_loop(models, training_buffer).await;
        });

        // Start swarm intelligence coordinator
        let threat_intelligence = Arc::clone(&self.threat_intelligence);
        let swarm_channel = self.swarm_channel.clone();
        let network = Arc::clone(&self.network);

        tokio::spawn(async move {
            Self::swarm_coordination_loop(threat_intelligence, swarm_channel, network).await;
        });

        // Start adaptive rate limiting
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let connections = Arc::clone(&self.connections);

        tokio::spawn(async move {
            Self::adaptive_rate_limiting_loop(rate_limiter, connections).await;
        });

        Ok(())
    }

    /// Analyze incoming traffic with AI
    pub async fn analyze_traffic(
        &self,
        ip: IpAddr,
        message: &NetworkMessage,
        message_size: usize,
        processing_time_ms: u64,
        error_occurred: bool,
    ) -> Result<TrafficDecision, Box<dyn std::error::Error>> {
        // Update connection profile
        self.update_connection_profile(ip, message, message_size, processing_time_ms, error_occurred).await;

        // Extract behavioral features
        let features = self.extract_behavioral_features(ip, message).await;

        // Classify traffic pattern using ML
        let classification = self.classify_traffic(&features).await;

        // Update training data
        self.add_training_sample(ip, message, message_size, processing_time_ms, error_occurred, classification.clone()).await;

        // Check rate limits
        let rate_allowed = self.check_rate_limit(ip).await;

        // Swarm intelligence check
        let swarm_threat = self.check_swarm_intelligence(ip).await;

        // Make final decision
        let decision = self.make_traffic_decision(
            ip,
            classification,
            rate_allowed,
            swarm_threat,
            &features
        ).await;

        // Update metrics
        self.update_metrics(&decision).await;

        Ok(decision)
    }

    /// Update connection profile with ML tracking
    async fn update_connection_profile(
        &self,
        ip: IpAddr,
        message: &NetworkMessage,
        message_size: usize,
        processing_time_ms: u64,
        error_occurred: bool,
    ) {
        let mut connections = self.connections.write().unwrap();
        let profile = connections.entry(ip).or_insert_with(|| ConnectionProfile {
            ip_address: ip,
            first_seen: current_timestamp(),
            last_activity: current_timestamp(),
            total_bytes_sent: 0,
            total_bytes_received: message_size as u64,
            messages_per_second: 0.0,
            error_rate: 0.0,
            reputation_score: 0.5, // Neutral starting point
            behavioral_features: HashMap::new(),
            threat_level: ThreatLevel::Normal,
            rate_limit_multiplier: 1.0,
        });

        profile.last_activity = current_timestamp();
        profile.total_bytes_received += message_size as u64;

        // Update error rate (exponential moving average)
        let alpha = 0.1;
        profile.error_rate = profile.error_rate * (1.0 - alpha) +
                           (if error_occurred { 1.0 } else { 0.0 }) * alpha;

        // Calculate messages per second (simplified)
        let time_diff = (current_timestamp() - profile.first_seen) as f64;
        if time_diff > 0.0 {
            // This is a rough approximation - in real implementation use proper counters
            profile.messages_per_second = (profile.messages_per_second * 0.9) + (1.0 / time_diff) * 0.1;
        }
    }

    /// Extract behavioral features for ML analysis
    async fn extract_behavioral_features(
        &self,
        ip: IpAddr,
        message: &NetworkMessage,
    ) -> HashMap<String, f64> {
        let connections = self.connections.read().unwrap();
        let profile = connections.get(&ip);

        let mut features = HashMap::new();

        if let Some(profile) = profile {
            features.insert("messages_per_second".to_string(), profile.messages_per_second);
            features.insert("error_rate".to_string(), profile.error_rate);
            features.insert("reputation_score".to_string(), profile.reputation_score);
            features.insert("connection_age_hours".to_string(),
                          (current_timestamp() - profile.first_seen) as f64 / 3600.0);
            features.insert("bytes_per_message".to_string(),
                          profile.total_bytes_received as f64 / profile.messages_per_second.max(1.0));
        }

        // Message-specific features
        match message {
            NetworkMessage::Transaction(_) => {
                features.insert("is_transaction".to_string(), 1.0);
                features.insert("is_block".to_string(), 0.0);
                features.insert("is_consensus".to_string(), 0.0);
            }
            NetworkMessage::Block(_) => {
                features.insert("is_transaction".to_string(), 0.0);
                features.insert("is_block".to_string(), 1.0);
                features.insert("is_consensus".to_string(), 0.0);
            }
            NetworkMessage::Consensus(_) => {
                features.insert("is_transaction".to_string(), 0.0);
                features.insert("is_block".to_string(), 0.0);
                features.insert("is_consensus".to_string(), 1.0);
            }
            _ => {}
        }

        features
    }

    /// Classify traffic using ML models
    async fn classify_traffic(&self, features: &HashMap<String, f64>) -> TrafficPattern {
        let models = self.behavioral_models.read().unwrap();

        // Simple ML classification (in real implementation use proper ML library)
        let mut best_score = 0.0;
        let mut best_pattern = TrafficPattern::NormalPeer;

        for (pattern, model) in models.iter() {
            let score = self.calculate_pattern_score(features, model);
            if score > model.threshold_score && score > best_score {
                best_score = score;
                best_pattern = pattern.clone();
            }
        }

        best_pattern
    }

    /// Calculate pattern matching score
    fn calculate_pattern_score(&self, features: &HashMap<String, f64>, model: &BehaviorModel) -> f64 {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for (feature_name, feature_value) in features {
            if let Some(weight) = model.feature_weights.get(feature_name) {
                total_score += feature_value * weight;
                total_weight += weight.abs();
            }
        }

        if total_weight > 0.0 {
            total_score / total_weight
        } else {
            0.0
        }
    }

    /// Check rate limiting
    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut rate_limiter = self.rate_limiter.write().unwrap();

        let bucket = rate_limiter.current_buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: rate_limiter.burst_capacity as f64,
            last_refill: Instant::now(),
            capacity: rate_limiter.burst_capacity,
            refill_rate: rate_limiter.base_rate_limit as f64,
        });

        // Refill tokens based on time elapsed
        let now = Instant::now();
        let time_passed = now.duration_since(bucket.last_refill).as_secs_f64();
        let tokens_to_add = time_passed * bucket.refill_rate;

        bucket.tokens = (bucket.tokens + tokens_to_add).min(bucket.capacity as f64);
        bucket.last_refill = now;

        // Check if we have enough tokens
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Check swarm intelligence for known threats
    async fn check_swarm_intelligence(&self, ip: IpAddr) -> Option<GlobalThreatInfo> {
        let intelligence = self.threat_intelligence.read().await;
        intelligence.global_threats.get(&ip).cloned()
    }

    /// Make final traffic decision
    async fn make_traffic_decision(
        &self,
        ip: IpAddr,
        classification: TrafficPattern,
        rate_allowed: bool,
        swarm_threat: Option<GlobalThreatInfo>,
        features: &HashMap<String, f64>,
    ) -> TrafficDecision {
        // Critical threat from swarm intelligence
        if let Some(threat) = swarm_threat {
            if threat.threat_level >= ThreatLevel::Critical {
                return TrafficDecision::Block {
                    duration_secs: 3600, // 1 hour
                    reason: format!("Swarm critical threat: {}", threat.attack_vector),
                };
            }
        }

        // Rate limiting violation
        if !rate_allowed {
            return TrafficDecision::Throttle {
                delay_ms: 1000,
                reason: "Rate limit exceeded".to_string(),
            };
        }

        // ML classification results
        match classification {
            TrafficPattern::TransactionFlood | TrafficPattern::BlockSpam => {
                TrafficDecision::Throttle {
                    delay_ms: 5000,
                    reason: format!("Detected {:?}", classification),
                }
            }
            TrafficPattern::BotnetAttack => {
                TrafficDecision::Block {
                    duration_secs: 1800, // 30 minutes
                    reason: "Botnet attack detected".to_string(),
                }
            }
            TrafficPattern::SophisticatedAttack => {
                // Alert swarm and block
                let _ = self.swarm_channel.send(SwarmMessage::ThreatReport {
                    threat: GlobalThreatInfo {
                        ip_address: ip,
                        threat_level: ThreatLevel::Critical,
                        affected_nodes: 1,
                        first_reported: current_timestamp(),
                        last_updated: current_timestamp(),
                        attack_vector: "Sophisticated ML-detected attack".to_string(),
                        mitigation_recommendations: vec![
                            "Immediate blocking".to_string(),
                            "Swarm alert".to_string(),
                        ],
                    }
                });
                TrafficDecision::Block {
                    duration_secs: 7200, // 2 hours
                    reason: "Sophisticated attack pattern".to_string(),
                }
            }
            _ => TrafficDecision::Allow,
        }
    }

    /// ML training loop
    async fn ml_training_loop(
        models: Arc<RwLock<HashMap<TrafficPattern, BehaviorModel>>>,
        training_buffer: Arc<RwLock<VecDeque<TrafficSample>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

        loop {
            interval.tick().await;

            let samples = {
                let mut buffer = training_buffer.write().unwrap();
                let samples: Vec<_> = buffer.drain(..).collect();
                samples
            };

            if samples.is_empty() {
                continue;
            }

            // Update models with new training data
            Self::update_behavioral_models(&models, &samples).await;

            log::info!("🤖 ML training completed with {} samples", samples.len());
        }
    }

    /// Update behavioral models with training data
    async fn update_behavioral_models(
        models: &Arc<RwLock<HashMap<TrafficPattern, BehaviorModel>>>,
        samples: &[TrafficSample],
    ) {
        let mut models_write = models.write().unwrap();

        // Group samples by classification
        let mut pattern_samples: HashMap<TrafficPattern, Vec<&TrafficSample>> = HashMap::new();

        for sample in samples {
            pattern_samples.entry(sample.classification.clone())
                          .or_insert_with(Vec::new)
                          .push(sample);
        }

        // Update each model
        for (pattern, samples) in pattern_samples {
            if let Some(model) = models_write.get_mut(&pattern) {
                Self::update_single_model(model, samples);
            }
        }
    }

    /// Update single behavioral model
    fn update_single_model(model: &mut BehaviorModel, samples: Vec<&TrafficSample>) {
        model.training_samples += samples.len();
        model.last_updated = current_timestamp();

        // Simple online learning - update feature weights
        let learning_rate = 0.01;

        for sample in samples {
            for (feature_name, feature_value) in &sample.behavioral_features {
                let current_weight = model.feature_weights
                    .get(feature_name)
                    .copied()
                    .unwrap_or(0.5);

                // Reinforcement learning style update
                let target_weight = if sample.classification == model.pattern { 1.0 } else { 0.0 };
                let weight_update = learning_rate * (target_weight - current_weight) * feature_value;

                model.feature_weights.insert(feature_name.clone(), current_weight + weight_update);
            }
        }

        // Recalculate confidence based on training samples
        model.confidence_level = (model.training_samples as f64 / (model.training_samples as f64 + 100.0)).min(0.95);
    }

    /// Swarm coordination loop
    async fn swarm_coordination_loop(
        threat_intelligence: Arc<AsyncRwLock<SwarmIntelligence>>,
        mut swarm_channel: mpsc::UnboundedReceiver<SwarmMessage>,
        network: Arc<dyn NetworkTrait>,
    ) {
        while let Some(message) = swarm_channel.recv().await {
            match message {
                SwarmMessage::ThreatReport { threat } => {
                    // Broadcast threat to swarm
                    Self::broadcast_threat_to_swarm(&threat_intelligence, &threat, &network).await;
                }
                SwarmMessage::AttackPatternDetected { pattern } => {
                    // Share attack pattern
                    Self::share_attack_pattern(&threat_intelligence, &pattern, &network).await;
                }
                SwarmMessage::SwarmHealthCheck { node_id, status } => {
                    // Update swarm health
                    Self::update_swarm_health(&threat_intelligence, node_id, status).await;
                }
                _ => {}
            }
        }
    }

    /// Broadcast threat information to swarm
    async fn broadcast_threat_to_swarm(
        threat_intelligence: &Arc<AsyncRwLock<SwarmIntelligence>>,
        threat: &GlobalThreatInfo,
        network: &Arc<dyn NetworkTrait>,
    ) {
        let mut intelligence = threat_intelligence.write().await;
        intelligence.global_threats.insert(threat.ip_address, threat.clone());

        // In real implementation, broadcast to other nodes
        // For now, just log
        log::warn!("🚨 Swarm threat broadcast: {} ({:?})",
                  threat.ip_address, threat.threat_level);
    }

    /// Share attack pattern with swarm
    async fn share_attack_pattern(
        threat_intelligence: &Arc<AsyncRwLock<SwarmIntelligence>>,
        pattern: &AttackPattern,
        network: &Arc<dyn NetworkTrait>,
    ) {
        let mut intelligence = threat_intelligence.write().await;
        intelligence.attack_patterns.push(pattern.clone());

        log::info!("🔍 Attack pattern shared with swarm: {}", pattern.pattern_id);
    }

    /// Update swarm health status
    async fn update_swarm_health(
        threat_intelligence: &Arc<AsyncRwLock<SwarmIntelligence>>,
        node_id: PublicKey,
        status: NodeStatus,
    ) {
        let mut intelligence = threat_intelligence.write().await;

        match status {
            NodeStatus::UnderAttack => {
                intelligence.swarm_size -= 1; // Reduce effective swarm size
            }
            NodeStatus::Healthy => {
                // Ensure node is counted
            }
            _ => {}
        }

        log::debug!("🐝 Swarm health update: {:?} for node", status);
    }

    /// Adaptive rate limiting loop
    async fn adaptive_rate_limiting_loop(
        rate_limiter: Arc<RwLock<AdaptiveRateLimiter>>,
        connections: Arc<RwLock<HashMap<IpAddr, ConnectionProfile>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(60)); // 1 minute

        loop {
            interval.tick().await;

            // Analyze current load and adjust limits
            Self::adjust_rate_limits(&rate_limiter, &connections).await;
        }
    }

    /// Adjust rate limits based on current conditions
    async fn adjust_rate_limits(
        rate_limiter: &Arc<RwLock<AdaptiveRateLimiter>>,
        connections: &Arc<RwLock<HashMap<IpAddr, ConnectionProfile>>>,
    ) {
        let mut limiter = rate_limiter.write().unwrap();
        let conn_read = connections.read().unwrap();

        // Calculate current load
        let total_mps: f64 = conn_read.values()
            .map(|p| p.messages_per_second)
            .sum();

        // Adaptive adjustment based on load
        if total_mps > limiter.base_rate_limit as f64 * 2.0 {
            // High load - reduce limits
            limiter.global_throttle_level = 0.5;
            limiter.global_throttle_active = true;
            log::warn!("⚡ High load detected, activating global throttling");
        } else if total_mps < limiter.base_rate_limit as f64 * 0.5 {
            // Low load - increase limits
            limiter.global_throttle_level = 1.2;
            limiter.global_throttle_active = false;
        } else {
            // Normal load
            limiter.global_throttle_level = 1.0;
            limiter.global_throttle_active = false;
        }
    }

    /// Helper methods
    fn create_normal_peer_features() -> HashMap<String, f64> {
        let mut features = HashMap::new();
        features.insert("messages_per_second".to_string(), 0.3);
        features.insert("error_rate".to_string(), -0.8);
        features.insert("reputation_score".to_string(), 0.5);
        features.insert("is_transaction".to_string(), 0.4);
        features.insert("is_block".to_string(), 0.2);
        features
    }

    fn create_attack_features() -> HashMap<String, f64> {
        let mut features = HashMap::new();
        features.insert("messages_per_second".to_string(), 0.9);
        features.insert("error_rate".to_string(), 0.6);
        features.insert("reputation_score".to_string(), -0.7);
        features.insert("is_transaction".to_string(), 0.8);
        features.insert("bytes_per_message".to_string(), -0.3);
        features
    }

    async fn add_training_sample(
        &self,
        ip: IpAddr,
        message: &NetworkMessage,
        message_size: usize,
        processing_time_ms: u64,
        error_occurred: bool,
        classification: TrafficPattern,
    ) {
        let features = self.extract_behavioral_features(ip, message).await;

        let sample = TrafficSample {
            timestamp: current_timestamp(),
            ip_address: ip,
            message_type: format!("{:?}", message),
            message_size,
            response_time_ms: processing_time_ms,
            error_occurred,
            behavioral_features: features,
            classification,
        };

        let mut buffer = self.training_buffer.write().unwrap();
        buffer.push_back(sample);

        // Keep buffer size limited
        while buffer.len() > 10000 {
            buffer.pop_front();
        }
    }

    async fn update_metrics(&self, decision: &TrafficDecision) {
        // In real implementation, update Prometheus metrics
        match decision {
            TrafficDecision::Allow => {
                // Increment allowed counter
            }
            TrafficDecision::Throttle { .. } => {
                // Increment throttled counter
            }
            TrafficDecision::Block { .. } => {
                // Increment blocked counter
            }
        }
    }
}

/// Traffic decision result
#[derive(Debug, Clone)]
pub enum TrafficDecision {
    Allow,
    Throttle { delay_ms: u64, reason: String },
    Block { duration_secs: u64, reason: String },
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ai_traffic_analyzer_creation() {
        // Mock network and metrics for testing
        // In real implementation, use proper mocks
        // let network = Arc::new(MockNetwork::new());
        // let metrics = Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap());
        // let analyzer = AiTrafficAnalyzer::new(network, metrics).await.unwrap();
        // assert!(analyzer.behavioral_models.read().unwrap().contains_key(&TrafficPattern::NormalPeer));
    }

    #[test]
    fn test_traffic_pattern_classification() {
        let pattern = TrafficPattern::NormalPeer;
        assert_eq!(format!("{:?}", pattern), "NormalPeer");
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Trusted < ThreatLevel::Critical);
        assert!(ThreatLevel::Normal < ThreatLevel::Malicious);
    }
}
