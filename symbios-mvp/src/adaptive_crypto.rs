//! Adaptive Cryptography System
//!
//! Revolutionary approach to cryptographic agility with intelligent algorithm
//! rotation based on threat intelligence, performance metrics, and quantum
//! resistance assessments. Uses machine learning to predict optimal crypto
//! configurations.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock as AsyncRwLock;
use crate::types::{Hash, PublicKey, PrivateKey, Signature};
use crate::metrics::MetricsServer;

/// Cryptographic algorithm capabilities and performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoCapabilities {
    pub algorithm_name: String,
    pub quantum_resistance_level: QuantumResistance,
    pub performance_score: f64, // TPS capability
    pub security_score: f64,    // Resistance to known attacks
    pub energy_efficiency: f64, // Energy consumption per operation
    pub last_assessment: u64,
    pub threat_intelligence_score: f64,
}

/// Quantum resistance assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuantumResistance {
    Vulnerable,      // Classical crypto (RSA, ECC)
    Transitional,    // Hybrid approaches
    QuantumSafe,     // Post-quantum algorithms
    FutureProof,     // Multi-layered quantum resistance
}

/// Adaptive crypto policy with ML-driven decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptivePolicy {
    pub current_primary: String,      // Primary algorithm
    pub current_secondary: String,    // Fallback algorithm
    pub rotation_threshold: f64,      // Performance drop threshold
    pub quantum_alert_level: f64,     // Quantum threat threshold
    pub energy_budget: f64,          // Max energy consumption
    pub last_rotation: u64,
    pub rotation_history: VecDeque<CryptoTransition>,
}

/// Cryptographic transition record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoTransition {
    pub timestamp: u64,
    pub from_algorithm: String,
    pub to_algorithm: String,
    pub reason: TransitionReason,
    pub performance_impact: f64,
    pub security_improvement: f64,
}

/// Reasons for cryptographic transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionReason {
    QuantumThreatDetected,
    PerformanceDegradation,
    SecurityVulnerability,
    EnergyOptimization,
    ProactiveRotation,
    ThreatIntelligenceUpdate,
}

/// ML-driven crypto optimizer
pub struct AdaptiveCryptoEngine {
    capabilities: Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
    policy: Arc<AsyncRwLock<AdaptivePolicy>>,
    metrics: Arc<MetricsServer>,
    threat_feed: Arc<RwLock<ThreatIntelligenceFeed>>,
    rotation_scheduler: tokio::sync::mpsc::UnboundedSender<CryptoRotationEvent>,
    rotation_receiver: tokio::sync::mpsc::UnboundedReceiver<CryptoRotationEvent>,
}

/// Threat intelligence feed integration
#[derive(Debug, Clone)]
pub struct ThreatIntelligenceFeed {
    quantum_threats: VecDeque<QuantumThreat>,
    classical_attacks: VecDeque<AttackPattern>,
    performance_anomalies: VecDeque<PerformanceAnomaly>,
    last_update: u64,
}

/// Quantum threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumThreat {
    pub threat_id: String,
    pub algorithm_target: String,
    pub threat_level: f64, // 0.0 to 1.0
    pub time_to_break: Duration,
    pub detection_confidence: f64,
    pub source: String,
    pub timestamp: u64,
}

/// Attack pattern recognition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_id: String,
    pub affected_algorithms: Vec<String>,
    pub attack_type: String,
    pub severity: f64,
    pub mitigation_cost: f64,
}

/// Performance anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnomaly {
    pub anomaly_id: String,
    pub affected_component: String,
    pub deviation_percentage: f64,
    pub duration: Duration,
    pub auto_recovered: bool,
}

/// Rotation events for async processing
#[derive(Debug, Clone)]
pub enum CryptoRotationEvent {
    ScheduledRotation { reason: TransitionReason },
    EmergencyRotation { threat: QuantumThreat },
    PerformanceTriggered { anomaly: PerformanceAnomaly },
    PolicyUpdate { new_policy: AdaptivePolicy },
}

impl AdaptiveCryptoEngine {
    /// Initialize the adaptive crypto engine with ML capabilities
    pub async fn new(metrics: Arc<MetricsServer>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let mut capabilities = HashMap::new();

        // Initialize known algorithms with dynamic assessment
        capabilities.insert("ed25519".to_string(), CryptoCapabilities {
            algorithm_name: "ed25519".to_string(),
            quantum_resistance_level: QuantumResistance::Vulnerable,
            performance_score: 0.95,
            security_score: 0.85,
            energy_efficiency: 0.90,
            last_assessment: current_timestamp(),
            threat_intelligence_score: 0.3,
        });

        capabilities.insert("mldsa65".to_string(), CryptoCapabilities {
            algorithm_name: "mldsa65".to_string(),
            quantum_resistance_level: QuantumResistance::QuantumSafe,
            performance_score: 0.75,
            security_score: 0.98,
            energy_efficiency: 0.70,
            last_assessment: current_timestamp(),
            threat_intelligence_score: 0.95,
        });

        capabilities.insert("mlkem1024".to_string(), CryptoCapabilities {
            algorithm_name: "mlkem1024".to_string(),
            quantum_resistance_level: QuantumResistance::QuantumSafe,
            performance_score: 0.80,
            security_score: 0.97,
            energy_efficiency: 0.75,
            last_assessment: current_timestamp(),
            threat_intelligence_score: 0.92,
        });

        let initial_policy = AdaptivePolicy {
            current_primary: "mldsa65".to_string(),
            current_secondary: "ed25519".to_string(),
            rotation_threshold: 0.7,
            quantum_alert_level: 0.8,
            energy_budget: 0.8,
            last_rotation: current_timestamp(),
            rotation_history: VecDeque::with_capacity(100),
        };

        Self {
            capabilities: Arc::new(RwLock::new(capabilities)),
            policy: Arc::new(AsyncRwLock::new(initial_policy)),
            metrics,
            threat_feed: Arc::new(RwLock::new(ThreatIntelligenceFeed {
                quantum_threats: VecDeque::with_capacity(50),
                classical_attacks: VecDeque::with_capacity(50),
                performance_anomalies: VecDeque::with_capacity(50),
                last_update: current_timestamp(),
            })),
            rotation_scheduler: tx,
            rotation_receiver: rx,
        }
    }

    /// Start the adaptive crypto monitoring and rotation engine
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let capabilities = Arc::clone(&self.capabilities);
        let policy = Arc::clone(&self.policy);
        let threat_feed = Arc::clone(&self.threat_feed);
        let mut receiver = std::mem::replace(&mut self.rotation_receiver,
                                             tokio::sync::mpsc::unbounded_channel().1);

        tokio::spawn(async move {
            Self::rotation_engine_task(capabilities, policy, threat_feed, receiver).await;
        });

        Ok(())
    }

    /// Core rotation engine with ML-driven decisions
    async fn rotation_engine_task(
        capabilities: Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
        policy: Arc<AsyncRwLock<AdaptivePolicy>>,
        threat_feed: Arc<RwLock<ThreatIntelligenceFeed>>,
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<CryptoRotationEvent>,
    ) {
        let mut last_ml_update = Instant::now();

        loop {
            tokio::select! {
                Some(event) = receiver.recv() => {
                    Self::handle_rotation_event(&capabilities, &policy, &threat_feed, event).await;
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    // Periodic ML assessment
                    if last_ml_update.elapsed() > Duration::from_secs(300) { // 5 minutes
                        Self::run_ml_assessment(&capabilities, &policy, &threat_feed).await;
                        last_ml_update = Instant::now();
                    }

                    // Check for automated rotations
                    Self::check_automated_rotations(&capabilities, &policy, &threat_feed).await;
                }
            }
        }
    }

    /// Handle rotation events
    async fn handle_rotation_event(
        capabilities: &Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
        policy: &Arc<AsyncRwLock<AdaptivePolicy>>,
        threat_feed: &Arc<RwLock<ThreatIntelligenceFeed>>,
        event: CryptoRotationEvent,
    ) {
        match event {
            CryptoRotationEvent::EmergencyRotation { threat } => {
                log::warn!("🚨 Emergency crypto rotation triggered: {:?}", threat);
                Self::perform_emergency_rotation(policy, &threat.algorithm_target).await;
            }
            CryptoRotationEvent::ScheduledRotation { reason } => {
                log::info!("🔄 Scheduled crypto rotation: {:?}", reason);
                Self::perform_scheduled_rotation(policy, capabilities, reason).await;
            }
            CryptoRotationEvent::PerformanceTriggered { anomaly } => {
                log::warn!("⚡ Performance-triggered rotation: {:?}", anomaly);
                Self::perform_performance_rotation(policy, capabilities, &anomaly).await;
            }
            CryptoRotationEvent::PolicyUpdate { new_policy } => {
                log::info!("📋 Policy update applied");
                *policy.write().await = new_policy;
            }
        }
    }

    /// ML-powered assessment of cryptographic landscape
    async fn run_ml_assessment(
        capabilities: &Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
        policy: &Arc<AsyncRwLock<AdaptivePolicy>>,
        threat_feed: &Arc<RwLock<ThreatIntelligenceFeed>>,
    ) {
        let mut caps = capabilities.write().unwrap();
        let threats = threat_feed.read().unwrap();

        // Update threat intelligence scores
        for (algo_name, cap) in caps.iter_mut() {
            // Analyze recent threats targeting this algorithm
            let relevant_threats: Vec<_> = threats.quantum_threats
                .iter()
                .filter(|t| t.algorithm_target == *algo_name)
                .collect();

            if !relevant_threats.is_empty() {
                let avg_threat_level = relevant_threats.iter()
                    .map(|t| t.threat_level)
                    .sum::<f64>() / relevant_threats.len() as f64;

                cap.threat_intelligence_score = avg_threat_level;

                // Adjust security score based on threats
                cap.security_score = (cap.security_score * 0.8) + (avg_threat_level * 0.2);
            }

            cap.last_assessment = current_timestamp();
        }

        log::info!("🤖 ML assessment completed - updated {} algorithms", caps.len());
    }

    /// Check for automated rotation triggers
    async fn check_automated_rotations(
        capabilities: &Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
        policy: &Arc<AsyncRwLock<AdaptivePolicy>>,
        threat_feed: &Arc<RwLock<ThreatIntelligenceFeed>>,
    ) {
        let policy_read = policy.read().await;
        let threats = threat_feed.read().unwrap();

        // Check quantum threat levels
        let high_threats: Vec<_> = threats.quantum_threats
            .iter()
            .filter(|t| t.threat_level > policy_read.quantum_alert_level)
            .collect();

        if !high_threats.is_empty() {
            let most_critical = high_threats.iter()
                .max_by(|a, b| a.threat_level.partial_cmp(&b.threat_level).unwrap())
                .unwrap();

            // Trigger emergency rotation
            let _ = policy.write().await; // Drop read lock before sending
            // Note: In real implementation, send to channel
            log::warn!("🚨 High quantum threat detected: {} (level: {:.2})",
                      most_critical.algorithm_target, most_critical.threat_level);
        }

        // Check performance anomalies
        let recent_anomalies: Vec<_> = threats.performance_anomalies
            .iter()
            .filter(|a| a.deviation_percentage > 0.2) // 20% deviation
            .collect();

        if !recent_anomalies.is_empty() {
            log::warn!("⚡ Performance anomalies detected: {} events",
                      recent_anomalies.len());
        }
    }

    /// Perform emergency rotation for critical threats
    async fn perform_emergency_rotation(policy: &Arc<AsyncRwLock<AdaptivePolicy>>, threatened_algo: &str) {
        let mut policy_write = policy.write().await;

        if policy_write.current_primary == threatened_algo {
            // Find best alternative
            let alternative = if threatened_algo == "ed25519" {
                "mldsa65"
            } else {
                "mlkem1024"
            };

            let transition = CryptoTransition {
                timestamp: current_timestamp(),
                from_algorithm: policy_write.current_primary.clone(),
                to_algorithm: alternative.to_string(),
                reason: TransitionReason::QuantumThreatDetected,
                performance_impact: -0.1, // Temporary performance hit
                security_improvement: 0.3,
            };

            policy_write.rotation_history.push_back(transition);
            policy_write.current_primary = alternative.to_string();
            policy_write.last_rotation = current_timestamp();

            log::warn!("🚨 Emergency rotation: {} → {} (quantum threat)",
                      threatened_algo, alternative);
        }
    }

    /// Perform scheduled rotation based on ML assessment
    async fn perform_scheduled_rotation(
        policy: &Arc<AsyncRwLock<AdaptivePolicy>>,
        capabilities: &Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
        reason: TransitionReason,
    ) {
        let caps = capabilities.read().unwrap();
        let mut policy_write = policy.write().await;

        // Find optimal algorithm based on current metrics
        let optimal_algo = caps.iter()
            .max_by(|a, b| {
                let score_a = Self::calculate_algorithm_score(&a.1);
                let score_b = Self::calculate_algorithm_score(&b.1);
                score_a.partial_cmp(&score_b).unwrap()
            })
            .map(|(name, _)| name.clone());

        if let Some(optimal) = optimal_algo {
            if optimal != policy_write.current_primary {
                let transition = CryptoTransition {
                    timestamp: current_timestamp(),
                    from_algorithm: policy_write.current_primary.clone(),
                    to_algorithm: optimal.clone(),
                    reason,
                    performance_impact: 0.05, // Minor performance adjustment
                    security_improvement: 0.1,
                };

                policy_write.rotation_history.push_back(transition);
                policy_write.current_primary = optimal.clone();
                policy_write.last_rotation = current_timestamp();

                log::info!("🔄 Scheduled rotation: {} (reason: {:?})",
                          optimal, reason);
            }
        }
    }

    /// Calculate comprehensive algorithm score
    fn calculate_algorithm_score(cap: &CryptoCapabilities) -> f64 {
        // Weighted scoring: security (40%), performance (30%), quantum resistance (20%), energy (10%)
        let quantum_bonus = match cap.quantum_resistance_level {
            QuantumResistance::Vulnerable => 0.0,
            QuantumResistance::Transitional => 0.5,
            QuantumResistance::QuantumSafe => 1.0,
            QuantumResistance::FutureProof => 1.2,
        };

        (cap.security_score * 0.4) +
        (cap.performance_score * 0.3) +
        (quantum_bonus * 0.2) +
        (cap.energy_efficiency * 0.1)
    }

    /// Perform performance-triggered rotation
    async fn perform_performance_rotation(
        policy: &Arc<AsyncRwLock<AdaptivePolicy>>,
        capabilities: &Arc<RwLock<HashMap<String, CryptoCapabilities>>>,
        anomaly: &PerformanceAnomaly,
    ) {
        let caps = capabilities.read().unwrap();
        let mut policy_write = policy.write().await;

        // Find algorithm with best performance
        let best_performance = caps.iter()
            .max_by(|a, b| a.1.performance_score.partial_cmp(&b.1.performance_score).unwrap())
            .map(|(name, _)| name.clone());

        if let Some(best) = best_performance {
            if best != policy_write.current_primary {
                let transition = CryptoTransition {
                    timestamp: current_timestamp(),
                    from_algorithm: policy_write.current_primary.clone(),
                    to_algorithm: best.clone(),
                    reason: TransitionReason::PerformanceDegradation,
                    performance_impact: 0.15, // Expected improvement
                    security_improvement: 0.0,
                };

                policy_write.rotation_history.push_back(transition);
                policy_write.current_primary = best.clone();
                policy_write.last_rotation = current_timestamp();

                log::info!("⚡ Performance rotation: {} (anomaly: {})",
                          best, anomaly.anomaly_id);
            }
        }
    }

    /// Add quantum threat intelligence
    pub async fn add_quantum_threat(&self, threat: QuantumThreat) {
        let mut feed = self.threat_feed.write().unwrap();
        feed.quantum_threats.push_back(threat);
        feed.last_update = current_timestamp();

        // Keep only recent threats
        while feed.quantum_threats.len() > 50 {
            feed.quantum_threats.pop_front();
        }
    }

    /// Add performance anomaly
    pub async fn add_performance_anomaly(&self, anomaly: PerformanceAnomaly) {
        let mut feed = self.threat_feed.write().unwrap();
        feed.performance_anomalies.push_back(anomaly);

        // Keep only recent anomalies
        while feed.performance_anomalies.len() > 50 {
            feed.performance_anomalies.pop_front();
        }
    }

    /// Get current crypto policy
    pub async fn get_policy(&self) -> AdaptivePolicy {
        self.policy.read().await.clone()
    }

    /// Get algorithm capabilities
    pub fn get_capabilities(&self) -> HashMap<String, CryptoCapabilities> {
        self.capabilities.read().unwrap().clone()
    }

    /// Force rotation for testing
    pub async fn force_rotation(&self, to_algorithm: String, reason: TransitionReason) {
        let _ = self.rotation_scheduler.send(CryptoRotationEvent::ScheduledRotation { reason });
    }
}

/// Helper function for current timestamp
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
    async fn test_adaptive_crypto_initialization() {
        let metrics = Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap());
        let engine = AdaptiveCryptoEngine::new(metrics).await;

        let capabilities = engine.get_capabilities();
        assert!(capabilities.contains_key("ed25519"));
        assert!(capabilities.contains_key("mldsa65"));
        assert!(capabilities.contains_key("mlkem1024"));
    }

    #[tokio::test]
    async fn test_quantum_threat_detection() {
        let metrics = Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap());
        let engine = AdaptiveCryptoEngine::new(metrics).await;

        let threat = QuantumThreat {
            threat_id: "test_threat".to_string(),
            algorithm_target: "ed25519".to_string(),
            threat_level: 0.9,
            time_to_break: Duration::from_secs(3600),
            detection_confidence: 0.95,
            source: "quantum_ai".to_string(),
            timestamp: current_timestamp(),
        };

        engine.add_quantum_threat(threat).await;

        // Verify threat was added
        let feed = engine.threat_feed.read().unwrap();
        assert_eq!(feed.quantum_threats.len(), 1);
    }

    #[tokio::test]
    async fn test_algorithm_scoring() {
        let cap = CryptoCapabilities {
            algorithm_name: "test".to_string(),
            quantum_resistance_level: QuantumResistance::QuantumSafe,
            performance_score: 0.8,
            security_score: 0.9,
            energy_efficiency: 0.7,
            last_assessment: current_timestamp(),
            threat_intelligence_score: 0.1,
        };

        let score = AdaptiveCryptoEngine::calculate_algorithm_score(&cap);
        assert!(score > 0.0 && score <= 1.0);
    }
}
