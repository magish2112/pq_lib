//! Consensus Protocol Benchmarks
//!
//! Comprehensive performance benchmarking for HotStuff consensus protocol
//! under various network conditions and validator configurations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use tokio::runtime::Runtime;
use std::sync::Arc;
use symbios_mvp::types::*;
use symbios_mvp::hotstuff_consensus::*;
use symbios_mvp::state_machine::*;
use symbios_mvp::storage::*;
use symbios_mvp::adaptive_crypto::*;

/// Benchmark HotStuff consensus performance
fn bench_hotstuff_consensus(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("hotstuff_single_validator", |b| {
        b.iter(|| {
            rt.block_on(async {
                let consensus = setup_single_validator_consensus().await;
                run_consensus_round(black_box(&consensus)).await;
            });
        });
    });

    c.bench_function("hotstuff_message_processing", |b| {
        b.iter(|| {
            rt.block_on(async {
                let consensus = setup_single_validator_consensus().await;
                process_messages_benchmark(black_box(&consensus)).await;
            });
        });
    });

    c.bench_function("hotstuff_qc_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let qc = create_quorum_certificate_benchmark().await;
                black_box(qc);
            });
        });
    });
}

/// Benchmark under network latency simulation
fn bench_network_conditions(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_conditions");
    group.measurement_time(Duration::from_secs(10));

    // Low latency (LAN)
    group.bench_function("lan_conditions_4_validators", |b| {
        b.iter(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                simulate_network_conditions(4, Duration::from_millis(1), 0.001).await;
            });
        });
    });

    // High latency (WAN)
    group.bench_function("wan_conditions_4_validators", |b| {
        b.iter(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                simulate_network_conditions(4, Duration::from_millis(100), 0.01).await;
            });
        });
    });

    // Packet loss simulation
    group.bench_function("packet_loss_10pct_4_validators", |b| {
        b.iter(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                simulate_packet_loss(4, 0.1).await;
            });
        });
    });

    group.finish();
}

/// Benchmark scalability with different validator counts
fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability");
    group.measurement_time(Duration::from_secs(15));

    for num_validators in [4, 7, 10, 21, 51].iter() {
        group.bench_with_input(
            format!("{}_validators", num_validators),
            num_validators,
            |b, &num_validators| {
                b.iter(|| {
                    tokio::runtime::Runtime::new().unwrap().block_on(async {
                        let consensus = setup_multi_validator_consensus(num_validators).await;
                        run_scalability_test(black_box(&consensus), num_validators).await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cryptographic operations in consensus
fn bench_crypto_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("ed25519_signing_consensus", |b| {
        b.iter(|| {
            rt.block_on(async {
                let crypto = setup_crypto_engine().await;
                let data = b"consensus message";
                let signature = crypto.sign(data, &crypto.generate_private_key().await).await.unwrap();
                black_box(signature);
            });
        });
    });

    c.bench_function("mlkem_key_exchange", |b| {
        b.iter(|| {
            rt.block_on(async {
                let crypto = setup_crypto_engine().await;
                let keypair = crypto.generate_pq_keypair().await.unwrap();
                black_box(keypair);
            });
        });
    });

    c.bench_function("hybrid_crypto_signing", |b| {
        b.iter(|| {
            rt.block_on(async {
                let crypto = setup_crypto_engine().await;
                let data = b"hybrid message";
                let signature = crypto.sign_hybrid(data, &crypto.generate_private_key().await).await.unwrap();
                black_box(signature);
            });
        });
    });
}

/// Setup single validator consensus for benchmarking
async fn setup_single_validator_consensus() -> Arc<HotStuffConsensus<Storage>> {
    let config = HotStuffConfig {
        view_timeout: Duration::from_secs(30),
        leader_replacement_timeout: Duration::from_secs(60),
        max_message_buffer: 1000,
        qc_aggregation_timeout: Duration::from_millis(500),
    };

    let validator_set = create_test_validator_set(1);
    let private_key = PrivateKey::new_ed25519(); // Mock key
    let storage = Arc::new(Storage::new_temp().unwrap());
    let state_machine = Arc::new(StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap());
    let crypto_engine = Arc::new(AdaptiveCryptoEngine::new(Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())).await);

    Arc::new(HotStuffConsensus::new(
        config,
        validator_set,
        private_key,
        state_machine,
        crypto_engine,
    ).await.unwrap())
}

/// Setup multi-validator consensus
async fn setup_multi_validator_consensus(num_validators: usize) -> Arc<HotStuffConsensus<Storage>> {
    let config = HotStuffConfig {
        view_timeout: Duration::from_secs(30),
        leader_replacement_timeout: Duration::from_secs(60),
        max_message_buffer: 1000,
        qc_aggregation_timeout: Duration::from_millis(500),
    };

    let validator_set = create_test_validator_set(num_validators);
    let private_key = PrivateKey::new_ed25519();
    let storage = Arc::new(Storage::new_temp().unwrap());
    let state_machine = Arc::new(StateMachine::new(storage.clone(), Hash::new(b"genesis")).unwrap());
    let crypto_engine = Arc::new(AdaptiveCryptoEngine::new(Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())).await);

    Arc::new(HotStuffConsensus::new(
        config,
        validator_set,
        private_key,
        state_machine,
        crypto_engine,
    ).await.unwrap())
}

/// Run single consensus round
async fn run_consensus_round(consensus: &Arc<HotStuffConsensus<Storage>>) {
    // Simulate proposing a block
    let transactions = create_test_transactions(10);
    let _ = consensus.propose_block(transactions).await;

    // Simulate message processing
    let message = HotStuffMessage::Prepare {
        view_number: 1,
        high_qc: QuorumCertificate {
            view_number: 0,
            block_hash: Hash::new(b"genesis"),
            phase: HotStuffPhase::Prepare,
            signatures: std::collections::HashMap::new(),
            signers: std::collections::HashSet::new(),
        },
        block: create_test_block(),
        sender: PublicKey::new_ed25519(),
    };

    let _ = consensus.process_message(message).await;
}

/// Process messages benchmark
async fn process_messages_benchmark(consensus: &Arc<HotStuffConsensus<Storage>>) {
    for i in 0..100 {
        let message = HotStuffMessage::Prepare {
            view_number: i,
            high_qc: QuorumCertificate {
                view_number: i - 1,
                block_hash: Hash::new(format!("block_{}", i).as_bytes()),
                phase: HotStuffPhase::Prepare,
                signatures: std::collections::HashMap::new(),
                signers: std::collections::HashSet::new(),
            },
            block: create_test_block(),
            sender: PublicKey::new_ed25519(),
        };

        let _ = consensus.process_message(message).await;
    }
}

/// Create quorum certificate benchmark
async fn create_quorum_certificate_benchmark() -> QuorumCertificate {
    let mut signatures = std::collections::HashMap::new();
    let mut signers = std::collections::HashSet::new();

    // Simulate 7 validators signing
    for i in 0..7 {
        let validator_id = PublicKey::new_ed25519();
        signatures.insert(validator_id, vec![i as u8; 64]); // Mock signature
        signers.insert(validator_id);
    }

    QuorumCertificate {
        view_number: 1,
        block_hash: Hash::new(b"test_block"),
        phase: HotStuffPhase::Prepare,
        signatures,
        signers,
    }
}

/// Simulate network conditions
async fn simulate_network_conditions(num_validators: usize, latency: Duration, packet_loss: f64) {
    let consensus = setup_multi_validator_consensus(num_validators).await;

    // Simulate network delays and losses
    tokio::time::sleep(latency).await;

    // Simulate packet loss by randomly dropping messages
    for i in 0..10 {
        if rand::random::<f64>() > packet_loss {
            let message = HotStuffMessage::Prepare {
                view_number: i as u64,
                high_qc: QuorumCertificate {
                    view_number: (i - 1) as u64,
                    block_hash: Hash::new(format!("block_{}", i).as_bytes()),
                    phase: HotStuffPhase::Prepare,
                    signatures: std::collections::HashMap::new(),
                    signers: std::collections::HashSet::new(),
                },
                block: create_test_block(),
                sender: PublicKey::new_ed25519(),
            };

            let _ = consensus.process_message(message).await;
        }
    }
}

/// Simulate packet loss conditions
async fn simulate_packet_loss(num_validators: usize, loss_rate: f64) {
    simulate_network_conditions(num_validators, Duration::from_millis(10), loss_rate).await;
}

/// Run scalability test
async fn run_scalability_test(consensus: &Arc<HotStuffConsensus<Storage>>, num_validators: usize) {
    let transactions = create_test_transactions(50);

    // Simulate consensus with multiple validators
    for round in 0..5 {
        let _ = consensus.propose_block(transactions.clone()).await;

        // Simulate other validators voting
        for validator in 1..num_validators {
            let vote_msg = HotStuffMessage::PreCommit {
                view_number: round,
                block_hash: Hash::new(format!("block_{}", round).as_bytes()),
                qc: QuorumCertificate {
                    view_number: round,
                    block_hash: Hash::new(format!("block_{}", round).as_bytes()),
                    phase: HotStuffPhase::Prepare,
                    signatures: std::collections::HashMap::new(),
                    signers: std::collections::HashSet::new(),
                },
                sender: PublicKey::new_ed25519(),
            };

            let _ = consensus.process_message(vote_msg).await;
        }
    }
}

/// Setup crypto engine for benchmarks
async fn setup_crypto_engine() -> Arc<AdaptiveCryptoEngine> {
    Arc::new(AdaptiveCryptoEngine::new(
        Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
    ).await)
}

/// Create test validator set
fn create_test_validator_set(num_validators: usize) -> ValidatorSet {
    let mut validators = std::collections::HashMap::new();

    for i in 0..num_validators {
        let validator_info = ValidatorInfo {
            public_key: PublicKey::new_ed25519(),
            stake_amount: 1000 + i as u64 * 100,
            network_address: format!("validator_{}:3030{}", i, 3),
            commission_rate: 0,
            uptime: 100,
            last_seen: 0,
        };

        validators.insert(validator_info.public_key, validator_info);
    }

    ValidatorSet { validators }
}

/// Create test transactions
fn create_test_transactions(count: usize) -> Vec<Transaction> {
    (0..count)
        .map(|i| {
            Transaction::new(
                PublicKey::new_ed25519(),
                PublicKey::new_ed25519(),
                100 + i as u64,
                1,
                i as u64,
            )
        })
        .collect()
}

/// Create test block
fn create_test_block() -> Block {
    Block::new(
        Hash::new(b"previous"),
        1,
        create_test_transactions(5),
        PublicKey::new_ed25519(),
    )
}

criterion_group!(
    benches,
    bench_hotstuff_consensus,
    bench_network_conditions,
    bench_scalability,
    bench_crypto_operations
);
criterion_main!(benches);
