use criterion::{criterion_group, criterion_main, Criterion, BatchSize, BenchmarkId};
use symbios_mvp::dag_mempool::SmartDagMempool;
use symbios_mvp::types::{PublicKey, Transaction, Block, PrivateKey, State};
use symbios_mvp::storage::Storage;
use symbios_mvp::network::{Network, NetworkRequest};
use symbios_mvp::pqcrypto::PQCrypto;
use symbios_mvp::simple_node::SimpleNode;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use std::sync::Arc;

fn bench_tps(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("dag_mempool_tps", |b| {
        b.to_async(&rt).iter_batched(|| {
            let validators = vec![PublicKey::new("v1".to_string())];
            SmartDagMempool::new(validators, 1000)
        }, |mut mp| async move {
            for i in 0..10_000u64 {
                let tx = Transaction::new_with_fee(
                    PublicKey::new("a".to_string()),
                    PublicKey::new("b".to_string()),
                    1,
                    1,
                    i,
                );
                mp.add_transaction(tx).await.unwrap();
            }
        }, BatchSize::SmallInput)
    });
}

fn bench_crypto_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_operations");

    // Ed25519 signature benchmark
    group.bench_function("ed25519_sign_verify", |b| {
        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 100, 0);

        b.iter(|| {
            tx.sign(&private_key).unwrap();
            tx.verify().unwrap();
        });
    });

    // PQ crypto benchmark
    group.bench_function("pq_crypto_sign_verify", |b| {
        let (sender, private_key) = Transaction::generate_keypair_with_pq().unwrap();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 100, 0);

        b.iter(|| {
            tx.sign(&private_key).unwrap();
            tx.verify().unwrap();
        });
    });

    // Hybrid crypto benchmark
    group.bench_function("hybrid_crypto_sign_verify", |b| {
        let (sender, private_key) = Transaction::generate_keypair_with_pq().unwrap();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 100, 0);

        b.iter(|| {
            tx.sign(&private_key).unwrap();
            tx.verify().unwrap();
        });
    });

    group.finish();
}

fn bench_storage_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("storage_operations");

    group.bench_function("rocksdb_transaction_store", |b| {
        b.to_async(&rt).iter_batched(|| {
            let temp_dir = TempDir::new().unwrap();
            let storage = Storage::new(temp_dir.path()).unwrap();
            let (sender, private_key) = Transaction::generate_keypair();

            (storage, sender, private_key, temp_dir)
        }, |(storage, sender, private_key, _temp_dir)| async move {
            for i in 0..100 {
                let receiver = PublicKey::new(format!("receiver{}", i));
                let mut tx = Transaction::new(sender.clone(), receiver, 100, i);
                tx.sign(&private_key).unwrap();
                storage.store_transaction(&tx).await.unwrap();
            }
        }, BatchSize::SmallInput)
    });

    group.bench_function("rocksdb_block_store", |b| {
        b.to_async(&rt).iter_batched(|| {
            let temp_dir = TempDir::new().unwrap();
            let storage = Storage::new(temp_dir.path()).unwrap();
            let validator = PublicKey::new("validator".to_string());
            let private_key = PrivateKey::new("validator_key".to_string());

            (storage, validator, private_key, temp_dir)
        }, |(storage, validator, private_key, _temp_dir)| async move {
            for height in 1..=100 {
                let mut block = Block::new(
                    symbios_mvp::types::Hash::new(format!("prev{}", height).as_bytes()),
                    height,
                    vec![],
                    validator.clone()
                );
                block.sign(&private_key).unwrap();
                storage.store_block(&block).await.unwrap();
            }
        }, BatchSize::SmallInput)
    });

    group.finish();
}

fn bench_network_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("network_operations");

    group.bench_function("network_request_processing", |b| {
        b.to_async(&rt).iter_batched(|| {
            let temp_dir = TempDir::new().unwrap();
            let storage = Box::new(Storage::new(temp_dir.path()).unwrap());
            let network = Network::new(storage).unwrap();

            (network, temp_dir)
        }, |(network, _temp_dir)| async move {
            for _ in 0..1000 {
                let response = network.process_request(NetworkRequest::Ping).await.unwrap();
                assert_eq!(response, symbios_mvp::network::NetworkResponse::Pong);
            }
        }, BatchSize::SmallInput)
    });

    group.finish();
}

fn bench_transaction_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_creation");

    group.bench_function("transaction_creation_ed25519", |b| {
        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());

        b.iter(|| {
            let mut tx = Transaction::new(sender.clone(), receiver.clone(), 100, 0);
            tx.sign(&private_key).unwrap();
        });
    });

    group.bench_function("transaction_creation_pq", |b| {
        let (sender, private_key) = Transaction::generate_keypair_with_pq().unwrap();
        let receiver = PublicKey::new("bob".to_string());

        b.iter(|| {
            let mut tx = Transaction::new(sender.clone(), receiver.clone(), 100, 0);
            tx.sign(&private_key).unwrap();
        });
    });

    group.finish();
}

fn bench_block_creation_and_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_operations");

    group.bench_function("block_creation_and_signing", |b| {
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        b.iter(|| {
            let mut block = Block::new(
                symbios_mvp::types::Hash::new(b"previous"),
                1,
                vec![],
                validator.clone()
            );
            block.sign(&private_key).unwrap();
        });
    });

    group.bench_function("block_validation", |b| {
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());
        let mut block = Block::new(
            symbios_mvp::types::Hash::new(b"previous"),
            1,
            vec![],
            validator
        );
        block.sign(&private_key).unwrap();

        b.iter(|| {
            block.verify().unwrap();
        });
    });

    group.finish();
}

fn bench_simple_node_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("simple_node_operations");

    group.bench_function("simple_node_transaction_processing", |b| {
        b.to_async(&rt).iter_batched(|| {
            SimpleNode::new("bench_node".to_string())
        }, |mut node| async move {
            for i in 0..100 {
                node.process_simple_transaction(
                    &format!("sender{}", i),
                    &format!("receiver{}", i),
                    100
                ).await.unwrap();
            }
        }, BatchSize::SmallInput)
    });

    group.finish();
}

fn bench_state_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_operations");

    group.bench_function("state_transaction_application", |b| {
        let mut state = State::new();
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());

        b.iter(|| {
            let tx = Transaction::new(sender.clone(), receiver.clone(), 100, 0);
            state.apply_transaction(&tx).unwrap();
        });
    });

    group.bench_function("state_block_application", |b| {
        let mut state = State::new();
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        b.iter(|| {
            let mut block = Block::new(
                state.last_block_hash,
                state.height + 1,
                vec![],
                validator.clone()
            );
            block.sign(&private_key).unwrap();
            state.apply_block(&block).unwrap();
        });
    });

    group.finish();
}

fn bench_hash_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_operations");

    group.bench_function("hash_creation_sha3", |b| {
        let data = b"The quick brown fox jumps over the lazy dog";

        b.iter(|| {
            symbios_mvp::types::Hash::new(data);
        });
    });

    group.bench_function("transaction_hash_calculation", |b| {
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());
        let tx = Transaction::new(sender, receiver, 100, 0);

        b.iter(|| {
            tx.calculate_hash();
        });
    });

    group.bench_function("block_hash_calculation", |b| {
        let validator = PublicKey::new("validator".to_string());
        let block = Block::new(
            symbios_mvp::types::Hash::new(b"previous"),
            1,
            vec![],
            validator
        );

        b.iter(|| {
            block.hash();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_tps,
    bench_crypto_operations,
    bench_storage_operations,
    bench_network_operations,
    bench_transaction_creation,
    bench_block_creation_and_validation,
    bench_simple_node_operations,
    bench_state_operations,
    bench_hash_operations
);
criterion_main!(benches);
