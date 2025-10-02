//! Comprehensive benchmarks for Symbios PQC

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use symbios_pqc::*;
use tokio::runtime::Runtime;

fn bench_keypair_generation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("keypair_generation");

    group.bench_function("ed25519", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::generate_keypair(AlgorithmId::Ed25519).await.unwrap())
            })
        })
    });

    if AlgorithmId::MlDsa65.is_available() {
        group.bench_function("ml_dsa_65_hybrid", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await.unwrap())
                })
            })
        });
    }

    if AlgorithmId::SlhDsaShake256f.is_available() {
        group.bench_function("slh_dsa_hybrid", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::generate_keypair(AlgorithmId::SlhDsaShake256f).await.unwrap())
                })
            })
        });
    }

    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Prepare keypairs
    let ed25519_keypair = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::Ed25519)).unwrap();
    let ml_dsa_keypair = if AlgorithmId::MlDsa65.is_available() {
        Some(rt.block_on(HybridSigner::generate_keypair(AlgorithmId::MlDsa65)).unwrap())
    } else {
        None
    };

    let test_data = b"Hello, Symbios Network! This is a test message for benchmarking hybrid cryptographic signatures. It should be long enough to provide realistic performance measurements.";

    let mut group = c.benchmark_group("signing");

    group.bench_function("ed25519_transaction", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::sign_with_domain(
                    test_data,
                    &ed25519_keypair.private_key,
                    DomainSeparator::Transaction,
                ).await.unwrap())
            })
        })
    });

    if let Some(ref keypair) = ml_dsa_keypair {
        group.bench_function("ml_dsa_65_transaction", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::sign_with_domain(
                        test_data,
                        &keypair.private_key,
                        DomainSeparator::Transaction,
                    ).await.unwrap())
                })
            })
        });
    }

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Prepare signatures
    let ed25519_keypair = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::Ed25519)).unwrap();
    let ed25519_sig = rt.block_on(HybridSigner::sign_with_domain(
        b"test data", &ed25519_keypair.private_key, DomainSeparator::Transaction
    )).unwrap();

    let ml_dsa_keypair = if AlgorithmId::MlDsa65.is_available() {
        Some(rt.block_on(HybridSigner::generate_keypair(AlgorithmId::MlDsa65)).unwrap())
    } else {
        None
    };
    let ml_dsa_sig = if let Some(ref keypair) = ml_dsa_keypair {
        Some(rt.block_on(HybridSigner::sign_with_domain(
            b"test data", &keypair.private_key, DomainSeparator::Transaction
        )).unwrap())
    } else {
        None
    };

    let test_data = b"test data";

    let mut group = c.benchmark_group("verification");

    group.bench_function("ed25519_classic_only", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::verify_with_policy(
                    test_data, &ed25519_sig, &ed25519_keypair.public_key,
                    ValidationPolicy::ClassicOnly,
                ).await.unwrap())
            })
        })
    });

    group.bench_function("ed25519_hybrid_preferred", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::verify_with_policy(
                    test_data, &ed25519_sig, &ed25519_keypair.public_key,
                    ValidationPolicy::HybridPreferred,
                ).await.unwrap())
            })
        })
    });

    if let (Some(ref keypair), Some(ref sig)) = (&ml_dsa_keypair, &ml_dsa_sig) {
        group.bench_function("ml_dsa_hybrid_required", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::verify_with_policy(
                        test_data, sig, &keypair.public_key,
                        ValidationPolicy::HybridRequired,
                    ).await.unwrap())
                })
            })
        });

        group.bench_function("ml_dsa_pq_only", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::verify_with_policy(
                        test_data, sig, &keypair.public_key,
                        ValidationPolicy::PqOnly,
                    ).await.unwrap())
                })
            })
        });
    }

    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let keypair = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::Ed25519)).unwrap();
    let signature = rt.block_on(HybridSigner::sign(
        b"serialization test", &keypair.private_key
    )).unwrap();

    let mut group = c.benchmark_group("serialization");

    group.bench_function("serialize_signature", |b| {
        b.iter(|| {
            black_box(symbios_pqc::serialization::serialize_signature(&signature).unwrap())
        })
    });

    let serialized = symbios_pqc::serialization::serialize_signature(&signature).unwrap();

    group.bench_function("deserialize_signature", |b| {
        b.iter(|| {
            black_box(symbios_pqc::serialization::deserialize_signature(&serialized).unwrap())
        })
    });

    group.bench_function("serialize_public_key", |b| {
        b.iter(|| {
            black_box(symbios_pqc::serialization::serialize_public_key(&keypair.public_key).unwrap())
        })
    });

    let pub_serialized = symbios_pqc::serialization::serialize_public_key(&keypair.public_key).unwrap();

    group.bench_function("deserialize_public_key", |b| {
        b.iter(|| {
            black_box(symbios_pqc::serialization::deserialize_public_key(&pub_serialized).unwrap())
        })
    });

    group.finish();
}

fn bench_domain_separation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let keypair = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::Ed25519)).unwrap();
    let test_data = b"Same message, different domains";

    let mut group = c.benchmark_group("domain_separation");

    group.bench_function("transaction_domain", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::sign_with_domain(
                    test_data, &keypair.private_key, DomainSeparator::Transaction,
                ).await.unwrap())
            })
        })
    });

    group.bench_function("block_domain", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::sign_with_domain(
                    test_data, &keypair.private_key, DomainSeparator::Block,
                ).await.unwrap())
            })
        })
    });

    group.bench_function("consensus_domain", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(HybridSigner::sign_with_domain(
                    test_data, &keypair.private_key, DomainSeparator::Consensus,
                ).await.unwrap())
            })
        })
    });

    group.finish();
}

fn bench_kem_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if let Ok(keypair) = rt.block_on(HybridSigner::generate_keypair(AlgorithmId::MlDsa65)) {
        let mut group = c.benchmark_group("kem_operations");

        group.bench_function("encapsulate", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::encapsulate(&keypair.public_key).await.unwrap())
                })
            })
        });

        let (shared_secret1, ciphertext) = rt.block_on(HybridSigner::encapsulate(&keypair.public_key)).unwrap();

        group.bench_function("decapsulate", |b| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(HybridSigner::decapsulate(&ciphertext, &keypair.private_key).await.unwrap())
                })
            })
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_signing,
    bench_verification,
    bench_serialization,
    bench_domain_separation,
    bench_kem_operations,
);
criterion_main!(benches);

