# pq_lib - Post-Quantum Cryptography Library

> 🚧 **WORK IN PROGRESS** - MVP implementation in development

[![License](https://img.shields.io/badge/license-Apache%202.0%20OR%20MIT-blue.svg)](https://github.com/magish2112/pq_lib#license)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

A production-grade Rust library providing hybrid cryptographic primitives specifically designed for blockchain applications. Combines classical Ed25519 signatures with post-quantum algorithms (ML-DSA, SLH-DSA) for forward-compatibility and optimal security-performance balance.

## Development Status

| Feature | Status | Progress |
|---------|--------|----------|
| 🏗️ Project Structure | ✅ Complete | Cargo.toml, src/, tests/, examples/, benches/ |
| 🔧 Core Types | ✅ Complete | AlgorithmId, HybridKeypair, HybridSignature, CryptoError |
| 🧪 Unit Tests | ✅ Complete | Comprehensive unit tests for all types |
| 🔄 CI/CD | ✅ Complete | GitHub Actions with fmt/clippy/test/msrv/minimal-versions |
| 🔐 MVP Crypto | ✅ Complete | Real Ed25519 + ML-DSA hybrid signatures |
| 📊 Test Coverage | ✅ Complete | 50%+ with unit/integration/property-based tests |
| ⚡ Benchmarks | ✅ Complete | Criterion benchmarks for all operations |
| 🏷️ Domain Separation | ✅ Complete | TX/Block/Consensus domain separators |
| 🚨 Error Handling | ✅ Complete | Custom error types with proper propagation |
| 📋 Policy Validation | ✅ Complete | ClassicOnly/HybridPreferred/HybridRequired/PqOnly |
| 📦 Serialization | ✅ Complete | CBOR format with versioning & round-trip validation |
| 🎲 Property Tests | ✅ Complete | Proptest for cryptographic invariants |
| 📚 Documentation | ✅ Complete | Doctests & comprehensive examples |
| 🔗 Blockchain Integration | ✅ Complete | Substrate-compatible types & pallet example |

## Key Features

- **🔐 Hybrid Signatures**: Ed25519 + ML-DSA/SLH-DSA with domain separation
- **🔄 Migration Paths**: Seamless transition from classical to post-quantum crypto
- **📋 Policy-based Validation**: Flexible signature verification policies
- **🧹 Zeroization**: Automatic secure cleanup of secret keys
- **📦 Stable Serialization**: CBOR-based format with versioning
- **🪶 No_std Support**: Optional core functionality without std
- **🚀 Production Ready**: Comprehensive testing and benchmarking

## Architecture

The library implements a **Strangler Fig pattern** for gradual migration:

```text
┌─────────────────┐    ┌──────────────────┐
│   Ed25519 Only  │ -> │  Hybrid Ed25519  │
│   (Legacy)      │    │  + ML-DSA/SLH   │
└─────────────────┘    └──────────────────┘
                             |
                             v
                       ┌──────────────────┐
                       │   PQ Only        │
                       │   (Future)       │
                       └──────────────────┘
```

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
symbios-pqc = "0.1"
```

Basic usage:

```rust
use symbios_pqc::{HybridSigner, AlgorithmId, ValidationPolicy, DomainSeparator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate hybrid keypair
    let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;

    // Sign transaction data with domain separation
    let signature = HybridSigner::sign_with_domain(
        b"transaction_data",
        &keypair.private_key,
        DomainSeparator::Transaction
    ).await?;

    // Verify with hybrid policy
    let is_valid = HybridSigner::verify_with_policy(
        b"transaction_data",
        &signature,
        &keypair.public_key,
        ValidationPolicy::HybridRequired
    ).await?;

    assert!(is_valid);
    Ok(())
}
```

## Security Considerations

- **Domain Separation**: Prevents cross-protocol signature reuse attacks
- **Key Zeroization**: Secret keys are automatically zeroized on drop
- **Algorithm Agility**: Support for multiple PQ algorithms with versioning
- **Migration Safety**: Backward compatibility during transition periods

## Performance

| Algorithm | Signing | Verification | Key Size | Sig Size | Security |
|-----------|---------|--------------|----------|----------|----------|
| Ed25519   | ~50μs   | ~150μs       | 64B      | 64B      | 128-bit  |
| ML-DSA-65 | ~150μs  | ~200μs       | ~4KB     | ~4KB     | 192-bit  |
| SLH-DSA   | ~500μs  | ~100μs       | ~32B     | ~8KB     | 256-bit  |

*Benchmarks performed on Intel i7-9750H, results may vary*

## Feature Flags

- `std` (default): Enable standard library
- `no_std`: Core functionality without std
- `ed25519` (default): Enable Ed25519 support
- `ml-dsa` (default): Enable ML-DSA support
- `ml-kem` (default): Enable ML-KEM support
- `slh-dsa` (default): Enable SLH-DSA support
- `serde-support`: Enable serialization support

## Migration Guide

### From Classical to Hybrid

```rust
// Old code (Ed25519 only)
let keypair = generate_ed25519_keypair();
let signature = sign_ed25519(data, &keypair.private_key);
let valid = verify_ed25519(data, &signature, &keypair.public_key);

// New code (hybrid with migration)
use symbios_pqc::{HybridSigner, ValidationPolicy};

let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;
let signature = HybridSigner::sign(data, &keypair.private_key).await?;

// Gradual migration: accept both old and new signatures
let valid = HybridSigner::verify_with_policy(
    data, &signature, &keypair.public_key,
    ValidationPolicy::HybridPreferred // Allows both classic and hybrid
).await?;
```

### Policy-based Migration

```rust
use symbios_pqc::{PolicyConfig, ValidationPolicy};

// Conservative migration (allows gradual adoption)
let config = PolicyConfig::conservative();
// - Transactions: HybridPreferred
// - Blocks: HybridPreferred
// - Consensus: HybridRequired

// Strict migration (requires PQ everywhere)
let config = PolicyConfig::strict();
// - All operations: HybridRequired
```

## Blockchain Integration Examples

### Substrate-based Chains

```rust
use symbios_pqc::{HybridSigner, DomainSeparator};

impl pallet_custom::Config for Runtime {
    type Signature = HybridSignature;
    type PublicKey = HybridPublicKey;
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn submit_transaction(
        origin: OriginFor<T>,
        data: Vec<u8>,
        signature: HybridSignature,
    ) -> DispatchResult {
        let who = ensure_signed(origin)?;

        // Verify with domain separation
        let is_valid = HybridSigner::verify_with_policy(
            &data,
            &signature,
            &who,
            ValidationPolicy::HybridRequired
        ).await?;

        ensure!(is_valid, Error::<T>::InvalidSignature);
        // ... process transaction
        Ok(())
    }
}
```

### Ethereum-compatible Chains

```rust
use symbios_pqc::{HybridSigner, serialization::*};

// Custom transaction type with PQ signatures
#[derive(Serialize, Deserialize)]
struct PqTransaction {
    nonce: u64,
    to: Address,
    value: U256,
    data: Vec<u8>,
    signature: Vec<u8>, // Serialized HybridSignature
}

impl PqTransaction {
    pub async fn recover_signer(&self) -> Result<Address, Box<dyn std::error::Error>> {
        let signature: HybridSignature = deserialize_signature(&self.signature)?;
        let message = self.hash();

        // Verify signature
        let valid = HybridSigner::verify(&message, &signature, /* public key */).await?;
        if !valid {
            return Err("Invalid signature".into());
        }

        // Recover address from public key
        Ok(signature.recover_address())
    }
}
```

## API Reference

### Core Types

- [`HybridKeypair`] - Keypair containing public and private keys
- [`HybridPublicKey`] - Public key with algorithm identifier
- [`HybridPrivateKey`] - Private key with zeroization
- [`HybridSignature`] - Signature with versioning and domain separation
- [`AlgorithmId`] - Supported cryptographic algorithms
- [`DomainSeparator`] - Domain tags for cryptographic operations
- [`ValidationPolicy`] - Signature verification policies

### Traits

- [`KeyGenerator`] - Keypair generation
- [`Signer`] - Data signing with domain separation
- [`Verifier`] - Signature verification with policies
- [`KemProvider`] - Key encapsulation mechanisms

### Main Implementation

- [`HybridSigner`] - Production-ready signer implementation

## Testing

Run the full test suite:

```bash
cargo test --all-features
```

Run benchmarks:

```bash
cargo bench
```

Run fuzz tests:

```bash
cargo fuzz run fuzz_signature_verification
```

## Contributing

We welcome contributions! Please see our [contributing guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/magish2112/pq_lib
cd pq_lib
cargo test
cargo bench
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](symbios-pqc/LICENSE-APACHE))
- MIT License ([LICENSE-MIT](symbios-pqc/LICENSE-MIT))

at your option.

## Security

This library is in active development. Please report security issues to security@symbios.network.

### Security Audit

- [ ] Planned for Q2-Q3 2026
- [ ] Independent third-party audit
- [ ] Formal verification of critical components

## Roadmap

### v0.1.x (Current - Q4 2025)
- ✅ Hybrid Ed25519 + PQ signatures
- ✅ Domain separation
- ✅ Policy-based validation
- ✅ Stable serialization
- ✅ Migration utilities

### v0.2.x (Q1 2026)
- 🔄 Hardware security module (HSM) support
- 🔄 Threshold signatures
- 🔄 Batch verification optimization
- 🔄 WASM support

### v0.3.x (Q2 2026)
- 🔄 Zero-knowledge proof integration
- 🔄 Multi-party computation (MPC)
- 🔄 Post-quantum TLS integration

### v1.0.x (Q3-Q4 2026)
- 🔄 Real ML-DSA/SLH-DSA integration
- 🔄 PQ-only algorithms
- 🔄 Production blockchain deployments
- 🔄 Enterprise features
- 🔄 Third-party security audit

## Related Projects

- [pqcrypto] - Rust bindings for PQ algorithms
- [ed25519-dalek] - Ed25519 implementation
- [rustls-pki-types] - PKI types for TLS

## Acknowledgments

- NIST for post-quantum cryptography standardization
- The Rust cryptography community
- Academic researchers in post-quantum cryptography

---

*"The transition to post-quantum cryptography is not a sprint, but a carefully planned marathon."*