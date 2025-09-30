# Symbios Network - Research Blockchain Prototype

⚠️ **EXPERIMENTAL RESEARCH PROJECT** ⚠️

[![Rust](https://img.shields.io/badge/rust-1.89+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Research prototype exploring DAG-based mempool design and post-quantum cryptography integration.**

## 📁 Repository Structure

This repository contains the **Symbios Network Research Prototype** - an experimental blockchain implementation for research purposes:

- **`symbios-mvp/`** - Main Rust prototype implementation
- **`README.md`** - Project overview and development status
- **`deploy_to_github.ps1`** - Development deployment script

## 🎯 Research Focus

### Current Implementation

1. **Smart DAG Mempool** - Basic priority queue implementation with fee-based ordering
2. **Post-Quantum Cryptography** - Integration with ML-KEM, ML-DSA, and SLH-DSA algorithms
3. **Modular Architecture** - Clean separation of concerns across 20+ modules
4. **Basic P2P Networking** - Libp2p integration for peer discovery and messaging

### Research Components

- 🔬 **DAG Mempool Design** - Exploring transaction ordering and batching strategies
- 🔬 **PQ Crypto Integration** - Post-quantum algorithm evaluation and testing
- 🔬 **Modular Architecture** - Component-based design for easy experimentation
- 🔬 **Basic Consensus Logic** - Simplified BFT concepts for research

## ⚠️ IMPORTANT DISCLAIMERS

### 🚨 NOT PRODUCTION READY
- **DO NOT USE in production environments**
- **No security audit performed**
- **Experimental cryptography implementation**
- **Performance claims are theoretical targets only**

### 🚨 CURRENT LIMITATIONS
- **Simple demo consensus** (not real BFT)
- **Basic transaction processing** (no parallel execution)
- **Limited testing coverage** (not 87% as previously claimed)
- **Research-grade networking** (not production P2P)
- **Simplified state management** (negative balances allowed)

## 🚀 Development Setup

### Prerequisites

- **Rust 1.70+** - [Install Rust](https://rustup.rs/)
- **Git** - Version control

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/symbios-network.git
cd symbios-network/symbios-mvp

# Build the project
cargo build --release

# Run basic tests
cargo test

# Run benchmarks (limited scope)
cargo bench
```

### Run Research Demo

```bash
# Simple node demo (research purposes only)
cargo run --bin simple_node

# Network demo (experimental)
cargo run --bin network_demo
```

## 📊 Current Status

| Component | Implementation Status | Notes |
|-----------|---------------------|--------|
| **DAG Mempool** | ✅ Basic implementation | Fee-based ordering, simplified batching |
| **PQ Cryptography** | ✅ Integrated | ML-KEM, ML-DSA, SLH-DSA available |
| **P2P Networking** | ✅ Basic libp2p | Peer discovery and messaging |
| **Storage** | ✅ RocksDB integration | Basic persistence |
| **Monitoring** | ✅ Basic metrics | Prometheus integration |
| **Consensus** | ⚠️ Demo only | Simplified BFT logic |
| **State Management** | ⚠️ Simplified | Basic account model |
| **Security** | ⚠️ Research level | No production audit |

## 🧪 Testing Status

Current testing includes:

### Available Tests
- **Unit Tests** - Core data structure validation
- **Property-based Tests** - Mathematical property verification
- **Integration Tests** - Basic component interaction
- **Benchmark Tests** - Performance measurement

### Test Coverage
- **Current**: ~30-40% (estimated)
- **Target**: Comprehensive coverage for research validation
- **Note**: Previous claims of 87%+ coverage were inaccurate

### Running Tests

```bash
# All tests
cargo test

# Property-based tests only
cargo test proptests

# Performance benchmarks
cargo bench
```

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   P2P Network   │    │   Consensus     │    │   Storage       │
│   (libp2p)      │◄──►│   (Demo)        │◄──►│   (RocksDB)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Smart DAG       │    │ PQ Crypto       │    │ Health Monitor  │
│ Mempool         │    │ (ML-KEM/DSA)    │    │ & Metrics       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Components

- **Network Layer**: Basic libp2p integration with gossipsub messaging
- **Consensus Engine**: Simplified demo consensus (not production BFT)
- **Storage Engine**: RocksDB with basic transaction/block storage
- **Cryptography**: Post-quantum algorithms integrated (research level)
- **Mempool**: DAG-based with fee prioritization (experimental)
- **Monitoring**: Basic Prometheus metrics collection

## 📚 Documentation

### Project Documentation

- **[Main README](symbios-mvp/README.md)** - Detailed implementation documentation
- **[Technical Documentation]** - Architecture and design decisions
- **[API Documentation](https://docs.rs/symbios-mvp)** - Generated Rust documentation

### Technical Specifications

- **Architecture**: Modular, async-first design for research
- **Security**: Post-quantum cryptography exploration
- **Performance**: Research benchmarks and profiling
- **Scalability**: Conceptual horizontal scaling design

## 🔧 Development

### Prerequisites for Development

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install development tools
rustup component add clippy rustfmt
cargo install cargo-audit
```

### Development Workflow

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

## 🚀 Research Roadmap

### Current Phase: Research & Experimentation
- [x] **Basic DAG mempool implementation**
- [x] **Post-quantum cryptography integration**
- [x] **Modular architecture design**
- [x] **Basic testing framework**

### Future Research Directions
- [ ] **Advanced consensus algorithms** - Move beyond demo implementation
- [ ] **Production-grade security** - Comprehensive audit and hardening
- [ ] **Performance optimization** - Real benchmarks and profiling
- [ ] **State management** - Proper transaction validation and state transitions
- [ ] **Network protocols** - Production-ready P2P implementation

## 🤝 Contributing

We welcome research contributions and experimental work!

### Research Areas
- 🔬 **DAG Consensus** - Advanced mempool and consensus research
- 🔬 **Post-Quantum Security** - Cryptography research and validation
- 🔬 **Performance Engineering** - Optimization and benchmarking
- 📚 **Documentation** - Technical writing and research papers

## 📄 License

This project is licensed under the MIT License - see [LICENSE](symbios-mvp/LICENSE) file.

## ⚠️ Important Research Notice

**This is experimental research software:**
- **Not for production use** - Research prototype only
- **No security guarantees** - Not audited or validated for security
- **Educational purposes** - Designed for research and learning
- **Experimental features** - May contain incomplete or untested code
- **Use at your own risk** - For development and research only

## 🌟 Acknowledgments

<<<<<<< HEAD
Built by magish
=======
Built with ❤️ for blockchain research and education
>>>>>>> 954f6d9 (docs: update documentation to reflect actual project status)

*"Exploring the frontiers of blockchain technology through research and experimentation."*

---

## 📞 Contact & Community

- **GitHub Issues**: [Bug reports & technical discussions](https://github.com/YOUR_USERNAME/symbios-network/issues)
- **Research Discussions**: [Academic and technical exchanges](https://github.com/YOUR_USERNAME/symbios-network/discussions)

---

**Research • Experiment • Learn** 🔬✨
