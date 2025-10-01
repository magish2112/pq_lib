# Symbios Network - Research Blockchain Prototype

⚠️ **EXPERIMENTAL RESEARCH PROJECT - NOT FOR PRODUCTION USE** ⚠️

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](symbios-mvp/LICENSE)

> **Academic research prototype exploring basic blockchain concepts. Contains known security vulnerabilities and performance limitations.**

## 📁 Repository Structure

```
symbios-network/
├── symbios-mvp/          # Main Rust research implementation
├── README.md             # Project overview
└── deploy_to_github.ps1  # Deployment script
```

## 🎯 Research Focus

### What This Project Actually Implements

1. **Basic DAG Mempool** - Simple priority queue with fee-based ordering
2. **Post-Quantum Cryptography** - ML-KEM, ML-DSA, SLH-DSA integration (research level)
3. **Modular Rust Architecture** - Clean code organization for research
4. **Basic P2P Networking** - Libp2p integration for peer discovery

### Research Areas Under Exploration

- Transaction ordering strategies in DAG structures
- Post-quantum cryptographic algorithm evaluation
- Modular blockchain architecture patterns
- Basic consensus concepts

## ⚠️ CRITICAL WARNINGS

### 🚨 SECURITY RISKS
- **Known security vulnerabilities** - Not audited or hardened
- **Experimental cryptography** - May contain implementation errors
- **No security guarantees** - Use at your own risk

### 🚨 FUNCTIONAL LIMITATIONS
- **Demo consensus only** - Not real Byzantine fault tolerance
- **Sequential processing** - No parallel transaction execution
- **Basic networking** - Research-grade P2P implementation
- **Simplified state** - No proper validation or pruning

### 🚨 PERFORMANCE REALITY
- **~100 TPS maximum** (not thousands as previously claimed)
- **Basic benchmarks only** - No comprehensive performance testing
- **Memory leaks possible** - Not optimized for long-running processes

## 🚀 Quick Setup (Research Only)

### Prerequisites
- Rust 1.70+
- Git

### Build & Test
```bash
git clone https://github.com/[username]/symbios-network
cd symbios-network/symbios-mvp

# Build research prototype
cargo build --release

# Run basic unit tests
cargo test
```

### Run Demo (Educational Purposes Only)
```bash
# Python simulation demo
python demo_node.py

# Performance benchmarks
./simple_benchmark.ps1
```

## 📊 Current Status

| Component | Status | Reality Check |
|-----------|--------|---------------|
| DAG Mempool | ✅ Basic | Simple priority queue, no advanced features |
| PQ Crypto | ✅ Research | Algorithms integrated but not production-hardened |
| Networking | ✅ Basic | Libp2p works but not production-ready |
| Storage | ✅ Basic | RocksDB integration, minimal features |
| Consensus | ⚠️ Demo | Simplified logic, not real BFT |
| Testing | ⚠️ Basic | ~30-40% coverage, needs improvement |

## 🧪 Testing Reality

### Actual Test Coverage
- **Unit Tests**: Basic data structure validation
- **Integration**: Simple component interaction
- **Benchmarks**: Basic performance measurement
- **Coverage**: ~30-40% (not 87%+ as previously stated)

### Known Issues
- Race conditions in concurrent operations
- Memory leaks in long-running processes
- Non-deterministic behavior with system time
- Unbounded data structure growth

## 🏗️ Architecture (Simplified)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Network   │    │  Consensus  │    │   Storage   │
│  (libp2p)   │◄──►│   (Demo)    │◄──►│ (RocksDB)   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                │                │
       ▼                ▼                ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ DAG Mempool │    │ PQ Crypto   │    │ Monitoring  │
│ (Priority Q)│    │ (Research)  │    │ (Prometheus)│
└─────────────┘    └─────────────┘    └─────────────┘
```

## 📚 Documentation

- **[Implementation Details](symbios-mvp/README.md)** - Technical documentation
- **[Limitations](symbios-mvp/LIMITATIONS.md)** - What doesn't work
- **[Benchmarks](symbios-mvp/benchmarks.md)** - Performance measurements
- **[License Check](symbios-mvp/LICENSE_CHECK.md)** - Dependency analysis

## 🔬 Research Directions

### Current Focus
- Basic DAG transaction ordering
- Post-quantum algorithm evaluation
- Modular architecture patterns
- Educational blockchain concepts

### Future Possibilities (Not Implemented)
- Real consensus algorithms
- Production security hardening
- Performance optimization
- Smart contract support

## 🤝 Research Contributions

We accept research contributions related to:
- Academic blockchain research
- Cryptographic algorithm evaluation
- Architecture pattern exploration
- Educational improvements

## 📄 License

**Proprietary License** - All rights reserved. No copying or distribution without explicit written permission.

See [LICENSE](symbios-mvp/LICENSE) for complete terms.

## ⚠️ FINAL WARNING

**This software is dangerous to use:**

- Contains known security vulnerabilities
- Not suitable for any production use
- May cause data loss or security breaches
- Use ONLY for personal research on isolated systems
- No warranty of any kind

**DO NOT use with real funds or in production environments.**

---

*"Educational blockchain research - handle with care"* 🔬⚠️