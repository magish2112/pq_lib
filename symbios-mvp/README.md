# Symbios Network - Technical Implementation

## Overview

This directory contains the Rust implementation of the Symbios Network research prototype. This is a basic blockchain system for educational and research purposes only.

## Architecture

### Core Components

- **types.rs** - Data structures and cryptography
- **state_machine.rs** - Account state management
- **minimal_dag.rs** - Basic DAG mempool implementation
- **consensus.rs** - Simple consensus logic (demo only)
- **storage.rs** - RocksDB persistence layer
- **network.rs** - Basic P2P networking with libp2p

### Research Modules (Experimental)

- **pqcrypto.rs** - Post-quantum cryptography integration
- **hotstuff_consensus.rs** - HotStuff consensus research
- **parallel_execution.rs** - Parallel transaction processing research

## Building

```bash
cargo build --release
```

## Testing

```bash
# Unit tests
cargo test

# DAG tests specifically
cargo test dag_tests
```

## Performance

Current performance is limited:
- ~100 TPS maximum
- Sequential transaction processing
- Basic benchmarks only

See [benchmarks.md](benchmarks.md) for details.

## Security

**WARNING**: This code contains known security vulnerabilities and should never be used in production.

- No security audit performed
- Experimental cryptography implementations
- Known race conditions and memory leaks

## License

See [LICENSE](LICENSE) file. This is proprietary software - no copying without permission.