#!/bin/bash

# Production Symbios Blockchain Node Launcher
# Optimized for resource-constrained environments

echo "🚀 Symbios Production Blockchain Node"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
HARDWARE_PROFILE="${HARDWARE_PROFILE:-standard}"
NODE_ID="${NODE_ID:-production-node}"
DATA_DIR="${DATA_DIR:-./data}"
METRICS_PORT="${METRICS_PORT:-9101}"

echo -e "${BLUE}Configuration:${NC}"
echo "  Hardware Profile: $HARDWARE_PROFILE"
echo "  Node ID: $NODE_ID"
echo "  Data Directory: $DATA_DIR"
echo "  Metrics Port: $METRICS_PORT"
echo ""

# Set environment variables based on hardware profile
case $HARDWARE_PROFILE in
    "minimal")
        echo -e "${YELLOW}🔧 Minimal hardware profile (for Raspberry Pi, old servers)${NC}"
        export MAX_MEMORY_MB=64
        export MAX_STORAGE_MB=256
        export CONSENSUS_ROUND_DURATION=5
        export MAX_PARALLEL_BATCH=10
        ;;
    "standard")
        echo -e "${GREEN}🔧 Standard hardware profile (for modern servers)${NC}"
        export MAX_MEMORY_MB=256
        export MAX_STORAGE_MB=1024
        export CONSENSUS_ROUND_DURATION=3
        export MAX_PARALLEL_BATCH=50
        ;;
    "high-performance")
        echo -e "${PURPLE}🔧 High-performance profile (for dedicated hardware)${NC}"
        export MAX_MEMORY_MB=1024
        export MAX_STORAGE_MB=10240
        export CONSENSUS_ROUND_DURATION=2
        export MAX_PARALLEL_BATCH=200
        ;;
    "ultra-performance")
        echo -e "${RED}🔧 Ultra-performance profile (for 100k TPS cluster)${NC}"
        export MAX_MEMORY_MB=8192
        export MAX_STORAGE_MB=51200
        export CONSENSUS_ROUND_DURATION=1
        export MAX_PARALLEL_BATCH=1000
        export DAG_MAX_VERTICES=10000
        export NETWORK_BATCH_SIZE=500
        export OPTIMISTIC_CONCURRENCY=true
        export SHARDING_ENABLED=true
        export NUM_SHARDS=16
        ;;
    *)
        echo -e "${RED}❌ Unknown hardware profile: $HARDWARE_PROFILE${NC}"
        echo "Available profiles: minimal, standard, high-performance, ultra-performance"
        exit 1
        ;;
esac

# Export common variables
export HARDWARE_PROFILE
export NODE_ID
export DATA_DIR
export METRICS_PORT

echo -e "${CYAN}Resource Limits:${NC}"
echo "  Memory: $MAX_MEMORY_MB MB"
echo "  Storage: $MAX_STORAGE_MB MB"
echo "  Consensus Round: $CONSENSUS_ROUND_DURATION seconds"
echo "  Max Parallel Batch: $MAX_PARALLEL_BATCH transactions"
echo ""

# Create data directory
echo -e "${BLUE}Setting up data directory...${NC}"
mkdir -p "$DATA_DIR"
echo "Data directory: $(realpath "$DATA_DIR")"

# Check if binary exists
if [ ! -f "./target/release/symbios-mvp" ]; then
    echo -e "${YELLOW}⚠️  Binary not found, building...${NC}"
    cargo build --release
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ Build completed${NC}"

# Start the node
echo -e "${GREEN}🚀 Starting Symbios Production Node...${NC}"
echo ""

# Run with logging
RUST_LOG=info ./target/release/symbios-mvp

echo ""
echo -e "${GREEN}✅ Node stopped${NC}"

