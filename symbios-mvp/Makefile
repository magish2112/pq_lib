# Symbios Network Production Makefile

.PHONY: help build run test clean production minimal high-perf docker-build docker-run docker-stop docker-logs load-test benchmark

# Default target
help:
	@echo "Symbios Network Production Blockchain"
	@echo ""
	@echo "Available commands:"
	@echo "  build         - Build the project"
	@echo "  run           - Run a single node locally"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
	@echo "  production    - Run production node (standard config)"
	@echo "  minimal       - Run minimal node (low resources)"
	@echo "  high-perf     - Run high-performance node"
	@echo "  ultra-perf    - Run ultra-performance node (100k TPS cluster)"
	@echo "  benchmark     - Run performance benchmark"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-run    - Run the full network with Docker Compose"
	@echo "  docker-stop   - Stop Docker containers"
	@echo "  docker-logs   - Show Docker logs"
	@echo "  load-test     - Run load generator"

# Build the project
build:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean
	rm -rf data/
	rm -rf monitoring/grafana/data/
	rm -rf monitoring/prometheus/data/

# Run single node locally (for development)
run:
	RUST_LOG=info cargo run

# Docker commands
docker-build:
	docker-compose build

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Load testing
load-test:
	docker-compose --profile load-test up load-generator

# Development setup
dev-setup:
	cargo install cargo-watch
	cargo install cargo-expand

# Watch for changes and rebuild
watch:
	cargo watch -x run

# Format code
fmt:
	cargo fmt

# Lint code
clippy:
	cargo clippy

# Full CI pipeline
ci: fmt clippy test build

# Production node configurations
production:
	@echo "Starting Production Node (Standard Configuration)..."
	export HARDWARE_PROFILE=standard && ./run_production.sh

minimal:
	@echo "Starting Minimal Node (Low Resource Configuration)..."
	export HARDWARE_PROFILE=minimal && ./run_production.sh

high-perf:
	@echo "Starting High-Performance Node..."
	export HARDWARE_PROFILE=high-performance && ./run_production.sh

ultra-perf:
	@echo "Starting Ultra-Performance Node (100k TPS Cluster)..."
	export HARDWARE_PROFILE=ultra-performance && ./run_production.sh

# Benchmarking
benchmark:
	@echo "Running Performance Benchmark..."
	@echo "This will test the node's performance under load"
	@echo "Make sure the node is running first with 'make production'"
	@echo ""
	@echo "Benchmark configuration:"
	@echo "  Duration: 60 seconds"
	@echo "  Target TPS: 300"
	@echo "  Batch size: 25 transactions"
	@echo ""
	python test_dag.py

# Create release build
release: clean
	cargo build --release --features production
	strip target/release/symbios-mvp

# Show project info
info:
	@echo "Project: Symbios Network Production"
	@echo "Version: $(shell cargo pkgid | cut -d# -f2 | cut -d: -f2)"
	@echo "Rust Version: $(shell rustc --version)"
	@echo "Target: $(shell rustc -vV | grep host | cut -d: -f2 | tr -d ' ')"
	@echo ""
	@echo "Hardware Profiles:"
	@echo "  minimal       - 64MB RAM, 256MB storage (Raspberry Pi)"
	@echo "  standard      - 256MB RAM, 1GB storage (modern server)"
	@echo "  high-perf     - 1GB RAM, 10GB storage (dedicated hardware)"
	@echo "  ultra-perf    - 8GB RAM, 50GB storage (100k TPS cluster)"

# Quick start
quick-start: build production
