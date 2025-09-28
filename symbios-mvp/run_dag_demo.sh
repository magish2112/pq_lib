#!/bin/bash

# DAG Mempool Demo Script
# Demonstrates the new DAG functionality

echo "🚀 Symbios Network DAG Mempool Demo"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Starting the network...${NC}"
docker-compose up -d

echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 10

echo -e "${GREEN}Step 2: Network is running!${NC}"
echo "Available services:"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
echo "  - Prometheus: http://localhost:9090"
echo "  - Validator 1: localhost:9001 (metrics: 9101)"
echo "  - Validator 2: localhost:9002 (metrics: 9102)"
echo "  - Validator 3: localhost:9003 (metrics: 9103)"
echo "  - Validator 4: localhost:9004 (metrics: 9104)"

echo -e "${BLUE}Step 3: Monitoring DAG metrics...${NC}"
echo "DAG metrics will be available in Grafana dashboard"
echo "Look for these panels:"
echo "  - DAG Vertices"
echo "  - DAG Certificates"
echo "  - DAG Round"
echo "  - DAG Blocks/Second"

echo -e "${YELLOW}Step 4: Running DAG test (optional)...${NC}"
echo "To test DAG functionality, run in another terminal:"
echo "  python test_dag.py"
echo ""
echo "This will send transaction batches and monitor DAG growth."

echo -e "${GREEN}Step 5: View logs${NC}"
echo "Monitor validator logs:"
echo "  docker-compose logs -f validator-1"
echo ""
echo "Monitor all services:"
echo "  docker-compose logs -f"

echo ""
echo -e "${RED}To stop the demo:${NC}"
echo "  docker-compose down"

echo ""
echo -e "${GREEN}🎉 DAG Mempool Demo is ready!${NC}"
echo "The network is now running with DAG capabilities enabled."

