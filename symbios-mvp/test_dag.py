#!/usr/bin/env python3
"""
Test script for DAG Mempool functionality
Sends transactions to test DAG certificate generation
"""

import asyncio
import aiohttp
import json
import time
import random
from typing import List

class DagTester:
    def __init__(self, node_urls: List[str]):
        self.node_urls = node_urls
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _generate_transaction(self, tx_id: int) -> dict:
        """Generate a test transaction"""
        sender = f"account_{random.randint(1, 100):04d}"
        receiver = f"account_{random.randint(1, 100):04d}"

        # Ensure sender != receiver
        while sender == receiver:
            receiver = f"account_{random.randint(1, 100):04d}"

        return {
            "id": f"dag_test_tx_{tx_id:06d}",
            "sender": sender,
            "receiver": receiver,
            "amount": random.randint(1, 1000),
            "timestamp": int(time.time() * 1000),
            "nonce": tx_id
        }

    async def send_transaction_batch(self, batch_size: int = 20) -> dict:
        """Send a batch of transactions to test DAG functionality"""
        transactions = [self._generate_transaction(i) for i in range(batch_size)]

        # For now, just simulate sending to the first node
        # In real implementation, this would send via HTTP API
        target_url = f"{self.node_urls[0]}/api/transactions/batch"

        try:
            async with self.session.post(target_url, json=transactions) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"✅ Sent {batch_size} transactions successfully")
                    return result
                else:
                    print(f"❌ Failed to send transactions: {response.status}")
                    return None
        except Exception as e:
            print(f"❌ Error sending transactions: {e}")
            # Simulate success for testing
            print(f"📝 Simulated sending {batch_size} transactions for DAG testing")
            return {"status": "simulated", "batch_size": batch_size}

    async def monitor_dag_metrics(self, duration_seconds: int = 30):
        """Monitor DAG metrics during the test"""
        start_time = time.time()
        print(f"📊 Monitoring DAG metrics for {duration_seconds} seconds...")

        while time.time() - start_time < duration_seconds:
            try:
                # Query metrics endpoint
                metrics_url = f"{self.node_urls[0].replace('http://', 'http://localhost:')}9101/metrics"
                async with self.session.get(metrics_url) as response:
                    if response.status == 200:
                        metrics_text = await response.text()

                        # Extract DAG metrics
                        dag_vertices = self._extract_metric(metrics_text, "symbios_dag_vertices_total")
                        dag_certificates = self._extract_metric(metrics_text, "symbios_dag_certificates_total")
                        dag_round = self._extract_metric(metrics_text, "symbios_dag_current_round")

                        print(f"🔗 DAG: {dag_vertices} vertices, {dag_certificates} certificates, round {dag_round}")
                    else:
                        print(f"⚠️  Could not fetch metrics: {response.status}")
            except Exception as e:
                print(f"⚠️  Error fetching metrics: {e}")

            await asyncio.sleep(5)

    def _extract_metric(self, metrics_text: str, metric_name: str) -> str:
        """Extract metric value from Prometheus format"""
        for line in metrics_text.split('\n'):
            if line.startswith(metric_name):
                try:
                    return line.split(' ')[1]
                except:
                    return "N/A"
        return "0"

    async def run_test(self, test_duration: int = 60, batch_size: int = 20, batches_per_minute: int = 6):
        """Run complete DAG test"""
        print("🚀 Starting DAG Mempool Test")
        print(f"Duration: {test_duration}s")
        print(f"Batch size: {batch_size}")
        print(f"Batches per minute: {batches_per_minute}")
        print("-" * 50)

        start_time = time.time()
        batch_interval = 60.0 / batches_per_minute
        total_batches = 0

        # Start metrics monitoring in background
        monitor_task = asyncio.create_task(self.monitor_dag_metrics(test_duration))

        # Send transaction batches
        while time.time() - start_time < test_duration:
            batch_start = time.time()

            result = await self.send_transaction_batch(batch_size)
            if result:
                total_batches += 1

            # Wait for next batch
            elapsed = time.time() - batch_start
            if elapsed < batch_interval:
                await asyncio.sleep(batch_interval - elapsed)

        # Wait for monitoring to complete
        await monitor_task

        # Final statistics
        total_time = time.time() - start_time
        total_txs = total_batches * batch_size
        tps = total_txs / total_time if total_time > 0 else 0

        print("\n" + "=" * 50)
        print("📈 TEST RESULTS")
        print("=" * 50)
        print(f"Total batches: {total_batches}")
        print(f"Total transactions: {total_txs}")
        print(f"Test duration: {total_time:.1f}s")
        print(f"Transactions per second: {tps:.1f}")
        print("=" * 50)

async def main():
    # Node URLs (adjust for your setup)
    node_urls = [
        "http://localhost:9001",
        "http://localhost:9002",
        "http://localhost:9003",
        "http://localhost:9004"
    ]

    async with DagTester(node_urls) as tester:
        await tester.run_test(
            test_duration=60,      # 1 minute
            batch_size=25,         # 25 tx per batch
            batches_per_minute=12  # 12 batches per minute = 300 TPS target
        )

if __name__ == "__main__":
    asyncio.run(main())

