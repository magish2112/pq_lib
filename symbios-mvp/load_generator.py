#!/usr/bin/env python3
"""
Simple load generator for Symbios Network MVP
Generates and sends transactions to validator nodes
"""

import asyncio
import random
import time
import os
import json
from typing import List

class TransactionGenerator:
    def __init__(self, target_nodes: List[str], tps_rate: int = 10):
        self.target_nodes = target_nodes
        self.tps_rate = tps_rate
        self.transaction_count = 0
        self.accounts = self._generate_accounts(100)  # 100 test accounts

    def _generate_accounts(self, count: int) -> List[str]:
        """Generate test account addresses"""
        return [f"account_{i:04d}" for i in range(count)]

    def _generate_transaction(self) -> dict:
        """Generate a random transaction"""
        sender = random.choice(self.accounts)
        receiver = random.choice([acc for acc in self.accounts if acc != sender])
        amount = random.randint(1, 1000)

        self.transaction_count += 1

        return {
            "id": f"tx_{self.transaction_count:06d}",
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "timestamp": int(time.time() * 1000),
            "nonce": self.transaction_count
        }

    async def _send_transaction(self, session, node_url: str, transaction: dict):
        """Send transaction to a specific node"""
        try:
            # For MVP, we'll just log the transaction
            # In real implementation, this would make HTTP requests
            print(f"Sending TX {transaction['id']} to {node_url}: {transaction['sender']} -> {transaction['receiver']} ({transaction['amount']})")

            # Simulate network delay
            await asyncio.sleep(random.uniform(0.001, 0.01))

        except Exception as e:
            print(f"Error sending transaction to {node_url}: {e}")

    async def _send_batch(self, session, transactions: List[dict]):
        """Send a batch of transactions to random nodes"""
        tasks = []
        for tx in transactions:
            # Randomly select target node
            target_node = random.choice(self.target_nodes)
            task = self._send_transaction(session, target_node, tx)
            tasks.append(task)

        await asyncio.gather(*tasks)

    async def run(self, duration_seconds: int = 60):
        """Run the load generator for specified duration"""
        print(f"Starting load generator: {self.tps_rate} TPS for {duration_seconds} seconds")
        print(f"Target nodes: {self.target_nodes}")

        start_time = time.time()
        batch_size = self.tps_rate // 10  # Send in batches every 100ms
        interval = 0.1  # 100ms between batches

        total_transactions = 0

        while time.time() - start_time < duration_seconds:
            batch_start = time.time()

            # Generate batch of transactions
            transactions = [self._generate_transaction() for _ in range(batch_size)]

            # Send batch
            await self._send_batch(None, transactions)

            total_transactions += len(transactions)

            # Calculate actual TPS
            elapsed = time.time() - start_time
            actual_tps = total_transactions / elapsed if elapsed > 0 else 0

            print(".1f"
            # Sleep to maintain rate
            batch_time = time.time() - batch_start
            if batch_time < interval:
                await asyncio.sleep(interval - batch_time)

        elapsed = time.time() - start_time
        final_tps = total_transactions / elapsed if elapsed > 0 else 0

        print("
Load generation completed:"        print(f"  Total transactions: {total_transactions}")
        print(".1f"        print(".1f"
async def main():
    # Get configuration from environment
    target_nodes_env = os.getenv("TARGET_NODES", "localhost:9001,localhost:9002")
    target_nodes = [f"http://{node.strip()}" for node in target_nodes_env.split(",")]

    tps_rate = int(os.getenv("TPS_RATE", "10"))

    generator = TransactionGenerator(target_nodes, tps_rate)
    await generator.run(60)  # Run for 60 seconds

if __name__ == "__main__":
    asyncio.run(main())

