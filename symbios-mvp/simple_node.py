#!/usr/bin/env python3
"""
Symbios Network Simple Node - Python Implementation
Рабочая демонстрация блокчейн-сети на минимальных ресурсах
"""

import time
import hashlib
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import threading
import signal
import sys

@dataclass
class Transaction:
    """Блокчейн транзакция"""
    id: str
    sender: str
    receiver: str
    amount: int
    timestamp: float
    signature: str = ""

    def calculate_hash(self) -> str:
        data = f"{self.sender}{self.receiver}{self.amount}{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()

    def sign(self, private_key: str):
        """Простая подпись (в реальности использовалась бы криптография)"""
        self.signature = hashlib.sha256(f"{self.id}{private_key}".encode()).hexdigest()

    def verify(self) -> bool:
        """Проверка подписи"""
        expected = hashlib.sha256(f"{self.id}genesis_key".encode()).hexdigest()
        return self.signature == expected

@dataclass
class Block:
    """Блокчейн блок"""
    id: int
    transactions: List[Transaction]
    timestamp: float
    previous_hash: str
    hash: str = ""
    validator: str = "symbios-validator"

    def calculate_hash(self) -> str:
        data = f"{self.id}{self.previous_hash}{self.timestamp}"
        for tx in self.transactions:
            data += tx.id
        return hashlib.sha256(data.encode()).hexdigest()

class BlockchainState:
    """Состояние блокчейна"""
    def __init__(self):
        self.accounts: Dict[str, int] = {}
        self.blocks: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.current_block_id = 0
        self.transaction_count = 0

    def initialize_genesis(self):
        """Создание genesis блока"""
        print("🏗️  Creating Genesis Block...")

        # Создаем genesis аккаунт с начальными монетами
        self.accounts["genesis"] = 1_000_000

        # Создаем genesis транзакцию
        genesis_tx = Transaction(
            id="genesis_tx_0",
            sender="system",
            receiver="genesis",
            amount=1_000_000,
            timestamp=time.time()
        )
        genesis_tx.sign("genesis_key")

        # Создаем genesis блок
        genesis_block = Block(
            id=0,
            transactions=[genesis_tx],
            timestamp=time.time(),
            previous_hash="0" * 64
        )
        genesis_block.hash = genesis_block.calculate_hash()

        self.blocks.append(genesis_block)
        self.current_block_id = 1

        print("✅ Genesis Block Created"        print(f"   Hash: {genesis_block.hash[:16]}...")
        print(f"   Transactions: {len(genesis_block.transactions)}")
        print(f"   Genesis Balance: {self.accounts['genesis']} coins")

    def create_transaction(self, sender: str, receiver: str, amount: int) -> Optional[Transaction]:
        """Создание новой транзакции"""
        # Проверяем баланс
        sender_balance = self.accounts.get(sender, 0)
        if sender_balance < amount:
            print(f"❌ Insufficient balance for {sender}: {sender_balance} < {amount}")
            return None

        # Создаем аккаунт получателя если его нет
        if receiver not in self.accounts:
            self.accounts[receiver] = 0

        # Создаем транзакцию
        tx = Transaction(
            id=f"tx_{self.transaction_count}",
            sender=sender,
            receiver=receiver,
            amount=amount,
            timestamp=time.time()
        )
        tx.sign("genesis_key")  # Простая подпись

        self.transaction_count += 1
        return tx

    def process_transaction(self, tx: Transaction) -> bool:
        """Обработка транзакции"""
        if not tx.verify():
            print("❌ Transaction verification failed")
            return False

        # Выполняем транзакцию
        sender_balance = self.accounts.get(tx.sender, 0)
        if sender_balance < tx.amount:
            return False

        self.accounts[tx.sender] -= tx.amount
        self.accounts[tx.receiver] += tx.amount

        print(f"✅ Transaction #{tx.id}: {tx.sender} -> {tx.receiver} ({tx.amount} coins)")
        return True

    def create_block(self, transactions: List[Transaction]) -> Block:
        """Создание нового блока"""
        block = Block(
            id=self.current_block_id,
            transactions=transactions,
            timestamp=time.time(),
            previous_hash=self.blocks[-1].hash if self.blocks else "0" * 64
        )
        block.hash = block.calculate_hash()

        self.blocks.append(block)
        self.current_block_id += 1

        print(f"📦 New Block #{block.id} created")
        print(f"   Hash: {block.hash[:16]}...")
        print(f"   Transactions: {len(block.transactions)}")
        print(f"   Total blocks: {len(self.blocks)}")

        return block

    def get_stats(self) -> Dict:
        """Получение статистики"""
        return {
            "uptime_seconds": int(time.time() - getattr(self, 'start_time', time.time())),
            "total_blocks": len(self.blocks),
            "total_transactions": self.transaction_count,
            "total_accounts": len(self.accounts),
            "pending_transactions": len(self.pending_transactions)
        }

    def print_state(self):
        """Вывод текущего состояния"""
        print("\n📊 Blockchain State:")
        print(f"   Blocks: {len(self.blocks)}")
        print(f"   Transactions: {self.transaction_count}")
        print(f"   Accounts: {len(self.accounts)}")
        print(f"   Pending TX: {len(self.pending_transactions)}")

        print("\n   Top accounts:")
        sorted_accounts = sorted(self.accounts.items(), key=lambda x: x[1], reverse=True)
        for account, balance in sorted_accounts[:5]:
            print(".2f"
class SimpleNode:
    """Простой блокчейн узел"""
    def __init__(self):
        self.state = BlockchainState()
        self.running = False
        self.block_interval = 10  # секунд между блоками

    async def start(self):
        """Запуск узла"""
        print("🚀 Symbios Network Simple Node")
        print("=" * 40)

        # Инициализируем genesis
        self.state.initialize_genesis()
        self.state.start_time = time.time()

        self.running = True

        print("✅ Node is operational")
        print("   Press Ctrl+C to stop")
        print()

        # Запускаем фоновые процессы
        import asyncio
        asyncio.create_task(self.block_creation_loop())
        asyncio.create_task(self.transaction_generation_loop())

        # Основной цикл
        try:
            while self.running:
                await asyncio.sleep(5)
                self.print_status()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
            self.running = False

    async def block_creation_loop(self):
        """Цикл создания блоков"""
        while self.running:
            await asyncio.sleep(self.block_interval)

            # Собираем pending транзакции
            if self.state.pending_transactions:
                transactions = self.state.pending_transactions[:10]  # Макс 10 TX per block
                self.state.pending_transactions = self.state.pending_transactions[10:]

                # Создаем блок
                block = self.state.create_block(transactions)

                # Очищаем обработанные транзакции
                for tx in transactions:
                    self.state.pending_transactions = [
                        t for t in self.state.pending_transactions if t.id != tx.id
                    ]

    async def transaction_generation_loop(self):
        """Цикл генерации транзакций для демонстрации"""
        while self.running:
            await asyncio.sleep(3)  # Новая транзакция каждые 3 секунды

            # Создаем случайную транзакцию
            accounts = list(self.state.accounts.keys())
            if len(accounts) >= 2:
                sender = accounts[0]  # genesis
                receiver = accounts[1 % len(accounts)]  # другой аккаунт

                amount = min(100, self.state.accounts.get(sender, 0))
                if amount > 0:
                    tx = self.state.create_transaction(sender, receiver, amount)
                    if tx:
                        self.state.pending_transactions.append(tx)
                        print(f"📝 New pending transaction: {tx.id}")

    def print_status(self):
        """Вывод статуса"""
        stats = self.state.get_stats()
        print(f"📊 Status: Blocks={stats['total_blocks']}, TXs={stats['total_transactions']}, Accounts={stats['total_accounts']}, Pending={stats['pending_transactions']}")

async def main():
    """Главная функция"""
    print("Symbios Network - Python Implementation")
    print("=======================================")

    # Создаем и запускаем узел
    node = SimpleNode()

    try:
        await node.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
