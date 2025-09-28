#!/usr/bin/env python3
"""
Symbios Network Demo Node
Простая демонстрация работы блокчейна
"""

import time
import hashlib
import signal
import sys
from typing import Dict, List

class Transaction:
    def __init__(self, sender: str, receiver: str, amount: int, tx_id: int):
        self.id = f"tx_{tx_id}"
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = time.time()
        self.signature = self._sign()

    def _sign(self) -> str:
        """Простая подпись"""
        data = f"{self.id}{self.sender}{self.receiver}{self.amount}"
        return hashlib.sha256(data.encode()).hexdigest()

    def verify(self) -> bool:
        """Проверка подписи"""
        expected = hashlib.sha256(f"{self.id}{self.sender}{self.receiver}{self.amount}".encode()).hexdigest()
        return self.signature == expected

class Block:
    def __init__(self, block_id: int, transactions: List[Transaction], previous_hash: str):
        self.id = block_id
        self.transactions = transactions
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.hash = self._calculate_hash()
        self.validator = "symbios-validator"

    def _calculate_hash(self) -> str:
        data = f"{self.id}{self.previous_hash}{self.timestamp}"
        for tx in self.transactions:
            data += tx.id
        return hashlib.sha256(data.encode()).hexdigest()

class BlockchainState:
    def __init__(self):
        self.accounts: Dict[str, int] = {}
        self.blocks: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.current_block_id = 0
        self.transaction_count = 0
        self.start_time = time.time()

    def initialize_genesis(self):
        """Создание genesis блока"""
        print("🏗️  Creating Genesis Block...")

        # Genesis аккаунт
        self.accounts["genesis"] = 1_000_000

        # Genesis транзакция
        genesis_tx = Transaction("system", "genesis", 1_000_000, 0)

        # Genesis блок
        genesis_block = Block(0, [genesis_tx], "0" * 64)
        self.blocks.append(genesis_block)
        self.current_block_id = 1

        print("✅ Genesis Block Created")
        print(f"   Hash: {genesis_block.hash[:16]}...")
        print(f"   Genesis Balance: {self.accounts['genesis']} coins\n")

    def create_transaction(self, sender: str, receiver: str, amount: int) -> Transaction:
        """Создание транзакции"""
        tx = Transaction(sender, receiver, amount, self.transaction_count)
        self.transaction_count += 1

        # Создаем аккаунт получателя если нужно
        if receiver not in self.accounts:
            self.accounts[receiver] = 0

        return tx

    def process_transaction(self, tx: Transaction) -> bool:
        """Обработка транзакции"""
        if not tx.verify():
            print(f"❌ Transaction verification failed for {tx.id}")
            return False

        sender_balance = self.accounts.get(tx.sender, 0)
        if sender_balance < tx.amount:
            print(f"❌ Insufficient balance: {sender_balance} < {tx.amount}")
            return False

        # Выполняем транзакцию
        self.accounts[tx.sender] -= tx.amount
        self.accounts[tx.receiver] += tx.amount

        print(f"✅ Transaction {tx.id}: {tx.sender} -> {tx.receiver} ({tx.amount} coins)")
        return True

    def create_block(self) -> Block:
        """Создание нового блока"""
        # Берем до 5 pending транзакций
        transactions = self.pending_transactions[:5]
        self.pending_transactions = self.pending_transactions[5:]

        previous_hash = self.blocks[-1].hash if self.blocks else "0" * 64
        block = Block(self.current_block_id, transactions, previous_hash)

        self.blocks.append(block)
        self.current_block_id += 1

        print(f"📦 Block #{block.id} created")
        print(f"   Hash: {block.hash[:16]}...")
        print(f"   Transactions: {len(block.transactions)}")
        print(f"   Total blocks: {len(self.blocks)}")

        return block

    def simulate_network_activity(self):
        """Симуляция сетевой активности"""
        print("\n🌐 Simulating network activity...")

        # Создаем тестовые аккаунты
        accounts = ["alice", "bob", "charlie", "diana", "eve"]
        for account in accounts:
            if account not in self.accounts:
                self.accounts[account] = 1000

        # Создаем случайные транзакции
        import random

        for i in range(10):
            sender = random.choice(accounts)
            receiver = random.choice([acc for acc in accounts if acc != sender])

            # Проверяем баланс
            sender_balance = self.accounts.get(sender, 0)
            amount = min(random.randint(10, 100), sender_balance)

            if amount > 0:
                tx = self.create_transaction(sender, receiver, amount)
                self.pending_transactions.append(tx)
                print(f"📝 Pending TX: {tx.id} ({sender} -> {receiver}, {amount} coins)")

                # Небольшая задержка
                time.sleep(0.5)

        print("✅ Network simulation complete\n")

    def print_stats(self):
        """Вывод статистики"""
        uptime = int(time.time() - self.start_time)
        print("📊 Blockchain Status:")
        print(f"   Uptime: {uptime}s")
        print(f"   Blocks: {len(self.blocks)}")
        print(f"   Transactions: {self.transaction_count}")
        print(f"   Accounts: {len(self.accounts)}")
        print(f"   Pending TX: {len(self.pending_transactions)}")

        # Top accounts
        print("   Top accounts:")
        sorted_accounts = sorted(self.accounts.items(), key=lambda x: x[1], reverse=True)
        for account, balance in sorted_accounts[:3]:
            print(f"   {account}: {balance:.2f}")
def main():
    """Главная функция демонстрации"""
    print("🚀 Symbios Network Demo Node")
    print("=" * 35)

    # Обработчик прерывания
    def signal_handler(sig, frame):
        print("\n👋 Goodbye! Thanks for trying Symbios Network!")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Создаем блокчейн
    blockchain = BlockchainState()
    blockchain.initialize_genesis()

    # Основной цикл демонстрации
    try:
        for cycle in range(5):  # 5 циклов демонстрации
            print(f"\n🔄 Demo Cycle #{cycle + 1}/5")
            print("-" * 25)

            # Показываем статус
            blockchain.print_stats()

            # Симулируем сетевую активность
            blockchain.simulate_network_activity()

            # Обрабатываем pending транзакции
            while blockchain.pending_transactions:
                tx = blockchain.pending_transactions.pop(0)
                blockchain.process_transaction(tx)
                time.sleep(0.3)

            # Создаем блок
            if cycle < 4:  # Не создаем блок в последнем цикле
                blockchain.create_block()
                print()

            time.sleep(2)  # Пауза между циклами

        print("\n🎉 Demo completed successfully!")
        print("Symbios Network is working on minimal hardware! 🎯")

        # Финальная статистика
        print("\n🏆 Final Results:")
        blockchain.print_stats()

        print("\n💡 What you saw:")
        print("   ✅ Genesis block creation")
        print("   ✅ Transaction processing")
        print("   ✅ Block creation and hashing")
        print("   ✅ Account balance management")
        print("   ✅ Network activity simulation")
        print("\n🚀 This demonstrates that Symbios Network can work on any device!")

    except KeyboardInterrupt:
        print("\n👋 Demo interrupted by user")

if __name__ == "__main__":
    main()

