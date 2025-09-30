# Symbios Network Protocol Specification

## Обзор

Symbios Network - высокопроизводительный блокчейн с DAG-мемпулом для оптимального упорядочивания транзакций. Протокол фокусируется на параллельном исполнении транзакций с использованием Optimistic Concurrency Control (OCC) и DAG-структуры для минимизации конфликтов.

## Архитектура

### Ядро: DAG-мемпул + упорядочивание транзакций

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Transactions  │───▶│  DAG Mempool     │───▶│  Ordering Queue │
│   (Clients)     │    │  (Priority-based)│    │  (Consensus)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   P2P Network   │◀───│  Gossip Protocol │◀───│  Block Creation │
│   (libp2p)      │    │  (Message Relay) │    │  (Leader-based) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Формат сообщений

### Transaction Message
```rust
pub struct Transaction {
    pub id: Hash,
    pub sender: PublicKey,
    pub receiver: PublicKey,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub signature: Option<Vec<u8>>,
    pub timestamp: u64,
    pub data: Vec<u8>, // Optional contract data
}
```

### Block Message
```rust
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub validator_set: ValidatorSet,
    pub execution_results: Vec<TransactionExecutionResult>,
}

pub struct BlockHeader {
    pub height: BlockHeight,
    pub timestamp: Timestamp,
    pub previous_hash: Hash,
    pub transactions_root: Hash,
    pub state_root: Hash,
    pub validator: PublicKey,
    pub signature: Option<Vec<u8>>,
    pub gas_used: Gas,
    pub gas_limit: Gas,
    pub transaction_count: u64,
}
```

### Gossip Messages
```rust
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    Consensus(ConsensusMessage),
    StateSync(StateSyncData),
    HealthCheck(NodeHealth),
}
```

## Сетевые допущения

### Latency Assumptions
- **Local network**: <1ms latency между узлами
- **WAN network**: <100ms p95 latency между регионами
- **Message ordering**: Не гарантируется (используем timestamps)

### Packet Loss Assumptions
- **Local network**: <0.1% packet loss
- **WAN network**: <1% packet loss
- **Recovery**: Автоматический retry с exponential backoff

### Валидаторы
- **Количество**: 3-100 валидаторов на сеть
- **География**: Распределены по регионам для fault tolerance
- **Connectivity**: Каждый валидатор подключен минимум к 2/3 других
- **Stake**: Минимум 1000 токенов для участия в консенсусе

## Инварианты безопасности и живучести

### Safety Invariants
1. **No Double-Spend**: Транзакция не может быть исполнена дважды
2. **Valid Signatures**: Все транзакции и блоки подписаны корректно
3. **State Consistency**: Финальное состояние детерминировано
4. **Block Validity**: Блоки валидны и связаны хешами

### Liveness Invariants
1. **Progress Guarantee**: Транзакции eventually финализируются
2. **Fairness**: Транзакции обрабатываются в порядке fee + timestamp
3. **Network Tolerance**: Сеть работает при потере <1/3 валидаторов
4. **Timeout Handling**: View changes происходят timely

### Fairness Properties
1. **Fee-based Priority**: Высокие fees получают приоритет
2. **Timestamp Ordering**: При равных fees - старые транзакции first
3. **No Starvation**: Все транзакции eventually обрабатываются
4. **Round-Robin Leaders**: Лидеры меняются предсказуемо

## Что НЕ делаем (пока)

### Параллельный VM
- Контракты исполняются последовательно в рамках блока
- Параллелизм только на уровне транзакций в мемпуле

### Экономика
- Нет токеномики, staking, governance
- Фиксированные fees и gas limits

### Post-Quantum Cryptography
- Используем Ed25519 для подписей
- PQC подготовлен но не обязателен для базового TPS

## DAG-мемпул

### Структура
```rust
pub struct SmartDagMempool {
    // Core DAG structure
    vertices: HashMap<Hash, DagVertex>,
    mempool_blocks: HashMap<Hash, MempoolBlock>,

    // Transaction management
    pending_transactions: BinaryHeap<PriorityTx>,
    processed_transactions: HashSet<Hash>,

    // Certificate management
    certificates: HashMap<Hash, Vec<Certificate>>,
    pending_certificates: HashMap<Hash, HashSet<PublicKey>>,
}
```

### Инварианты DAG
1. **Acyclic**: Граф не содержит циклов
2. **Connected**: Все транзакции связаны через зависимости
3. **Conflict-Free**: Конфликтующие транзакции не в одном блоке
4. **Priority Order**: Высокий приоритет → раннее исполнение

### Метрики
- **Transaction Count**: Количество pending транзакций
- **DAG Depth**: Максимальная глубина зависимостей
- **Batch Size**: Средний размер mempool блоков
- **Conflict Rate**: Процент конфликтующих транзакций

## Proto-BFT Консенсус

### Фазы консенсуса
1. **PrePrepare**: Лидер предлагает блок
2. **Prepare**: Валидаторы подтверждают блок
3. **Commit**: Валидаторы фиксируют блок
4. **Finalize**: Блок добавляется в цепочку

### Leader Selection
- **Round-Robin**: Лидеры меняются по раундам
- **View Changes**: При timeout или подозрении в malicious behavior

### Safety Rules
- **2/3+1 Quorum**: Нужно согласие большинства валидаторов
- **Lock Protection**: Валидаторы не меняют решение после prepare
- **View Stability**: Стабильные view для прогресса

## Реализация Devnet

### Локальный Devnet (3 узла)
```yaml
# docker-compose.yml
version: '3.8'
services:
  node1:
    build: .
    ports: ["30303:30303"]
    environment:
      - NODE_ID=node1
      - VALIDATOR=true
      - LISTEN_ADDR=/ip4/0.0.0.0/tcp/30303
      - BOOTSTRAP_PEERS=/dns4/node2/tcp/30304,/dns4/node3/tcp/30305

  node2:
    build: .
    ports: ["30304:30304"]
    environment:
      - NODE_ID=node2
      - VALIDATOR=true
      - LISTEN_ADDR=/ip4/0.0.0.0/tcp/30304

  node3:
    build: .
    ports: ["30305:30305"]
    environment:
      - NODE_ID=node3
      - VALIDATOR=true
      - LISTEN_ADDR=/ip4/0.0.0.0/tcp/30305
```

### Мониторинг
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'symbios-nodes'
    static_configs:
      - targets: ['node1:9090', 'node2:9090', 'node3:9090']
```

## Метрики производительности

### Baseline Metrics
- **TPS**: 1000+ (локальный devnet)
- **Latency p50**: <100ms (добавление транзакции)
- **DAG Depth**: <10 уровней зависимостей
- **Network Throughput**: 10MB/s между узлами

### Стресс-тесты
- **Load Test**: 1000 tx/s в течение 5 минут
- **Network Stress**: 10% packet loss симуляция
- **Latency Test**: 100ms искусственная задержка
- **Recovery Test**: Восстановление после потери 1 узла

## Подписи и верификация

### Ed25519 Integration
```rust
impl Transaction {
    pub fn sign(&mut self, private_key: &PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        let data = self.calculate_signing_data();
        let signature = private_key.sign(&data)?;
        self.signature = Some(signature);
        Ok(())
    }

    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(signature) = &self.signature {
            let data = self.calculate_signing_data();
            Ok(self.sender.verify(&data, signature)?)
        } else {
            Ok(false)
        }
    }
}
```

### Интеграция в DAG
- Все транзакции подписаны отправителем
- Блоки подписаны валидатором
- Подписи проверяются при добавлении в мемпул
- Невалидные транзакции отбрасываются

## Тесты и верификация

### Unit Tests
- DAG инварианты (acyclic, connected)
- Priority ordering корректность
- Конфликт детекция
- State machine consistency

### Интеграционные тесты
- 3-узловой devnet
- Транзакции от создания до финализации
- Network message flow
- Consensus liveness

### Stress Tests
- High throughput scenarios
- Network partition recovery
- Malicious node simulation
- Performance regression tests

## Roadmap

### Phase 1: Core Protocol ✅
- [x] DAG-мемпул реализация
- [x] Базовый консенсус
- [x] Рабочий devnet
- [x] Метрики и мониторинг

### Phase 2: Production Features (будущие)
- [ ] Шардинг и параллельный VM
- [ ] Экономика и токеномика
- [ ] Post-quantum криптография
- [ ] Advanced consensus algorithms

### Phase 3: Ecosystem (будущие)
- [ ] DeFi протоколы
- [ ] Cross-chain bridges
- [ ] Governance mechanisms
- [ ] Developer tools

---

*Symbios Network Protocol v1.0 - Минимальная спецификация для DAG-мемпула и консенсуса*
