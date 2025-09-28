# Symbios Network Production Node

## 🚀 Быстрый запуск

### Стандартная конфигурация (рекомендуется)
```bash
make quick-start
# или
./run_production.sh
```

### Минимальная конфигурация (для Raspberry Pi, старых серверов)
```bash
make minimal
# или
export HARDWARE_PROFILE=minimal && ./run_production.sh
```

### Высокопроизводительная конфигурация
```bash
make high-perf
# или
export HARDWARE_PROFILE=high-performance && ./run_production.sh
```

## 📊 Профиль производительности

| Профиль | RAM | Storage | CPU | TPS | Для чего |
|---------|-----|---------|-----|-----|----------|
| minimal | 64MB | 256MB | 1 core | ~50 | Raspberry Pi, старые серверы |
| standard | 256MB | 1GB | 2+ cores | ~500 | Современные серверы |
| high-perf | 1GB | 10GB | 4+ cores | ~2000+ | Выделенные серверы |

## 🖥️ Системные требования

### Минимальные (Raspberry Pi 4)
- **RAM**: 64MB
- **Storage**: 256MB
- **CPU**: 1 core @ 1GHz
- **OS**: Linux, Windows, macOS
- **Network**: 1 Mbps

### Рекомендуемые (Современный сервер)
- **RAM**: 256MB+
- **Storage**: 1GB+
- **CPU**: 2+ cores
- **Network**: 10 Mbps+

## ⚙️ Конфигурация

### Переменные окружения

```bash
# Профиль оборудования
export HARDWARE_PROFILE=standard  # minimal, standard, high-performance

# Идентификатор узла
export NODE_ID=my-node-01

# Директория данных
export DATA_DIR=./data

# Порт метрик
export METRICS_PORT=9101

# Детальные настройки
export MAX_MEMORY_MB=256
export MAX_STORAGE_MB=1024
export CONSENSUS_ROUND_DURATION=3
export MAX_PARALLEL_BATCH=50
```

### Примеры конфигураций

#### Для Raspberry Pi
```bash
export HARDWARE_PROFILE=minimal
export NODE_ID=raspberry-node
export DATA_DIR=/home/pi/symbios-data
```

#### Для сервера
```bash
export HARDWARE_PROFILE=standard
export NODE_ID=server-node-01
export DATA_DIR=/var/lib/symbios
```

## 📈 Мониторинг

### Метрики в реальном времени
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090

### Ключевые метрики
- **TPS**: Транзакций в секунду
- **Block Time**: Время создания блока
- **Memory Usage**: Использование памяти
- **Storage Usage**: Использование диска
- **Network Peers**: Количество подключенных узлов

## 🧪 Тестирование производительности

```bash
# Запуск бенчмарка
make benchmark

# Детальный тест DAG
python test_dag.py

# Тест постквантовой криптографии
python test_pqcrypto.py
```

## 🔧 Технические характеристики

### Архитектура
- **DAG-мемпул**: Для высокой пропускной способности
- **Lightweight BFT**: Оптимизированный консенсус
- **Parallel Execution**: Параллельное выполнение транзакций
- **Minimal Storage**: Эффективное хранение данных

### Безопасность
- **Post-Quantum Crypto**: ML-KEM, ML-DSA, SLH-DSA
- **Certificate-based DAG**: Защита от двойных трат
- **Memory-safe**: Rust guarantees

### Масштабируемость
- **Horizontal**: Легко добавлять новые узлы
- **Vertical**: Автоматическая оптимизация под ресурсы
- **Resource-aware**: Адаптация под доступное оборудование

## 🚦 Статус и метрики

Узел выводит статус каждые 30 секунд:

```
📊 Production Node Status:
   Uptime: 300s
   Blocks Processed: 45
   Transactions Processed: 1250
   Average TPS: 4.17
   Memory Usage: 45 MB
   Storage Usage: 12 MB
   Consensus Rounds: 15
   Active Transactions: 3
   Total Storage Entries: 234
```

## 🐛 Устранение неполадок

### Низкая производительность
```bash
# Проверьте профиль оборудования
echo $HARDWARE_PROFILE

# Увеличьте лимиты памяти
export MAX_MEMORY_MB=512
export MAX_PARALLEL_BATCH=100
```

### Проблемы с памятью
```bash
# Используйте минимальный профиль
export HARDWARE_PROFILE=minimal

# Уменьшите размер батча
export MAX_PARALLEL_BATCH=10
```

### Проблемы с хранением
```bash
# Проверьте доступное место
df -h $DATA_DIR

# Увеличьте лимит хранения
export MAX_STORAGE_MB=2048
```

## 📚 Документация

- **Architecture**: Техническая архитектура
- **API**: REST API для интеграции
- **Deployment**: Руководство по развертыванию
- **Monitoring**: Настройка мониторинга

## 🤝 Поддержка

- **GitHub Issues**: Для багов и фич
- **Documentation**: Подробная документация
- **Community**: Сообщество разработчиков

---

**Symbios Network** - блокчейн, который работает даже на калькуляторах! 🚀

