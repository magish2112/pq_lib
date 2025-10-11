# Архитектурный рефакторинг: От хорошего к изящному

## 🎯 Цель
Превратить pq_lib в произведение искусства через применение продвинутых Rust паттернов, type-level programming и zero-cost abstractions.

---

## 📊 Текущий анализ

### ✅ Сильные стороны
- Хорошая trait-based архитектура
- Правильное разделение модулей
- Comprehensive error handling
- Strong type safety

### ⚠️ Возможности улучшения

#### 1. **Code Duplication** (HIGH PRIORITY)
**Проблема:** Повторяющиеся match statements для algorithm sizes
```rust
// src/algorithm.rs, src/pqc.rs - дублирование
match algorithm {
    AlgorithmId::MlDsa65 => 3309,
    AlgorithmId::MlDsa87 => 4627,
    ...
}
```

**Решение:** Использовать const fn + trait с associated constants

#### 2. **Boxing Overhead** (PERFORMANCE)
**Проблема:** `Box<dyn PqcOperations>` создает runtime dispatch
```rust
pub fn get_pqc_ops_for_algorithm(algorithm: AlgorithmId) -> CryptoResult<Box<dyn PqcOperations>>
```

**Решение:** Enum-based dispatch или compile-time monomorphization

#### 3. **Type Safety** (ELEGANCE)
**Проблема:** Raw `Vec<u8>` для ключей/подписей теряет type information
```rust
pub ed25519_key: Vec<u8>,  // Could be any bytes
pub pq_key: Option<Vec<u8>>,  // No algorithm association
```

**Решение:** Newtype pattern + phantom types

#### 4. **Builder Pattern** (API ERGONOMICS)
**Проблема:** Императивный стиль создания конфигураций
```rust
let mut config = PolicyConfig::conservative();
config.transaction_policy = ValidationPolicy::HybridRequired;
```

**Решение:** Fluent builder API

#### 5. **Macro Magic** (DRY)
**Проблема:** Шаблонный код в algorithm implementations
```rust
// Repeated pattern for each algorithm
impl PqcOperations for MlDsa65Ops { ... }
impl PqcOperations for MlDsa87Ops { ... }
```

**Решение:** Declarative macros для codegen

#### 6. **Const Generics** (ZERO-COST)
**Проблема:** Runtime size checks
```rust
if private_key.len() != 32 {
    return Err(...);
}
```

**Решение:** Const generic arrays `[u8; N]`

---

## 🚀 Рефакторинг Plan

### Phase 1: Type-Level Architecture (FOUNDATION)

#### 1.1. Algorithm Traits с Associated Types
```rust
/// Type-level algorithm specification
pub trait Algorithm: Sealed {
    /// Algorithm identifier
    const ID: AlgorithmId;
    
    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;
    
    /// Private key size in bytes
    const PRIVATE_KEY_SIZE: usize;
    
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;
    
    /// Security level (NIST category)
    const SECURITY_LEVEL: u8;
    
    /// Human-readable name
    const NAME: &'static str;
    
    /// Type-safe public key
    type PublicKey: PublicKeyMarker;
    
    /// Type-safe private key
    type PrivateKey: PrivateKeyMarker;
    
    /// Type-safe signature
    type Signature: SignatureMarker;
}

/// Marker trait for public keys
pub trait PublicKeyMarker: Sized + Clone {}

/// Marker trait for private keys
pub trait PrivateKeyMarker: Sized + Zeroize {}

/// Marker trait for signatures
pub trait SignatureMarker: Sized + Clone {}
```

#### 1.2. Concrete Algorithm Types
```rust
/// Ed25519 algorithm specification
pub struct Ed25519;

impl Algorithm for Ed25519 {
    const ID: AlgorithmId = AlgorithmId::Ed25519;
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;
    const SIGNATURE_SIZE: usize = 64;
    const SECURITY_LEVEL: u8 = 2;
    const NAME: &'static str = "Ed25519";
    
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;
}

/// ML-DSA-65 algorithm specification
pub struct MlDsa65;

impl Algorithm for MlDsa65 {
    const ID: AlgorithmId = AlgorithmId::MlDsa65;
    const PUBLIC_KEY_SIZE: usize = 32 + 1952;
    const PRIVATE_KEY_SIZE: usize = 32 + 4032;
    const SIGNATURE_SIZE: usize = 64 + 3309;
    const SECURITY_LEVEL: u8 = 3;
    const NAME: &'static str = "ML-DSA-65 + Ed25519";
    
    type PublicKey = MlDsa65PublicKey;
    type PrivateKey = MlDsa65PrivateKey;
    type Signature = MlDsa65Signature;
}
```

#### 1.3. Type-Safe Keys с Const Generics
```rust
/// Type-safe public key with compile-time size
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<A: Algorithm> {
    bytes: [u8; A::PUBLIC_KEY_SIZE],
    _phantom: PhantomData<A>,
}

/// Type-safe private key with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey<A: Algorithm> {
    bytes: [u8; A::PRIVATE_KEY_SIZE],
    _phantom: PhantomData<A>,
}

/// Type-safe signature
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<A: Algorithm> {
    bytes: [u8; A::SIGNATURE_SIZE],
    _phantom: PhantomData<A>,
}

impl<A: Algorithm> PublicKey<A> {
    /// Create from bytes (compile-time size check)
    pub const fn from_bytes(bytes: [u8; A::PUBLIC_KEY_SIZE]) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }
    
    /// Get algorithm at compile time
    pub const fn algorithm() -> AlgorithmId {
        A::ID
    }
}
```

### Phase 2: Elegant Crypto Operations (ZERO-COST)

#### 2.1. Generic Signer Trait
```rust
/// Generic signing operations (zero-cost abstraction)
pub trait CryptoSigner<A: Algorithm> {
    /// Sign data with domain separation
    fn sign(
        &self,
        data: &[u8],
        private_key: &PrivateKey<A>,
        domain: DomainSeparator,
    ) -> Result<Signature<A>, CryptoError>;
    
    /// Verify signature
    fn verify(
        &self,
        data: &[u8],
        signature: &Signature<A>,
        public_key: &PublicKey<A>,
        domain: DomainSeparator,
    ) -> Result<bool, CryptoError>;
}

/// Ed25519 signer implementation (monomorphized, no boxing)
pub struct Ed25519Signer;

impl CryptoSigner<Ed25519> for Ed25519Signer {
    fn sign(
        &self,
        data: &[u8],
        private_key: &PrivateKey<Ed25519>,
        domain: DomainSeparator,
    ) -> Result<Signature<Ed25519>, CryptoError> {
        let domain_msg = domain.apply(data);
        let signing_key = SigningKey::from_bytes(&private_key.bytes);
        let sig = signing_key.sign(&domain_msg);
        Ok(Signature::from_bytes(sig.to_bytes()))
    }
    
    fn verify(
        &self,
        data: &[u8],
        signature: &Signature<Ed25519>,
        public_key: &PublicKey<Ed25519>,
        domain: DomainSeparator,
    ) -> Result<bool, CryptoError> {
        let domain_msg = domain.apply(data);
        let verifying_key = VerifyingKey::from_bytes(&public_key.bytes)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature.bytes);
        Ok(verifying_key.verify(&domain_msg, &sig).is_ok())
    }
}
```

#### 2.2. Hybrid Operations через Type System
```rust
/// Hybrid keypair combining two algorithms
pub struct HybridKeypair<Classical, PQ>
where
    Classical: Algorithm,
    PQ: Algorithm,
{
    classical: Keypair<Classical>,
    pq: Keypair<PQ>,
}

/// Hybrid signature
pub struct HybridSignature<Classical, PQ>
where
    Classical: Algorithm,
    PQ: Algorithm,
{
    classical: Signature<Classical>,
    pq: Signature<PQ>,
    domain: DomainSeparator,
    version: u8,
}

impl<C, PQ> HybridKeypair<C, PQ>
where
    C: Algorithm,
    PQ: Algorithm,
{
    /// Create hybrid signature (compile-time type safety)
    pub fn sign(
        &self,
        data: &[u8],
        domain: DomainSeparator,
    ) -> Result<HybridSignature<C, PQ>, CryptoError>
    where
        C: CryptoSigner<C>,
        PQ: CryptoSigner<PQ>,
    {
        let classical_sig = C::sign(data, &self.classical.private, domain)?;
        let pq_sig = PQ::sign(data, &self.pq.private, domain)?;
        
        Ok(HybridSignature {
            classical: classical_sig,
            pq: pq_sig,
            domain,
            version: 1,
        })
    }
}

/// Type alias for common combinations
pub type Ed25519MlDsa65 = HybridKeypair<Ed25519, MlDsa65>;
pub type Ed25519MlDsa87 = HybridKeypair<Ed25519, MlDsa87>;
```

### Phase 3: Builder Pattern (ERGONOMICS)

#### 3.1. Fluent Configuration Builder
```rust
/// Fluent policy configuration builder
pub struct PolicyConfigBuilder {
    transaction_policy: Option<ValidationPolicy>,
    block_policy: Option<ValidationPolicy>,
    consensus_policy: Option<ValidationPolicy>,
    migration: Option<MigrationConfig>,
}

impl PolicyConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set transaction policy
    pub fn transaction(mut self, policy: ValidationPolicy) -> Self {
        self.transaction_policy = Some(policy);
        self
    }
    
    /// Set block policy
    pub fn block(mut self, policy: ValidationPolicy) -> Self {
        self.block_policy = Some(policy);
        self
    }
    
    /// Set consensus policy
    pub fn consensus(mut self, policy: ValidationPolicy) -> Self {
        self.consensus_policy = Some(policy);
        self
    }
    
    /// Configure migration
    pub fn migration(mut self, config: MigrationConfig) -> Self {
        self.migration = Some(config);
        self
    }
    
    /// Build configuration
    pub fn build(self) -> PolicyConfig {
        PolicyConfig {
            transaction_policy: self.transaction_policy.unwrap_or(ValidationPolicy::HybridPreferred),
            block_policy: self.block_policy.unwrap_or(ValidationPolicy::HybridPreferred),
            consensus_policy: self.consensus_policy.unwrap_or(ValidationPolicy::HybridRequired),
            migration: self.migration.unwrap_or_default(),
        }
    }
}

// Elegant API usage:
let config = PolicyConfigBuilder::new()
    .transaction(ValidationPolicy::HybridPreferred)
    .block(ValidationPolicy::HybridRequired)
    .consensus(ValidationPolicy::HybridRequired)
    .migration(MigrationConfig::gradual())
    .build();
```

#### 3.2. Keypair Builder
```rust
/// Elegant keypair generation
pub struct KeypairBuilder<A: Algorithm> {
    algorithm: PhantomData<A>,
    rng: Option<Box<dyn RngCore>>,
}

impl<A: Algorithm> KeypairBuilder<A> {
    pub fn new() -> Self {
        Self {
            algorithm: PhantomData,
            rng: None,
        }
    }
    
    /// Use custom RNG
    pub fn with_rng<R: RngCore + 'static>(mut self, rng: R) -> Self {
        self.rng = Some(Box::new(rng));
        self
    }
    
    /// Generate keypair
    pub fn generate(self) -> Result<Keypair<A>, CryptoError> {
        let mut rng = self.rng.unwrap_or_else(|| Box::new(thread_rng()));
        A::generate_keypair(&mut *rng)
    }
}

// Usage:
let keypair = KeypairBuilder::<Ed25519>::new()
    .with_rng(OsRng)
    .generate()?;
```

### Phase 4: Macro Magic (DRY)

#### 4.1. Algorithm Definition Macro
```rust
/// Declarative algorithm definition
macro_rules! define_algorithm {
    (
        $name:ident,
        id = $id:expr,
        public_key_size = $pub_size:expr,
        private_key_size = $priv_size:expr,
        signature_size = $sig_size:expr,
        security_level = $sec_level:expr,
        display_name = $display:expr
    ) => {
        pub struct $name;
        
        impl Algorithm for $name {
            const ID: AlgorithmId = $id;
            const PUBLIC_KEY_SIZE: usize = $pub_size;
            const PRIVATE_KEY_SIZE: usize = $priv_size;
            const SIGNATURE_SIZE: usize = $sig_size;
            const SECURITY_LEVEL: u8 = $sec_level;
            const NAME: &'static str = $display;
            
            type PublicKey = PublicKey<Self>;
            type PrivateKey = PrivateKey<Self>;
            type Signature = Signature<Self>;
        }
        
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", Self::NAME)
            }
        }
    };
}

// Usage:
define_algorithm!(
    Ed25519,
    id = AlgorithmId::Ed25519,
    public_key_size = 32,
    private_key_size = 32,
    signature_size = 64,
    security_level = 2,
    display_name = "Ed25519"
);

define_algorithm!(
    MlDsa65Hybrid,
    id = AlgorithmId::MlDsa65,
    public_key_size = 32 + 1952,
    private_key_size = 32 + 4032,
    signature_size = 64 + 3309,
    security_level = 3,
    display_name = "ML-DSA-65 + Ed25519"
);
```

#### 4.2. Test Generation Macro
```rust
/// Generate property tests for all algorithms
macro_rules! algorithm_property_tests {
    ($($alg:ty),+) => {
        $(
            paste::paste! {
                proptest! {
                    #[test]
                    fn [<test_ $alg:lower _sign_verify>](data in prop::collection::vec(any::<u8>(), 1..100)) {
                        let keypair = Keypair::<$alg>::generate()?;
                        let signature = keypair.sign(&data, DomainSeparator::Transaction)?;
                        let valid = keypair.verify(&data, &signature, DomainSeparator::Transaction)?;
                        prop_assert!(valid);
                    }
                }
            }
        )+
    };
}

algorithm_property_tests!(Ed25519, MlDsa65, MlDsa87);
```

### Phase 5: State Machine для Migration (ELEGANCE)

#### 5.1. Type-State Pattern
```rust
/// Migration states as types
pub struct LegacyState;
pub struct TransitionState;
pub struct ModernState;

/// Migration context with type-state
pub struct MigrationContext<State> {
    config: PolicyConfig,
    deadline: Option<SystemTime>,
    _state: PhantomData<State>,
}

impl MigrationContext<LegacyState> {
    /// Start migration
    pub fn begin_migration(self, deadline: SystemTime) -> MigrationContext<TransitionState> {
        MigrationContext {
            config: self.config.transition(),
            deadline: Some(deadline),
            _state: PhantomData,
        }
    }
}

impl MigrationContext<TransitionState> {
    /// Check if ready to complete
    pub fn is_ready(&self) -> bool {
        if let Some(deadline) = self.deadline {
            SystemTime::now() >= deadline
        } else {
            false
        }
    }
    
    /// Complete migration (compile-time enforces state)
    pub fn complete(self) -> Result<MigrationContext<ModernState>, MigrationError> {
        if !self.is_ready() {
            return Err(MigrationError::NotReady);
        }
        
        Ok(MigrationContext {
            config: self.config.complete(),
            deadline: None,
            _state: PhantomData,
        })
    }
}

// Type system prevents invalid transitions!
// migration.complete() only available in TransitionState
```

### Phase 6: Advanced Features

#### 6.1. GATs для Generic Async
```rust
/// Generic async trait with GATs
pub trait AsyncSigner {
    type Algorithm: Algorithm;
    type Error;
    type SignFuture<'a>: Future<Output = Result<Signature<Self::Algorithm>, Self::Error>> + 'a
    where
        Self: 'a;
    
    fn sign<'a>(
        &'a self,
        data: &'a [u8],
        private_key: &'a PrivateKey<Self::Algorithm>,
        domain: DomainSeparator,
    ) -> Self::SignFuture<'a>;
}
```

#### 6.2. Sealed Traits для API Stability
```rust
mod sealed {
    pub trait Sealed {}
}

pub trait Algorithm: sealed::Sealed {
    // Public API
}

impl sealed::Sealed for Ed25519 {}
impl sealed::Sealed for MlDsa65 {}
// Пользователи не могут добавлять свои реализации
```

#### 6.3. Const Evaluation
```rust
/// Compile-time validation
pub const fn validate_key_size<A: Algorithm>(size: usize) -> bool {
    size == A::PUBLIC_KEY_SIZE
}

// Compile-time check
const _: () = assert!(validate_key_size::<Ed25519>(32));
```

---

## 📈 Преимущества после рефакторинга

### Performance
- ✅ Zero-cost abstractions (no boxing for common paths)
- ✅ Monomorphization вместо dynamic dispatch
- ✅ Compile-time size checks eliminates runtime validation
- ✅ Stack allocation где возможно

### Type Safety
- ✅ Phantom types предотвращают algorithm mixing
- ✅ Const generics гарантируют корректные sizes
- ✅ Type-state pattern для invalid state transitions
- ✅ Newtype pattern для domain-specific types

### Elegance
- ✅ Fluent builder APIs
- ✅ Declarative algorithm definitions
- ✅ Macro-generated boilerplate
- ✅ Self-documenting type signatures

### Maintainability
- ✅ DRY через macros
- ✅ Compile-time guarantees
- ✅ Sealed traits для API stability
- ✅ Clear separation of concerns

---

## 🎨 "Произведение искусства" аспекты

### 1. **Symmetry** - Все algorithms следуют единому паттерну
### 2. **Clarity** - Type signatures раскрывают намерения
### 3. **Efficiency** - Zero-cost где возможно
### 4. **Safety** - Type system предотвращает ошибки
### 5. **Elegance** - Минимум boilerplate, максимум выразительности

---

## 🚀 Implementation Order

1. **Week 1**: Phase 1 (Type-Level Architecture) - Foundation
2. **Week 2**: Phase 2 (Crypto Operations) - Core functionality  
3. **Week 3**: Phase 3 (Builders) - API ergonomics
4. **Week 4**: Phase 4 (Macros) - DRY improvements
5. **Week 5**: Phase 5 (State Machine) - Migration elegance
6. **Week 6**: Phase 6 (Advanced) + Polish

---

## ⚠️ Backward Compatibility

Создать facade layer для smooth migration:
```rust
/// Compatibility wrapper (deprecated)
#[deprecated(note = "Use type-safe APIs")]
pub struct HybridKeypair {
    inner: Box<dyn Any>,
}
```

---

## 📊 Metrics

### Before Refactoring
- Lines of code: ~2000
- Match statements: 40+
- Runtime checks: 30+
- Heap allocations: High (boxing)

### After Refactoring (Target)
- Lines of code: ~1500 (DRY)
- Match statements: <10 (macros)
- Runtime checks: <5 (compile-time)
- Heap allocations: Minimal

---

*"Simplicity is the ultimate sophistication." - Leonardo da Vinci*
*"Make illegal states unrepresentable." - Yaron Minsky*

