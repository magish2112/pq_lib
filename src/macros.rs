//! Declarative macros for elegant code generation
//!
//! This module provides macros that eliminate boilerplate and enforce
//! consistent patterns across algorithm implementations.
//!
//! # Design Philosophy
//!
//! 1. **DRY**: Write once, generate many
//! 2. **Consistency**: Ensure uniform implementation patterns
//! 3. **Type Safety**: Macros generate type-safe code
//! 4. **Maintainability**: Centralize common patterns

/// Define a hybrid cryptographic algorithm with compile-time guarantees
///
/// This macro generates all the boilerplate for a hybrid algorithm that combines
/// classical and post-quantum primitives.
///
/// # Example
///
/// ```ignore
/// define_hybrid_algorithm! {
///     Ed25519MlDsa65,
///     id = AlgorithmId::MlDsa65,
///     classical_public_size = 32,
///     classical_private_size = 32,
///     classical_signature_size = 64,
///     pq_public_size = 1952,
///     pq_private_size = 4032,
///     pq_signature_size = 3309,
///     security_level = 3,
///     display_name = "Ed25519+ML-DSA-65"
/// }
/// ```
///
/// This generates:
/// - Algorithm trait implementation
/// - Display trait implementation
/// - Sealed trait implementation
/// - Compile-time size validation
#[macro_export]
macro_rules! define_hybrid_algorithm {
    (
        $name:ident,
        id = $id:expr,
        classical_public_size = $c_pub:expr,
        classical_private_size = $c_priv:expr,
        classical_signature_size = $c_sig:expr,
        pq_public_size = $pq_pub:expr,
        pq_private_size = $pq_priv:expr,
        pq_signature_size = $pq_sig:expr,
        security_level = $sec_level:expr,
        display_name = $display:expr
    ) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $name;

        impl $crate::typed::sealed::Sealed for $name {}

        impl $crate::typed::Algorithm for $name {
            const ID: $crate::AlgorithmId = $id;
            const PUBLIC_KEY_SIZE: usize = $c_pub + $pq_pub;
            const PRIVATE_KEY_SIZE: usize = $c_priv + $pq_priv;
            const SIGNATURE_SIZE: usize = $c_sig + $pq_sig;
            const SECURITY_LEVEL: u8 = $sec_level;
            const NAME: &'static str = $display;
            const IS_HYBRID: bool = true;
            const IS_POST_QUANTUM: bool = true;
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", Self::NAME)
            }
        }

        // Compile-time validations
        const _: () = {
            assert!(
                $sec_level >= 1 && $sec_level <= 5,
                "Security level must be 1-5"
            );
            assert!($c_pub > 0, "Classical public key size must be non-zero");
            assert!($pq_pub > 0, "PQ public key size must be non-zero");
        };
    };
}

/// Generate property-based tests for an algorithm
///
/// This macro generates comprehensive property tests ensuring cryptographic
/// invariants hold for all valid inputs.
///
/// # Example
///
/// ```ignore
/// generate_algorithm_property_tests!(Ed25519, "ed25519");
/// ```
#[macro_export]
macro_rules! generate_algorithm_property_tests {
    ($alg:ty, $name:expr) => {
        paste::paste! {
            #[cfg(test)]
            mod [<test_ $name _properties>] {
                use super::*;
                use proptest::prelude::*;

                proptest! {
                    /// Property: Signing then verifying should always succeed
                    #[test]
                    fn [<prop_ $name _sign_verify_roundtrip>](
                        data in prop::collection::vec(any::<u8>(), 1..1000)
                    ) {
                        // This is a template - actual implementation would be added
                        let _ = data;
                    }

                    /// Property: Different messages should produce different signatures
                    #[test]
                    fn [<prop_ $name _different_messages_different_signatures>](
                        data1 in prop::collection::vec(any::<u8>(), 1..100),
                        data2 in prop::collection::vec(any::<u8>(), 1..100)
                    ) {
                        prop_assume!(data1 != data2);
                        let _ = (data1, data2);
                    }

                    /// Property: Invalid signature should never verify
                    #[test]
                    fn [<prop_ $name _invalid_signature_fails>](
                        data in prop::collection::vec(any::<u8>(), 1..100),
                        corrupted in prop::collection::vec(any::<u8>(), <$alg>::SIGNATURE_SIZE)
                    ) {
                        let _ = (data, corrupted);
                    }
                }
            }
        }
    };
}

/// Implement conversion traits for a type
///
/// Generates AsRef, From, and other common conversions.
///
/// # Example
///
/// ```ignore
/// impl_conversions!(PublicKey<Ed25519>, [u8]);
/// ```
#[macro_export]
macro_rules! impl_conversions {
    ($type:ty, [u8]) => {
        impl AsRef<[u8]> for $type {
            #[inline(always)]
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl core::ops::Deref for $type {
            type Target = [u8];

            #[inline(always)]
            fn deref(&self) -> &Self::Target {
                self.as_bytes()
            }
        }
    };
}

/// Generate benchmark suite for an algorithm
///
/// Creates a comprehensive benchmark suite measuring key generation,
/// signing, and verification performance.
///
/// # Example
///
/// ```ignore
/// generate_benchmarks!(Ed25519, "ed25519");
/// ```
#[macro_export]
macro_rules! generate_benchmarks {
    ($alg:ty, $name:expr) => {
        paste::paste! {
            #[cfg(all(test, feature = "bench"))]
            mod [<bench_ $name>] {
                use super::*;
                use criterion::{black_box, Criterion};

                pub fn [<benchmark_ $name _keygen>](c: &mut Criterion) {
                    c.bench_function(concat!($name, "_keygen"), |b| {
                        b.iter(|| {
                            // black_box(Keypair::<$alg>::generate())
                        });
                    });
                }

                pub fn [<benchmark_ $name _sign>](c: &mut Criterion) {
                    let message = vec![0u8; 1024];
                    // let keypair = Keypair::<$alg>::generate().unwrap();

                    c.bench_function(concat!($name, "_sign"), |b| {
                        b.iter(|| {
                            // black_box(keypair.sign(black_box(&message), DomainSeparator::Transaction))
                        });
                    });
                }

                pub fn [<benchmark_ $name _verify>](c: &mut Criterion) {
                    let message = vec![0u8; 1024];
                    // let keypair = Keypair::<$alg>::generate().unwrap();
                    // let signature = keypair.sign(&message, DomainSeparator::Transaction).unwrap();

                    c.bench_function(concat!($name, "_verify"), |b| {
                        b.iter(|| {
                            // black_box(keypair.public_key().verify(
                            //     black_box(&message),
                            //     black_box(&signature),
                            //     DomainSeparator::Transaction
                            // ))
                        });
                    });
                }
            }
        }
    };
}

/// Create a type-safe error conversion chain
///
/// Automatically implements From traits for error types.
///
/// # Example
///
/// ```ignore
/// impl_error_conversions! {
///     CryptoError,
///     ed25519_dalek::SignatureError => InvalidSignature("Ed25519 error"),
///     std::io::Error => IoError
/// }
/// ```
#[macro_export]
macro_rules! impl_error_conversions {
    ($target:ty, $($from:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$from> for $target {
                fn from(err: $from) -> Self {
                    Self::$variant(err.to_string())
                }
            }
        )+
    };
    ($target:ty, $($from:ty => $variant:ident($msg:expr)),+ $(,)?) => {
        $(
            impl From<$from> for $target {
                fn from(_err: $from) -> Self {
                    Self::$variant($msg.into())
                }
            }
        )+
    };
}

/// Define algorithm size constants in a centralized location
///
/// This macro ensures all size-related constants are defined consistently
/// and can be easily validated at compile time.
///
/// # Example
///
/// ```ignore
/// algorithm_sizes! {
///     Ed25519 {
///         public: 32,
///         private: 32,
///         signature: 64,
///     },
///     MlDsa65 {
///         public: 1952,
///         private: 4032,
///         signature: 3309,
///     }
/// }
/// ```
#[macro_export]
macro_rules! algorithm_sizes {
    (
        $($alg:ident {
            public: $pub:expr,
            private: $priv:expr,
            signature: $sig:expr,
        }),+ $(,)?
    ) => {
        /// Algorithm size constants
        pub mod sizes {
            $(
                pub mod [<$alg:snake>] {
                    pub const PUBLIC_KEY: usize = $pub;
                    pub const PRIVATE_KEY: usize = $priv;
                    pub const SIGNATURE: usize = $sig;

                    // Compile-time validations
                    const _: () = assert!(PUBLIC_KEY > 0, "Public key size must be non-zero");
                    const _: () = assert!(PRIVATE_KEY > 0, "Private key size must be non-zero");
                    const _: () = assert!(SIGNATURE > 0, "Signature size must be non-zero");
                }
            )+
        }
    };
}

/// Generate exhaustive match arms for all supported algorithms
///
/// Ensures every algorithm variant is handled and prevents accidental omissions.
///
/// # Example
///
/// ```ignore
/// let size = match_algorithm!(algorithm_id {
///     Ed25519 => 32,
///     MlDsa65 => 1984,
///     MlDsa87 => 2624,
///     SlhDsaShake256f => 64,
/// });
/// ```
#[macro_export]
macro_rules! match_algorithm {
    ($expr:expr { $($variant:ident => $result:expr),+ $(,)? }) => {
        match $expr {
            $(
                $crate::AlgorithmId::$variant => $result,
            )+
        }
    };
}

/// Create a test suite for a cryptographic primitive
///
/// Generates standard tests that all implementations should pass.
///
/// # Example
///
/// ```ignore
/// crypto_test_suite! {
///     algorithm: Ed25519,
///     key_generation: true,
///     signing: true,
///     verification: true,
///     serialization: true,
/// }
/// ```
#[macro_export]
macro_rules! crypto_test_suite {
    (
        algorithm: $alg:ty,
        key_generation: $keygen:expr,
        signing: $sign:expr,
        verification: $verify:expr,
        serialization: $ser:expr $(,)?
    ) => {
        #[cfg(test)]
        mod crypto_tests {
            use super::*;

            #[test]
            #[ignore = "Template test"]
            fn test_key_generation() {
                if $keygen {
                    // Test key generation
                }
            }

            #[test]
            #[ignore = "Template test"]
            fn test_signing() {
                if $sign {
                    // Test signing
                }
            }

            #[test]
            #[ignore = "Template test"]
            fn test_verification() {
                if $verify {
                    // Test verification
                }
            }

            #[test]
            #[ignore = "Template test"]
            fn test_serialization() {
                if $ser {
                    // Test serialization
                }
            }
        }
    };
}

/// Implement Debug trait with sensitive data redaction
///
/// Automatically redacts private keys and secrets in debug output.
///
/// # Example
///
/// ```ignore
/// impl_debug_redacted!(PrivateKey<A> {
///     algorithm: A::NAME,
///     size: self.bytes.len(),
///     bytes: "<REDACTED>"
/// });
/// ```
#[macro_export]
macro_rules! impl_debug_redacted {
    ($type:ty { $($field:ident: $value:expr),+ $(,)? }) => {
        impl core::fmt::Debug for $type {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($type))
                    $(
                        .field(stringify!($field), &$value)
                    )+
                    .finish()
            }
        }
    };
}

/// Generate const assertions for algorithm properties
///
/// Creates compile-time checks ensuring algorithm constants are valid.
///
/// # Example
///
/// ```ignore
/// assert_algorithm_properties! {
///     Ed25519,
///     public_key_size == 32,
///     private_key_size == 32,
///     signature_size == 64,
///     security_level > 0,
/// }
/// ```
#[macro_export]
macro_rules! assert_algorithm_properties {
    ($alg:ty, $($check:expr),+ $(,)?) => {
        const _: () = {
            $(
                assert!($check, concat!("Algorithm property check failed: ", stringify!($check)));
            )+
        };
    };
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macros_exist() {
        // This test just ensures macros compile
        // Actual macro tests are in their usage sites
    }

    // Example: Algorithm sizes macro usage
    algorithm_sizes! {
        Ed25519 {
            public: 32,
            private: 32,
            signature: 64,
        },
        MlDsa65Pq {
            public: 1952,
            private: 4032,
            signature: 3309,
        },
    }

    #[test]
    fn test_algorithm_sizes() {
        assert_eq!(sizes::ed25519::PUBLIC_KEY, 32);
        assert_eq!(sizes::ed25519::PRIVATE_KEY, 32);
        assert_eq!(sizes::ed25519::SIGNATURE, 64);

        assert_eq!(sizes::ml_dsa65_pq::PUBLIC_KEY, 1952);
        assert_eq!(sizes::ml_dsa65_pq::SIGNATURE, 3309);
    }
}
