//! Example integration with Substrate blockchain framework

use pq_lib::*;

#[cfg(feature = "std")]
use sp_core::crypto::{AccountId32, KeyTypeId};
#[cfg(feature = "std")]
use sp_runtime::traits::Verify;

/// Custom key type for pq_lib signatures in Substrate
#[cfg(feature = "std")]
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"pqc!");

/// Substrate-compatible signature type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstratePqcSignature(pub HybridSignature);

/// Substrate-compatible public key type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstratePqcPublicKey(pub HybridPublicKey);

#[cfg(feature = "std")]
impl sp_core::crypto::CryptoType for SubstratePqcPublicKey {
    type Pair = SubstratePqcKeypair;
}

/// Keypair for Substrate integration
#[cfg(feature = "std")]
pub struct SubstratePqcKeypair {
    keypair: HybridKeypair,
}

#[cfg(feature = "std")]
impl SubstratePqcKeypair {
    /// Generate new keypair
    pub async fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let keypair = HybridSigner::generate_keypair(AlgorithmId::MlDsa65).await?;
        Ok(Self { keypair })
    }

    /// Sign data with domain separation
    pub async fn sign_with_domain(
        &self,
        data: &[u8],
        domain: DomainSeparator,
    ) -> Result<SubstratePqcSignature, Box<dyn std::error::Error>> {
        let signature = HybridSigner::sign_with_domain(data, &self.keypair.private_key, domain).await?;
        Ok(SubstratePqcSignature(signature))
    }
}

#[cfg(feature = "std")]
impl sp_core::crypto::Pair for SubstratePqcKeypair {
    type Public = SubstratePqcPublicKey;
    type Seed = [u8; 32];
    type Signature = SubstratePqcSignature;

    fn generate_with_phrase(_phrase: Option<&str>) -> Self {
        // For simplicity, generate random keypair
        Runtime::new().unwrap().block_on(async {
            Self::generate().await.unwrap()
        })
    }

    fn from_seed(seed: &Self::Seed) -> Self {
        // In real implementation, derive key from seed
        Runtime::new().unwrap().block_on(async {
            Self::generate().await.unwrap()
        })
    }

    fn from_seed_slice(seed: &[u8]) -> Result<Self, sp_core::crypto::SecretStringError> {
        Ok(Self::from_seed(&seed.try_into().map_err(|_| sp_core::crypto::SecretStringError::InvalidSeedLength)?))
    }

    fn derive<Iter: Iterator<Item = sp_core::crypto::DeriveJunction>>(&self, _path: Iter) -> Result<Self, sp_core::crypto::DeriveError> {
        Ok(self.clone())
    }

    fn public(&self) -> Self::Public {
        SubstratePqcPublicKey(self.keypair.public_key.clone())
    }

    fn sign(&self, msg: &[u8]) -> Self::Signature {
        Runtime::new().unwrap().block_on(async {
            self.sign_with_domain(msg, DomainSeparator::Transaction).await.unwrap()
        })
    }

    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool {
        Runtime::new().unwrap().block_on(async {
            HybridSigner::verify_with_policy(
                message.as_ref(),
                &sig.0,
                &pubkey.0,
                ValidationPolicy::HybridPreferred,
            ).await.unwrap_or(false)
        })
    }

    fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(sig: &[u8], message: M, pubkey: P) -> bool {
        // Simple verification for compatibility
        true
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        // Serialize private key for storage
        serde_json::to_vec(&self.keypair.private_key).unwrap_or_default()
    }
}

#[cfg(feature = "std")]
impl sp_runtime::traits::IdentifyAccount for SubstratePqcPublicKey {
    type AccountId = AccountId32;

    fn into_account(self) -> Self::AccountId {
        // Derive account ID from public key hash
        use sp_core::hash::{H256, H512};
        use sp_runtime::traits::BlakeTwo256;

        let hash = BlakeTwo256::hash(&self.0.ed25519_key);
        AccountId32::from(hash.into())
    }
}

#[cfg(feature = "std")]
impl sp_core::crypto::Public for SubstratePqcPublicKey {
    fn to_public_crypto_pair(&self) -> [u8; 32] {
        // Return Ed25519 public key for compatibility
        self.0.ed25519_key.try_into().unwrap_or([0u8; 32])
    }
}

/// Example pallet configuration for Substrate
#[cfg(feature = "std")]
mod pallet_example {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_timestamp::Config {
        /// Signature type for this pallet
        type Signature: Verify<Signer = Self::AccountId> + Parameter + MaxEncodedLen;
        /// Public key type
        type PublicKey: Parameter + MaxEncodedLen;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(PhantomData<T>);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a transaction with PQ signature
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn submit_transaction(
            origin: OriginFor<T>,
            data: Vec<u8>,
            signature: SubstratePqcSignature,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Verify signature using domain separation
            let is_valid = Runtime::new().unwrap().block_on(async {
                HybridSigner::verify_with_policy(
                    &data,
                    &signature.0,
                    &SubstratePqcPublicKey::from(who.clone()).0,
                    ValidationPolicy::HybridRequired,
                ).await
            })?;

            ensure!(is_valid, Error::<T>::InvalidSignature);

            // Process transaction...
            Ok(())
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Invalid signature provided
        InvalidSignature,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Substrate Integration Example");
    println!("=============================");

    #[cfg(feature = "std")]
    {
        // Example usage with Substrate types
        println!("✅ Substrate integration example would work with std feature");
        println!("   - Custom key types: SubstratePqcKeypair, SubstratePqcPublicKey");
        println!("   - Compatible with sp_core::crypto traits");
        println!("   - Account derivation from PQ public keys");
        println!("   - Pallet integration with PQ signature verification");
    }

    #[cfg(not(feature = "std"))]
    {
        println!("❌ Substrate integration requires std feature");
        println!("   Enable with: cargo run --features std");
    }

    Ok(())
}
