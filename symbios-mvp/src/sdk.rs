//! Symbios Network SDK
//!
//! High-level SDK for developers to easily integrate with Symbios Network.
//! Provides simplified APIs for:
//! - Transaction creation and signing
//! - Smart contract deployment and interaction
//! - Account management
//! - Network monitoring
//! - Validator operations

use std::collections::HashMap;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::hybrid_crypto::*;
use crate::adaptive_crypto::*;
use crate::metrics::*;

/// Main SDK instance
pub struct SymbiosSDK {
    hybrid_crypto: HybridCryptoEngine,
    adaptive_crypto: Arc<AdaptiveCryptoEngine>,
    metrics: Arc<MetricsServer>,
    accounts: HashMap<String, Account>,
    network_config: SDKNetworkConfig,
}

/// Account abstraction for SDK users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub address: Address,
    pub public_key: HybridPublicKey,
    pub private_key: HybridPrivateKey,
    pub balance: u64,
    pub nonce: u64,
}

/// Transaction builder for easy transaction creation
#[derive(Debug)]
pub struct TransactionBuilder {
    sender: Option<String>,
    receiver: Option<Address>,
    amount: Option<u64>,
    fee: Option<u64>,
    data: Option<Vec<u8>>,
    sdk: Arc<SymbiosSDK>,
}

/// Smart contract abstraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContract {
    pub address: Address,
    pub abi: ContractABI,
    pub bytecode: Vec<u8>,
    pub creator: Address,
    pub deployed_at: u64,
}

/// Contract ABI definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractABI {
    pub functions: HashMap<String, FunctionABI>,
    pub events: HashMap<String, EventABI>,
}

/// Function ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionABI {
    pub name: String,
    pub inputs: Vec<ABIType>,
    pub outputs: Vec<ABIType>,
    pub state_mutability: StateMutability,
}

/// Event ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventABI {
    pub name: String,
    pub inputs: Vec<ABIType>,
    pub anonymous: bool,
}

/// ABI type definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ABIType {
    Address,
    Uint(u32), // bits
    Int(u32),  // bits
    Bool,
    String,
    Bytes,
    Array(Box<ABIType>),
}

/// State mutability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateMutability {
    Pure,
    View,
    NonPayable,
    Payable,
}

/// Network configuration for SDK
#[derive(Debug, Clone)]
pub struct SDKNetworkConfig {
    pub rpc_endpoints: Vec<String>,
    pub chain_id: u64,
    pub gas_price: u64,
    pub timeout: std::time::Duration,
}

/// SDK Result type
pub type SDKResult<T> = Result<T, SDKError>;

/// SDK Error types
#[derive(Debug)]
pub enum SDKError {
    AccountNotFound(String),
    InsufficientFunds { required: u64, available: u64 },
    InvalidTransaction(String),
    NetworkError(String),
    CryptoError(String),
    ContractError(String),
}

impl SymbiosSDK {
    /// Create new SDK instance
    pub async fn new(network_config: SDKNetworkConfig) -> SDKResult<Self> {
        let adaptive_crypto = Arc::new(AdaptiveCryptoEngine::new(
            Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap())
        ).await);

        let hybrid_crypto = HybridCryptoEngine::new(adaptive_crypto.clone()).await;

        Ok(Self {
            hybrid_crypto,
            adaptive_crypto,
            metrics: Arc::new(MetricsServer::new("127.0.0.1:9090".parse().unwrap()).await.unwrap()),
            accounts: HashMap::new(),
            network_config,
        })
    }

    /// Create new account
    pub async fn create_account(&mut self, name: String) -> SDKResult<Account> {
        let keypair = self.hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await
            .map_err(|e| SDKError::CryptoError(format!("Key generation failed: {:?}", e)))?;

        let address = Address::from_public_key(&keypair.public_key.ed25519_key.clone().into());

        let account = Account {
            name: name.clone(),
            address,
            public_key: keypair.public_key,
            private_key: keypair.private_key,
            balance: 0,
            nonce: 0,
        };

        self.accounts.insert(name, account.clone());
        Ok(account)
    }

    /// Get account by name
    pub fn get_account(&self, name: &str) -> SDKResult<&Account> {
        self.accounts.get(name)
            .ok_or_else(|| SDKError::AccountNotFound(name.to_string()))
    }

    /// Get mutable account reference
    pub fn get_account_mut(&mut self, name: &str) -> SDKResult<&mut Account> {
        self.accounts.get_mut(name)
            .ok_or_else(|| SDKError::AccountNotFound(name.to_string()))
    }

    /// Create transaction builder
    pub fn build_transaction(&self, sender: &str) -> SDKResult<TransactionBuilder> {
        if !self.accounts.contains_key(sender) {
            return Err(SDKError::AccountNotFound(sender.to_string()));
        }

        Ok(TransactionBuilder {
            sender: Some(sender.to_string()),
            receiver: None,
            amount: None,
            fee: Some(self.network_config.gas_price),
            data: None,
            sdk: Arc::new(self.clone()),
        })
    }

    /// Send transaction to network
    pub async fn send_transaction(&mut self, tx: Transaction) -> SDKResult<TransactionReceipt> {
        // Validate transaction
        self.validate_transaction(&tx).await?;

        // Update sender account
        if let Some(sender_account) = self.accounts.get_mut(&format!("{:?}", tx.sender)) {
            sender_account.nonce += 1;
            sender_account.balance = sender_account.balance.saturating_sub(tx.amount + tx.fee.unwrap_or(0));
        }

        // Simulate network submission (in real implementation, this would send to network)
        let receipt = TransactionReceipt {
            tx_hash: tx.id,
            block_hash: Hash::new(b"mock_block"),
            block_height: 1,
            gas_used: 21000,
            gas_price: tx.fee.unwrap_or(0),
            status: ExecutionStatus::Success,
            logs: vec![],
            contract_address: None,
        };

        Ok(receipt)
    }

    /// Get account balance
    pub fn get_balance(&self, account_name: &str) -> SDKResult<u64> {
        let account = self.get_account(account_name)?;
        Ok(account.balance)
    }

    /// Transfer tokens between accounts
    pub async fn transfer(&mut self, from: &str, to: &str, amount: u64) -> SDKResult<TransactionReceipt> {
        let from_account = self.get_account(from)?.clone();
        let to_account = self.get_account(to)?.clone();

        if from_account.balance < amount {
            return Err(SDKError::InsufficientFunds {
                required: amount,
                available: from_account.balance,
            });
        }

        // Create and send transaction
        let mut tx_builder = self.build_transaction(from)?;
        let tx = tx_builder
            .to(to_account.address)
            .value(amount)
            .build()?;

        self.send_transaction(tx).await
    }

    /// Deploy smart contract
    pub async fn deploy_contract(&mut self, deployer: &str, bytecode: Vec<u8>, abi: ContractABI) -> SDKResult<SmartContract> {
        let deployer_account = self.get_account(deployer)?;

        // Create contract address (simplified - in real implementation use CREATE opcode logic)
        let contract_address = Address::from_public_key(&PublicKey::new_ed25519());

        let contract = SmartContract {
            address: contract_address,
            abi,
            bytecode,
            creator: deployer_account.address,
            deployed_at: current_timestamp(),
        };

        // Create deployment transaction
        let mut tx_builder = self.build_transaction(deployer)?;
        let tx = tx_builder
            .data(bytecode)
            .build()?;

        let _receipt = self.send_transaction(tx).await?;

        Ok(contract)
    }

    /// Call smart contract function
    pub async fn call_contract(&mut self, caller: &str, contract: &SmartContract, function_name: &str, args: Vec<ABIValue>) -> SDKResult<ContractCallResult> {
        let function = contract.abi.functions.get(function_name)
            .ok_or_else(|| SDKError::ContractError(format!("Function {} not found", function_name)))?;

        // Encode function call (simplified)
        let encoded_call = self.encode_function_call(function, args)?;

        // Create transaction
        let mut tx_builder = self.build_transaction(caller)?;
        let tx = tx_builder
            .to(contract.address)
            .data(encoded_call)
            .build()?;

        let receipt = self.send_transaction(tx).await?;

        // Decode result (simplified - in real implementation would decode return data)
        let result = ContractCallResult {
            success: matches!(receipt.status, ExecutionStatus::Success),
            return_data: vec![],
            gas_used: receipt.gas_used,
        };

        Ok(result)
    }

    /// Get network status
    pub async fn get_network_status(&self) -> SDKResult<NetworkStatus> {
        // In real implementation, this would query the network
        Ok(NetworkStatus {
            chain_id: self.network_config.chain_id,
            block_height: 1000,
            gas_price: self.network_config.gas_price,
            peer_count: 10,
            syncing: false,
        })
    }

    // Private helper methods

    async fn validate_transaction(&self, tx: &Transaction) -> SDKResult<()> {
        // Check sender exists and has sufficient balance
        let sender_key = &tx.sender;
        let sender_balance = 0; // In real implementation, query network

        let total_cost = tx.amount + tx.fee.unwrap_or(0);
        if sender_balance < total_cost {
            return Err(SDKError::InsufficientFunds {
                required: total_cost,
                available: sender_balance,
            });
        }

        Ok(())
    }

    fn encode_function_call(&self, function: &FunctionABI, args: Vec<ABIValue>) -> SDKResult<Vec<u8>> {
        // Simplified ABI encoding (in real implementation, use proper Ethereum ABI encoding)
        let mut encoded = Vec::new();

        // Function signature (first 4 bytes of keccak256)
        let signature = format!("{}({})", function.name,
            function.inputs.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>().join(","));
        let hash = Hash::new(signature.as_bytes());
        encoded.extend_from_slice(&hash.as_bytes()[0..4]);

        // Encode arguments (simplified)
        for arg in args {
            match arg {
                ABIValue::Uint(value) => encoded.extend_from_slice(&value.to_be_bytes()),
                ABIValue::Address(addr) => encoded.extend_from_slice(addr.as_bytes()),
                _ => return Err(SDKError::ContractError("Unsupported argument type".to_string())),
            }
        }

        Ok(encoded)
    }
}

impl TransactionBuilder {
    /// Set receiver address
    pub fn to(mut self, address: Address) -> Self {
        self.receiver = Some(address);
        self
    }

    /// Set transfer amount
    pub fn value(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set transaction fee
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Set transaction data (for contract calls)
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Build the transaction
    pub fn build(self) -> SDKResult<Transaction> {
        let sender_name = self.sender.ok_or_else(|| SDKError::InvalidTransaction("Sender not set".to_string()))?;
        let receiver = self.receiver.ok_or_else(|| SDKError::InvalidTransaction("Receiver not set".to_string()))?;
        let amount = self.amount.ok_or_else(|| SDKError::InvalidTransaction("Amount not set".to_string()))?;
        let fee = self.fee.unwrap_or(0);

        // Get sender account from SDK
        let sdk = Arc::try_unwrap(self.sdk).map_err(|_| SDKError::InvalidTransaction("SDK arc error".to_string()))?;
        let sender_account = sdk.get_account(&sender_name)?;

        let tx = Transaction::new(
            sender_account.address.as_bytes().try_into().unwrap(),
            receiver.as_bytes().try_into().unwrap(),
            amount,
            fee,
            sender_account.nonce,
        );

        Ok(tx)
    }
}

impl Clone for SymbiosSDK {
    fn clone(&self) -> Self {
        // Simplified clone - in real implementation, proper cloning would be needed
        Self {
            hybrid_crypto: HybridCryptoEngine::new(self.adaptive_crypto.clone()).await,
            adaptive_crypto: self.adaptive_crypto.clone(),
            metrics: self.metrics.clone(),
            accounts: self.accounts.clone(),
            network_config: self.network_config.clone(),
        }
    }
}

/// ABI value types for contract calls
#[derive(Debug)]
pub enum ABIValue {
    Uint(u64),
    Address(Address),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
}

/// Contract call result
#[derive(Debug)]
pub struct ContractCallResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
}

/// Network status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub chain_id: u64,
    pub block_height: u64,
    pub gas_price: u64,
    pub peer_count: usize,
    pub syncing: bool,
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sdk_account_creation() {
        let config = SDKNetworkConfig {
            rpc_endpoints: vec!["http://localhost:8545".to_string()],
            chain_id: 1,
            gas_price: 20,
            timeout: std::time::Duration::from_secs(30),
        };

        let mut sdk = SymbiosSDK::new(config).await.unwrap();

        let account = sdk.create_account("alice".to_string()).await.unwrap();
        assert_eq!(account.name, "alice");
        assert_eq!(account.balance, 0);
        assert_eq!(account.nonce, 0);
    }

    #[tokio::test]
    async fn test_sdk_transaction_building() {
        let config = SDKNetworkConfig {
            rpc_endpoints: vec!["http://localhost:8545".to_string()],
            chain_id: 1,
            gas_price: 20,
            timeout: std::time::Duration::from_secs(30),
        };

        let mut sdk = SymbiosSDK::new(config).await.unwrap();
        sdk.create_account("alice".to_string()).await.unwrap();

        let tx_builder = sdk.build_transaction("alice").unwrap();
        let bob_address = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();

        let tx = tx_builder
            .to(bob_address)
            .value(1000)
            .fee(10)
            .build()
            .unwrap();

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee.unwrap_or(0), 10);
    }

    #[tokio::test]
    async fn test_sdk_transfer() {
        let config = SDKNetworkConfig {
            rpc_endpoints: vec!["http://localhost:8545".to_string()],
            chain_id: 1,
            gas_price: 20,
            timeout: std::time::Duration::from_secs(30),
        };

        let mut sdk = SymbiosSDK::new(config).await.unwrap();

        // Create accounts
        let mut alice = sdk.create_account("alice".to_string()).await.unwrap();
        alice.balance = 10000; // Manually set balance for testing
        sdk.accounts.insert("alice".to_string(), alice);

        let bob = sdk.create_account("bob".to_string()).await.unwrap();
        sdk.accounts.insert("bob".to_string(), bob);

        // Perform transfer
        let receipt = sdk.transfer("alice", "bob", 1000).await.unwrap();
        assert!(matches!(receipt.status, ExecutionStatus::Success));

        // Check balances
        let alice_balance = sdk.get_balance("alice").unwrap();
        let bob_balance = sdk.get_balance("bob").unwrap();

        assert_eq!(alice_balance, 8980); // 10000 - 1000 - 20 (gas)
        assert_eq!(bob_balance, 1000);
    }

    #[test]
    fn test_abi_encoding() {
        let config = SDKNetworkConfig {
            rpc_endpoints: vec!["http://localhost:8545".to_string()],
            chain_id: 1,
            gas_price: 20,
            timeout: std::time::Duration::from_secs(30),
        };

        let sdk = tokio::runtime::Runtime::new().unwrap().block_on(SymbiosSDK::new(config)).unwrap();

        let function = FunctionABI {
            name: "transfer".to_string(),
            inputs: vec![ABIType::Address, ABIType::Uint(256)],
            outputs: vec![ABIType::Bool],
            state_mutability: StateMutability::NonPayable,
        };

        let args = vec![
            ABIValue::Address(Address::from_hex("0x1234567890123456789012345678901234567890").unwrap()),
            ABIValue::Uint(1000),
        ];

        let encoded = sdk.encode_function_call(&function, args).unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(encoded.len(), 4 + 32 + 32); // 4 byte signature + 2 args * 32 bytes
    }
}
