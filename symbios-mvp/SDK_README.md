# Symbios Network SDK

## Overview

The Symbios SDK provides a high-level, developer-friendly interface for interacting with the Symbios Network. It abstracts away complex blockchain operations and provides simple APIs for common tasks like account management, token transfers, and smart contract interactions.

## Features

- **Account Management**: Create and manage blockchain accounts with hybrid cryptography
- **Transaction Building**: Intuitive API for creating and signing transactions
- **Token Operations**: Easy token transfers and balance queries
- **Smart Contracts**: Deploy and interact with smart contracts using ABI definitions
- **Network Monitoring**: Real-time network status and health monitoring
- **Error Handling**: Comprehensive error handling with detailed error messages

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
symbios-sdk = { git = "https://github.com/magish2112/symbios-network", path = "symbios-mvp/src/sdk.rs" }
```

## Quick Start

```rust
use symbios_sdk::*;

#[tokio::main]
async fn main() -> SDKResult<()> {
    // Initialize SDK
    let config = SDKNetworkConfig {
        rpc_endpoints: vec!["http://localhost:8545".to_string()],
        chain_id: 1,
        gas_price: 20,
        timeout: std::time::Duration::from_secs(30),
    };

    let mut sdk = SymbiosSDK::new(config).await?;

    // Create account
    let account = sdk.create_account("my_account".to_string()).await?;
    println!("Account created: {}", account.address.to_hex());

    // Transfer tokens
    let receipt = sdk.transfer("alice", "bob", 1000).await?;
    println!("Transfer successful: {:?}", receipt.status);

    Ok(())
}
```

## Account Management

### Creating Accounts

```rust
let account = sdk.create_account("my_wallet".to_string()).await?;
println!("Address: {}", account.address.to_hex());
println!("Balance: {}", account.balance);
println!("Nonce: {}", account.nonce);
```

### Account Security

Accounts use hybrid cryptography (Ed25519 + Post-Quantum) for maximum security:

- **Ed25519**: Fast, widely supported classical cryptography
- **Post-Quantum**: Protection against quantum computer attacks
- **Automatic Selection**: SDK chooses optimal algorithm based on security/performance requirements

## Transactions

### Building Transactions

```rust
// Create transaction builder
let tx_builder = sdk.build_transaction("sender_account")?;

// Configure transaction
let tx = tx_builder
    .to(recipient_address)
    .value(1000)
    .fee(20)
    .build()?;

// Send transaction
let receipt = sdk.send_transaction(tx).await?;
```

### Transaction Status

```rust
match receipt.status {
    ExecutionStatus::Success => println!("Transaction successful!"),
    ExecutionStatus::Failed(msg) => println!("Transaction failed: {}", msg),
    ExecutionStatus::Reverted(msg) => println!("Transaction reverted: {}", msg),
}
```

## Token Operations

### Balance Queries

```rust
let balance = sdk.get_balance("account_name")?;
println!("Balance: {} tokens", balance);
```

### Token Transfers

```rust
let receipt = sdk.transfer("sender", "receiver", amount).await?;
match receipt.status {
    ExecutionStatus::Success => println!("Transfer completed"),
    _ => println!("Transfer failed"),
}
```

## Smart Contracts

### Contract Deployment

```rust
// Define contract ABI
let abi = ContractABI {
    functions: HashMap::new(), // Define your functions
    events: HashMap::new(),
};

// Deploy contract
let contract = sdk.deploy_contract(
    "deployer_account",
    contract_bytecode,
    abi
).await?;

println!("Contract deployed at: {}", contract.address.to_hex());
```

### Contract Calls

```rust
// Call contract function
let result = sdk.call_contract(
    "caller_account",
    &contract,
    "function_name",
    vec![ABIValue::Uint(1000)]
).await?;

if result.success {
    println!("Contract call successful, gas used: {}", result.gas_used);
}
```

### ABI Definition

```rust
let mut functions = HashMap::new();

functions.insert("transfer".to_string(), FunctionABI {
    name: "transfer".to_string(),
    inputs: vec![
        ABIType::Address,  // recipient
        ABIType::Uint(256) // amount
    ],
    outputs: vec![ABIType::Bool], // success
    state_mutability: StateMutability::NonPayable,
});
```

## Network Operations

### Network Status

```rust
let status = sdk.get_network_status().await?;
println!("Block height: {}", status.block_height);
println!("Gas price: {}", status.gas_price);
println!("Peers: {}", status.peer_count);
```

### Error Handling

The SDK provides comprehensive error handling:

```rust
match sdk.transfer("alice", "bob", 1000).await {
    Ok(receipt) => println!("Success: {:?}", receipt),
    Err(SDKError::InsufficientFunds { required, available }) => {
        println!("Need {} tokens, have {}", required, available);
    }
    Err(SDKError::AccountNotFound(name)) => {
        println!("Account '{}' not found", name);
    }
    Err(SDKError::NetworkError(msg)) => {
        println!("Network error: {}", msg);
    }
    Err(e) => println!("Other error: {:?}", e),
}
```

## Advanced Features

### Hybrid Cryptography

```rust
// SDK automatically uses hybrid crypto for all operations
// Choose algorithm version based on your needs:

let keypair_v1 = sdk.hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V1).await?; // Balanced
let keypair_v2 = sdk.hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V2).await?; // Max security
let keypair_v3 = sdk.hybrid_crypto.generate_keypair(HybridAlgorithmVersion::V3).await?; // Long-term
```

### Performance Monitoring

The SDK includes built-in performance monitoring:

```rust
// SDK automatically tracks:
// - Transaction success rates
// - Gas usage patterns
// - Network latency
// - Cryptographic operation performance

// Access metrics through the underlying metrics server
let metrics = sdk.get_metrics().await?;
```

## Examples

### Basic Token Transfer

```rust
use symbios_sdk::*;

#[tokio::main]
async fn main() -> SDKResult<()> {
    let mut sdk = SymbiosSDK::new(get_network_config()).await?;

    // Create accounts
    sdk.create_account("alice".to_string()).await?;
    sdk.create_account("bob".to_string()).await?;

    // Fund alice (in real app, this would be from existing balance)
    if let Some(alice) = sdk.accounts.get_mut("alice") {
        alice.balance = 10000;
    }

    // Transfer tokens
    sdk.transfer("alice", "bob", 1000).await?;

    println!("Transfer successful!");
    println!("Alice balance: {}", sdk.get_balance("alice")?);
    println!("Bob balance: {}", sdk.get_balance("bob")?);

    Ok(())
}

fn get_network_config() -> SDKNetworkConfig {
    SDKNetworkConfig {
        rpc_endpoints: vec!["http://localhost:8545".to_string()],
        chain_id: 1,
        gas_price: 20,
        timeout: std::time::Duration::from_secs(30),
    }
}
```

### Smart Contract Interaction

```rust
// Deploy ERC-20 token contract
let token_contract = sdk.deploy_contract(
    "deployer",
    token_bytecode,
    create_erc20_abi()
).await?;

// Mint tokens
sdk.call_contract(
    "deployer",
    &token_contract,
    "mint",
    vec![ABIValue::Address(user_address), ABIValue::Uint(1000000)]
).await?;

// Transfer tokens
sdk.call_contract(
    "user",
    &token_contract,
    "transfer",
    vec![ABIValue::Address(recipient), ABIValue::Uint(1000)]
).await?;
```

## API Reference

### Core Types

- `SymbiosSDK`: Main SDK instance
- `Account`: User account with keys and balance
- `TransactionBuilder`: Fluent API for transaction building
- `SmartContract`: Deployed contract with ABI
- `ContractABI`: Contract interface definition

### Error Types

- `SDKError::AccountNotFound`
- `SDKError::InsufficientFunds`
- `SDKError::InvalidTransaction`
- `SDKError::NetworkError`
- `SDKError::ContractError`

## Best Practices

1. **Error Handling**: Always handle SDK errors appropriately
2. **Gas Estimation**: Monitor gas usage for cost optimization
3. **Security**: Use hardware security modules for production keys
4. **Testing**: Test thoroughly on testnet before mainnet deployment
5. **Monitoring**: Use built-in metrics for performance monitoring

## Troubleshooting

### Common Issues

**Connection Failed**
```
SDKError::NetworkError("Connection refused")
```
- Check if RPC endpoint is running
- Verify network configuration
- Check firewall settings

**Insufficient Funds**
```
SDKError::InsufficientFunds { required: 1000, available: 500 }
```
- Ensure account has sufficient balance
- Include fee in balance calculations
- Check for pending transactions

**Contract Call Failed**
```
SDKError::ContractError("Function not found")
```
- Verify function name in ABI
- Check function signature
- Ensure contract is deployed

## Contributing

Contributions welcome! Please see our [Contributing Guide](../CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](../LICENSE) file for details.
