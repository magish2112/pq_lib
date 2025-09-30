//! Symbios SDK Usage Examples
//!
//! This file demonstrates how to use the Symbios SDK for common operations:
//! - Account management
//! - Token transfers
//! - Smart contract deployment and interaction
//! - Network monitoring

use symbios_mvp::sdk::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> SDKResult<()> {
    println!("🚀 Symbios SDK Usage Examples");
    println!("===============================\n");

    // Initialize SDK
    let network_config = SDKNetworkConfig {
        rpc_endpoints: vec!["http://localhost:8545".to_string()],
        chain_id: 1,
        gas_price: 20,
        timeout: std::time::Duration::from_secs(30),
    };

    let mut sdk = SymbiosSDK::new(network_config).await?;
    println!("✅ SDK initialized\n");

    // Example 1: Account Management
    println!("📝 Example 1: Account Management");
    println!("--------------------------------");

    let alice = sdk.create_account("alice".to_string()).await?;
    let bob = sdk.create_account("bob".to_string()).await?;

    println!("Created accounts:");
    println!("  Alice: {} ({})", alice.name, alice.address.to_hex());
    println!("  Bob:   {} ({})", bob.name, bob.address.to_hex());
    println!();

    // Example 2: Token Transfer
    println!("💸 Example 2: Token Transfer");
    println!("----------------------------");

    // For demo purposes, manually set Alice's balance
    if let Some(alice_account) = sdk.accounts.get_mut("alice") {
        alice_account.balance = 10000;
    }

    println!("Alice's initial balance: {} tokens", sdk.get_balance("alice")?);
    println!("Bob's initial balance: {} tokens", sdk.get_balance("bob")?);

    // Transfer 1000 tokens from Alice to Bob
    let receipt = sdk.transfer("alice", "bob", 1000).await?;
    println!("✅ Transfer completed!");
    println!("  Transaction hash: {}", receipt.tx_hash);
    println!("  Gas used: {}", receipt.gas_used);
    println!("  Status: {:?}", receipt.status);

    println!("Alice's new balance: {} tokens", sdk.get_balance("alice")?);
    println!("Bob's new balance: {} tokens", sdk.get_balance("bob")?);
    println!();

    // Example 3: Smart Contract Deployment
    println!("📄 Example 3: Smart Contract Deployment");
    println!("---------------------------------------");

    // Simple ERC-20 like contract bytecode (placeholder)
    let contract_bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Minimal bytecode

    // Define contract ABI
    let mut functions = HashMap::new();
    functions.insert("transfer".to_string(), FunctionABI {
        name: "transfer".to_string(),
        inputs: vec![ABIType::Address, ABIType::Uint(256)],
        outputs: vec![ABIType::Bool],
        state_mutability: StateMutability::NonPayable,
    });

    functions.insert("balanceOf".to_string(), FunctionABI {
        name: "balanceOf".to_string(),
        inputs: vec![ABIType::Address],
        outputs: vec![ABIType::Uint(256)],
        state_mutability: StateMutability::View,
    });

    let contract_abi = ContractABI {
        functions,
        events: HashMap::new(),
    };

    // Deploy contract
    let contract = sdk.deploy_contract("alice", contract_bytecode, contract_abi).await?;
    println!("✅ Contract deployed!");
    println!("  Contract address: {}", contract.address.to_hex());
    println!("  Creator: {}", contract.creator.to_hex());
    println!("  Deployed at: {}", contract.deployed_at);
    println!();

    // Example 4: Smart Contract Interaction
    println!("🔄 Example 4: Smart Contract Interaction");
    println!("---------------------------------------");

    // Call transfer function on the contract
    let transfer_args = vec![
        ABIValue::Address(bob.address),
        ABIValue::Uint(500),
    ];

    let call_result = sdk.call_contract("alice", &contract, "transfer", transfer_args).await?;
    println!("✅ Contract call completed!");
    println!("  Success: {}", call_result.success);
    println!("  Gas used: {}", call_result.gas_used);
    println!();

    // Example 5: Network Monitoring
    println!("🌐 Example 5: Network Monitoring");
    println!("-------------------------------");

    let network_status = sdk.get_network_status().await?;
    println!("Network Status:");
    println!("  Chain ID: {}", network_status.chain_id);
    println!("  Block Height: {}", network_status.block_height);
    println!("  Gas Price: {} wei", network_status.gas_price);
    println!("  Peer Count: {}", network_status.peer_count);
    println!("  Syncing: {}", network_status.syncing);
    println!();

    // Example 6: Error Handling
    println!("⚠️  Example 6: Error Handling");
    println!("-----------------------------");

    // Try to transfer more than available balance
    match sdk.transfer("bob", "alice", 5000).await {
        Ok(_) => println!("Unexpected success"),
        Err(SDKError::InsufficientFunds { required, available }) => {
            println!("✅ Error handled correctly!");
            println!("  Required: {} tokens", required);
            println!("  Available: {} tokens", available);
        }
        Err(e) => println!("Other error: {:?}", e),
    }

    // Try to access non-existent account
    match sdk.get_balance("charlie") {
        Ok(_) => println!("Unexpected success"),
        Err(SDKError::AccountNotFound(name)) => {
            println!("✅ Account not found error handled!");
            println!("  Account: {}", name);
        }
        Err(e) => println!("Other error: {:?}", e),
    }

    println!();
    println!("🎉 All SDK examples completed successfully!");
    println!("📚 Check the SDK documentation for more advanced features.");

    Ok(())
}

/// Advanced example: DeFi token swap simulation
pub async fn defi_token_swap_example() -> SDKResult<()> {
    println!("\n💱 Advanced Example: DeFi Token Swap Simulation");
    println!("=================================================");

    let network_config = SDKNetworkConfig {
        rpc_endpoints: vec!["http://localhost:8545".to_string()],
        chain_id: 1,
        gas_price: 30,
        timeout: std::time::Duration::from_secs(60),
    };

    let mut sdk = SymbiosSDK::new(network_config).await?;

    // Create users
    let user = sdk.create_account("trader".to_string()).await?;
    if let Some(account) = sdk.accounts.get_mut("trader") {
        account.balance = 100000; // Give user tokens
    }

    // Deploy DEX contract (simplified)
    let dex_abi = create_dex_abi();
    let dex_bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Placeholder

    let dex_contract = sdk.deploy_contract("trader", dex_bytecode, dex_abi).await?;
    println!("✅ DEX contract deployed at: {}", dex_contract.address.to_hex());

    // Simulate token swap
    let swap_args = vec![
        ABIValue::Address(user.address), // User address
        ABIValue::Uint(1000),           // Input amount
        ABIValue::Uint(950),            // Min output amount
        ABIValue::Address(Address::from_hex("0x1234567890123456789012345678901234567890").unwrap()), // Output token
    ];

    let swap_result = sdk.call_contract("trader", &dex_contract, "swapExactTokensForTokens", swap_args).await?;

    if swap_result.success {
        println!("✅ Token swap completed successfully!");
        println!("  Gas used: {}", swap_result.gas_used);
    } else {
        println!("❌ Token swap failed");
    }

    Ok(())
}

/// Create DEX contract ABI
fn create_dex_abi() -> ContractABI {
    let mut functions = HashMap::new();

    functions.insert("swapExactTokensForTokens".to_string(), FunctionABI {
        name: "swapExactTokensForTokens".to_string(),
        inputs: vec![
            ABIType::Uint(256), // amountIn
            ABIType::Uint(256), // amountOutMin
            ABIType::Array(Box::new(ABIType::Address)), // path
            ABIType::Address,   // to
        ],
        outputs: vec![ABIType::Array(Box::new(ABIType::Uint(256)))], // amounts
        state_mutability: StateMutability::NonPayable,
    });

    functions.insert("getAmountsOut".to_string(), FunctionABI {
        name: "getAmountsOut".to_string(),
        inputs: vec![
            ABIType::Uint(256), // amountIn
            ABIType::Array(Box::new(ABIType::Address)), // path
        ],
        outputs: vec![ABIType::Array(Box::new(ABIType::Uint(256)))], // amounts
        state_mutability: StateMutability::View,
    });

    ContractABI {
        functions,
        events: HashMap::new(),
    }
}

/// Example of batch transaction processing
pub async fn batch_transaction_example() -> SDKResult<()> {
    println!("\n📦 Advanced Example: Batch Transaction Processing");
    println!("==================================================");

    let network_config = SDKNetworkConfig {
        rpc_endpoints: vec!["http://localhost:8545".to_string()],
        chain_id: 1,
        gas_price: 25,
        timeout: std::time::Duration::from_secs(30),
    };

    let mut sdk = SymbiosSDK::new(network_config).await?;

    // Create multiple accounts
    let accounts = vec!["user1", "user2", "user3", "user4", "user5"];
    for account_name in &accounts {
        let account = sdk.create_account(account_name.to_string()).await?;
        if let Some(acc) = sdk.accounts.get_mut(account_name) {
            acc.balance = 10000; // Fund each account
        }
        println!("Created account: {} ({})", account_name, account.address.to_hex());
    }

    // Perform batch transfers
    println!("\n📤 Performing batch transfers...");
    let mut receipts = Vec::new();

    for (i, sender) in accounts.iter().enumerate() {
        if i < accounts.len() - 1 {
            let receiver = accounts[i + 1];
            let receipt = sdk.transfer(sender, receiver, 500).await?;
            receipts.push(receipt);
            println!("  {} → {}: 500 tokens", sender, receiver);
        }
    }

    println!("\n✅ Batch processing completed!");
    println!("  Total transactions: {}", receipts.len());
    println!("  All transactions successful: {}", receipts.iter().all(|r| matches!(r.status, ExecutionStatus::Success)));

    // Check final balances
    println!("\n💰 Final balances:");
    for account_name in &accounts {
        let balance = sdk.get_balance(account_name)?;
        println!("  {}: {} tokens", account_name, balance);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_examples_run_without_panic() {
        // Test that examples can be called without panicking
        let result = main().await;
        assert!(result.is_ok(), "Main example should run without errors");

        let result = defi_token_swap_example().await;
        assert!(result.is_ok(), "DeFi example should run without errors");

        let result = batch_transaction_example().await;
        assert!(result.is_ok(), "Batch example should run without errors");
    }
}
