//! Network Demo - Demonstrates the complete P2P networking stack
//!
//! This module shows how to use the advanced P2P network layer with:
//! - libp2p-based networking
//! - Topic-based message broadcasting
//! - Peer discovery and management
//! - Network events handling

use crate::network::{Network, NetworkConfig, NetworkEvent, NetworkManager, NetworkTrait};
use crate::types::{Transaction, PublicKey, Block};
use crate::dag_mempool::SmartDagMempool;
use crate::storage::{Storage, StorageTrait};
use std::time::Duration;
use tokio::time::sleep;

/// Network demonstration node
pub struct NetworkDemo {
    network_manager: NetworkManager,
    dag_mempool: SmartDagMempool,
}

impl NetworkDemo {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("🔧 Initializing Network Demo...");

        // Create storage
        let temp_dir = tempfile::tempdir()?;
        let storage = Box::new(Storage::new(temp_dir.path())?);

        // Create network manager
        let mut network_manager = NetworkManager::new();

        // Add main network
        let main_config = NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/38383".to_string(),
            ..Default::default()
        };

        network_manager.add_network("main".to_string(), main_config, storage).await?;
        println!("✅ Main network initialized on port 38383");

        // Create DAG mempool
        let validators = vec![
            PublicKey::new("validator_1".to_string()),
            PublicKey::new("validator_2".to_string()),
            PublicKey::new("validator_3".to_string()),
        ];
        let dag_mempool = SmartDagMempool::new(validators, 100);

        Ok(Self {
            network_manager,
            dag_mempool,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting Network Demo");
        println!("========================");

        // Start network event processing
        let mut network_manager = std::mem::take(&mut self.network_manager);
        tokio::spawn(async move {
            Self::process_network_events(&mut network_manager).await;
        });

        // Give network time to start
        sleep(Duration::from_secs(2)).await;

        // Demonstrate transaction broadcasting
        self.demonstrate_transaction_broadcast().await?;

        // Demonstrate peer discovery
        self.demonstrate_peer_discovery().await?;

        // Demonstrate DAG mempool integration
        self.demonstrate_dag_integration().await?;

        println!("\n🎉 Network Demo completed successfully!");
        println!("📊 Demonstrated:");
        println!("   ✅ P2P network initialization");
        println!("   ✅ Transaction broadcasting");
        println!("   ✅ Peer discovery");
        println!("   ✅ Network event handling");
        println!("   ✅ DAG mempool integration");

        Ok(())
    }

    async fn process_network_events(network_manager: &mut NetworkManager) {
        println!("📡 Network event processor started");

        loop {
            match network_manager.process_all_events().await {
                Ok(events) => {
                    for event in events {
                        match event {
                            NetworkEvent::TransactionReceived(tx) => {
                                println!("📦 Received transaction: {:?}", tx.id);
                            }
                            NetworkEvent::BlockReceived(block) => {
                                println!("🧱 Received block: height {}", block.header.height);
                            }
                            NetworkEvent::PeerConnected(peer_id) => {
                                println!("🔗 Peer connected: {}", peer_id);
                            }
                            NetworkEvent::PeerDisconnected(peer_id) => {
                                println!("🔌 Peer disconnected: {}", peer_id);
                            }
                            NetworkEvent::PeerDiscovered(peer_id) => {
                                println!("🔍 Peer discovered: {}", peer_id);
                            }
                            _ => {
                                println!("📨 Other network event: {:?}", event);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Network error: {}", e);
                }
            }

            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn demonstrate_transaction_broadcast(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n📢 Demonstrating Transaction Broadcasting");
        println!("==========================================");

        // Create sample transaction
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 1000, 1);

        // Sign the transaction
        let (_, private_key) = Transaction::generate_keypair();
        tx.sign(&private_key)?;

        println!("💰 Created transaction: {} -> {} (amount: {})",
                 tx.sender.as_str(), tx.receiver.as_str(), tx.amount);

        // Broadcast to all networks
        self.network_manager.broadcast_to_all(&tx).await?;
        println!("📡 Transaction broadcasted to all networks");

        // Add to DAG mempool
        self.dag_mempool.add_transaction(tx.clone()).await?;
        println!("💾 Transaction added to DAG mempool");

        Ok(())
    }

    async fn demonstrate_peer_discovery(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🔍 Demonstrating Peer Discovery");
        println!("===============================");

        if let Some(network) = self.network_manager.get_network("main") {
            let connected_peers = network.get_connected_peers().await;
            println!("🌐 Connected peers: {}", connected_peers.len());

            for peer in connected_peers {
                println!("   • {}", peer);
            }
        }

        Ok(())
    }

    async fn demonstrate_dag_integration(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🔗 Demonstrating DAG Mempool Integration");
        println!("========================================");

        println!("📊 DAG Mempool Stats:");
        println!("   • Pending transactions: {}", self.dag_mempool.pending_transactions_count());
        println!("   • Processed transactions: {}", self.dag_mempool.get_dag_stats().total_mempool_blocks);

        // Create a few more transactions to show DAG building
        for i in 0..3 {
            let sender = PublicKey::new(format!("user_{}", i));
            let receiver = PublicKey::new(format!("user_{}", i + 1));
            let mut tx = Transaction::new(sender, receiver, 100 * (i + 1), i as u64 + 2);

            let (_, private_key) = Transaction::generate_keypair();
            tx.sign(&private_key)?;

            self.dag_mempool.add_transaction(tx).await?;
        }

        println!("✅ Added transactions to DAG mempool");

        Ok(())
    }
}
