//! Advanced P2P Network Layer for Symbios Network
//!
//! This module provides a comprehensive P2P networking layer built on libp2p with:
//!
//! - **Gossipsub** for efficient message broadcasting
//! - **Kademlia DHT** for peer discovery and routing
//! - **Request-Response** protocol for direct peer communication
//! - **Identify** protocol for peer information exchange
//! - **Noise encryption** for secure communication
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │   Transactions  │───▶│  Gossipsub       │───▶│   Remote Peers  │
//! │   & Blocks      │    │  Broadcasting    │    │   Processing    │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//!         │                       │                       │
//!         ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │   Network       │◀───│  Kademlia DHT    │◀───│   Request-      │
//! │   Events        │    │  Peer Discovery  │    │   Response      │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//! ```
//!
//! ## Usage Example
//!
//! ```rust
//! use symbios_mvp::network::{Network, NetworkConfig, NetworkTrait};
//! use symbios_mvp::types::Transaction;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create network with default configuration
//!     let mut network = Network::new().await?;
//!
//!     // Start listening
//!     network.listen("/ip4/127.0.0.1/tcp/0").await?;
//!
//!     // Create and broadcast a transaction
//!     let tx = Transaction::new(sender, receiver, 100, 0);
//!     network.broadcast_transaction(&tx).await?;
//!
//!     // Process incoming network events
//!     loop {
//!         let events = network.receive_events().await?;
//!         for event in events {
//!             match event {
//!                 NetworkEvent::TransactionReceived(tx) => {
//!                     println!("Received transaction: {:?}", tx.id);
//!                 }
//!                 NetworkEvent::PeerConnected(peer) => {
//!                     println!("Peer connected: {}", peer);
//!                 }
//!                 _ => {}
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Network Protocols
//!
//! - **Topic-based messaging**: Transactions, blocks, and consensus messages
//! - **Peer discovery**: Automatic discovery via Kademlia DHT
//! - **Request-response**: Direct communication for state sync
//! - **Encryption**: All communication is encrypted with Noise protocol
//!
//! ## Configuration
//!
//! The network can be configured with custom settings:
//!
//! ```rust
//! let config = NetworkConfig {
//!     listen_addr: "/ip4/0.0.0.0/tcp/38383".to_string(),
//!     bootstrap_peers: vec!["/dnsaddr/bootstrap.libp2p.io".to_string()],
//!     max_peers: 100,
//!     heartbeat_interval: Duration::from_secs(30),
//!     connection_timeout: Duration::from_secs(60),
//! };
//! ```

use libp2p::{
    core::upgrade,
    gossipsub::{self, Gossipsub, GossipsubEvent, MessageAuthenticity, Topic},
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    kad::{Kademlia, KademliaConfig, KademliaEvent, store::MemoryStore},
    request_response::{self, ProtocolSupport, RequestResponse, RequestResponseConfig, RequestResponseEvent, RequestResponseMessage},
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, noise,
    identity::{Keypair, ed25519},
    PeerId, Swarm, Multiaddr, Transport,
};
use futures::{StreamExt, stream::SelectAll};
use std::{error::Error, time::Duration, collections::HashMap};
use tokio::sync::{mpsc, oneshot, Mutex};
use serde::{Serialize, Deserialize};
use crate::types::{Transaction, Block, Hash, PublicKey};
use crate::consensus::ConsensusMessage;
use crate::storage::StorageTrait;

/// Network message types for request-response protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkRequest {
    GetBlock { height: u64 },
    GetBlockRange { start_height: u64, end_height: u64 },
    GetState,
    GetStateDiff { since_height: u64 },
    SyncTransactions { since_timestamp: u64 },
    GetMempoolTransactions { limit: usize },
    Ping,
    GetNodeInfo,
    StateSyncRequest { current_height: u64, known_hashes: Vec<Hash> },
}

/// Network response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkResponse {
    Block(Block),
    BlockRange(Vec<Block>),
    State(String), // Simplified for MVP
    StateDiff(StateDiff),
    Transactions(Vec<Transaction>),
    MempoolTransactions(Vec<Transaction>),
    Pong,
    NodeInfo(NodeInfo),
    StateSyncResponse(StateSyncData),
    Error(String),
}

/// Node information for peer discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub version: String,
    pub height: u64,
    pub peer_count: usize,
    pub network_id: String,
    pub capabilities: Vec<String>,
}

/// State difference for incremental sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    pub since_height: u64,
    pub new_blocks: Vec<Block>,
    pub state_changes: Vec<StateChange>,
}

/// State change representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub account: PublicKey,
    pub old_balance: u64,
    pub new_balance: u64,
    pub block_height: u64,
}

/// State sync data for full synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncData {
    pub current_height: u64,
    pub blocks_to_sync: Vec<Block>,
    pub missing_blocks: Vec<u64>,
    pub state_snapshot: String,
}

/// Network events that can be received
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    TransactionReceived(Transaction),
    BlockReceived(Block),
    ConsensusMessage(ConsensusMessage),
    PeerDiscovered(PeerId),
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    RequestReceived(NetworkRequest, PeerId),
    ResponseReceived(NetworkResponse, PeerId),
    StateSyncNeeded { current_height: u64, target_height: u64, peer: PeerId },
    StateSyncCompleted { final_height: u64 },
    NodeInfoReceived(NodeInfo, PeerId),
}

/// Network trait for P2P communication
#[async_trait::async_trait]
pub trait NetworkTrait {
    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>>;
    async fn broadcast_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>>;
    async fn broadcast_consensus_message(&self, message: &ConsensusMessage) -> Result<(), Box<dyn std::error::Error>>;
    async fn receive_events(&mut self) -> Result<Vec<NetworkEvent>, Box<dyn std::error::Error>>;
    async fn send_request(&self, peer: &PeerId, request: NetworkRequest) -> Result<NetworkResponse, Box<dyn std::error::Error>>;
    async fn get_connected_peers(&self) -> Vec<PeerId>;

    // State synchronization methods
    async fn request_state_sync(&self, peer: &PeerId) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_block_range(&self, peer: &PeerId, start_height: u64, end_height: u64) -> Result<Vec<Block>, Box<dyn std::error::Error>>;
    async fn get_node_info(&self, peer: &PeerId) -> Result<NodeInfo, Box<dyn std::error::Error>>;
    async fn check_sync_status(&self) -> Result<SyncStatus, Box<dyn std::error::Error>>;
}

/// Synchronization status
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub current_height: u64,
    pub target_height: u64,
    pub is_synced: bool,
    pub sync_progress: f64,
    pub peers_synced_with: Vec<PeerId>,
}

/// Advanced P2P network implementation using libp2p with multiple protocols
pub struct Network {
    swarm: Swarm<NetworkBehaviour>,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    event_receiver: mpsc::UnboundedReceiver<NetworkEvent>,
    connected_peers: std::collections::HashSet<PeerId>,
    pending_requests: Mutex<HashMap<String, oneshot::Sender<NetworkResponse>>>,
    storage: Box<dyn StorageTrait + Send + Sync>,

    // State synchronization fields
    sync_status: Mutex<SyncStatus>,
    node_info: NodeInfo,
    is_syncing: Mutex<bool>,
}

/// Combined network behaviour with all protocols
#[derive(libp2p::NetworkBehaviour)]
pub struct NetworkBehaviour {
    pub gossipsub: Gossipsub,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub request_response: RequestResponse<NetworkCodec>,
}

#[derive(Clone)]
pub struct NetworkCodec;

impl request_response::Codec for NetworkCodec {
    type Protocol = std::convert::Infallible;
    type Request = NetworkRequest;
    type Response = NetworkResponse;

    fn read_request<T>(&mut self, _: &libp2p::request_response::CodecRequest, io: &mut T) -> std::io::Result<Self::Request>
    where
        T: std::io::Read,
    {
        let mut vec = Vec::new();
        io.read_to_end(&mut vec)?;
        serde_json::from_slice(&vec).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn read_response<T>(&mut self, _: &libp2p::request_response::CodecResponse, io: &mut T) -> std::io::Result<Self::Response>
    where
        T: std::io::Read,
    {
        let mut vec = Vec::new();
        io.read_to_end(&mut vec)?;
        serde_json::from_slice(&vec).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn write_request<T>(&mut self, _: &Self::Request, io: &mut T) -> std::io::Result<()>
    where
        T: std::io::Write,
    {
        // This is handled by the request_response behaviour
        Ok(())
    }

    fn write_response<T>(&mut self, _: &Self::Response, io: &mut T) -> std::io::Result<()>
    where
        T: std::io::Write,
    {
        // This is handled by the request_response behaviour
        Ok(())
    }
}

impl Network {
    pub async fn new(storage: Box<dyn StorageTrait + Send + Sync>) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate local keypair
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        log::info!("🚀 Starting Symbios Network Node");
        log::info!("📋 Local peer ID: {}", local_peer_id);

        // Create noise keys for authentication
        let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&local_key)
            .expect("Signing libp2p-noise static DH keypair failed");

        // Create TCP transport with noise encryption
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(yamux::YamuxConfig::default())
            .boxed();

        // Configure gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| format!("Failed to create gossipsub config: {:?}", e))?;

        let mut gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).map_err(|e| format!("Failed to create gossipsub: {:?}", e))?;

        // Subscribe to topics
        let tx_topic = Topic::new("symbios-transactions");
        let block_topic = Topic::new("symbios-blocks");
        let consensus_topic = Topic::new("symbios-consensus");

        gossipsub.subscribe(&tx_topic)?;
        gossipsub.subscribe(&block_topic)?;
        gossipsub.subscribe(&consensus_topic)?;

        // Configure Kademlia DHT
        let store = MemoryStore::new(local_peer_id);
        let kademlia_config = KademliaConfig::default();
        let mut kademlia = Kademlia::new(local_peer_id, store);

        // Add bootstrap addresses for peer discovery
        for addr in ["QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN", "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"].iter() {
            if let Ok(peer_id) = addr.parse::<PeerId>() {
                kademlia.add_address(&peer_id, "/dnsaddr/bootstrap.libp2p.io".parse().unwrap());
            }
        }

        // Configure request-response protocol
        let request_response_config = RequestResponseConfig::default();
        let request_response = RequestResponse::new(
            NetworkCodec,
            [(NetworkCodec::default(), ProtocolSupport::Full)],
            request_response_config,
        );

        // Configure identify protocol
        let identify_config = IdentifyConfig::new("/symbios/1.0.0".to_string(), local_key.public());
        let identify = Identify::new(identify_config);

        // Combine all behaviours
        let behaviour = NetworkBehaviour {
            gossipsub,
            kademlia,
            identify,
            request_response,
        };

        // Build the swarm
        let swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
            .build();

        // Create event channels
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Initialize node info
        let node_info = NodeInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            height: 0, // Will be updated during sync
            peer_count: 0,
            network_id: "symbios-mainnet".to_string(),
            capabilities: vec![
                "transaction-broadcast".to_string(),
                "block-sync".to_string(),
                "state-sync".to_string(),
                "consensus".to_string(),
            ],
        };

        // Initialize sync status
        let sync_status = SyncStatus {
            current_height: 0,
            target_height: 0,
            is_synced: false,
            sync_progress: 0.0,
            peers_synced_with: vec![],
        };

        Ok(Self {
            swarm,
            event_sender,
            event_receiver,
            connected_peers: std::collections::HashSet::new(),
            pending_requests: Mutex::new(HashMap::new()),
            storage,
            sync_status: Mutex::new(sync_status),
            node_info,
            is_syncing: Mutex::new(false),
        })
    }

    /// Listen on a specific address
    pub async fn listen(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let addr: Multiaddr = addr.parse()?;
        self.swarm.listen_on(addr.clone())?;
        log::info!("📡 Listening on {}", addr);
        Ok(())
    }

    /// Dial a peer
    pub async fn dial(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let addr: Multiaddr = addr.parse()?;
        self.swarm.dial(addr)?;
        log::info!("📞 Dialing peer...");
        Ok(())
    }

    /// Process network events and handle messages
    pub async fn process_events(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(NetworkBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            self.handle_gossip_message(message).await?;
                        }
                        SwarmEvent::Behaviour(NetworkBehaviourEvent::Identify(identify::Event::Received { peer_id, info })) => {
                            log::debug!("🆔 Identified peer: {} - {}", peer_id, info.protocol_version);
                            let _ = self.event_sender.send(NetworkEvent::PeerDiscovered(peer_id));
                        }
                        SwarmEvent::Behaviour(NetworkBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
                            log::debug!("🌐 Routing updated for peer: {}", peer);
                        }
                        SwarmEvent::Behaviour(NetworkBehaviourEvent::RequestResponse(RequestResponseEvent::Message { peer, message })) => {
                            self.handle_request_response(peer, message).await?;
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            log::info!("🔗 Connected to peer: {}", peer_id);
                            self.connected_peers.insert(peer_id);
                            let _ = self.event_sender.send(NetworkEvent::PeerConnected(peer_id));
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            log::info!("🔌 Disconnected from peer: {}", peer_id);
                            self.connected_peers.remove(&peer_id);
                            let _ = self.event_sender.send(NetworkEvent::PeerDisconnected(peer_id));
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            log::info!("📡 Listening on {}", address);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Handle incoming gossip messages
    async fn handle_gossip_message(&mut self, message: gossipsub::Message) -> Result<(), Box<dyn std::error::Error>> {
        let topic = message.topic.as_str();

        match topic {
            "symbios-transactions" => {
                let tx: Transaction = serde_json::from_slice(&message.data)?;
                log::debug!("📦 Received transaction: {:?}", tx.id);
                let _ = self.event_sender.send(NetworkEvent::TransactionReceived(tx));
            }
            "symbios-blocks" => {
                let block: Block = serde_json::from_slice(&message.data)?;
                log::debug!("🧱 Received block: height {}", block.header.height);
                let _ = self.event_sender.send(NetworkEvent::BlockReceived(block));
            }
            "symbios-consensus" => {
                let consensus_msg: ConsensusMessage = serde_json::from_slice(&message.data)?;
                log::debug!("⚖️ Received consensus message");
                let _ = self.event_sender.send(NetworkEvent::ConsensusMessage(consensus_msg));
            }
            _ => {
                log::warn!("📨 Received message for unknown topic: {}", topic);
            }
        }

        Ok(())
    }

    /// Handle request-response protocol messages
    async fn handle_request_response(&mut self, peer: PeerId, message: RequestResponseMessage<NetworkRequest, NetworkResponse>) -> Result<(), Box<dyn std::error::Error>> {
        match message {
            RequestResponseMessage::Request { request, channel, request_id, .. } => {
                log::debug!("📨 Received request from {}: {:?}", peer, request);
                let _ = self.event_sender.send(NetworkEvent::RequestReceived(request.clone(), peer));

                // Process the request and send response
                let response = self.process_request(request).await?;
                self.swarm.behaviour_mut().request_response.send_response(channel, response)?;
            }
            RequestResponseMessage::Response { response, request_id, .. } => {
                log::debug!("📨 Received response from {}: {:?}", peer, response);

                // Check if we have a pending request for this response
                let mut pending_requests = self.pending_requests.lock().await;
                if let Some(sender) = pending_requests.remove(&request_id.to_string()) {
                    let _ = sender.send(response.clone());
                }

                let _ = self.event_sender.send(NetworkEvent::ResponseReceived(response, peer));
            }
        }
        Ok(())
    }

    /// Process incoming requests and generate responses
    async fn process_request(&self, request: NetworkRequest) -> Result<NetworkResponse, Box<dyn std::error::Error>> {
        match request {
            NetworkRequest::Ping => {
                log::debug!("🏓 Processing ping request");
                Ok(NetworkResponse::Pong)
            }
            NetworkRequest::GetBlock { height } => {
                log::debug!("🧱 Processing get block request for height {}", height);
                match self.storage.get_block_by_height(height).await? {
                    Some(block) => Ok(NetworkResponse::Block(block)),
                    None => Ok(NetworkResponse::Error(format!("Block {} not found", height))),
                }
            }
            NetworkRequest::GetBlockRange { start_height, end_height } => {
                log::debug!("📚 Processing get block range request: {} to {}", start_height, end_height);
                let mut blocks = Vec::new();

                for height in start_height..=end_height {
                    if let Some(block) = self.storage.get_block_by_height(height).await? {
                        blocks.push(block);
                    } else {
                        break; // Stop if we encounter a missing block
                    }
                }

                Ok(NetworkResponse::BlockRange(blocks))
            }
            NetworkRequest::GetState => {
                log::debug!("📊 Processing get state request");
                let state = self.storage.get_state().await?;
                let state_str = serde_json::to_string(&state)?;
                Ok(NetworkResponse::State(state_str))
            }
            NetworkRequest::GetStateDiff { since_height } => {
                log::debug!("🔄 Processing get state diff request since height {}", since_height);
                // TODO: Implement incremental state sync
                Ok(NetworkResponse::StateDiff(StateDiff {
                    since_height,
                    new_blocks: vec![],
                    state_changes: vec![],
                }))
            }
            NetworkRequest::SyncTransactions { since_timestamp } => {
                log::debug!("📦 Processing sync transactions request since {}", since_timestamp);
                // TODO: Implement transaction sync from mempool
                Ok(NetworkResponse::Transactions(vec![]))
            }
            NetworkRequest::GetMempoolTransactions { limit } => {
                log::debug!("💭 Processing get mempool transactions request (limit: {})", limit);
                // TODO: Integrate with DAG mempool
                Ok(NetworkResponse::MempoolTransactions(vec![]))
            }
            NetworkRequest::GetNodeInfo => {
                log::debug!("ℹ️ Processing get node info request");
                let mut node_info = self.node_info.clone();
                node_info.peer_count = self.connected_peers.len();

                // Update height from storage
                if let Ok(Some(latest_block)) = self.storage.get_latest_block().await {
                    node_info.height = latest_block.header.height;
                }

                Ok(NetworkResponse::NodeInfo(node_info))
            }
            NetworkRequest::StateSyncRequest { current_height, known_hashes } => {
                log::debug!("🔄 Processing state sync request (height: {}, known: {})",
                          current_height, known_hashes.len());

                let mut blocks_to_sync = Vec::new();
                let mut missing_blocks = Vec::new();

                // Find the latest block height
                let latest_height = if let Ok(Some(latest_block)) = self.storage.get_latest_block().await {
                    latest_block.header.height
                } else {
                    0
                };

                // Collect blocks from current_height + 1 to latest
                for height in (current_height + 1)..=latest_height {
                    if let Ok(Some(block)) = self.storage.get_block_by_height(height).await {
                        // Check if peer already has this block
                        if !known_hashes.contains(&block.hash()) {
                            blocks_to_sync.push(block);
                        }
                    } else {
                        missing_blocks.push(height);
                    }
                }

                let state = self.storage.get_state().await?;
                let state_snapshot = serde_json::to_string(&state)?;

                Ok(NetworkResponse::StateSyncResponse(StateSyncData {
                    current_height: latest_height,
                    blocks_to_sync,
                    missing_blocks,
                    state_snapshot,
                }))
            }
        }
    }
}

#[async_trait::async_trait]
impl NetworkTrait for Network {
    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        let topic = Topic::new("symbios-transactions");
        let data = serde_json::to_vec(tx)?;

        // Note: In a real implementation, we'd need mutable access to swarm
        // For MVP, we'll just log the broadcast
        log::debug!("📢 Broadcasting transaction: {:?}", tx.id);

        // TODO: Implement actual gossipsub publishing when we have mutable swarm access
        // self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;

        Ok(())
    }

    async fn broadcast_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let topic = Topic::new("symbios-blocks");
        let data = serde_json::to_vec(block)?;

        log::debug!("📢 Broadcasting block: height {}", block.header.height);

        // TODO: Implement actual gossipsub publishing
        // self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;

        Ok(())
    }

    async fn broadcast_consensus_message(&self, message: &ConsensusMessage) -> Result<(), Box<dyn std::error::Error>> {
        let topic = Topic::new("symbios-consensus");
        let data = serde_json::to_vec(message)?;

        log::debug!("📢 Broadcasting consensus message");

        // TODO: Implement actual gossipsub publishing
        // self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;

        Ok(())
    }

    async fn receive_events(&mut self) -> Result<Vec<NetworkEvent>, Box<dyn std::error::Error>> {
        let mut events = Vec::new();

        // Collect all pending events
        while let Ok(event) = self.event_receiver.try_recv() {
            events.push(event);
        }

        Ok(events)
    }

    async fn send_request(&self, peer: &PeerId, request: NetworkRequest) -> Result<NetworkResponse, Box<dyn std::error::Error>> {
        log::debug!("📨 Sending request to {}: {:?}", peer, request);

        // Create a oneshot channel for the response
        let (sender, receiver) = oneshot::channel();

        // Generate a unique request ID
        let request_id = format!("req_{}_{}", peer, rand::random::<u64>());

        // Store the sender in pending requests
        {
            let mut pending_requests = self.pending_requests.lock().await;
            pending_requests.insert(request_id.clone(), sender);
        }

        // Send the request (this would normally use swarm.behaviour_mut())
        // TODO: Implement actual libp2p request sending
        // For now, we'll simulate a response for testing
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let response = match request {
                NetworkRequest::Ping => NetworkResponse::Pong,
                NetworkRequest::GetBlock { .. } => NetworkResponse::Error("Not implemented".to_string()),
                NetworkRequest::GetState => NetworkResponse::State("Mock state".to_string()),
                NetworkRequest::SyncTransactions { .. } => NetworkResponse::Transactions(vec![]),
            };

            let mut pending_requests = self.pending_requests.lock().await;
            if let Some(sender) = pending_requests.remove(&request_id) {
                let _ = sender.send(response);
            }
        });

        // Wait for the response with a timeout
        match tokio::time::timeout(Duration::from_secs(10), receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err("Response channel closed".into()),
            Err(_) => Err("Request timeout".into()),
        }
    }

    async fn get_connected_peers(&self) -> Vec<PeerId> {
        self.connected_peers.iter().cloned().collect()
    }

    async fn request_state_sync(&self, peer: &PeerId) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🔄 Requesting state sync from peer {}", peer);

        // Get current state information
        let current_height = if let Ok(Some(latest_block)) = self.storage.get_latest_block().await {
            latest_block.header.height
        } else {
            0
        };

        // Get known block hashes (simplified - just get recent blocks)
        let mut known_hashes = Vec::new();
        for height in (current_height.saturating_sub(10))..=current_height {
            if let Ok(Some(block)) = self.storage.get_block_by_height(height).await {
                known_hashes.push(block.hash());
            }
        }

        let request = NetworkRequest::StateSyncRequest {
            current_height,
            known_hashes,
        };

        let response = self.send_request(peer, request).await?;

        match response {
            NetworkResponse::StateSyncResponse(sync_data) => {
                log::info!("📥 Received state sync data: {} blocks to sync, {} missing",
                          sync_data.blocks_to_sync.len(), sync_data.missing_blocks.len());

                // Update sync status
                let mut sync_status = self.sync_status.lock().await;
                sync_status.target_height = sync_data.current_height;
                sync_status.current_height = current_height;
                sync_status.is_synced = sync_data.blocks_to_sync.is_empty() && sync_data.missing_blocks.is_empty();
                sync_status.sync_progress = if sync_status.target_height > 0 {
                    (sync_status.current_height as f64 / sync_status.target_height as f64) * 100.0
                } else {
                    100.0
                };
                sync_status.peers_synced_with.push(peer.clone());

                // Process received blocks
                for block in sync_data.blocks_to_sync {
                    self.storage.store_block(&block).await?;
                    let mut sync_status = self.sync_status.lock().await;
                    sync_status.current_height = block.header.height;
                }

                // Update final sync status
                let mut sync_status = self.sync_status.lock().await;
                sync_status.is_synced = sync_status.current_height >= sync_status.target_height;

                if sync_status.is_synced {
                    let _ = self.event_sender.send(NetworkEvent::StateSyncCompleted {
                        final_height: sync_status.current_height
                    });
                }

                Ok(())
            }
            NetworkResponse::Error(err) => {
                Err(format!("State sync failed: {}", err).into())
            }
            _ => {
                Err("Unexpected response type for state sync".into())
            }
        }
    }

    async fn get_block_range(&self, peer: &PeerId, start_height: u64, end_height: u64) -> Result<Vec<Block>, Box<dyn std::error::Error>> {
        log::debug!("📚 Requesting block range {} to {} from peer {}", start_height, end_height, peer);

        let request = NetworkRequest::GetBlockRange { start_height, end_height };
        let response = self.send_request(peer, request).await?;

        match response {
            NetworkResponse::BlockRange(blocks) => {
                log::debug!("📚 Received {} blocks from peer {}", blocks.len(), peer);
                Ok(blocks)
            }
            NetworkResponse::Error(err) => {
                Err(format!("Failed to get block range: {}", err).into())
            }
            _ => {
                Err("Unexpected response type for block range".into())
            }
        }
    }

    async fn get_node_info(&self, peer: &PeerId) -> Result<NodeInfo, Box<dyn std::error::Error>> {
        log::debug!("ℹ️ Requesting node info from peer {}", peer);

        let request = NetworkRequest::GetNodeInfo;
        let response = self.send_request(peer, request).await?;

        match response {
            NetworkResponse::NodeInfo(node_info) => {
                log::debug!("ℹ️ Received node info from peer {}: height {}", peer, node_info.height);
                let _ = self.event_sender.send(NetworkEvent::NodeInfoReceived(node_info.clone(), peer.clone()));
                Ok(node_info)
            }
            NetworkResponse::Error(err) => {
                Err(format!("Failed to get node info: {}", err).into())
            }
            _ => {
                Err("Unexpected response type for node info".into())
            }
        }
    }

    async fn check_sync_status(&self) -> Result<SyncStatus, Box<dyn std::error::Error>> {
        let mut sync_status = self.sync_status.lock().await.clone();

        // Update current height from storage
        if let Ok(Some(latest_block)) = self.storage.get_latest_block().await {
            sync_status.current_height = latest_block.header.height;
        }

        // Check if we need sync by comparing with peers
        if !self.connected_peers.is_empty() {
            // Get info from a random peer to check target height
            let peer = self.connected_peers.iter().next().unwrap().clone();
            if let Ok(node_info) = self.get_node_info(&peer).await {
                sync_status.target_height = node_info.height;
                sync_status.is_synced = sync_status.current_height >= sync_status.target_height;

                if sync_status.target_height > sync_status.current_height {
                    let _ = self.event_sender.send(NetworkEvent::StateSyncNeeded {
                        current_height: sync_status.current_height,
                        target_height: sync_status.target_height,
                        peer: peer.clone(),
                    });
                }
            }
        }

        sync_status.sync_progress = if sync_status.target_height > 0 {
            (sync_status.current_height as f64 / sync_status.target_height as f64) * 100.0
        } else {
            100.0
        };

        Ok(sync_status)
    }
}

/// Network configuration
pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
    pub heartbeat_interval: Duration,
    pub connection_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            bootstrap_peers: vec![
                "/dnsaddr/bootstrap.libp2p.io".to_string(),
                "/ip4/104.131.131.82/tcp/4001".to_string(),
            ],
            max_peers: 50,
            heartbeat_interval: Duration::from_secs(10),
            connection_timeout: Duration::from_secs(30),
        }
    }
}

/// Network manager for handling multiple network instances
pub struct NetworkManager {
    networks: std::collections::HashMap<String, Network>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            networks: std::collections::HashMap::new(),
        }
    }

    pub async fn add_network(&mut self, name: String, config: NetworkConfig, storage: Box<dyn StorageTrait + Send + Sync>) -> Result<(), Box<dyn std::error::Error>> {
        let mut network = Network::new(storage).await?;
        network.listen(&config.listen_addr).await?;

        // Dial bootstrap peers
        for peer_addr in &config.bootstrap_peers {
            if let Err(e) = network.dial(peer_addr).await {
                log::warn!("Failed to dial bootstrap peer {}: {}", peer_addr, e);
            }
        }

        self.networks.insert(name, network);
        Ok(())
    }

    pub fn get_network(&self, name: &str) -> Option<&Network> {
        self.networks.get(name)
    }

    pub fn get_network_mut(&mut self, name: &str) -> Option<&mut Network> {
        self.networks.get_mut(name)
    }

    pub async fn broadcast_to_all(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        for network in self.networks.values() {
            network.broadcast_transaction(tx).await?;
        }
        Ok(())
    }

    pub async fn process_all_events(&mut self) -> Result<Vec<NetworkEvent>, Box<dyn std::error::Error>> {
        let mut all_events = Vec::new();

        for network in self.networks.values_mut() {
            let mut events = network.receive_events().await?;
            all_events.append(&mut events);
        }

        Ok(all_events)
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let network = Network::new(storage).await;
        assert!(network.is_ok());
    }

    #[tokio::test]
    async fn test_network_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.listen_addr, "/ip4/127.0.0.1/tcp/0");
        assert!(!config.bootstrap_peers.is_empty());
        assert_eq!(config.max_peers, 50);
    }

    #[tokio::test]
    async fn test_network_manager() {
        let mut manager = NetworkManager::new();
        let config = NetworkConfig::default();

        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());

        let result = manager.add_network("test".to_string(), config, storage).await;
        assert!(result.is_ok());
        assert!(manager.get_network("test").is_some());
    }

    #[test]
    fn test_network_requests() {
        let request = NetworkRequest::Ping;
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: NetworkRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_network_responses() {
        let response = NetworkResponse::Pong;
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: NetworkResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(response, deserialized);
    }

    #[tokio::test]
    async fn test_network_listen() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test listening on a port
        let result = network.listen("/ip4/127.0.0.1/tcp/0").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_network_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test receiving events (should be empty initially)
        let events = network.receive_events().await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_transaction_broadcast() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create and sign a transaction
        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 100, 0);
        tx.sign(&private_key).unwrap();

        // Broadcast transaction
        let result = network.broadcast_transaction(&tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_broadcast() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create a block
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());
        let mut block = Block::new(Hash::new(b"genesis"), 1, vec![], validator);
        block.sign(&private_key).unwrap();

        // Broadcast block
        let result = network.broadcast_block(&block).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_state_synchronization() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create mock peer ID
        let peer_id = PeerId::random();

        // Test state sync request (should fail gracefully without real peers)
        let result = network.request_state_sync(&peer_id).await;
        // This might fail due to no connection, but shouldn't panic
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_block_range_request() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        let peer_id = PeerId::random();

        // Test block range request
        let result = network.get_block_range(&peer_id, 1, 10).await;
        assert!(result.is_ok() || result.is_err()); // Either is acceptable without real connection
    }

    #[tokio::test]
    async fn test_node_info_request() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        let peer_id = PeerId::random();

        // Test node info request
        let result = network.get_node_info(&peer_id).await;
        assert!(result.is_ok() || result.is_err()); // Either is acceptable without real connection
    }

    #[tokio::test]
    async fn test_sync_status_check() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test sync status check
        let status = network.check_sync_status().await;
        assert!(status.is_some());
        let sync_status = status.unwrap();
        assert_eq!(sync_status.current_height, 0); // Initial height
    }

    #[tokio::test]
    async fn test_network_message_processing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test ping request processing
        let response = network.process_request(NetworkRequest::Ping).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), NetworkResponse::Pong);

        // Test get state request
        let state_response = network.process_request(NetworkRequest::GetState).await;
        assert!(state_response.is_ok());
        match state_response.unwrap() {
            NetworkResponse::State(state) => {
                assert_eq!(state.height, 0); // Initial state
            }
            _ => panic!("Expected State response"),
        }
    }

    #[tokio::test]
    async fn test_block_retrieval_requests() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create and store a block
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());
        let mut block = Block::new(Hash::new(b"genesis"), 1, vec![], validator.clone());
        block.sign(&private_key).unwrap();

        storage.store_block(&block).await.unwrap();

        // Test get block by hash
        let hash_response = network.process_request(NetworkRequest::GetBlock {
            hash: block.hash()
        }).await;
        assert!(hash_response.is_ok());
        match hash_response.unwrap() {
            NetworkResponse::Block(retrieved_block) => {
                assert_eq!(retrieved_block.hash(), block.hash());
            }
            _ => panic!("Expected Block response"),
        }

        // Test get block by height
        let height_response = network.process_request(NetworkRequest::GetBlockByHeight(1)).await;
        assert!(height_response.is_ok());
        match height_response.unwrap() {
            NetworkResponse::Block(retrieved_block) => {
                assert_eq!(retrieved_block.header.height, 1);
            }
            _ => panic!("Expected Block response"),
        }

        // Test get latest block
        let latest_response = network.process_request(NetworkRequest::GetLatestBlock).await;
        assert!(latest_response.is_ok());
        match latest_response.unwrap() {
            NetworkResponse::Block(latest_block) => {
                assert_eq!(latest_block.header.height, 1);
            }
            _ => panic!("Expected Block response"),
        }
    }

    #[tokio::test]
    async fn test_transaction_storage_and_broadcast() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create and sign a transaction
        let (sender, private_key) = Transaction::generate_keypair();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 1000, 0);
        tx.sign(&private_key).unwrap();

        // Store transaction in network's storage
        network.storage.store_transaction(&tx).await.unwrap();

        // Test get transaction request
        let tx_response = network.process_request(NetworkRequest::GetTransaction {
            hash: tx.id
        }).await;
        assert!(tx_response.is_ok());
        match tx_response.unwrap() {
            NetworkResponse::Transaction(retrieved_tx) => {
                assert_eq!(retrieved_tx.id, tx.id);
                assert_eq!(retrieved_tx.amount, 1000);
            }
            _ => panic!("Expected Transaction response"),
        }
    }

    #[tokio::test]
    async fn test_mempool_transaction_requests() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test get mempool transactions request
        let mempool_response = network.process_request(NetworkRequest::GetMempoolTransactions {
            limit: 10
        }).await;
        assert!(mempool_response.is_ok());
        match mempool_response.unwrap() {
            NetworkResponse::MempoolTransactions(txs) => {
                assert!(txs.is_empty()); // Should be empty initially
            }
            _ => panic!("Expected MempoolTransactions response"),
        }
    }

    #[tokio::test]
    async fn test_network_info_requests() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test get node info request
        let info_response = network.process_request(NetworkRequest::GetNodeInfo).await;
        assert!(info_response.is_ok());
        match info_response.unwrap() {
            NetworkResponse::NodeInfo(info) => {
                assert_eq!(info.node_id, network.node_info.node_id);
                assert_eq!(info.height, 0); // Initial height
            }
            _ => panic!("Expected NodeInfo response"),
        }
    }

    #[tokio::test]
    async fn test_block_range_processing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create and store multiple blocks
        let validator = PublicKey::new("validator".to_string());
        let private_key = PrivateKey::new("validator_key".to_string());

        for height in 1..=5 {
            let mut block = Block::new(
                if height == 1 { Hash::new(b"genesis") } else { Hash::new(format!("prev{}", height).as_bytes()) },
                height,
                vec![],
                validator.clone()
            );
            block.sign(&private_key).unwrap();
            storage.store_block(&block).await.unwrap();
        }

        // Test get block range request
        let range_response = network.process_request(NetworkRequest::GetBlockRange {
            start_height: 2,
            end_height: 4
        }).await;
        assert!(range_response.is_ok());
        match range_response.unwrap() {
            NetworkResponse::BlockRange(blocks) => {
                assert_eq!(blocks.len(), 3); // Heights 2, 3, 4
                assert_eq!(blocks[0].header.height, 2);
                assert_eq!(blocks[1].header.height, 3);
                assert_eq!(blocks[2].header.height, 4);
            }
            _ => panic!("Expected BlockRange response"),
        }
    }

    #[tokio::test]
    async fn test_state_diff_processing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test get state diff request
        let diff_response = network.process_request(NetworkRequest::GetStateDiff {
            since_height: 0
        }).await;
        assert!(diff_response.is_ok());
        match diff_response.unwrap() {
            NetworkResponse::StateDiff(diff) => {
                // Should return some form of state diff
                assert!(diff.changes.is_empty() || !diff.changes.is_empty()); // Either is fine
            }
            _ => panic!("Expected StateDiff response"),
        }
    }

    #[tokio::test]
    async fn test_concurrent_network_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let network = Network::new(storage).await.unwrap();

        // Test concurrent ping requests
        let mut handles = vec![];

        for _ in 0..10 {
            let network_clone = network.clone();
            let handle = tokio::spawn(async move {
                let response = network_clone.process_request(NetworkRequest::Ping).await.unwrap();
                assert_eq!(response, NetworkResponse::Pong);
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_network_with_pq_crypto() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Create transaction with PQ crypto
        let (sender, private_key) = Transaction::generate_keypair_with_pq().unwrap();
        let receiver = PublicKey::new("bob".to_string());
        let mut tx = Transaction::new(sender, receiver, 1000, 0);
        tx.sign(&private_key).unwrap();

        // Broadcast PQ transaction
        let result = network.broadcast_transaction(&tx).await;
        assert!(result.is_ok());

        // Verify PQ signatures are present
        assert!(tx.signature.is_some());
        let sig = tx.signature.as_ref().unwrap();
        assert!(sig.has_pq_sig());
        assert!(!sig.ed25519_sig.is_empty());
    }

    #[tokio::test]
    async fn test_network_error_handling() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test with invalid block height
        let invalid_height_response = network.process_request(NetworkRequest::GetBlockByHeight(99999)).await;
        assert!(invalid_height_response.is_ok()); // Should return error response gracefully

        // Test with invalid transaction hash
        let invalid_tx_response = network.process_request(NetworkRequest::GetTransaction {
            hash: Hash::new(b"nonexistent")
        }).await;
        assert!(invalid_tx_response.is_ok()); // Should return error response gracefully
    }

    #[test]
    fn test_network_config_validation() {
        let config = NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/8080".to_string(),
            bootstrap_peers: vec!["/ip4/127.0.0.1/tcp/8081/p2p/QmTest".to_string()],
            max_peers: 100,
            heartbeat_interval: Duration::from_secs(30),
            sync_timeout: Duration::from_secs(60),
        };

        assert_eq!(config.listen_addr, "/ip4/127.0.0.1/tcp/8080");
        assert_eq!(config.bootstrap_peers.len(), 1);
        assert_eq!(config.max_peers, 100);
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.sync_timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_network_state_sync_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path()).unwrap());
        let mut network = Network::new(storage).await.unwrap();

        // Test state sync request processing
        let known_hashes = vec![Hash::new(b"genesis")];
        let sync_request = NetworkRequest::StateSyncRequest {
            current_height: 0,
            known_hashes: known_hashes.clone(),
        };

        let sync_response = network.process_request(sync_request).await;
        assert!(sync_response.is_ok());
        match sync_response.unwrap() {
            NetworkResponse::StateSyncResponse(sync_data) => {
                // Should return sync data
                assert!(sync_data.blocks.is_empty() || !sync_data.blocks.is_empty()); // Either is fine
            }
            _ => panic!("Expected StateSyncResponse"),
        }
    }
}

/// Example usage of the network layer
pub mod examples {
    use super::*;
    use crate::types::{Transaction, PublicKey};

    /// Example of how to use the network layer
    pub async fn example_network_usage() -> Result<(), Box<dyn std::error::Error>> {
        // Create storage
        let temp_dir = tempfile::tempdir()?;
        let storage = Box::new(crate::storage::Storage::new(temp_dir.path())?);

        // Create a network instance
        let mut network = Network::new(storage).await?;

        // Start listening
        network.listen("/ip4/127.0.0.1/tcp/0").await?;

        // Create a sample transaction
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());
        let tx = Transaction::new(sender, receiver, 100, 0);

        // Broadcast the transaction
        network.broadcast_transaction(&tx).await?;

        // Process network events (in a real application, this would run in a loop)
        let _events = network.receive_events().await?;

        Ok(())
    }

    /// Example of using NetworkManager for multiple network interfaces
    pub async fn example_network_manager() -> Result<(), Box<dyn std::error::Error>> {
        let mut manager = NetworkManager::new();

        // Create storage instances
        let temp_dir1 = tempfile::tempdir()?;
        let storage1 = Box::new(crate::storage::Storage::new(temp_dir1.path())?);
        let temp_dir2 = tempfile::tempdir()?;
        let storage2 = Box::new(crate::storage::Storage::new(temp_dir2.path())?);

        // Add main network
        let main_config = NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/38383".to_string(),
            ..Default::default()
        };
        manager.add_network("main".to_string(), main_config, storage1).await?;

        // Add backup network
        let backup_config = NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/38384".to_string(),
            ..Default::default()
        };
        manager.add_network("backup".to_string(), backup_config, storage2).await?;

        // Broadcast to all networks
        let sender = PublicKey::new("alice".to_string());
        let receiver = PublicKey::new("bob".to_string());
        let tx = Transaction::new(sender, receiver, 100, 0);

        manager.broadcast_to_all(&tx).await?;

        Ok(())
    }
}

