//! State Synchronization Module
//!
//! This module handles synchronization of blockchain state between nodes,
//! including block sync, state diff sync, and incremental updates.

use crate::network::{NetworkTrait, SyncStatus, NodeInfo, NetworkEvent};
use crate::storage::StorageTrait;
use crate::types::{Block, State};
use std::sync::Arc;
use tokio::sync::RwLock;
use log::*;

/// State synchronization manager
pub struct StateSyncManager<T: NetworkTrait + Send + Sync, S: StorageTrait + Send + Sync> {
    network: Arc<T>,
    storage: Arc<S>,
    sync_status: Arc<RwLock<SyncStatus>>,
    max_blocks_per_batch: usize,
    sync_interval_secs: u64,
}

impl<T: NetworkTrait + Send + Sync, S: StorageTrait + Send + Sync> StateSyncManager<T, S> {
    /// Create a new state sync manager
    pub fn new(network: Arc<T>, storage: Arc<S>) -> Self {
        Self {
            network,
            storage,
            sync_status: Arc::new(RwLock::new(SyncStatus {
                current_height: 0,
                target_height: 0,
                is_synced: false,
                sync_progress: 0.0,
                peers_synced_with: vec![],
            })),
            max_blocks_per_batch: 100,
            sync_interval_secs: 30,
        }
    }

    /// Start the state synchronization process
    pub async fn start_sync(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("🔄 Starting state synchronization process");

        loop {
            // Check current sync status
            let status = self.network.check_sync_status().await?;

            {
                let mut sync_status = self.sync_status.write().await;
                *sync_status = status.clone();
            }

            if status.is_synced {
                debug!("✅ Node is already synchronized (height: {})", status.current_height);
                tokio::time::sleep(tokio::time::Duration::from_secs(self.sync_interval_secs)).await;
                continue;
            }

            info!("🔄 Node needs synchronization: {}/{} ({:.1}%)",
                  status.current_height, status.target_height, status.sync_progress);

            // Find best peer for sync
            let best_peer = self.find_best_sync_peer().await?;
            if let Some(peer) = best_peer {
                info!("🎯 Selected peer {} for synchronization", peer);

                // Perform state sync
                if let Err(e) = self.network.request_state_sync(&peer).await {
                    error!("❌ State sync failed with peer {}: {}", peer, e);
                } else {
                    info!("✅ State sync completed with peer {}", peer);
                }
            } else {
                warn!("⚠️ No suitable peers found for synchronization");
            }

            // Wait before next sync attempt
            tokio::time::sleep(tokio::time::Duration::from_secs(self.sync_interval_secs)).await;
        }
    }

    /// Find the best peer for synchronization based on height and capabilities
    async fn find_best_sync_peer(&self) -> Result<Option<libp2p::PeerId>, Box<dyn std::error::Error>> {
        let peers = self.network.get_connected_peers().await;
        let mut best_peer = None;
        let mut best_height = 0u64;

        for peer in peers {
            match self.network.get_node_info(&peer).await {
                Ok(node_info) => {
                    // Check if peer has required capabilities
                    if node_info.capabilities.contains(&"state-sync".to_string()) {
                        // Select peer with highest height
                        if node_info.height > best_height {
                            best_height = node_info.height;
                            best_peer = Some(peer);
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to get node info from peer {}: {}", peer, e);
                }
            }
        }

        Ok(best_peer)
    }

    /// Handle incoming sync requests
    pub async fn handle_sync_request(&self, request: crate::network::NetworkRequest)
        -> Result<crate::network::NetworkResponse, Box<dyn std::error::Error>>
    {
        match request {
            crate::network::NetworkRequest::StateSyncRequest { current_height, known_hashes } => {
                self.process_state_sync_request(current_height, known_hashes).await
            }
            _ => Err("Unsupported sync request type".into())
        }
    }

    /// Process state sync request
    async fn process_state_sync_request(&self, current_height: u64, known_hashes: Vec<crate::types::Hash>)
        -> Result<crate::network::NetworkResponse, Box<dyn std::error::Error>>
    {
        info!("🔄 Processing state sync request from height {} with {} known hashes",
              current_height, known_hashes.len());

        let mut blocks_to_sync = Vec::new();
        let mut missing_blocks = Vec::new();

        // Get current blockchain height
        let latest_height = if let Ok(Some(latest_block)) = self.storage.get_latest_block().await {
            latest_block.header.height
        } else {
            0
        };

        // Collect blocks to sync
        for height in (current_height + 1)..=(current_height + self.max_blocks_per_batch as u64) {
            if height > latest_height {
                break;
            }

            if let Ok(Some(block)) = self.storage.get_block_by_height(height).await {
                // Check if the block is already known to the peer
                if !known_hashes.contains(&block.hash()) {
                    blocks_to_sync.push(block);
                }
            } else {
                missing_blocks.push(height);
            }
        }

        // Get current state snapshot
        let state = self.storage.get_state().await?;
        let state_snapshot = serde_json::to_string(&state)?;

        let sync_data = crate::network::StateSyncData {
            current_height: latest_height,
            blocks_to_sync,
            missing_blocks,
            state_snapshot,
        };

        info!("📤 Sending sync data: {} blocks, {} missing blocks",
              sync_data.blocks_to_sync.len(), sync_data.missing_blocks.len());

        Ok(crate::network::NetworkResponse::StateSyncResponse(sync_data))
    }

    /// Apply received sync data
    pub async fn apply_sync_data(&self, sync_data: crate::network::StateSyncData)
        -> Result<(), Box<dyn std::error::Error>>
    {
        info!("📥 Applying sync data: {} blocks to sync", sync_data.blocks_to_sync.len());

        // Apply blocks in order
        for block in &sync_data.blocks_to_sync {
            // Validate block before storing
            if self.validate_block_for_sync(block).await? {
                self.storage.store_block(block).await?;
                debug!("✅ Applied block at height {}", block.header.height);
            } else {
                warn!("❌ Block validation failed for height {}", block.header.height);
                continue;
            }
        }

        // Update sync status
        {
            let mut status = self.sync_status.write().await;
            status.current_height = sync_data.current_height;
            status.is_synced = true;
            status.sync_progress = 100.0;
        }

        info!("✅ Sync data applied successfully. Current height: {}", sync_data.current_height);
        Ok(())
    }

    /// Validate block for sync (simplified validation)
    async fn validate_block_for_sync(&self, block: &Block) -> Result<bool, Box<dyn std::error::Error>> {
        // Basic validation - check if previous block exists
        if block.header.height > 0 {
            if let Ok(Some(prev_block)) = self.storage.get_block_by_height(block.header.height - 1).await {
                if prev_block.hash() != block.header.previous_hash {
                    return Ok(false);
                }
            } else {
                return Ok(false); // Previous block not found
            }
        }

        // TODO: Add more comprehensive validation
        Ok(true)
    }

    /// Get current sync status
    pub async fn get_sync_status(&self) -> SyncStatus {
        self.sync_status.read().await.clone()
    }

    /// Force sync with a specific peer
    pub async fn force_sync_with_peer(&self, peer: &libp2p::PeerId) -> Result<(), Box<dyn std::error::Error>> {
        info!("🔄 Forcing sync with peer {}", peer);
        self.network.request_state_sync(peer).await
    }

    /// Get sync statistics
    pub async fn get_sync_stats(&self) -> SyncStats {
        let status = self.sync_status.read().await;

        SyncStats {
            current_height: status.current_height,
            target_height: status.target_height,
            sync_progress: status.sync_progress,
            is_synced: status.is_synced,
            peers_count: status.peers_synced_with.len(),
            last_sync_time: std::time::SystemTime::now(),
        }
    }
}

/// Synchronization statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub current_height: u64,
    pub target_height: u64,
    pub sync_progress: f64,
    pub is_synced: bool,
    pub peers_count: usize,
    pub last_sync_time: std::time::SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use tempfile::tempdir;

    // Mock network for testing
    struct MockNetwork;
    impl NetworkTrait for MockNetwork {
        async fn broadcast_transaction(&self, _tx: &crate::types::Transaction) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
        async fn broadcast_block(&self, _block: &Block) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
        async fn broadcast_consensus_message(&self, _message: &crate::consensus::ConsensusMessage) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
        async fn receive_events(&mut self) -> Result<Vec<crate::network::NetworkEvent>, Box<dyn std::error::Error>> { Ok(vec![]) }
        async fn send_request(&self, _peer: &libp2p::PeerId, _request: crate::network::NetworkRequest) -> Result<crate::network::NetworkResponse, Box<dyn std::error::Error>> {
            Err("Mock not implemented".into())
        }
        async fn get_connected_peers(&self) -> Vec<libp2p::PeerId> { vec![] }
        async fn request_state_sync(&self, _peer: &libp2p::PeerId) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
        async fn get_block_range(&self, _peer: &libp2p::PeerId, _start_height: u64, _end_height: u64) -> Result<Vec<Block>, Box<dyn std::error::Error>> { Ok(vec![]) }
        async fn get_node_info(&self, _peer: &libp2p::PeerId) -> Result<crate::network::NodeInfo, Box<dyn std::error::Error>> { Err("Mock".into()) }
        async fn check_sync_status(&self) -> Result<crate::network::SyncStatus, Box<dyn std::error::Error>> {
            Ok(crate::network::SyncStatus {
                current_height: 0,
                target_height: 100,
                is_synced: false,
                sync_progress: 0.0,
                peers_synced_with: vec![],
            })
        }
    }

    #[tokio::test]
    async fn test_state_sync_manager_creation() {
        let temp_dir = tempdir().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        let network = Arc::new(MockNetwork);

        let sync_manager = StateSyncManager::new(network, Arc::new(storage));
        let stats = sync_manager.get_sync_stats().await;

        assert_eq!(stats.current_height, 0);
        assert!(!stats.is_synced);
    }
}
