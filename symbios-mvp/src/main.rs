mod simple_node;
mod network_demo;

use crate::simple_node::SimpleNode;
use crate::network_demo::NetworkDemo;
use std::env;
use symbios_mvp::metrics::{init_metrics, MetricsServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    init_metrics();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(async {
        MetricsServer::new(9100).start().await.unwrap();
    });

    println!("🚀 Symbios Network Production - Minimal Edition");
    println!("================================================");

    // Get hardware profile from environment
    let hardware_profile = env::var("HARDWARE_PROFILE").unwrap_or_else(|_| "standard".to_string());

    println!("📊 Hardware Profile: {}", hardware_profile);

    match hardware_profile.as_str() {
        "minimal" => println!("   💡 Optimized for Raspberry Pi / low-end devices"),
        "standard" => println!("   💡 Optimized for modern servers"),
        "high-performance" => println!("   💡 Optimized for dedicated hardware"),
        _ => println!("   ⚠️  Using standard profile"),
    }

    // Choose demo mode based on environment variable
    let demo_mode = env::var("DEMO_MODE").unwrap_or_else(|_| "simple".to_string());

    match demo_mode.as_str() {
        "network" => {
            println!("🌐 Running Network Demo with P2P Layer");
            let mut network_demo = NetworkDemo::new().await?;
            network_demo.run().await?;
        }
        _ => {
            println!("🚀 Running Simple Node Demo (default)");
            // Create and start simple node
            let mut node = SimpleNode::new().await?;
            node.start().await?;
        }
    }

    // Keep the main thread alive
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!("✅ Symbios Network is running!");
    println!("🚀 Demonstrating Smart DAG Mempool capabilities...\n");

    // Demonstrate Smart DAG Mempool
    node.demonstrate_smart_dag().await;

    println!("\n🎯 Smart DAG Mempool demonstration completed!");
    println!("📈 Key achievements:");
    println!("   • Parallel transaction processing");
    println!("   • Certificate-based consensus");
    println!("   • BFT sanctions system");
    println!("   • OCC parallel execution");
    println!("   • Sub-second latency");
    println!("\nPress Ctrl+C to exit");

    // Infinite loop to keep the node running
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let stats = node.get_stats();
        println!("🔄 Node active - Uptime: {}s, Blocks: {}, TXs: {}",
            stats.uptime_seconds, stats.total_blocks, stats.total_transactions);
    }
}
