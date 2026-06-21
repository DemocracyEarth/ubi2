//! ubi2 node (M1) — single-node devnet.
//!
//! Stands up the M1 devnet (see `docs/specs/01-evm-rpc-and-wallet.md`):
//!   * genesis with **one pre-verified dev account** so a balance streams at 1 UBI/hour from t=0,
//!   * an EVM-compatible JSON-RPC server (HTTP + WS) on `127.0.0.1:8545`,
//!   * a **2-second block tick** that advances height and feeds `newHeads` subscribers.
//!
//! ## Run the devnet
//! ```sh
//! cargo run -p ubi2-node            # serves HTTP+WS JSON-RPC on http://127.0.0.1:8545
//! ```
//! Optional env vars:
//!   * `UBI2_RPC_ADDR`  — socket to bind (default `127.0.0.1:8545`).
//!   * `UBI2_BLOCK_MS`  — block tick interval in ms (default `2000`).
//!   * `RUST_LOG`       — tracing filter (default `info`).
//!
//! ## Add to MetaMask / viem
//!   * Network name: `ubi2 devnet`
//!   * RPC URL:      `http://127.0.0.1:8545`
//!   * Chain ID:     `21826` (`0x5542`)
//!   * Currency:     `UBI` (18 decimals)
//!
//! Import the dev account below to sign txs (its key is PUBLIC — see the constant).

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::address;
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::Account;

/// **PUBLIC, NON-SECRET devnet key.** This is the well-known Hardhat/Anvil test account #0. It is
/// published in every Ethereum dev toolkit and is the standard MetaMask-import key for local nets.
/// Never use it for anything holding real value.
///
///   private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
///   address    : 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const DEV_PRIVKEY_PUBLIC: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr = std::env::var("UBI2_RPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8545".into())
        .parse()?;
    let block_ms: u64 = std::env::var("UBI2_BLOCK_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);

    let genesis_time = now_secs();
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis_time);

    // Genesis: the pre-verified dev account (M3 proof-of-humanity stands in for this `verified` flag
    // via the runtime `Verifier` trait). Streams 1 UBI/hour from genesis.
    let dev_addr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    chain.seed_account(Account {
        address: dev_addr.into_array(),
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 0,
        nonce: 0,
    });

    let handle = serve(addr, chain.clone()).await?;

    tracing::info!("ubi2-node (M1 devnet) up");
    tracing::info!("  JSON-RPC (HTTP+WS): http://{addr}");
    tracing::info!("  chainId           : 0x{DEVNET_CHAIN_ID:x} ({DEVNET_CHAIN_ID})");
    tracing::info!("  genesis (unix)    : {}", chain.genesis_time());
    tracing::info!(
        "  dev account       : 0x{}",
        hex::encode(dev_addr.as_slice())
    );
    tracing::info!("  dev key (PUBLIC)  : {DEV_PRIVKEY_PUBLIC}");
    tracing::info!("  block tick        : {block_ms} ms");

    // Block-production loop: tick every `block_ms`, mine pending txs, advance height + newHeads.
    let block_chain = chain.clone();
    let mut ticker = tokio::time::interval(Duration::from_millis(block_ms));
    ticker.tick().await; // consume the immediate first tick

    tokio::select! {
        _ = async {
            loop {
                ticker.tick().await;
                let b = block_chain.produce_block(now_secs());
                tracing::debug!(number = b.number, txs = b.txs.len(), "block produced");
            }
        } => {},
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
        }
    }

    handle.stop()?;
    let _ = handle.stopped().await;
    Ok(())
}

/// Tiny hex encoder for log output (avoids pulling a crate into the node just for this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }
}
