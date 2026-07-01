//! ubi2 node binary (M1) — single-node + multi-node devnet.
//!
//! This is a THIN wrapper over [`ubi2_node::run`]: the entire node body (config resolution, genesis
//! seeding, RPC/sync serving, block production, the P2P loop) lives in `crates/node/src/lib.rs` so the
//! operator CLI (`crates/cli`, the `ubi` binary) can drive the node **in-process** with zero change to
//! how config is resolved (env-driven). Running `ubi2-node` directly is byte-for-byte identical to the
//! former single-crate binary — including the `ubi2-node peer-id <seed>` utility subcommand.
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ubi2_node::run().await
}
