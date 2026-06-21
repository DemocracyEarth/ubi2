//! ubi2 node (M0 skeleton).
//!
//! M1 target (see `docs/specs/01-evm-rpc-and-wallet.md`): a single-node devnet that produces blocks
//! on a clock tick and serves the EVM JSON-RPC. The `protocol-engineer` adds the async runtime
//! (tokio), the JSON-RPC server, networking, and block production. This stub establishes genesis
//! with one pre-verified dev account (standing in for M3 proof-of-humanity) so a balance streams
//! from t=0, and prints the devnet parameters.

use std::time::{SystemTime, UNIX_EPOCH};

use ubi2_rpc::{eth_chain_id, eth_get_balance, DEVNET_CHAIN_ID, M1_METHODS};
use ubi2_runtime::Account;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() {
    let genesis_time = now_secs();

    // Genesis: one pre-verified dev account so the stream is observable immediately.
    let dev = Account {
        address: [0x11; 20],
        verified: true,
        verified_at: genesis_time,
        settled_balance: 0,
        last_settled_at: genesis_time,
    };

    println!("ubi2-node (M0 skeleton)");
    println!("  chainId        : {} ({})", eth_chain_id(DEVNET_CHAIN_ID), DEVNET_CHAIN_ID);
    println!("  genesis (unix) : {genesis_time}");
    println!("  dev account    : 0x{}", hex20(&dev.address));
    println!("  dev balance    : {} (streaming 1 UBI/hour)", eth_get_balance(&dev, now_secs()));
    println!("  rpc methods    : {} planned for M1", M1_METHODS.len());
    println!();
    println!("TODO(protocol-engineer): start the JSON-RPC server + block tick (task M1-T3/M1-T4).");
}

fn hex20(bytes: &[u8; 20]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
