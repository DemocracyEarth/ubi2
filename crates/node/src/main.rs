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

/// **PUBLIC, NON-SECRET devnet juror set (M3).** The standard Hardhat/Anvil accounts #1..#3 — the
/// deterministic verifier quorum for the devnet (JURY_SIZE = 3, so every case's jury is exactly this
/// set). Each juror submits its canonical verdict by signing a `submitVerdict` tx with its matching
/// key (published in every EVM dev toolkit — NOT SECRETS). Register-only in M3 (staking is M5).
///   acct #1 key: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
///   acct #2 key: 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
///   acct #3 key: 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
const DEVNET_JURORS: [alloy_primitives::Address; 3] = [
    address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
    address!("90F79bf6EB2c4f870365E785982E1f101E93b906"),
];

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
    // M3 (spec criterion 5): migrate the dev account to a `Verified` human in the proof-of-humanity
    // registry, so `ubi_getHuman` reports it Verified and the M3 lifecycle treats it as a founder
    // (it can vouch outward). The account cache above already gates emission; this keeps the two in
    // sync at genesis.
    chain.seed_verified_human(&dev_addr.into_array(), genesis_time);

    // M3 (board M3-T4 §4): register a few deterministic devnet jurors so every case has a jury to
    // draw from (the lifecycle fails closed with `NoJurors` otherwise). Register-only in M3 (staking
    // is M5); the addresses below are fixed, documented, non-secret devnet constants. With JURY_SIZE
    // = 3 and these three jurors, every case's jury is exactly this set, and a juror submits its
    // verdict by signing a `submitVerdict` tx from the matching key (the keys are the standard
    // Hardhat/Anvil accounts #1..#3, published in every EVM dev toolkit — NOT SECRETS).
    //   juror #1: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (Anvil acct #1)
    //   juror #2: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC (Anvil acct #2)
    //   juror #3: 0x90F79bf6EB2c4f870365E785982E1f101E93b906 (Anvil acct #3)
    //
    // M4 (board M4-T4 §4): the SAME registered jurors double as the prompt-contract **interpreter
    // quorum** — `invoke_contract` selects its interpreters from `active_jurors()` exactly the way a
    // case selects its jury (one shared verifier/interpreter set; spec 04 §"reuses the M3 substrate").
    // The devnet runs the deterministic `MockInterpreter` (the `Chain::new` default), so a contract
    // invocation commits its canonical effect end-to-end with no model calls (I5). No NEW genesis seed
    // is needed for M4 — the M3 juror set is the interpreter set, and contract escrows live in the
    // ContractHub address space derived purely from the contract id (no per-contract seeding).
    for juror in DEVNET_JURORS {
        chain.register_juror(&juror.into_array(), 0);
    }

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
    for (i, juror) in DEVNET_JURORS.iter().enumerate() {
        tracing::info!(
            "  juror #{}           : 0x{}",
            i + 1,
            hex::encode(juror.as_slice())
        );
    }
    // M4: the reserved hub system addresses a wallet sends write ops to (all derived from ASCII tags).
    tracing::info!("  StreamHub         : 0x0000000000000000000000000000000000005742 (\"WB\")");
    tracing::info!("  HumanityHub       : 0x0000000000000000000000000000000000005048 (\"PH\")");
    tracing::info!("  ContractHub       : 0x0000000000000000000000000000000000005043 (\"PC\")");
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
