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

mod net;
mod netcfg;
mod oracle_cfg;

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::sync::Arc;

use alloy_primitives::address;
use ubi2_rpc::{serve, AdminAccess, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::Account;

/// Env var: comma-separated list of browser origins allowed to call the loopback admin RPC
/// (`ubi_getOracleConfig`/`ubi_setOracleConfig`). Default: the local wallet at `http://localhost:3000`.
/// A foreign `Origin` (a malicious page) is refused regardless; absent `Origin` (curl) is allowed.
const ENV_ADMIN_ALLOWED_ORIGINS: &str = "UBI2_ADMIN_ALLOWED_ORIGINS";

/// Resolve the admin-method `Origin` allowlist from the env (or the default wallet origin).
fn admin_access_from_env() -> AdminAccess {
    match std::env::var(ENV_ADMIN_ALLOWED_ORIGINS) {
        Ok(raw) if !raw.trim().is_empty() => {
            let origins: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            AdminAccess::with_allowed_origins(origins)
        }
        _ => AdminAccess::default(),
    }
}

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
    // M5 (Stage A): a tiny utility subcommand — `ubi2-node peer-id <32-byte-hex-seed>` — prints the
    // libp2p PeerId derived from an Ed25519 seed and exits. The multi-node devnet script uses it to
    // precompute every node's PeerId (from its fixed seed) so it can wire a FULL cross-bootstrap mesh
    // deterministically, with no mDNS (which is unavailable in sandboxed CI). Pure, no networking.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() >= 3 && args[1] == "peer-id" {
            match netcfg::peer_id_for_seed_hex(&args[2]) {
                Ok(id) => {
                    println!("{id}");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("peer-id: {e}");
                    std::process::exit(2);
                }
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr = std::env::var("UBI2_RPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8545".into())
        .parse()?;

    // M5 (Stage A): resolve the node-network config from env (genesis time, P2P listen/bootstrap,
    // proposer/validator keys, the designated proposer). With no `UBI2_P2P_ADDR` set, networking is
    // disabled and the node boots exactly as the M1–M4 single-node devnet did.
    let netcfg = netcfg::resolve(now_secs());
    let block_ms = netcfg.block_ms;
    let genesis_time = netcfg.genesis_time;

    // Select the AI backend (proof-of-humanity oracle + prompt-contract interpreter) from the node's
    // config file (`<data_dir>/oracle.json`) + `UBI2_ORACLE_*` env overrides. Absent a provider — or if
    // the backend can't be built (missing key, etc.) — the chain runs the deterministic Mock impls so the
    // devnet always boots (I4). The wallet's Settings panel can hot-swap this at runtime over the
    // localhost-only `ubi_setOracleConfig` admin RPC.
    let data_dir = oracle_cfg::data_dir();
    let oracle_config = oracle_cfg::load_config(&data_dir);
    // Build the admin on the blocking pool: constructing a live backend creates a blocking HTTP client,
    // which must not run on the async runtime thread. (For the default Mock config this is a no-op build,
    // but the blocking hop keeps the live-config boot path safe too.)
    let admin_data_dir = data_dir.clone();
    let oracle_admin =
        tokio::task::spawn_blocking(move || oracle_cfg::build_admin(admin_data_dir, oracle_config))
            .await?;

    // Admin-RPC browser access policy (C5-SEC-2): the loopback admin methods additionally enforce
    // Host-header pinning (DNS-rebinding defense) + an Origin allowlist (browser-CSRF defense). The
    // default allows only the local wallet origin (`http://localhost:3000`); override via
    // `UBI2_ADMIN_ALLOWED_ORIGINS`.
    let admin_access = Arc::new(admin_access_from_env());

    // M5 (FU-3): persistence. The chain (blocks + full state) is snapshotted under the data dir; on
    // restart we reload it and resume at the same tip with the same `state_root` (no re-seed of
    // genesis, no lost blocks). A fresh data dir (no snapshot) boots genesis as before. The oracle /
    // admin / proposer wiring is node config, NOT part of the snapshot, so we re-attach it either way.
    let dev_addr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    let loaded_snapshot = match ubi2_rpc::persist::load(&data_dir) {
        Ok(Some(snap)) if snap.chain_id() == DEVNET_CHAIN_ID => Some(snap),
        Ok(Some(_)) => {
            tracing::warn!("ignoring snapshot: chain_id mismatch with this node's config");
            None
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load chain snapshot; starting from genesis");
            None
        }
    };

    // M5 (Stage A): if this node is the designated proposer it holds a signing key; stamp every block it
    // produces with `proposer` + a header signature so followers recover the author (spec §2.2).
    let proposer_key_arc: Option<Arc<ProposerKey>> = netcfg
        .proposer_secret
        .and_then(|b| ProposerKey::from_bytes(&b).ok())
        .map(Arc::new);

    let chain = if let Some(snap) = loaded_snapshot {
        let tip = snap.tip_height();
        let mut chain = Chain::from_snapshot(&snap)
            .with_oracle_admin(oracle_admin)
            .with_admin_access(admin_access);
        if let Some(k) = &proposer_key_arc {
            chain = chain.with_proposer_key(k.clone());
        }
        tracing::info!(
            tip_height = tip,
            "restored chain from persisted snapshot (FU-3)"
        );
        chain
    } else {
        let mut chain = Chain::new(DEVNET_CHAIN_ID, genesis_time)
            .with_oracle_admin(oracle_admin)
            .with_admin_access(admin_access);
        if let Some(k) = &proposer_key_arc {
            chain = chain.with_proposer_key(k.clone());
        }

        // Genesis: the pre-verified dev account (M3 proof-of-humanity stands in for this `verified`
        // flag via the runtime `Verifier` trait). Streams 1 UBI/hour from genesis.
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
        chain
    };

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
    // AI backend: which impl ended up active after resolving the config (Mock unless a reachable live
    // provider was configured). The admin RPC (`ubi_getOracleConfig`/`ubi_setOracleConfig`) is
    // localhost-only; the secret-free config lives at `<data_dir>/oracle.json`.
    let admin_status = chain.oracle_admin().get_config_json();
    tracing::info!(
        "  AI backend        : {} (provider={}, model={})",
        admin_status["active"].as_str().unwrap_or("mock"),
        admin_status["health"]["provider"]
            .as_str()
            .unwrap_or("mock"),
        admin_status["health"]["model"].as_str().unwrap_or(""),
    );
    tracing::info!(
        "  oracle config     : {} (admin RPC: ubi_getOracleConfig/ubi_setOracleConfig, localhost-only)",
        oracle_cfg::config_path(&data_dir).display()
    );

    // ---- M5 (Stage A): start the P2P network (if enabled) + run the node loop ----
    //
    // Networking is enabled iff `UBI2_P2P_ADDR` was set (see `netcfg`). When enabled we start the libp2p
    // swarm, build a `NetDriver` that bridges it to the chain, and run a single loop that: processes
    // inbound network events, ticks the proposer (only the designated proposer produces blocks),
    // relays locally-submitted txs, and persists every new tip. With networking disabled the node runs
    // the legacy single-node tick (this node mines every block — unchanged M1–M4 behaviour).
    //
    // NOTE (C5-SEC-3): the multi-node devnet runs the deterministic `MockOracle`/`MockInterpreter` (no
    // blocking HTTP), so producing/applying blocks inline on the node loop is safe. A LIVE oracle (which
    // uses a blocking reqwest client) is a single-node configuration; the networked Stage-A devnet does
    // not use it. The legacy single-node tick below keeps its `spawn_blocking` hop for the live path.
    tracing::info!(
        "  role              : {}",
        if netcfg.is_proposer {
            "PROPOSER (produces blocks)"
        } else if netcfg.network.is_some() {
            "FOLLOWER (validates + applies)"
        } else {
            "SINGLE-NODE (no p2p)"
        }
    );
    if let Some(dp) = netcfg.designated_proposer {
        tracing::info!("  designated prop.  : 0x{}", hex::encode(dp.as_slice()));
    }

    let mut interval = tokio::time::interval(Duration::from_millis(block_ms));
    interval.tick().await; // consume the immediate first tick

    if let Some(mut net_config) = netcfg.network {
        // Fill the real genesis hash now that the chain exists (the handshake anchor, §4.1).
        net_config.genesis_hash = chain.genesis_hash();
        let (net_handle, mut events) = ubi2_network::start(net_config)
            .map_err(|e| anyhow::anyhow!("network start failed: {e}"))?;
        tracing::info!("  p2p peer id       : {}", net_handle.local_peer_id());

        let mut driver = net::NetDriver::new(
            chain.clone(),
            net_handle,
            netcfg.validator_key,
            netcfg.designated_proposer,
            netcfg.is_proposer,
        );
        driver.announce_start();

        // A fast, separate tx-relay timer so a LOCALLY-submitted tx (`eth_sendRawTransaction`, which
        // lands straight in the mempool) reaches peers well within the EC-2 2-second bar, rather than
        // waiting up to a full block interval. gossipsub dedups by tx-hash, so re-publishing is cheap.
        //
        // Bootstrap connectivity is NOT driven from here: the network layer owns a reconnect-until-
        // connected sweep (re-dials any not-yet-connected bootstrap peer with bounded backoff), so the
        // full mesh converges regardless of node boot order or transient dial failures — no node-side
        // re-dial timer is needed (and the old count-gated one could wedge a node below full peer count).
        let mut relay = tokio::time::interval(Duration::from_millis(250));
        relay.tick().await;

        loop {
            tokio::select! {
                ev = events.recv() => {
                    match ev {
                        Some(ev) => driver.on_event(ev),
                        None => { tracing::warn!("network event stream closed"); break; }
                    }
                }
                _ = relay.tick() => {
                    driver.relay_pending_txs();
                }
                _ = interval.tick() => {
                    // The proposer mines a block; persist the latest tip so a restart resumes
                    // deterministically (FU-3). Followers do not produce blocks (Stage A).
                    if let Some(b) = driver.tick_proposer(now_secs()) {
                        tracing::debug!(number = b.number, txs = b.txs.len(), "block produced");
                    }
                    let snap = chain.export_snapshot();
                    if let Err(e) = ubi2_rpc::persist::save(&data_dir, &snap) {
                        tracing::warn!(error = %e, "failed to persist chain snapshot");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("shutdown signal received");
                    break;
                }
            }
        }
    } else {
        // ---- Legacy single-node devnet tick (no p2p) ----
        let block_chain = chain.clone();
        let persist_dir = data_dir.clone();
        tokio::select! {
            _ = async {
                loop {
                    interval.tick().await;
                    let tick_chain = block_chain.clone();
                    let snap_dir = persist_dir.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        let b = tick_chain.produce_block(now_secs());
                        let snap = tick_chain.export_snapshot();
                        if let Err(e) = ubi2_rpc::persist::save(&snap_dir, &snap) {
                            tracing::warn!(error = %e, "failed to persist chain snapshot");
                        }
                        b
                    })
                    .await;
                    match res {
                        Ok(b) => tracing::debug!(number = b.number, txs = b.txs.len(), "block produced"),
                        Err(e) => tracing::error!(error = %e, "block tick panicked; continuing"),
                    }
                }
            } => {},
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received");
            }
        }
    }

    // Final snapshot on graceful shutdown so a clean stop always persists the latest tip.
    let final_snap = chain.export_snapshot();
    if let Err(e) = ubi2_rpc::persist::save(&data_dir, &final_snap) {
        tracing::warn!(error = %e, "failed to persist final chain snapshot on shutdown");
    } else {
        tracing::info!("persisted final chain snapshot (FU-3)");
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
