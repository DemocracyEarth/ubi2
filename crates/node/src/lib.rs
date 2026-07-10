//! ubi2 node library.
//!
//! This crate is split into a thin binary (`src/main.rs` → `ubi2-node`) and this library so the
//! operator CLI (`crates/cli`, the `ubi` binary) can drive the node **in-process** — it sets the
//! `UBI2_*` env vars from its flags/presets and calls [`run`], the verbatim former `main()` body.
//! Config resolution stays 100% in [`crate::netcfg`] (env-driven), so there is zero change to how the
//! node resolves its configuration and thus zero consensus risk from the CLI layer.
//!
//! The canonical devnet genesis seeding lives in ONE place ([`canonical_devnet_genesis`] +
//! [`seed_canonical_devnet_genesis`]) so the fresh-boot path, the FU-3 restore path, the CLI's
//! `ubi genesis anchor`, and the pinned-anchor regression test all derive from the SAME seed list —
//! killing the drift problem (spec 07 §3.4, `ln-trust-2`).

mod net;
pub mod netcfg;
mod oracle_cfg;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{address, Address as AlloyAddr};
use ubi2_rpc::{serve, serve_sync_gateway, AdminAccess, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MemState, State};

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
pub const DEV_PRIVKEY_PUBLIC: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The genesis dev account address (Anvil acct #0). Pre-verified at genesis; streams 1 UBI/hour.
pub const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// **PUBLIC, NON-SECRET devnet juror set (M3).** The standard Hardhat/Anvil accounts #1..#3 — the
/// deterministic verifier quorum for the devnet (JURY_SIZE = 3, so every case's jury is exactly this
/// set). Each juror submits its canonical verdict by signing a `submitVerdict` tx with its matching
/// key (published in every EVM dev toolkit — NOT SECRETS). Register-only in M3 (staking is M5).
///   acct #1 key: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
///   acct #2 key: 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
///   acct #3 key: 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
pub const DEVNET_JURORS: [AlloyAddr; 3] = [
    address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
    address!("90F79bf6EB2c4f870365E785982E1f101E93b906"),
];

/// M6: a single curated devnet CSCA trust anchor `key_id` (spec §7.3 — a static genesis set). A fixed,
/// documented, NON-SECRET devnet constant — NOT a real ICAO CSCA key. Stage-1 uses the deterministic
/// `MockZkVerifier`, so the registry need only be non-empty for a proof to bind a valid `cscaRegistryRoot`.
const DEVNET_CSCA_KEY_ID: [u8; 32] = [0xC5; 32];
/// The raw `pubkey` bytes for the devnet CSCA (opaque to the runtime). Fixed devnet constant.
const DEVNET_CSCA_PUBKEY: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Apply the canonical devnet genesis seeds to a live [`Chain`]. This is the SINGLE source of truth for
/// the genesis seed list — the fresh-boot path (in [`run`]), the CLI `ubi genesis anchor`, and the
/// pinned-anchor regression test all seed via this exact sequence, so a seed change can never drift the
/// live chain from the pinned light-client anchor undetected (spec 07 §3.4, `ln-trust-2`).
///
/// Seeds, in order:
///   1. the pre-verified dev account (streams 1 UBI/hour from genesis),
///   2. the dev account as a `Verified` human in the proof-of-humanity registry,
///   3. the 3 devnet jurors (the deterministic verifier/interpreter quorum),
///   4. the CSCA governance authority (the dev account on devnet),
///   5. a single curated devnet CSCA trust anchor (so a proof can bind a non-empty registry root).
///
/// Does NOT seal the anchor — the caller seals (so a fresh boot and a FU-3 restore can seal from the
/// appropriate state). `state_root` sorts, so the seed insertion order does not affect the root.
pub fn seed_canonical_devnet_genesis(chain: &Chain, genesis_time: u64) {
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 0,
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), genesis_time);
    for juror in DEVNET_JURORS {
        chain.register_juror(&juror.into_array(), 0);
    }
    chain.set_csca_governance(&DEV_ADDR.into_array());
    chain.seed_csca(*b"USA", DEVNET_CSCA_KEY_ID, DEVNET_CSCA_PUBKEY.to_vec());
}

/// M5 Stage B (spec 08 §13 setup): seed the multi-validator devnet's validator set into genesis. Each
/// address in `UBI2_GENESIS_VALIDATORS` (comma-separated 20-byte hex, identical on every node) is seeded
/// as a **`Verified` human** (so it accrues emission + qualifies for `V`) AND a **registered juror** (the
/// shared PoH-gated validator registry, §2.1). All three qualify, so the epoch snapshot `V` is
/// `{n1, n2, n3}` on every node by replay — the deterministic multi-validator schedule (EC-B1). Absent
/// the env var (the Stage-A / single-node devnet) this is a no-op, so the pinned light-client genesis
/// anchor is unchanged. Deterministic: `state_root` sorts, so the seed order does not affect the root.
pub fn seed_genesis_validators(chain: &Chain, genesis_time: u64) {
    let raw = match std::env::var("UBI2_GENESIS_VALIDATORS") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return,
    };
    for tok in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let hex = tok.strip_prefix("0x").unwrap_or(tok);
        if hex.len() != 40 {
            tracing::warn!(
                token = tok,
                "UBI2_GENESIS_VALIDATORS: skipping non-20-byte address"
            );
            continue;
        }
        let mut addr = [0u8; 20];
        let mut ok = true;
        for i in 0..20 {
            match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                Ok(b) => addr[i] = b,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            tracing::warn!(
                token = tok,
                "UBI2_GENESIS_VALIDATORS: skipping non-hex address"
            );
            continue;
        }
        chain.seed_account(Account {
            address: addr,
            verified: true,
            verified_at: genesis_time,
            last_settled_at: genesis_time,
            settled_balance: 0,
            nonce: 0,
        });
        chain.seed_verified_human(&addr, genesis_time);
        chain.register_juror(&addr, 0);
        tracing::info!(validator = %hex::encode(addr.as_slice()), "seeded genesis validator");
    }
}

/// Compute the canonical devnet **genesis anchor** — the sealed genesis `(hash, state_root)` — for a
/// given `genesis_time`, as `0x`-free lowercase hex strings. Builds a throwaway [`Chain`] with the SAME
/// seeds [`run`] applies on a fresh boot (via [`seed_canonical_devnet_genesis`]), seals it, and returns
/// its hash + seeded state root.
///
/// This is what `ubi genesis anchor` prints and what the pinned light-client constants in
/// `apps/light-node/src/config.ts` are derived from. `optional_proposer_secret`, when supplied, is
/// attached before sealing so `genesis_proposer()` resolves — it does NOT change the genesis hash or
/// state root (the anchor is a pure function of the seeded state + genesis time), but it keeps this
/// function faithful to the boot path.
pub fn canonical_devnet_genesis(
    genesis_time: u64,
    optional_proposer_secret: Option<[u8; 32]>,
) -> (String, String) {
    let mut chain = Chain::new(DEVNET_CHAIN_ID, genesis_time);
    if let Some(secret) = optional_proposer_secret {
        if let Ok(key) = ProposerKey::from_bytes(&secret) {
            chain = chain.with_proposer_key(Arc::new(key));
        }
    }
    seed_canonical_devnet_genesis(&chain, genesis_time);
    chain.seal_genesis();
    (
        hex::encode(chain.genesis_hash().as_slice()),
        hex::encode(
            chain
                .genesis_state_root()
                .expect("sealed genesis has a state root")
                .as_slice(),
        ),
    )
}

/// Spec 07 §3.4 (`ln-trust-2`): reconstruct the canonical seeded genesis state into a throwaway
/// `MemState`, applying the EXACT same genesis seeds the fresh-boot path applies to the live chain (the
/// dev account + verified human, the devnet jurors, the CSCA governance authority + curated CSCA). Used
/// to seal the genesis anchor on a node booted from a FU-3 persistence snapshot (whose live state has
/// advanced past genesis). The result must be byte-identical to the fresh path's height-0 state — it
/// seeds the same entries; `state_root` sorts, so insertion order is irrelevant. Kept in sync with the
/// fresh-genesis seeding via [`seed_canonical_devnet_genesis`] (the shared seed list).
fn build_genesis_state(dev_addr: &[u8; 20], genesis_time: u64) -> MemState {
    let mut s = MemState::new();
    s.put(Account {
        address: *dev_addr,
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 0,
        nonce: 0,
    });
    ubi2_runtime::seed_verified_human(&mut s, dev_addr, genesis_time);
    for juror in DEVNET_JURORS {
        ubi2_runtime::register_juror(&mut s, &juror.into_array(), 0);
    }
    s.set_csca_governance(*dev_addr);
    ubi2_runtime::seed_csca(
        &mut s,
        *b"USA",
        DEVNET_CSCA_KEY_ID,
        DEVNET_CSCA_PUBKEY.to_vec(),
    );
    s
}

/// The node's run entrypoint — the verbatim former `main()` body. `crates/node`'s `main.rs` and the
/// operator CLI (`ubi node`) both call this; behaviour is identical either way (the CLI only sets
/// `UBI2_*` env vars first). Handles the `ubi2-node peer-id <seed>` utility subcommand too, so the
/// standalone binary keeps that behaviour.
pub async fn run() -> anyhow::Result<()> {
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
    let dev_addr = DEV_ADDR;
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

    // True iff we booted from a persisted snapshot — used to skip re-seeding genesis-only state (the dev
    // account, the M6 CSCA registry) that a restored snapshot already carries (FU-3).
    let restored_from_snapshot = loaded_snapshot.is_some();

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
        // flag via the runtime `Verifier` trait). Streams 1 UBI/hour from genesis. The full canonical
        // seed set (dev account + verified human + jurors + CSCA governance + curated CSCA) is applied
        // by the SHARED `seed_canonical_devnet_genesis` below so the live chain can never drift from the
        // pinned light-client anchor.
        seed_canonical_devnet_genesis(&chain, genesis_time);
        // Stage B: seed the multi-validator set (if configured) so the on-chain epoch snapshot `V`
        // rotates over `{n1, n2, n3}` (§2.1). A no-op on the Stage-A / single-node devnet.
        seed_genesis_validators(&chain, genesis_time);
        chain
    };

    // M3 (board M3-T4 §4): the deterministic devnet jurors (Anvil accts #1..#3) are registered above via
    // `seed_canonical_devnet_genesis` so every case has a jury to draw from (the lifecycle fails closed
    // with `NoJurors` otherwise). Register-only in M3 (staking is M5). With JURY_SIZE = 3 and these three
    // jurors, every case's jury is exactly this set, and a juror submits its verdict by signing a
    // `submitVerdict` tx from the matching key (the keys are the standard Hardhat/Anvil accounts #1..#3,
    // published in every EVM dev toolkit — NOT SECRETS).
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

    // M6 (ZK-passport, spec 06 §6.1/§7.3): the chain runs the deterministic `MockZkVerifier` on the
    // consensus path by default (exactly as M3 ships `MockOracle`) — the `Chain::new` default — so the
    // ZK lifecycle verifies end-to-end with no pairing math (I5). A production node swaps the real
    // `ubi2_zkpoh::Groth16Verifier` (genesis-pinned VK) here via `Chain::with_verifier` once the
    // trusted-setup ceremony VK is wired. The CSCA trust-anchor registry (governance authority + the
    // curated static genesis CSCA set) is seeded on a FRESH genesis by `seed_canonical_devnet_genesis`
    // above; a restored snapshot already carries it (FU-3).
    if !restored_from_snapshot {
        tracing::info!(
            csca_root = %hex::encode(chain.csca_registry_root().as_slice()),
            "M6: seeded the genesis CSCA trust-anchor registry + governance authority"
        );
    }

    // Spec 07 §3.4 (`ln-trust-2`): seal the **seeded genesis anchor** so the sync gateway can serve a
    // browser light client the verifiable genesis (the seeded accounts/jurors/CSCA/governance + its
    // recomputed `state_root`). For a FRESH genesis the live state IS the height-0 state — `seal_genesis`
    // captures it directly. For a chain RESTORED from a FU-3 snapshot the live state has advanced past
    // genesis, so we reconstruct the canonical seeded genesis into a throwaway state (the SAME seeds the
    // fresh path applies) and seal from that. Either way the anchor is the deterministic devnet genesis,
    // and the shipped app's PINNED `state_root` constant catches a lying gateway.
    if restored_from_snapshot {
        let genesis_state = build_genesis_state(&dev_addr.into_array(), genesis_time);
        chain.seal_genesis_from_state(&genesis_state);
    } else {
        chain.seal_genesis();
    }
    if let Some(root) = chain.genesis_state_root() {
        tracing::info!(
            genesis_state_root = %hex::encode(root.as_slice()),
            genesis_hash = %hex::encode(chain.genesis_hash().as_slice()),
            "M5-LN: sealed the seeded genesis anchor (light-client pinned root)"
        );
    }

    let handle = serve(addr, chain.clone()).await?;

    // Sync gateway (spec 07 §3.1 / ADR-0006 Decision 2): a separate WebSocket endpoint that serves
    // the M5 `ubi2/sync/1` `SyncRequest`/`SyncResponse` payloads so browser light clients can sync
    // without libp2p. Enabled when `UBI2_SYNC_ADDR` is set (default off; integration tests enable it).
    let sync_addr_str = std::env::var("UBI2_SYNC_ADDR").unwrap_or_default();
    let _sync_handle = if !sync_addr_str.is_empty() {
        let sync_addr: SocketAddr = sync_addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("bad UBI2_SYNC_ADDR: {e}"))?;
        let gw = serve_sync_gateway(sync_addr, chain.clone())
            .await
            .map_err(|e| anyhow::anyhow!("sync gateway bind failed: {e}"))?;
        tracing::info!("  sync gateway      : ws://{sync_addr}/sync");
        Some(gw)
    } else {
        None
    };

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
            netcfg.validator_override,
            netcfg.is_proposer,
            block_ms,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Anvil acct #2 secret (PUBLIC, non-secret devnet key) — the lightnode/multi designated proposer.
    const PROPOSER_SECRET: [u8; 32] = [
        0x5d, 0xe4, 0x11, 0x1a, 0xfa, 0x1a, 0x4b, 0x94, 0x90, 0x8f, 0x83, 0x10, 0x3e, 0xb1, 0xf1,
        0x70, 0x63, 0x67, 0xc2, 0xe6, 0x8c, 0xa8, 0x70, 0xfc, 0x3f, 0xb9, 0x80, 0x4c, 0xda, 0xb3,
        0x65, 0x5a,
    ];

    /// The canonical anchor is a pure function of the seeds + genesis time (attaching the proposer key
    /// must NOT change it), and it must equal the constant pinned in `apps/light-node/src/config.ts`.
    #[test]
    fn canonical_anchor_matches_pinned_lightnode_constants() {
        let pinned_hash = "bc53563fa41f719abe0358f106b067e31915a6ed68d0656ba7443a36f01224e3";
        let pinned_root = "2ceab410e36255e646826ae52093e4ed438700e4654104b2f79ae74a4f03fb98";

        let (hash_no_key, root_no_key) = canonical_devnet_genesis(1_700_000_000, None);
        assert_eq!(hash_no_key, pinned_hash);
        assert_eq!(root_no_key, pinned_root);

        // Attaching the proposer key must not perturb the anchor (pure function of seeds + time).
        let (hash_key, root_key) = canonical_devnet_genesis(1_700_000_000, Some(PROPOSER_SECRET));
        assert_eq!(hash_key, pinned_hash);
        assert_eq!(root_key, pinned_root);
    }
}
