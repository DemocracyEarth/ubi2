//! `ubi` — run and operate the UBI chain.
//!
//! One discoverable binary for running/operating the chain, replacing env-var sprawl + shell scripts +
//! fictional README flags. Every command has `--help`.
//!
//! ## Design: flags are sugar over the existing `UBI2_*` env config (zero consensus risk)
//! The node resolves its ENTIRE configuration from `UBI2_*` env vars (`crates/node/src/netcfg.rs`,
//! `oracle_cfg.rs`). This CLI does NOT re-implement that resolution. Instead, `ubi node` parses its
//! flags/preset, sets the corresponding `UBI2_*` env vars in-process (a flag OVERRIDES the env var; an
//! unset flag leaves the existing env var as the documented fallback), and then calls the node's
//! in-process entrypoint [`ubi2_node::run`]. The env vars remain the mechanism + the fallback; the flags
//! are ergonomic sugar. Because config resolution is untouched, the CLI adds zero consensus risk.
//!
//! ## Commands
//!   * `ubi node`            — run a full node (presets: devnet | lightnode | multi).
//!   * `ubi genesis anchor`  — print/verify the canonical genesis hash + seeded state_root.
//!   * `ubi keys`            — print the PUBLIC devnet accounts the presets use.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::Command;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

// ───────────────────────── Public, NON-SECRET devnet keys (Anvil/Hardhat) ─────────────────────────
// These are the standard Hardhat/Anvil test accounts, published in every EVM dev toolkit. They are NOT
// secrets — never use them for anything holding real value. The presets wire them the same way the
// scripts/tests do.

/// Anvil acct #0 — the pre-verified genesis dev account (streams 1 UBI/hour). The MetaMask-import key.
const DEV_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Anvil acct #1 — the `multi` preset's designated PoA proposer + juror #1.
const ACCT1_ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ACCT1_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Anvil acct #2 — the `lightnode` preset's PoA proposer (the pinned light-client validator) + juror #2.
const ACCT2_ADDR: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const ACCT2_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

/// Anvil acct #3 — juror #3.
const ACCT3_ADDR: &str = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
const ACCT3_KEY: &str = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";

/// The pinned canonical genesis time (`apps/light-node/src/config.ts`), shared by `lightnode` + `multi`.
const CANONICAL_GENESIS_TIME: u64 = 1_700_000_000;

/// The lightnode proposer key (Anvil acct #2) — bare hex the node's `UBI2_PROPOSER_KEY` expects.
const LIGHTNODE_PROPOSER_KEY: &str =
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
/// The multi proposer key (Anvil acct #1) — bare hex for `UBI2_PROPOSER_KEY`.
const MULTI_PROPOSER_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// The multi designated-proposer address (Anvil acct #1) — bare hex for `UBI2_DESIGNATED_PROPOSER`.
const MULTI_DESIGNATED_PROPOSER: &str = "70997970C51812dc3A010C7d01b50e0d17dc79C8";

// ─────────────────────────────────────── CLI definition ───────────────────────────────────────────

/// The `ubi` release version — CalVer (`year.month.day`), the modern AI-tooling style; shown by
/// `ubi --version` and the launch banner. A literal (not the Cargo semver) so the zero-padded date form
/// `2026.07.01` renders exactly — semver forbids leading zeros in `07`/`01`. Bump this per release.
const VERSION: &str = "2026.07.01";

#[derive(Parser)]
#[command(
    name = "ubi",
    version = VERSION,
    about = "ubi — run and operate the UBI chain.",
    long_about = "ubi — run and operate the UBI chain.\n\n\
        `ubi node` runs a full node; its flags are ergonomic sugar over the UBI2_* env vars the node \
        already reads (a flag overrides the env var; an unset flag leaves the env var as the fallback). \
        `ubi genesis anchor` prints/verifies the canonical genesis anchor pinned by the browser light \
        node. `ubi keys` prints the PUBLIC devnet accounts the presets use."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a full node (HTTP+WS JSON-RPC, block production, optional P2P / sync gateway).
    Node(NodeArgs),
    /// Genesis anchor tools (hash + seeded state_root of the canonical genesis).
    #[command(subcommand)]
    Genesis(GenesisCmd),
    /// Print the PUBLIC, non-secret devnet accounts the presets use (dev, jurors, PoA proposer).
    Keys,
}

/// Which canned configuration to boot. Flags still OVERRIDE the preset's values.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Preset {
    /// Plain single node (== scripts/devnet.sh): 2s blocks, wall-clock genesis, no proposer key.
    Devnet,
    /// Single node the browser light node accepts: pinned genesis 1700000000, Anvil acct #2 proposer,
    /// 1s blocks, sync gateway on :8546, isolated data dir. Reproduces the pinned genesis anchor.
    Lightnode,
    /// Multi-node local network (== scripts/devnet-multi.sh): one designated proposer + N-1 followers
    /// over libp2p, pinned genesis. Launches N processes itself (`--nodes`, default 3).
    Multi,
}

#[derive(Args)]
struct NodeArgs {
    /// Canned configuration: devnet | lightnode | multi. Flags below still override preset values.
    #[arg(long, value_enum)]
    preset: Option<Preset>,

    /// JSON-RPC (HTTP+WS) listen address. Overrides UBI2_RPC_ADDR. [preset/default: 127.0.0.1:8545]
    #[arg(long, value_name = "ADDR")]
    rpc: Option<String>,

    /// Enable the WebSocket sync gateway (browser light-node) on this address. Overrides UBI2_SYNC_ADDR.
    #[arg(long, value_name = "ADDR")]
    sync_gateway: Option<String>,

    /// Pinned genesis unix time (shared across a network so genesis hashes match). Overrides
    /// UBI2_GENESIS_TIME. Absent (and no preset that pins it) ⇒ wall-clock genesis.
    #[arg(long, value_name = "UNIX")]
    genesis_time: Option<u64>,

    /// Proposer signing key (32-byte hex, PoA block author). Overrides UBI2_PROPOSER_KEY.
    #[arg(long, value_name = "HEX32")]
    proposer_key: Option<String>,

    /// Block interval in milliseconds. Overrides UBI2_BLOCK_MS. [preset/default: 2000]
    #[arg(long, value_name = "MS")]
    block_ms: Option<u64>,

    /// Data directory (chain snapshot + oracle config). Overrides UBI2_DATA_DIR. [default: ./.ubi2-devnet]
    #[arg(long, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    /// Enable libp2p on this listen multiaddr (e.g. /ip4/127.0.0.1/tcp/19001). Overrides UBI2_P2P_ADDR.
    #[arg(long, value_name = "ADDR")]
    p2p: Option<String>,

    /// (multi preset only) number of nodes to launch. [default: 3]
    #[arg(short = 'n', long, value_name = "N", default_value_t = 3)]
    nodes: usize,
}

#[derive(Subcommand)]
enum GenesisCmd {
    /// Print the genesis HASH + seeded genesis STATE_ROOT of the canonical genesis. Used to
    /// regenerate/verify the pin in apps/light-node/src/config.ts.
    Anchor(AnchorArgs),
}

#[derive(Args)]
struct AnchorArgs {
    /// Which genesis to anchor. `lightnode` pins genesis_time=1700000000 (the shipped light-node pin).
    #[arg(long, value_enum, default_value_t = AnchorPreset::Lightnode)]
    preset: AnchorPreset,

    /// Override the genesis unix time (advanced; a different time ⇒ a different, non-pinned anchor).
    #[arg(long, value_name = "UNIX")]
    genesis_time: Option<u64>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum AnchorPreset {
    /// The canonical pinned genesis (genesis_time=1700000000) the browser light node accepts.
    Lightnode,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Cmd::Node(args)) => run_node(args),
        Some(Cmd::Genesis(GenesisCmd::Anchor(args))) => genesis_anchor(args),
        Some(Cmd::Keys) => {
            print_keys();
            Ok(())
        }
        // Bare `ubi` (no subcommand): the banner + the help, so the tool introduces itself.
        None => {
            banner();
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

/// The `ubi` launch banner — Proof-of-Humanity yellow→pink — printed to STDERR on `ubi node` startup and
/// on a bare `ubi`. Suppressed by `UBI_NO_BANNER=1` (set on the `multi` child nodes). Colour is used only
/// on a tty with `NO_COLOR` unset; the art always prints. Never touches stdout, so the scriptable output
/// of `ubi genesis anchor` / `ubi keys` stays clean.
fn banner() {
    if std::env::var_os("UBI_NO_BANNER").is_some() {
        return;
    }
    // A spaced block "UBI" wordmark. The gradient sweeps HORIZONTALLY (yellow #FFFF00 on the left →
    // pink #FF6699 on the right — the Proof-of-Humanity ramp), so it reads as one smooth left-to-right
    // sweep across the whole wordmark rather than banded rows.
    const ART: [&str; 6] = [
        "  ██╗   ██╗ ██████╗  ██╗",
        "  ██║   ██║ ██╔══██╗ ██║",
        "  ██║   ██║ ██████╔╝ ██║",
        "  ██║   ██║ ██╔══██╗ ██║",
        "  ╚██████╔╝ ██████╔╝ ██║",
        "   ╚═════╝  ╚═════╝  ╚═╝",
    ];
    let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let width = ART.iter().map(|l| l.chars().count()).max().unwrap_or(1);
    let dim = |s: &str| -> String {
        if color {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    eprintln!();
    for line in ART {
        eprintln!("{}", h_gradient(line, width, color));
    }
    eprintln!(
        "{}",
        dim(&format!("   universal basic income   ·   ubi {VERSION}"))
    );
    eprintln!(
        "{}",
        dim("   a human-verified, AI-executed chain   ~   streaming 1 UBI/hour")
    );
    eprintln!();
}

/// Colour `line` with a HORIZONTAL yellow→pink gradient (per-column) — the PoH brand ramp. Each non-space
/// glyph gets a truecolor escape keyed to its column; spaces pass through. `width` is the wordmark width,
/// so every row shares the same left→right ramp. Integer math only.
fn h_gradient(line: &str, width: usize, color: bool) -> String {
    if !color {
        return line.to_string();
    }
    let denom = width.saturating_sub(1).max(1);
    let mut out = String::with_capacity(line.len() * 20);
    for (i, ch) in line.chars().enumerate() {
        if ch == ' ' {
            out.push(' ');
            continue;
        }
        let t = i.min(denom);
        let g = 255 - (t * (255 - 102)) / denom; // 255 → 102
        let b = (t * 153) / denom; // 0 → 153
        out.push_str(&format!("\x1b[1;38;2;255;{g};{b}m{ch}"));
    }
    out.push_str("\x1b[0m");
    out
}

// ─────────────────────────────────────── `ubi node` ───────────────────────────────────────────────

/// Set an env var only if it is not already meaningfully set OR force it. We use `set_var` for flags
/// (they OVERRIDE) and preset defaults; a flag left unset never clears an env var (the fallback holds).
fn set_env(key: &str, val: &str) {
    std::env::set_var(key, val);
}

fn run_node(args: NodeArgs) -> anyhow::Result<()> {
    banner();

    // The `multi` preset is a process launcher, not a single in-process node — handle it separately.
    if args.preset == Some(Preset::Multi) {
        return run_multi(&args);
    }

    // 1) Apply the preset's env baseline FIRST (so explicit flags below override it). A preset only sets
    //    the vars that define it; everything else keeps the node's own env fallback.
    match args.preset {
        Some(Preset::Lightnode) => {
            // Single node the browser light node accepts — reproduces the pinned genesis anchor.
            set_env("UBI2_GENESIS_TIME", &CANONICAL_GENESIS_TIME.to_string());
            set_env("UBI2_PROPOSER_KEY", LIGHTNODE_PROPOSER_KEY);
            set_env("UBI2_RPC_ADDR", "127.0.0.1:8545");
            set_env("UBI2_SYNC_ADDR", "127.0.0.1:8546");
            set_env("UBI2_BLOCK_MS", "1000");
            set_env("UBI2_DATA_DIR", ".devnet-lightnode-data");
        }
        Some(Preset::Devnet) => {
            // Plain single node (== scripts/devnet.sh): wall-clock genesis, 2s blocks, no proposer key,
            // gateway off unless --sync-gateway is given. Only pin the vars that define the preset.
            set_env("UBI2_RPC_ADDR", "127.0.0.1:8545");
            set_env("UBI2_BLOCK_MS", "2000");
        }
        Some(Preset::Multi) => unreachable!("handled above"),
        None => {}
    }

    // 2) Apply explicit flags — these OVERRIDE both the preset baseline and any pre-existing env var.
    if let Some(rpc) = &args.rpc {
        set_env("UBI2_RPC_ADDR", rpc);
    }
    if let Some(sync) = &args.sync_gateway {
        set_env("UBI2_SYNC_ADDR", sync);
    }
    if let Some(gt) = args.genesis_time {
        set_env("UBI2_GENESIS_TIME", &gt.to_string());
    }
    if let Some(pk) = &args.proposer_key {
        set_env("UBI2_PROPOSER_KEY", pk.trim_start_matches("0x"));
    }
    if let Some(ms) = args.block_ms {
        set_env("UBI2_BLOCK_MS", &ms.to_string());
    }
    if let Some(dir) = &args.data_dir {
        set_env("UBI2_DATA_DIR", &dir.to_string_lossy());
    }
    if let Some(p2p) = &args.p2p {
        set_env("UBI2_P2P_ADDR", p2p);
    }

    // 3) Boot the node in-process. Its config resolution (env-driven) is 100% unchanged, so behaviour is
    //    identical to running `ubi2-node` with the same env vars.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(ubi2_node::run())
}

// ─────────────────────────────────────── `ubi node --preset multi` ────────────────────────────────

/// Launch a multi-node devnet: one designated proposer (Anvil acct #1) + N-1 followers over libp2p, all
/// on localhost with distinct RPC/P2P ports + data dirs, wired via a full cross-bootstrap mesh (no mDNS
/// — deterministic). Mirrors `scripts/devnet-multi.sh`, but the CLI owns the process launching.
fn run_multi(args: &NodeArgs) -> anyhow::Result<()> {
    let n = args.nodes.max(1);
    let block_ms = args.block_ms.unwrap_or(2000);
    let genesis_time = args.genesis_time.unwrap_or(CANONICAL_GENESIS_TIME);
    let rpc_base: u16 = 18540;
    let p2p_base: u16 = 19540;
    let data_root = ".ubi2-multi";

    // Re-invoke THIS `ubi` binary for each child node, so a plain `cargo install --path crates/cli` is
    // fully self-sufficient — no separate `ubi2-node` binary required. `ubi node` with the child's env
    // vars boots a node identically to `ubi2-node`.
    let ubi_exe = std::env::current_exe().map_err(|e| {
        anyhow::anyhow!("cannot locate the running `ubi` executable to relaunch: {e}")
    })?;

    // Derive every node's PeerId up front (pure, IN-PROCESS — no subprocess) so we can wire a FULL
    // cross-bootstrap mesh deterministically. Node i's seed = the hex of `i` repeated to 64 chars.
    let mut seeds = Vec::with_capacity(n);
    let mut peer_ids = Vec::with_capacity(n);
    for i in 1..=n {
        let d = format!("{i:x}");
        let seed: String = d.repeat(64 / d.len().max(1));
        let seed = format!("{seed:0>64}"); // pad/truncate defensively to 64 hex chars
        let seed = seed[..64].to_string();
        let peer_id = ubi2_node::netcfg::peer_id_for_seed_hex(&seed)
            .map_err(|e| anyhow::anyhow!("deriving PeerId for node {i}: {e}"))?;
        seeds.push(seed);
        peer_ids.push(peer_id);
    }

    let p2p_addr = |i: usize| format!("/ip4/127.0.0.1/tcp/{}", p2p_base as usize + i);
    let rpc_addr = |i: usize| format!("127.0.0.1:{}", rpc_base as usize + i);

    // Node i's bootstrap list = the full multiaddrs of every OTHER node (a complete mesh).
    let bootstrap_for = |self_i: usize| -> String {
        (1..=n)
            .filter(|&j| j != self_i)
            .map(|j| format!("{}/p2p/{}", p2p_addr(j), peer_ids[j - 1]))
            .collect::<Vec<_>>()
            .join(",")
    };

    println!("ubi node --preset multi: launching {n} nodes (proposer = node 1)");
    println!("  genesis_time = {genesis_time}, block_ms = {block_ms}, data root = {data_root}/");

    let mut children = Vec::with_capacity(n);
    for i in 1..=n {
        let mut cmd = Command::new(&ubi_exe);
        cmd.arg("node")
            .env("UBI_NO_BANNER", "1") // one banner (the launcher's) is enough
            .env("UBI2_RPC_ADDR", rpc_addr(i))
            .env("UBI2_P2P_ADDR", p2p_addr(i))
            .env("UBI2_P2P_SEED", &seeds[i - 1])
            .env("UBI2_BOOTSTRAP", bootstrap_for(i))
            .env("UBI2_DESIGNATED_PROPOSER", MULTI_DESIGNATED_PROPOSER)
            .env("UBI2_GENESIS_TIME", genesis_time.to_string())
            .env("UBI2_BLOCK_MS", block_ms.to_string())
            .env("UBI2_DATA_DIR", format!("{data_root}/node{i}"));
        if i == 1 {
            cmd.env("UBI2_PROPOSER_KEY", MULTI_PROPOSER_KEY);
        }
        // Inherit RUST_LOG (default info) + stdio so logs stream to the terminal.
        if std::env::var("RUST_LOG").is_err() {
            cmd.env("RUST_LOG", "info");
        }
        let role = if i == 1 { "PROPOSER" } else { "follower" };
        println!(
            "  node {i}  RPC http://{}  P2P {}  PeerId {}  ({role})",
            rpc_addr(i),
            p2p_addr(i),
            peer_ids[i - 1]
        );
        let child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!("failed to spawn node {i} ({}): {e}", ubi_exe.display())
        })?;
        children.push(child);
    }

    println!();
    println!("all {n} nodes up. Ctrl-C to stop.");
    println!(
        "  watch: curl -s {} -H 'content-type: application/json' \\",
        rpc_addr(1)
    );
    println!("           -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ubi_consensusStatus\",\"params\":[]}}'");

    // Wait for Ctrl-C, then SIGTERM every child (best-effort). We block on the OS signal via a tiny
    // single-thread runtime so this stays a plain synchronous launcher.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    println!("\nstopping {} node(s)…", children.len());
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    println!("multi devnet stopped.");
    Ok(())
}

// ─────────────────────────────────────── `ubi genesis anchor` ─────────────────────────────────────

/// The genesis anchor constant currently pinned in `apps/light-node/src/config.ts` — printed alongside
/// the recomputed anchor for a visible match/mismatch (the CLI is used to regenerate/verify this pin).
const PINNED_LIGHTNODE_HASH: &str =
    "bc53563fa41f719abe0358f106b067e31915a6ed68d0656ba7443a36f01224e3";
const PINNED_LIGHTNODE_STATE_ROOT: &str =
    "fa0360178cd29e57affe89478e19cbdc5bdc94fad00212695a4b241f2dcba1ac";

fn genesis_anchor(args: AnchorArgs) -> anyhow::Result<()> {
    let genesis_time = args.genesis_time.unwrap_or(match args.preset {
        AnchorPreset::Lightnode => CANONICAL_GENESIS_TIME,
    });

    // Attach the lightnode proposer key so this is faithful to the boot path (it does NOT change the
    // anchor — the anchor is a pure function of the seeded state + genesis time).
    let proposer_secret = parse_hex32(LIGHTNODE_PROPOSER_KEY);
    let (hash, state_root) = ubi2_node::canonical_devnet_genesis(genesis_time, proposer_secret);

    println!("genesis_time : {genesis_time}");
    println!("genesis_hash : {hash}");
    println!("state_root   : {state_root}");

    // When anchoring the canonical pinned time, verify equality with the shipped config.ts pin and
    // fail loudly on drift (so this command doubles as a pin verifier).
    if args.genesis_time.is_none() && args.preset == AnchorPreset::Lightnode {
        let hash_ok = hash == PINNED_LIGHTNODE_HASH;
        let root_ok = state_root == PINNED_LIGHTNODE_STATE_ROOT;
        if hash_ok && root_ok {
            println!(
                "pin check    : OK (matches apps/light-node/src/config.ts PINNED_GENESIS_HASH/STATE_ROOT)"
            );
        } else {
            eprintln!(
                "pin check    : MISMATCH — the shipped light-node pin is stale, re-pin config.ts:"
            );
            if !hash_ok {
                eprintln!("  expected genesis_hash {PINNED_LIGHTNODE_HASH}");
            }
            if !root_ok {
                eprintln!("  expected state_root   {PINNED_LIGHTNODE_STATE_ROOT}");
            }
            anyhow::bail!("genesis anchor drifted from the pinned config.ts constants");
        }
    }
    Ok(())
}

/// Parse a bare or `0x`-prefixed 32-byte hex string; `None` if malformed (the anchor is still printed).
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ─────────────────────────────────────── `ubi keys` ───────────────────────────────────────────────

fn print_keys() {
    println!("PUBLIC, NON-SECRET devnet accounts (standard Hardhat/Anvil test keys).");
    println!("These are published in every EVM dev toolkit — NEVER use them for real value.\n");

    println!("  role                                 address                                       private key");
    println!("  -----------------------------------  --------------------------------------------  ------------------------------------------------------------------");
    row("dev account (Anvil #0)", DEV_ADDR, DEV_KEY);
    row(
        "juror #1 / multi proposer (Anvil #1)",
        ACCT1_ADDR,
        ACCT1_KEY,
    );
    row(
        "juror #2 / lightnode proposer (Anvil #2)",
        ACCT2_ADDR,
        ACCT2_KEY,
    );
    row("juror #3 (Anvil #3)", ACCT3_ADDR, ACCT3_KEY);

    println!("\nProposer roles:");
    println!("  `ubi node --preset lightnode` uses juror #2 (Anvil #2) as the PoA proposer");
    println!("     (the address pinned in apps/light-node/src/config.ts: {ACCT2_ADDR}).");
    println!("  `ubi node --preset multi` uses juror #1 (Anvil #1) as the designated proposer");
    println!("     ({ACCT1_ADDR}); the other nodes are followers.");
}

fn row(role: &str, addr: &str, key: &str) {
    println!("  {role:<35}  {addr}  {key}");
}
