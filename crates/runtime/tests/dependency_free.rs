//! M5 determinism gate (spec `05-p2p-network.md` §0, §12.7; ADR-0004 Decision 1):
//!
//! > **Non-negotiable structural rule:** `crates/runtime` stays deterministic and dependency-free.
//! > No async, no networking, no floats, no `HashMap` ordering on any consensus path. All
//! > networking/async lives in the new `crates/network` crate. `runtime` never imports
//! > libp2p/tokio/reqwest.
//!
//! This is the **build-level assertion** the spec asks for: it reads the runtime crate's own
//! `Cargo.toml` and fails the build if any forbidden async/networking dependency is declared. It is a
//! cheap, fast guard that catches the mistake at `cargo test` time rather than letting a heavy,
//! non-deterministic dependency silently creep onto the consensus path. (The full transitive-graph
//! check is the reliability gate's job; this catches the direct-dependency regression that matters.)

/// Crates that must NEVER be a direct dependency of `crates/runtime`.
const FORBIDDEN: &[&str] = &[
    "libp2p",
    "tokio",
    "reqwest",
    "hyper",
    "jsonrpsee",
    "async-std",
    "futures",
    "smol",
];

#[test]
fn runtime_declares_no_async_or_networking_deps() {
    let manifest = include_str!("../Cargo.toml");

    // Walk the manifest line by line, tracking which `[section]` we are in. We only police real
    // dependency tables ([dependencies], [dev-dependencies], [build-dependencies] and their
    // `target.*` variants); a forbidden token appearing in a comment or the [package] description is
    // ignored. A dependency line starts with the crate name (`name = ...` or `name.workspace = ...`).
    let mut in_dep_section = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_dep_section = line.contains("dependencies");
            continue;
        }
        if !in_dep_section {
            continue;
        }
        // The dependency key is the text before the first '=' or '.'.
        let key = line
            .split(['=', '.'])
            .next()
            .map(str::trim)
            .unwrap_or("")
            .trim_matches('"');
        assert!(
            !FORBIDDEN.contains(&key),
            "crates/runtime must stay dependency-free: forbidden async/networking dependency `{key}` \
             declared in its Cargo.toml. Networking/async must live in crates/network (ADR-0004)."
        );
    }
}
