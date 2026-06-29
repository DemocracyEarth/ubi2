//! Build-level dependency-purity assertion for the verifier path (spec §6.1, §12.1, §14.4; ADR-0005
//! Decision 2 — "`crates/zkpoh` must pull no async/network/clock/float dep").
//!
//! This mirrors `crates/runtime/tests/dependency_free.rs`: it reads this crate's own `Cargo.toml` and
//! fails the build if any forbidden async/network/clock/float dependency is declared in a real
//! `[dependencies]` table. The verifier runs on every node in the consensus path and (later) in a
//! browser light node, so a non-deterministic / non-wasm dependency creeping in is exactly the
//! regression this guards. (The full transitive-graph audit is the reliability gate's job; this catches
//! the direct-dependency regression that matters and runs at `cargo test` time.)
//!
//! `[dev-dependencies]` are intentionally NOT policed: the real-curve test legitimately uses
//! `ark-relations` / `ark-snark` (the prover side) + `ark-std`'s `rng` to GENERATE a proof — that path
//! is dev-only and never compiled into the verifier the runtime calls.

/// Crates that must NEVER be a non-dev dependency of `crates/zkpoh` — they introduce async, networking,
/// wall-clock, or floating-point nondeterminism, any of which would break bit-reproducible verification
/// across nodes and/or the wasm32 build.
const FORBIDDEN: &[&str] = &[
    // async / networking (the runtime/network forbidden set)
    "libp2p",
    "tokio",
    "reqwest",
    "hyper",
    "jsonrpsee",
    "async-std",
    "futures",
    "smol",
    // wall-clock — any reachable clock breaks determinism (the op reads only block.timestamp)
    "chrono",
    "time",
    "instant",
    // floats / parallelism — reduction-order nondeterminism is forbidden on the verify path
    "rayon",
    "rug",
];

#[test]
fn zkpoh_declares_no_async_network_clock_or_float_deps() {
    let manifest = include_str!("../Cargo.toml");

    // Walk the manifest tracking which `[section]` we are in. We police ONLY the real non-dev dependency
    // tables: `[dependencies]` and its `target.*` variants. `[dev-dependencies]` (the prover-side test
    // deps) and `[build-dependencies]` are skipped — they never reach the verifier the runtime calls.
    let mut policed = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            // A dependency table that is NOT a dev/build table. Matches `[dependencies]` and
            // `[target.'cfg(..)'.dependencies]`, but excludes `[dev-dependencies]` /
            // `[build-dependencies]`.
            let is_dep_table = line.contains("dependencies")
                && !line.contains("dev-dependencies")
                && !line.contains("build-dependencies");
            policed = is_dep_table;
            continue;
        }
        if !policed {
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
            "crates/zkpoh must stay verifier-pure: forbidden async/network/clock/float dependency \
             `{key}` declared in a non-dev [dependencies] table. The verifier path must be \
             deterministic + wasm32-compilable (ADR-0005 Decision 2)."
        );
    }
}

/// A second, positive guard: the only non-dev dependencies are the pinned arkworks crates. If a new
/// non-arkworks dependency is added to `[dependencies]`, this fails so the addition is a deliberate,
/// reviewed decision (the verifier's dependency surface is load-bearing for determinism + wasm).
#[test]
fn zkpoh_non_dev_deps_are_only_pinned_arkworks() {
    let manifest = include_str!("../Cargo.toml");
    let mut policed = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            policed = line.contains("dependencies")
                && !line.contains("dev-dependencies")
                && !line.contains("build-dependencies");
            continue;
        }
        if !policed {
            continue;
        }
        let key = line
            .split(['=', '.'])
            .next()
            .map(str::trim)
            .unwrap_or("")
            .trim_matches('"');
        if key.is_empty() {
            continue;
        }
        // The verifier's dependency surface is the pinned arkworks crates PLUS `ubi2-runtime` — the
        // dependency-free crate that OWNS the `ZkPassportVerifier` trait this crate implements (ADR-0005
        // D2 / spec §6.1). `ubi2-runtime` itself pulls no crypto/async/network/clock/float dep (asserted
        // by its own `dependency_free` test), so it does not perturb verifier purity or the wasm32 build.
        assert!(
            key.starts_with("ark-") || key == "ubi2-runtime",
            "crates/zkpoh non-dev dependency `{key}` is neither a pinned arkworks crate nor \
             `ubi2-runtime`. The verifier's dependency surface is intentionally arkworks + the \
             dependency-free runtime trait crate only (ADR-0005 Decision 2); add new deps deliberately \
             and re-review determinism + wasm32."
        );
    }
}
