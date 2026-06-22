//! Runtime-configurable AI backend: the node's LLM provider/model/key can be selected at boot (a JSON
//! config file under the devnet data dir + env overrides) **and** changed at runtime from the wallet's
//! Settings panel via a **localhost-only** admin RPC. This module owns:
//!
//!   * [`OracleConfig`] — the JSON config shape the node persists (provider/model/base_url/api_key_env;
//!     **never the secret value**, only the *name* of the env var the key is read from — I6).
//!   * [`OracleHealth`] — the live status the wallet shows (which impl is active, reachable?, model).
//!   * [`OracleFactory`] — the seam the **node** fills with `ubi2-oracle` (`crates/rpc` stays free of the
//!     oracle crate): given a config + an optional raw API key, build the boxed runtime trait objects
//!     and a health probe. The Mock impls are the fail-closed fallback the runtime already ships.
//!   * [`OracleAdmin`] — the hot-swappable state (current config + status + the live trait objects) the
//!     [`Chain`](crate::Chain) holds behind a lock, plus the [`ubi_getOracleConfig`] /
//!     [`ubi_setOracleConfig`] handlers.
//!
//! ## Determinism caveat (honored + documented)
//! Running a real LLM **inline on the node's block-production path** is fine for THIS single-node devnet:
//! one node interprets, so there is no cross-node divergence to reconcile (invariant I1 is trivially
//! satisfied by a quorum of one). The multi-node end-state moves interpretation/verification **off** the
//! consensus path into independent juror/interpreter daemons (FU-7) that submit canonical effects/verdicts
//! the chain tallies. This admin surface configures the node's *local* inline oracle/interpreter; it does
//! NOT change that seam — the `submitVerdict`/`submitEffect` quorum path is untouched and remains the
//! multi-node story.
//!
//! ## Security note (localhost devnet only)
//! [`ubi_setOracleConfig`] can change which model/endpoint the node calls and carries a raw API key in its
//! params. It is therefore **rejected for any non-loopback caller** ([`is_loopback`]) — the peer address
//! is injected per-request by [`serve`](crate::serve)'s accept loop. The raw key is used to construct the
//! live backend and is **never persisted to disk or logged**: only the env-var *name* (`api_key_env`) is
//! written to the config file (the node sets the process env var from the provided key in-memory). This is
//! a devnet convenience; a production deployment must gate this behind real auth, which is out of scope.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use jsonrpsee::types::error::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ubi2_runtime::{ContractInterpreter, HumanityOracle};

/// JSON-RPC error code for a rejected non-loopback admin call (server error range).
pub const ERR_NOT_LOOPBACK: i32 = -32099;
/// JSON-RPC error code for an invalid / unbuildable oracle config.
pub const ERR_BAD_CONFIG: i32 = -32098;

/// The persisted oracle config — the exact JSON the node writes under the devnet data dir
/// (`<data_dir>/oracle.json`) and the shape [`ubi_getOracleConfig`] returns (secret redacted). Mirrors
/// `ubi2_oracle::Backend` field-for-field so the node can `serde` straight across, but is defined here so
/// `crates/rpc` does not depend on `crates/oracle`.
///
/// **No secret ever lives here.** `api_key_env` is the *name* of the env var the live backend reads the
/// key from (e.g. `"ANTHROPIC_API_KEY"`); the key value is read from the environment at construction time
/// (I6). `None` provider ⇒ the node runs the deterministic Mock impls (the devnet default).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleConfig {
    /// `"anthropic"` | `"ollama"` | `"openai"`. `None` ⇒ run the deterministic Mock impls (devnet default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Pinned model id. `None` ⇒ the provider's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Base URL override (Ollama / OpenAI-compatible). `None` ⇒ the provider's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The **name** of the env var the API key is read from. Never the key value (I6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
}

impl OracleConfig {
    /// Is this config asking for a live provider (vs. the Mock default)?
    pub fn is_live(&self) -> bool {
        self.provider
            .as_deref()
            .map(|p| !p.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Which implementation is currently wired into the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActiveImpl {
    /// The deterministic `MockOracle` / `MockInterpreter` (devnet default / fail-closed fallback).
    Mock,
    /// A live provider-backed oracle + interpreter.
    Live,
}

/// Live status the wallet shows: which impl is active, whether the backend is reachable, the resolved
/// model, and (for a failed live attempt) a redacted, secret-free error string.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OracleHealth {
    /// Resolved provider (`"mock"` when running the deterministic impls).
    pub provider: String,
    /// Resolved, pinned model id (empty for Mock).
    pub model: String,
    /// Did the most recent health probe reach the backend? `false` for Mock (no backend) and for a live
    /// backend that failed to construct / probe.
    pub reachable: bool,
    /// Secret-free detail for a failed live attempt (e.g. `"ANTHROPIC_API_KEY unset"`); empty on success.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// The product of building a backend from an [`OracleConfig`]: the two runtime trait objects to swap in,
/// plus the health to report. The node fills this via [`OracleFactory::build`].
pub struct BuiltOracle {
    pub oracle: Arc<dyn HumanityOracle>,
    pub interpreter: Arc<dyn ContractInterpreter>,
    pub health: OracleHealth,
}

/// The node-supplied seam that turns an [`OracleConfig`] into live trait objects. Implemented in
/// `crates/node` over `ubi2_oracle::Backend` so `crates/rpc` need not depend on the oracle crate.
///
/// `build` is handed the raw API key when the caller supplied one (an in-memory `setOracleConfig` param),
/// or `None` to read it from the configured env var. On any failure it returns `Err(message)` (secret-free)
/// and the caller falls back to Mock — the devnet always works (I4).
pub trait OracleFactory: Send + Sync {
    /// Build the live oracle + interpreter for `cfg`. `api_key` (when `Some`) is the raw key to use
    /// instead of reading the env var. `Err` ⇒ fall back to Mock.
    fn build(&self, cfg: &OracleConfig, api_key: Option<&str>) -> Result<BuiltOracle, String>;

    /// The deterministic Mock pair (the devnet default + the fail-closed fallback). Always succeeds.
    fn mock(&self) -> BuiltOracle;

    /// Persist `cfg` to the node's config file (secret-free). Best-effort; an `Err` is surfaced to the
    /// caller but the in-memory hot-swap still takes effect. A node with no persistence returns `Ok(())`.
    fn persist(&self, _cfg: &OracleConfig) -> Result<(), String> {
        Ok(())
    }
}

/// The hot-swappable oracle state the [`Chain`](crate::Chain) holds. Read on every block (the chain clones
/// the inner `Arc`s before locking state, so a swap mid-flight is atomic per-block). Guarded by an
/// `RwLock`: block production takes a read lock (cheap, uncontended); `setOracleConfig` takes a write lock.
pub struct OracleAdmin {
    factory: Arc<dyn OracleFactory>,
    inner: RwLock<AdminState>,
}

struct AdminState {
    config: OracleConfig,
    health: OracleHealth,
    active: ActiveImpl,
    oracle: Arc<dyn HumanityOracle>,
    interpreter: Arc<dyn ContractInterpreter>,
}

impl OracleAdmin {
    /// Construct from the node's factory and the boot config. If `config` requests a live provider, try
    /// to build it; on any failure log nothing here (the node logs) and fall back to Mock so the devnet
    /// always boots (I4). The resolved state is recorded for [`ubi_getOracleConfig`].
    pub fn new(factory: Arc<dyn OracleFactory>, config: OracleConfig) -> Self {
        let built = if config.is_live() {
            match factory.build(&config, None) {
                Ok(b) => b,
                Err(_) => factory.mock(),
            }
        } else {
            factory.mock()
        };
        let active = if config.is_live() && built.health.reachable {
            ActiveImpl::Live
        } else {
            ActiveImpl::Mock
        };
        OracleAdmin {
            factory,
            inner: RwLock::new(AdminState {
                config,
                health: built.health,
                active,
                oracle: built.oracle,
                interpreter: built.interpreter,
            }),
        }
    }

    /// A Mock-only admin (no live factory) — used by tests and any default `Chain::new` path.
    pub fn mock_only() -> Self {
        Self::new(Arc::new(MockFactory), OracleConfig::default())
    }

    /// An admin wrapping a fixed oracle + interpreter (no runtime swap). Back-compat for
    /// `Chain::with_oracle` / `Chain::with_interpreter` and tests that inject a specific impl directly.
    pub fn with_fixed(
        oracle: Arc<dyn HumanityOracle>,
        interpreter: Arc<dyn ContractInterpreter>,
    ) -> Self {
        OracleAdmin {
            factory: Arc::new(MockFactory),
            inner: RwLock::new(AdminState {
                config: OracleConfig::default(),
                health: OracleHealth {
                    provider: "fixed".to_string(),
                    model: String::new(),
                    reachable: false,
                    error: String::new(),
                },
                active: ActiveImpl::Mock,
                oracle,
                interpreter,
            }),
        }
    }

    /// The current `HumanityOracle` (cloned `Arc`; cheap). Block production calls this once per block.
    pub fn oracle(&self) -> Arc<dyn HumanityOracle> {
        Arc::clone(&self.inner.read().unwrap().oracle)
    }

    /// The current `ContractInterpreter` (cloned `Arc`; cheap).
    pub fn interpreter(&self) -> Arc<dyn ContractInterpreter> {
        Arc::clone(&self.inner.read().unwrap().interpreter)
    }

    /// `ubi_getOracleConfig` body: the current config (secret-free by construction) + live health.
    pub fn get_config_json(&self) -> Value {
        let g = self.inner.read().unwrap();
        json!({
            "config": &g.config,
            "active": g.active,
            "health": &g.health,
        })
    }

    /// `ubi_setOracleConfig` body: validate, build, hot-swap, persist. `api_key` (when present) is the raw
    /// secret used to construct the backend and is **never persisted** (only `api_key_env` is). On a build
    /// failure the call returns the (secret-free) error and the state is left unchanged — fail-closed; the
    /// previous (possibly Mock) impl keeps serving. Returns the new `getOracleConfig` body on success.
    pub fn set_config(
        &self,
        config: OracleConfig,
        api_key: Option<String>,
    ) -> Result<Value, String> {
        // Build first (so a bad config never tears down the working impl), then swap under the write lock.
        let (built, active) = if config.is_live() {
            let b = self.factory.build(&config, api_key.as_deref())?;
            // A live config that built but cannot reach the backend is recorded but still Live-intent;
            // we surface `reachable:false` so the wallet can warn, but we keep the previous working impl
            // rather than swap in an unreachable one — fail-closed (I4).
            if !b.health.reachable {
                let mut g = self.inner.write().unwrap();
                g.config = config.clone();
                g.health = b.health;
                g.active = ActiveImpl::Mock;
                // keep the existing oracle/interpreter (do not swap in an unreachable backend)
                let _ = self.factory.persist(&config);
                return Ok(self.get_config_json());
            }
            (b, ActiveImpl::Live)
        } else {
            (self.factory.mock(), ActiveImpl::Mock)
        };

        {
            let mut g = self.inner.write().unwrap();
            g.config = config.clone();
            g.health = built.health;
            g.active = active;
            g.oracle = built.oracle;
            g.interpreter = built.interpreter;
        }
        // Persist is best-effort and secret-free; surface (but don't roll back) a persistence error.
        self.factory.persist(&config)?;
        Ok(self.get_config_json())
    }
}

/// Is `addr` a loopback peer (the only callers the admin RPC accepts)? IPv4 `127.0.0.0/8` and IPv6 `::1`.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Map a missing/non-loopback peer to the standard rejection error (secret-free).
pub fn not_loopback_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ERR_NOT_LOOPBACK,
        "ubi_setOracleConfig/ubi_getOracleConfig are localhost-only (loopback callers); \
         this is a devnet admin surface",
        None::<()>,
    )
}

/// Map a bad-config build failure to a JSON-RPC error (the message is already secret-free).
pub fn bad_config_error(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ERR_BAD_CONFIG, msg.into(), None::<()>)
}

/// A factory that only ever yields the deterministic Mock pair — the default when the node wires no live
/// factory (and what every test uses). `build` errors (there is no live backend to build), so the caller
/// stays on Mock.
pub struct MockFactory;

impl OracleFactory for MockFactory {
    fn build(&self, _cfg: &OracleConfig, _api_key: Option<&str>) -> Result<BuiltOracle, String> {
        Err("no live oracle factory wired (devnet runs the deterministic Mock impls)".to_string())
    }
    fn mock(&self) -> BuiltOracle {
        BuiltOracle {
            oracle: Arc::new(ubi2_runtime::MockOracle::default()),
            interpreter: Arc::new(ubi2_runtime::MockInterpreter::default()),
            health: OracleHealth {
                provider: "mock".to_string(),
                model: String::new(),
                reachable: false,
                error: String::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips_and_omits_none_fields() {
        let c = OracleConfig {
            provider: Some("anthropic".to_string()),
            model: None,
            base_url: None,
            api_key_env: Some("ANTHROPIC_API_KEY".to_string()),
        };
        let s = serde_json::to_string(&c).unwrap();
        // `model`/`base_url` are None → omitted; no secret field exists at all.
        assert!(!s.contains("model"));
        assert!(!s.contains("base_url"));
        assert!(s.contains("api_key_env"));
        assert!(!s.contains("api_key\"")); // the raw-key field name never appears in the persisted shape
        let back: OracleConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn default_config_is_mock_and_not_live() {
        let c = OracleConfig::default();
        assert!(!c.is_live());
        let admin = OracleAdmin::mock_only();
        let body = admin.get_config_json();
        assert_eq!(body["active"], json!("mock"));
        assert_eq!(body["health"]["provider"], json!("mock"));
    }

    #[test]
    fn set_live_config_without_factory_falls_back_but_persists_intent() {
        // MockFactory has no live backend, so a live `set` errors on build and leaves Mock serving.
        let admin = OracleAdmin::mock_only();
        let live = OracleConfig {
            provider: Some("ollama".to_string()),
            model: Some("llama3.1".to_string()),
            base_url: None,
            api_key_env: None,
        };
        let err = admin.set_config(live, None).unwrap_err();
        assert!(err.contains("no live oracle factory"));
        // Still Mock — fail-closed.
        assert_eq!(admin.get_config_json()["active"], json!("mock"));
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback(&"127.0.0.1:8545".parse().unwrap()));
        assert!(is_loopback(&"[::1]:8545".parse().unwrap()));
        assert!(!is_loopback(&"10.0.0.5:8545".parse().unwrap()));
        assert!(!is_loopback(&"192.168.1.2:8545".parse().unwrap()));
    }

    // A stub factory that builds a fake reachable "live" pair so we can exercise the hot-swap path.
    struct StubFactory;
    impl OracleFactory for StubFactory {
        fn build(&self, cfg: &OracleConfig, _key: Option<&str>) -> Result<BuiltOracle, String> {
            Ok(BuiltOracle {
                oracle: Arc::new(ubi2_runtime::MockOracle::default()),
                interpreter: Arc::new(ubi2_runtime::MockInterpreter::default()),
                health: OracleHealth {
                    provider: cfg.provider.clone().unwrap_or_default(),
                    model: cfg
                        .model
                        .clone()
                        .unwrap_or_else(|| "default-model".to_string()),
                    reachable: true,
                    error: String::new(),
                },
            })
        }
        fn mock(&self) -> BuiltOracle {
            MockFactory.mock()
        }
    }

    #[test]
    fn hot_swap_to_live_updates_config_and_health() {
        let admin = OracleAdmin::new(Arc::new(StubFactory), OracleConfig::default());
        assert_eq!(admin.get_config_json()["active"], json!("mock"));
        let live = OracleConfig {
            provider: Some("openai".to_string()),
            model: Some("gpt-4o".to_string()),
            base_url: None,
            api_key_env: Some("OPENAI_API_KEY".to_string()),
        };
        let body = admin
            .set_config(live, Some("sk-secret".to_string()))
            .unwrap();
        assert_eq!(body["active"], json!("live"));
        assert_eq!(body["health"]["provider"], json!("openai"));
        assert_eq!(body["health"]["model"], json!("gpt-4o"));
        assert_eq!(body["health"]["reachable"], json!(true));
        // The persisted config carries the env-var NAME, never the raw key.
        assert_eq!(body["config"]["api_key_env"], json!("OPENAI_API_KEY"));
        let s = serde_json::to_string(&body).unwrap();
        assert!(!s.contains("sk-secret"), "raw key must never surface");
    }
}
