//! Node-side wiring for the runtime-configurable AI backend.
//!
//! The node selects which LLM the proof-of-humanity oracle + the prompt-contract interpreter call, from:
//!   1. a JSON config file under the devnet data dir (`<data_dir>/oracle.json`), then
//!   2. environment overrides (`UBI2_ORACLE_*`), which win over the file.
//!
//! It then constructs the provider-backed [`HumanityOracle`] + [`ContractInterpreter`] via
//! `ubi2_oracle::Backend` and fills `ubi2_rpc`'s [`OracleFactory`] seam (so `crates/rpc` never depends on
//! `crates/oracle`). When no provider is configured — or the backend cannot be built (missing key, etc.)
//! — the node falls back to the deterministic Mock impls so the devnet **always** boots (invariant I4).
//!
//! ## Secret handling (I6)
//! The persisted config never holds a key value, only the *name* of the env var the key is read from
//! (`api_key_env`). When the localhost admin RPC supplies a raw `api_key`, the node sets that env var in
//! its own process memory (so `Backend` can read it) and persists only the name — the secret never
//! touches disk or logs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ubi2_oracle::{Backend, Provider};
use ubi2_rpc::{BuiltOracle, OracleConfig, OracleFactory, OracleHealth};

/// Env var selecting the devnet data dir (where `oracle.json` lives). Defaults to `./.ubi2-devnet`.
pub const ENV_DATA_DIR: &str = "UBI2_DATA_DIR";
/// Per-field oracle overrides (win over the config file). Empty/unset ⇒ no override for that field.
pub const ENV_PROVIDER: &str = "UBI2_ORACLE_PROVIDER";
pub const ENV_MODEL: &str = "UBI2_ORACLE_MODEL";
pub const ENV_BASE_URL: &str = "UBI2_ORACLE_BASE_URL";
pub const ENV_API_KEY_ENV: &str = "UBI2_ORACLE_API_KEY_ENV";

/// The config file name under the data dir.
pub const CONFIG_FILE: &str = "oracle.json";

/// Resolve the devnet data dir (`UBI2_DATA_DIR` or `./.ubi2-devnet`).
pub fn data_dir() -> PathBuf {
    std::env::var(ENV_DATA_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./.ubi2-devnet"))
}

/// The oracle config file path under the data dir.
pub fn config_path(dir: &Path) -> PathBuf {
    dir.join(CONFIG_FILE)
}

/// Read a non-empty env var, trimmed; `None` if unset/blank.
fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Load the boot oracle config: the file under `dir` (if present + parseable) with env overrides applied
/// on top. A missing/invalid file is not fatal — it yields the Mock default (the node logs + continues).
pub fn load_config(dir: &Path) -> OracleConfig {
    let mut cfg = read_config_file(dir).unwrap_or_default();
    apply_env_overrides(&mut cfg);
    cfg
}

/// Read + parse `<dir>/oracle.json` into an [`OracleConfig`]. `None` if the file is absent or unparseable
/// (the caller falls back to the default; an unparseable file must never crash the devnet).
pub fn read_config_file(dir: &Path) -> Option<OracleConfig> {
    let path = config_path(dir);
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice::<OracleConfig>(&bytes) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "oracle.json unparseable; ignoring");
            None
        }
    }
}

/// Apply `UBI2_ORACLE_*` env overrides onto `cfg` (each set var wins over the file).
pub fn apply_env_overrides(cfg: &mut OracleConfig) {
    if let Some(p) = env_opt(ENV_PROVIDER) {
        cfg.provider = Some(p);
    }
    if let Some(m) = env_opt(ENV_MODEL) {
        cfg.model = Some(m);
    }
    if let Some(b) = env_opt(ENV_BASE_URL) {
        cfg.base_url = Some(b);
    }
    if let Some(k) = env_opt(ENV_API_KEY_ENV) {
        cfg.api_key_env = Some(k);
    }
}

/// Persist `cfg` (secret-free) to `<dir>/oracle.json`, creating the data dir if needed.
pub fn write_config_file(dir: &Path, cfg: &OracleConfig) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create data dir: {e}"))?;
    let path = config_path(dir);
    let json = serde_json::to_string_pretty(cfg).map_err(|e| format!("serialize config: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Parse an [`OracleConfig`]'s provider string into the oracle crate's [`Provider`] enum (serde respects
/// the `lowercase` rename). `None` config provider ⇒ `None` (Mock). An unknown provider ⇒ `Err`.
fn parse_provider(cfg: &OracleConfig) -> Result<Option<Provider>, String> {
    match cfg
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => Ok(None),
        Some(p) => serde_json::from_value::<Provider>(serde_json::Value::String(p.to_lowercase()))
            .map(Some)
            .map_err(|_| format!("unknown provider '{p}' (expected anthropic|ollama|openai)")),
    }
}

/// Build a `ubi2_oracle::Backend` from an [`OracleConfig`] (provider already known to be `Some`).
fn backend_from_config(cfg: &OracleConfig, provider: Provider) -> Backend {
    Backend {
        provider,
        model: cfg.model.clone(),
        base_url: cfg.base_url.clone(),
        api_key_env: cfg.api_key_env.clone(),
    }
}

/// The node's [`OracleFactory`]: builds live trait objects from config (over `ubi2_oracle::Backend`) and
/// persists the secret-free config under the data dir.
pub struct NodeOracleFactory {
    data_dir: PathBuf,
}

impl NodeOracleFactory {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }
}

impl OracleFactory for NodeOracleFactory {
    fn build(&self, cfg: &OracleConfig, api_key: Option<&str>) -> Result<BuiltOracle, String> {
        let provider =
            parse_provider(cfg)?.ok_or_else(|| "no provider configured (Mock)".to_string())?;
        let backend = backend_from_config(cfg, provider);

        // If the admin RPC supplied a raw key, set the resolved env var in-process so `Backend` reads it.
        // The key is used in-memory only; only `api_key_env` is ever persisted (I6).
        if let Some(key) = api_key {
            if let Some(env_name) = backend.resolved_api_key_env() {
                // SAFETY: single-threaded config path at construction; we only ever set our own var.
                std::env::set_var(&env_name, key);
            }
        }

        let model = backend.resolved_model();
        // Construct both trait objects. This reads the API key from the env var and validates the
        // backend is buildable; a missing key / bad config is the fail-closed signal to fall back to
        // Mock. We do NOT make a live network call here (I5: boot/CI never touch the network) — the
        // health `reachable` reflects "the backend was constructed", a structural probe, not a ping.
        // The oracle crate already scrubs any key value from its error strings, so `to_string()` here is
        // secret-free; the construction path only ever sees env-var *names*, never values.
        let oracle: Arc<dyn ubi2_runtime::HumanityOracle> =
            Arc::from(backend.humanity_oracle().map_err(|e| e.to_string())?);
        let interpreter: Arc<dyn ubi2_runtime::ContractInterpreter> =
            Arc::from(backend.contract_interpreter().map_err(|e| e.to_string())?);

        Ok(BuiltOracle {
            oracle,
            interpreter,
            health: OracleHealth {
                provider: provider.to_string(),
                model,
                reachable: true,
                error: String::new(),
            },
        })
    }

    fn mock(&self) -> BuiltOracle {
        // Reuse rpc's Mock default via the MockFactory mock (kept in one place).
        ubi2_rpc::oracle_admin::MockFactory.mock()
    }

    fn persist(&self, cfg: &OracleConfig) -> Result<(), String> {
        write_config_file(&self.data_dir, cfg)
    }
}

/// Build the [`OracleAdmin`](ubi2_rpc::OracleAdmin) the node hands to the chain: the node factory + the
/// resolved boot config. Logs which impl ended up active.
pub fn build_admin(data_dir: PathBuf, config: OracleConfig) -> Arc<ubi2_rpc::OracleAdmin> {
    let factory = Arc::new(NodeOracleFactory::new(data_dir));
    Arc::new(ubi2_rpc::OracleAdmin::new(factory, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("ubi2-oracle-cfg-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn missing_file_yields_default_mock_config() {
        let dir = temp_dir();
        let cfg = load_config(&dir);
        assert!(!cfg.is_live(), "no file ⇒ Mock default");
    }

    #[test]
    fn write_then_read_round_trips_secret_free() {
        let dir = temp_dir();
        let cfg = OracleConfig {
            provider: Some("ollama".to_string()),
            model: Some("llama3.1".to_string()),
            base_url: Some("http://localhost:11434".to_string()),
            api_key_env: None,
        };
        write_config_file(&dir, &cfg).unwrap();
        let back = read_config_file(&dir).unwrap();
        assert_eq!(back.provider.as_deref(), Some("ollama"));
        assert_eq!(back.model.as_deref(), Some("llama3.1"));
        // The on-disk JSON has no key value (there is no api_key field at all).
        let raw = std::fs::read_to_string(config_path(&dir)).unwrap();
        assert!(!raw.contains("api_key\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_overrides_win_over_file() {
        let dir = temp_dir();
        let file_cfg = OracleConfig {
            provider: Some("ollama".to_string()),
            model: Some("llama3.1".to_string()),
            base_url: None,
            api_key_env: None,
        };
        write_config_file(&dir, &file_cfg).unwrap();
        std::env::set_var(ENV_MODEL, "qwen2.5");
        let cfg = load_config(&dir);
        assert_eq!(cfg.provider.as_deref(), Some("ollama"));
        assert_eq!(cfg.model.as_deref(), Some("qwen2.5"), "env override wins");
        std::env::remove_var(ENV_MODEL);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ollama_backend_constructs_without_key() {
        // Ollama needs no API key, so the node factory builds it (no network is touched).
        let dir = temp_dir();
        let factory = NodeOracleFactory::new(dir);
        let cfg = OracleConfig {
            provider: Some("ollama".to_string()),
            model: Some("llama3.1".to_string()),
            base_url: None,
            api_key_env: None,
        };
        let built = factory.build(&cfg, None).expect("ollama builds keyless");
        assert_eq!(built.health.provider, "ollama");
        assert_eq!(built.health.model, "llama3.1");
        assert!(built.health.reachable);
    }

    #[test]
    fn anthropic_without_key_falls_back() {
        std::env::remove_var("ANTHROPIC_API_KEY");
        let factory = NodeOracleFactory::new(temp_dir());
        let cfg = OracleConfig {
            provider: Some("anthropic".to_string()),
            model: None,
            base_url: None,
            api_key_env: None,
        };
        // No key ⇒ build errors (the caller falls back to Mock).
        assert!(factory.build(&cfg, None).is_err());
    }

    #[test]
    fn unknown_provider_errors() {
        let factory = NodeOracleFactory::new(temp_dir());
        let cfg = OracleConfig {
            provider: Some("definitely-not-a-provider".to_string()),
            ..Default::default()
        };
        let err = match factory.build(&cfg, None) {
            Ok(_) => panic!("unknown provider must not build"),
            Err(e) => e,
        };
        assert!(err.contains("unknown provider"));
    }
}
