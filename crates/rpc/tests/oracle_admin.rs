//! Admin-RPC acceptance for the runtime-configurable AI backend (`ubi_getOracleConfig` /
//! `ubi_setOracleConfig`). Maps to the task's DoD:
//!
//!   * default (no config) ⇒ the deterministic **Mock** is active;
//!   * `ubi_setOracleConfig` persists + hot-swaps, and `ubi_getOracleConfig` reflects it with the secret
//!     **redacted** (only the env-var name survives, never the raw key);
//!   * a **non-loopback** caller is rejected (the localhost-only gate).
//!
//! These drive the real `build_module` `RpcModule` directly and inject the caller's peer `SocketAddr`
//! into the module extensions (exactly the way `serve`'s accept loop injects it per request), so the
//! loopback gate is exercised deterministically without binding a non-loopback socket.
//!
//! The "hot-swap to live" cases inject a **stub factory** that builds a fake reachable backend (the rpc
//! crate ships no live provider — that is the node's job over `ubi2-oracle`). This keeps the test offline
//! (I5) while exercising the full validate → build → swap → persist → reflect admin path.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use ubi2_rpc::oracle_admin::MockFactory;
use ubi2_rpc::{
    build_module, BuiltOracle, Chain, OracleAdmin, OracleConfig, OracleFactory, OracleHealth,
    DEVNET_CHAIN_ID,
};
use ubi2_runtime::{MockInterpreter, MockOracle};

const LOOPBACK: &str = "127.0.0.1:54321";
const LOOPBACK_V6: &str = "[::1]:54321";
const NON_LOOPBACK: &str = "203.0.113.7:443";

/// A factory that "builds" a reachable live backend from any config — so the admin hot-swap path can be
/// exercised offline. (The real node factory lives in `crates/node` over `ubi2-oracle`.)
struct StubLiveFactory;
impl OracleFactory for StubLiveFactory {
    fn build(&self, cfg: &OracleConfig, _key: Option<&str>) -> Result<BuiltOracle, String> {
        Ok(BuiltOracle {
            oracle: Arc::new(MockOracle::default()),
            interpreter: Arc::new(MockInterpreter::default()),
            health: OracleHealth {
                provider: cfg.provider.clone().unwrap_or_default(),
                model: cfg
                    .model
                    .clone()
                    .unwrap_or_else(|| "stub-model".to_string()),
                reachable: true,
                error: String::new(),
            },
        })
    }
    fn mock(&self) -> BuiltOracle {
        MockFactory.mock()
    }
}

/// Build the module (default Mock admin) with `peer` injected as the call's remote address.
fn module_with_peer(peer: &str) -> jsonrpsee::RpcModule<Chain> {
    inject_peer(Chain::new(DEVNET_CHAIN_ID, 1_700_000_000), peer)
}

/// Build the module with a node-style live factory (so a live `setOracleConfig` actually swaps).
fn live_module_with_peer(peer: &str) -> jsonrpsee::RpcModule<Chain> {
    let admin = Arc::new(OracleAdmin::new(
        Arc::new(StubLiveFactory),
        OracleConfig::default(),
    ));
    let chain = Chain::new(DEVNET_CHAIN_ID, 1_700_000_000).with_oracle_admin(admin);
    inject_peer(chain, peer)
}

fn inject_peer(chain: Chain, peer: &str) -> jsonrpsee::RpcModule<Chain> {
    let mut m = build_module(chain);
    let addr: SocketAddr = peer.parse().unwrap();
    m.extensions_mut().insert(addr);
    m
}

/// Issue a JSON-RPC call against the module and return the parsed response object.
async fn call(
    m: &jsonrpsee::RpcModule<Chain>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let (resp, _rx) = m.raw_json_request(&req, 1).await.expect("call");
    serde_json::from_str(&resp).expect("json")
}

#[tokio::test]
async fn default_config_reports_mock_active() {
    let m = module_with_peer(LOOPBACK);
    let resp = call(&m, "ubi_getOracleConfig", json!([])).await;
    let result = &resp["result"];
    assert_eq!(result["active"], json!("mock"), "no config ⇒ Mock active");
    assert_eq!(result["health"]["provider"], json!("mock"));
    // The Mock config carries no provider (it is the absence of a live backend).
    assert!(result["config"]["provider"].is_null());
}

#[tokio::test]
async fn set_config_hot_swaps_and_get_reflects_it_with_secret_redacted() {
    let m = live_module_with_peer(LOOPBACK);

    let params = json!([{
        "provider": "ollama",
        "model": "llama3.1",
        "base_url": "http://localhost:11434",
        "api_key": "sk-this-is-a-secret-and-must-never-surface"
    }]);
    let set = call(&m, "ubi_setOracleConfig", params).await;
    assert!(set.get("error").is_none(), "set should succeed: {set}");
    let body = &set["result"];
    assert_eq!(body["active"], json!("live"), "config hot-swaps to live");
    assert_eq!(body["health"]["provider"], json!("ollama"));
    assert_eq!(body["health"]["model"], json!("llama3.1"));

    // getOracleConfig now reflects the new config...
    let got = call(&m, "ubi_getOracleConfig", json!([])).await;
    let cfg = &got["result"]["config"];
    assert_eq!(cfg["provider"], json!("ollama"));
    assert_eq!(cfg["model"], json!("llama3.1"));
    assert_eq!(cfg["base_url"], json!("http://localhost:11434"));

    // ...and the raw key NEVER appears anywhere in either response (I6).
    let dump = format!("{set}{got}");
    assert!(
        !dump.contains("sk-this-is-a-secret"),
        "raw api_key must be redacted from all admin responses"
    );
    assert!(
        !dump.contains("\"api_key\""),
        "the raw-key field is never echoed back"
    );
}

#[tokio::test]
async fn set_config_with_api_key_env_keeps_only_the_env_var_name() {
    let m = live_module_with_peer(LOOPBACK);
    let params = json!([{
        "provider": "openai",
        "model": "gpt-4o",
        "api_key_env": "UBI2_TEST_OPENAI_KEY",
        "api_key": "sk-live-secret-value"
    }]);
    let set = call(&m, "ubi_setOracleConfig", params).await;
    assert!(
        set.get("error").is_none(),
        "openai set should succeed: {set}"
    );
    let cfg = &set["result"]["config"];
    assert_eq!(cfg["provider"], json!("openai"));
    assert_eq!(cfg["api_key_env"], json!("UBI2_TEST_OPENAI_KEY"));
    // The secret value must not appear; the env-var NAME may (it is not a secret).
    let dump = format!("{set}");
    assert!(!dump.contains("sk-live-secret-value"), "key value redacted");
}

#[tokio::test]
async fn live_set_without_factory_falls_back_to_mock_fail_closed() {
    // The default (rpc-only) chain has no live factory, so a live `set` cannot build a backend; the call
    // returns an error and the previous Mock impl keeps serving — fail-closed (I4).
    let m = module_with_peer(LOOPBACK);
    let set = call(&m, "ubi_setOracleConfig", json!([{ "provider": "ollama" }])).await;
    assert!(set.get("error").is_some(), "no live factory ⇒ build error");
    let got = call(&m, "ubi_getOracleConfig", json!([])).await;
    assert_eq!(got["result"]["active"], json!("mock"), "still Mock");
}

#[tokio::test]
async fn non_loopback_caller_is_rejected_for_both_admin_methods() {
    let m = module_with_peer(NON_LOOPBACK);

    let get = call(&m, "ubi_getOracleConfig", json!([])).await;
    assert!(
        get.get("result").is_none(),
        "non-loopback get must not return a result"
    );
    assert_eq!(
        get["error"]["code"],
        json!(-32099),
        "non-loopback get rejected with the loopback-only error"
    );

    let set = call(&m, "ubi_setOracleConfig", json!([{ "provider": "ollama" }])).await;
    assert!(
        set.get("result").is_none(),
        "non-loopback set must not return a result"
    );
    assert_eq!(set["error"]["code"], json!(-32099));
}

#[tokio::test]
async fn loopback_v6_is_accepted() {
    let m = module_with_peer(LOOPBACK_V6);
    let resp = call(&m, "ubi_getOracleConfig", json!([])).await;
    assert!(
        resp.get("result").is_some(),
        "::1 is loopback and accepted: {resp}"
    );
}

#[tokio::test]
async fn missing_peer_address_is_rejected_fail_closed() {
    // A module with NO peer address injected must be rejected — we never default-allow an unidentified
    // caller.
    let chain = Chain::new(DEVNET_CHAIN_ID, 1_700_000_000);
    let m = build_module(chain);
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "ubi_getOracleConfig", "params": [] })
        .to_string();
    let (resp, _rx) = m.raw_json_request(&req, 1).await.expect("call");
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"],
        json!(-32099),
        "no peer ⇒ rejected (fail-closed)"
    );
}
