//! GATE 3 (security, cycle 5) regression tests for the new attack surface. After the C5 remediation the
//! former PoCs are **inverted**: the attacks that used to succeed must now be BLOCKED.
//!
//!   * C5-SEC-1 (Critical) — SSRF + key exfiltration via `base_url`: a metadata/loopback/RFC1918
//!     `base_url` is now rejected by the per-provider URL policy before any dial, and the operator key is
//!     never handed to a rejected destination. A *public* https host is still accepted (the feature).
//!   * C5-SEC-2 (High) — browser CSRF / DNS-rebinding: the loopback TCP-peer gate stays, and the admin
//!     methods additionally reject a foreign `Origin` or a non-loopback `Host`, while the real wallet
//!     (`Origin: http://localhost:3000`, loopback `Host`) is accepted.
//!   * C5-SEC-3 (High) — a live (blocking-client) backend driven through `produce_block` must NOT panic
//!     the block-production task, and must produce a committed/aborted outcome.
//!   * C5-SEC-4 (info) — the raw key never surfaces in the admin response (unchanged; still asserted).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::json;
use ubi2_rpc::oracle_admin::{AdminHttpMeta, MockFactory};
use ubi2_rpc::{
    build_module, AdminAccess, BuiltOracle, Chain, OracleAdmin, OracleConfig, OracleFactory,
    OracleHealth, DEVNET_CHAIN_ID,
};
use ubi2_runtime::{MockInterpreter, MockOracle};

const LOOPBACK: &str = "127.0.0.1:54321";
const NON_LOOPBACK: &str = "203.0.113.7:443";
const WALLET_ORIGIN: &str = "http://localhost:3000";

/// Recorded `(base_url, raw_api_key)` pairs the factory was asked to dial with.
type Seen = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

/// A factory that records the `base_url`/`api_key` it is asked to build with, and APPLIES THE SAME URL
/// POLICY THE NODE FACTORY APPLIES (`ubi2_oracle::validate_base_url`) — so this test exercises the real
/// remediation: a rejected `base_url` errors out of `build` (no hot-swap, key never recorded), while an
/// allowed one builds. It does not touch the network (I5).
#[derive(Default)]
struct PolicyFactory {
    seen: Seen,
}

impl OracleFactory for PolicyFactory {
    fn build(&self, cfg: &OracleConfig, api_key: Option<&str>) -> Result<BuiltOracle, String> {
        // Mirror the node factory: refuse a disallowed base_url BEFORE recording/handing off the key.
        let provider = match cfg.provider.as_deref() {
            Some("anthropic") => ubi2_oracle::Provider::Anthropic,
            Some("ollama") => ubi2_oracle::Provider::Ollama,
            Some("openai") => ubi2_oracle::Provider::Openai,
            other => return Err(format!("unknown provider {other:?}")),
        };
        ubi2_oracle::validate_base_url(provider, cfg.base_url.as_deref())
            .map_err(|e| format!("invalid base_url: {e}"))?;
        // Only a config that PASSED the policy reaches the key/dial seam.
        self.seen
            .lock()
            .unwrap()
            .push((cfg.base_url.clone(), api_key.map(str::to_string)));
        Ok(BuiltOracle {
            oracle: Arc::new(MockOracle::default()),
            interpreter: Arc::new(MockInterpreter::default()),
            health: OracleHealth {
                provider: cfg.provider.clone().unwrap_or_default(),
                model: cfg.model.clone().unwrap_or_else(|| "policy-model".into()),
                reachable: true,
                error: String::new(),
            },
        })
    }
    fn mock(&self) -> BuiltOracle {
        MockFactory.mock()
    }
}

/// Build the real `RpcModule` with the policy factory, injecting a peer `SocketAddr` and (optionally) the
/// admin HTTP metadata exactly the way `serve`'s accept loop injects them per request.
fn module_with(peer: &str, meta: Option<AdminHttpMeta>) -> (jsonrpsee::RpcModule<Chain>, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let factory = Arc::new(PolicyFactory { seen: seen.clone() });
    let admin = Arc::new(OracleAdmin::new(factory, OracleConfig::default()));
    let chain = Chain::new(DEVNET_CHAIN_ID, 1_700_000_000)
        .with_oracle_admin(admin)
        .with_admin_access(Arc::new(AdminAccess::default()));
    let mut m = build_module(chain);
    let addr: SocketAddr = peer.parse().unwrap();
    m.extensions_mut().insert(addr);
    if let Some(meta) = meta {
        m.extensions_mut().insert(meta);
    }
    (m, seen)
}

/// A loopback request from the real wallet: loopback `Host`, the wallet `Origin`.
fn wallet_meta() -> AdminHttpMeta {
    AdminHttpMeta {
        host: Some("127.0.0.1:8545".to_string()),
        origin: Some(WALLET_ORIGIN.to_string()),
    }
}

async fn call(
    m: &jsonrpsee::RpcModule<Chain>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let (resp, _rx) = m.raw_json_request(&req, 1).await.expect("call");
    serde_json::from_str(&resp).expect("json")
}

// =================================================================================================
// C5-SEC-1 — SSRF + key exfiltration via base_url is now BLOCKED.
// =================================================================================================

/// The former exfiltration PoC, inverted: an OpenAI `base_url` pointed at the cloud-metadata address is
/// REJECTED, the call returns an error, and the key is NEVER handed to the factory (so it can't ride to
/// the attacker). The wallet (loopback host + allowed origin) is the caller, proving the block is the URL
/// policy — not the origin gate.
#[tokio::test]
async fn ssrf_metadata_base_url_is_rejected_and_key_never_sent() {
    let (m, seen) = module_with(LOOPBACK, Some(wallet_meta()));

    let attacker_url = "http://169.254.169.254/latest/meta-data";
    let params = json!([{
        "provider": "openai",
        "model": "gpt-4o",
        "base_url": attacker_url,
        "api_key": "sk-operator-secret-key"
    }]);
    let set = call(&m, "ubi_setOracleConfig", params).await;
    assert!(
        set.get("error").is_some(),
        "metadata base_url must be rejected, got: {set}"
    );
    // The factory was never handed the key for a rejected URL — no exfiltration seam.
    assert!(
        seen.lock().unwrap().is_empty(),
        "the key must never reach the dial seam for a rejected base_url"
    );
}

/// Every internal SSRF target class is refused: loopback ports, the metadata IP, link-local, RFC1918, and
/// a plain-http cloud endpoint (https is required). Each is rejected with an error and no key handed off.
#[tokio::test]
async fn ssrf_internal_targets_are_all_rejected() {
    for target in [
        "https://127.0.0.1:9000/admin", // loopback port
        "https://169.254.169.254/",     // cloud metadata
        "https://[::1]:6379/",          // local redis (v6 loopback)
        "https://10.0.0.5/v1",          // RFC1918
        "https://192.168.1.10/v1",      // RFC1918
        "https://[fd00::1]/v1",         // ULA
        "http://169.254.169.254/",      // not https
        "http://api.openai.com/",       // openai compat requires https
    ] {
        let (m, seen) = module_with(LOOPBACK, Some(wallet_meta()));
        let set = call(
            &m,
            "ubi_setOracleConfig",
            json!([{ "provider": "openai", "base_url": target, "api_key": "sk-x" }]),
        )
        .await;
        assert!(
            set.get("error").is_some(),
            "internal SSRF target {target} must be rejected: {set}"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "no key may be handed off for rejected target {target}"
        );
    }
}

/// Ollama may only be pointed at loopback; an external Ollama `base_url` is refused (and no key is
/// involved for Ollama anyway).
#[tokio::test]
async fn ollama_external_base_url_is_rejected() {
    let (m, _seen) = module_with(LOOPBACK, Some(wallet_meta()));
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "ollama", "base_url": "http://attacker.evil:1234" }]),
    )
    .await;
    assert!(
        set.get("error").is_some(),
        "external ollama base_url must be rejected: {set}"
    );
}

/// The feature still works: a PUBLIC https endpoint (an OpenAI-compatible host) is ACCEPTED and the key is
/// handed to exactly that destination. `1.1.1.1` is a public IP literal (resolves to itself, not
/// internal), standing in for a real provider host without a DNS round-trip in CI.
#[tokio::test]
async fn public_https_endpoint_is_accepted_with_its_key() {
    let (m, seen) = module_with(LOOPBACK, Some(wallet_meta()));
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "openai", "model": "gpt-4o", "base_url": "https://1.1.1.1/v1", "api_key": "sk-operator" }]),
    )
    .await;
    assert!(set.get("error").is_none(), "public https must pass: {set}");
    assert_eq!(set["result"]["active"], json!("live"));
    let seen = seen.lock().unwrap();
    let (base, key) = seen.last().expect("factory built for the allowed URL");
    assert_eq!(base.as_deref(), Some("https://1.1.1.1/v1"));
    assert_eq!(
        key.as_deref(),
        Some("sk-operator"),
        "key rides only the allowed host"
    );
}

// =================================================================================================
// C5-SEC-2 — browser CSRF / DNS-rebinding against the loopback admin RPC is now BLOCKED.
// =================================================================================================

/// A malicious page: loopback peer (the browser POSTs from localhost) BUT a foreign `Origin`. The admin
/// call is now REJECTED by the Origin allowlist, even though the TCP peer is loopback.
#[tokio::test]
async fn foreign_origin_admin_call_is_rejected() {
    let meta = AdminHttpMeta {
        host: Some("127.0.0.1:8545".to_string()),
        origin: Some("https://evil.example.com".to_string()),
    };
    let (m, seen) = module_with(LOOPBACK, Some(meta));
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "ollama", "base_url": "http://127.0.0.1:11434" }]),
    )
    .await;
    assert_eq!(
        set["error"]["code"],
        json!(-32097),
        "foreign-origin admin call must be rejected (CSRF defense): {set}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "no backend swap on rejected origin"
    );
    // getOracleConfig is gated the same way.
    let get = call(&m, "ubi_getOracleConfig", json!([])).await;
    assert_eq!(get["error"]["code"], json!(-32097));
}

/// DNS-rebinding: the page resolves `attacker.com` to `127.0.0.1`, so the peer is loopback, but the HTTP
/// `Host` header carries the rebound hostname. Host-pinning REJECTS it.
#[tokio::test]
async fn rebound_host_header_admin_call_is_rejected() {
    let meta = AdminHttpMeta {
        host: Some("attacker.com".to_string()),
        origin: None, // a rebinding attack typically has no/again-attacker origin; host alone must block
    };
    let (m, _seen) = module_with(LOOPBACK, Some(meta));
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "ollama", "base_url": "http://127.0.0.1:11434" }]),
    )
    .await;
    assert_eq!(
        set["error"]["code"],
        json!(-32097),
        "non-loopback Host must be rejected (DNS-rebinding defense): {set}"
    );
}

/// The REAL wallet still works: loopback peer, loopback `Host`, and the allowlisted wallet `Origin`
/// (`http://localhost:3000`). The admin call is accepted (here the config is a valid loopback Ollama).
#[tokio::test]
async fn wallet_origin_admin_call_is_accepted() {
    let (m, _seen) = module_with(LOOPBACK, Some(wallet_meta()));
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "ollama", "model": "llama3.1", "base_url": "http://127.0.0.1:11434" }]),
    )
    .await;
    assert!(
        set.get("error").is_none(),
        "the real wallet (allowed origin + loopback host) must be accepted: {set}"
    );
    assert_eq!(set["result"]["active"], json!("live"));
    // And the read path works too for the wallet.
    let get = call(&m, "ubi_getOracleConfig", json!([])).await;
    assert!(get.get("error").is_none(), "wallet read must work: {get}");
}

/// curl / non-browser (absent Origin) over loopback still works (Origin is only checked when present).
#[tokio::test]
async fn absent_origin_loopback_call_is_accepted() {
    let meta = AdminHttpMeta {
        host: Some("localhost:8545".to_string()),
        origin: None,
    };
    let (m, _seen) = module_with(LOOPBACK, Some(meta));
    let get = call(&m, "ubi_getOracleConfig", json!([])).await;
    assert!(
        get.get("error").is_none(),
        "curl (no Origin) must work: {get}"
    );
}

/// The loopback TCP-peer gate is still primary and not header-spoofable: a non-loopback peer is rejected
/// with -32099 regardless of a spoofed loopback `Host`/`Origin`.
#[tokio::test]
async fn non_loopback_peer_is_rejected_even_with_spoofed_headers() {
    let (m, _seen) = module_with(NON_LOOPBACK, Some(wallet_meta()));
    for method in ["ubi_getOracleConfig", "ubi_setOracleConfig"] {
        let resp = call(&m, method, json!([{ "provider": "openai" }])).await;
        assert_eq!(
            resp["error"]["code"],
            json!(-32099),
            "{method} must reject a non-loopback peer even with spoofed loopback headers"
        );
    }
}

// =================================================================================================
// C5-SEC-4 (info) — the raw key never surfaces in the admin response (unchanged).
// =================================================================================================

#[tokio::test]
async fn raw_api_key_never_surfaces_in_the_admin_response() {
    let (m, _seen) = module_with(LOOPBACK, Some(wallet_meta()));
    let secret = "sk-this-must-never-surface-abc123";
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "openai", "model": "gpt-4o", "base_url": "https://1.1.1.1", "api_key": secret }]),
    )
    .await;
    let body = serde_json::to_string(&set).unwrap();
    assert!(
        !body.contains(secret),
        "raw key leaked in set response: {body}"
    );

    let got = call(&m, "ubi_getOracleConfig", json!([])).await;
    let body = serde_json::to_string(&got).unwrap();
    assert!(
        !body.contains(secret),
        "raw key leaked in get response: {body}"
    );
    assert!(
        !body.contains("api_key\""),
        "no api_key field is exposed: {body}"
    );
}
