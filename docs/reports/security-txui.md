# Security gate — tx-confirmation fix + explorer routes + 2 read-RPCs + contract-UX batch

Branch `fix/tx-confirmation-explorer-routes` (`ca58581` + `bf06b21`), diff vs `main`.
**Verdict: PASS** — no open High/Critical. PoCs: `crates/rpc/tests/sec_txui.rs` (5, all green; live on
:38545). *(Reconstructed by the orchestrator from the gate's structured result — the gate's own file write
did not land.)*

## Boundaries verified intact
- **Secret redaction holds (cycle-5 was CRITICAL here).** `OracleConfig` / `ubi_getOracleConfig` carry only
  `api_key_env` (the env-var *name*), never a key value; the raw `api_key` stays in-memory only. Nothing in the
  new AI/Settings section (`ai-section.tsx`) sends a full secret to the client, logs, or persisted config. The
  oracle-admin write path remains **loopback-only + Host-pinned + Origin-allowlisted**; `base_url` SSRF
  validation intact (live codes `-32097` / `-32098`).
- **New reads fail closed.** `ubi_getRecentBlocks` / `ubi_getContracts` clamp `limit` to `1..=100` and reject
  hostile params (huge / negative / float / object / overflow → `-32602`) with no panic. `contract_title` is
  char-boundary-safe on multibyte / emoji / CJK / control / `<script>` text and bounded to ≤81 chars; directory
  rows expose only already-public on-chain fields (no PII, no internal-only fields).
- **Explorer routes are injection-free.** `/tx/[hash]`, `/block/[id]`, `/address/[addr]`, `/account/[addr]`
  path params flow only into JSON-RPC params and React-escaped text — **no new `dangerouslySetInnerHTML`** — so
  no reflected XSS, SSRF, or path traversal; bad input renders the friendly not-found, not a 500/crash. The
  not-found panel leaks nothing.
- **Parties/deploy change safe.** The empty-parties → fallback-to-sender path binds only the sender; it cannot
  bind a third party or bypass the ≥1-party rule.
- **No regression** in the cycle-5/6 + PoH-NFT defenses (oracle-admin, contract-text cap, fees, soulbound).

## Findings (no High/Critical)
| # | Severity | Title | Disposition |
|---|---|---|---|
| 1 | Low | **`ubi_getRecentBlocks(nonEmptyOnly=true)` scans the unbounded blocks Vec** under the consensus mutex (`.iter().rev().filter(!empty).take(limit)`). Bounded by chain length on a localhost devnet and matches the existing O(N) read shape (`recent_contracts`), so not a release blocker. Future: side-index non-empty heights or cap the scan window. | **FU-18** |
| 2 | Info | `contract_summary.createdAt` is emitted as a raw `u64` while every other RPC timestamp uses `hex_u64` — deterministic + intentional (the SDK expects an integer) but inconsistent; document the deviation. | **FU-19** |
