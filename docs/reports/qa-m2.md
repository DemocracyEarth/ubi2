# QA report — M2 (Streaming primitive)

**Gate:** Definition-of-Done GATE 1 (qa-engineer) · **Board task:** M2-T5
**Spec:** `docs/specs/02-streaming.md` · **Invariants:** `docs/specs/00-overview.md` (I2)
**Date:** 2026-06-21 · **Verdict: PASS** (all 8 acceptance criteria have passing evidence)

The M2 build was GREEN on arrival. This gate maps every acceptance criterion (1–8) to an executable
test, runs the full relevant suite, and **adds the integration coverage that was thin** — chiefly a
real-RPC test of `ubi_getStreams` (criterion 6: in/out split + live `accrued_now` for both parties)
and an ERC-721 collection-metadata + `eth_call`-soulbound test (criterion 7 over the simulate path).
No production code was changed.

## Acceptance criteria → evidence

| # | Criterion (spec) | Evidence | Result |
|---|---|---|---|
| 1 | Open locks the sender's deposit (spendable drops by `deposit` immediately); signable/sendable as an EVM tx to StreamHub by a standard signer. | Integration `stream_lock_accrual_solvency_stop` (real k256-signed `openStream` tx → StreamHub, deposit-drop assertion; receipt carries `StreamOpened` + 2 mints) **+** runtime unit `open_locks_deposit_and_indexes`. | **PASS** |
| 2 | Recipient `eth_getBalance` increases at `rate` live; sender's spendable does not double-count the locked deposit. | Integration `stream_lock_accrual_solvency_stop` (accrual = `rate*1000`/`rate*2500` at +1000s/+2500s) **+** runtime `recipient_balance_climbs_at_rate` (sender spendable == `emission − deposit`). | **PASS** |
| 3 | Pays out **at most `deposit`** — accrued caps exactly at `deposit` past `t_end` (solvency, no over-draw). | Integration `stream_lock_accrual_solvency_stop` (balance a year past open == `deposit`, `14400`) **+** runtime `accrued_caps_at_deposit_past_t_end` (`accrued(u64::MAX)==deposit`) **+** property `property_streams_solvent_conserved_reproducible` (20k random: `accrued(now) ≤ deposit` always). | **PASS** |
| 4 | `stopStream` by sender pays accrued-to-stop + **refunds the remainder**; totals conserved to the base unit. | Integration `stream_lock_accrual_solvency_stop` (stop @+1h: recipient `3600`, refund `10800`, pre==post total `51e18`, accrual frozen after stop) **+** runtime `stop_pays_accrued_refunds_remainder_conserved` + `open_accrue_stop_conserves_no_ubi_created_or_lost`. | **PASS** |
| 5 | Reproducibility (I2): stream balances identical across two nodes & random timelines (property over `rate, deposit, started_at, now, stop?`). | Runtime property `property_streams_solvent_conserved_reproducible` (20k random, two independent states agree on both balances + refund) **+** reliability `crates/runtime/tests/m2_stream_consistency.rs` (S1/S2 consistency + boundary). | **PASS** |
| 6 | `ubi_getStreams` returns correct in/out streams with live `accrued_now`; wallet shows a stream dripping and lets the sender stop it. | **NEW** integration `ubi_get_streams_in_out_split_and_live_accrual` (over the real RPC: sender out=1/in=0, recipient in=1/out=0, same id; live `accrued_now`=7200, `0 < accrued ≤ deposit`, cross-checked vs runtime `accrued`; unknown id → null) **+** SDK `projectStreamAccrued`/`getStreams` + wallet Outgoing/Incoming lists with Stop button (`apps/wallet/app/streams.tsx`). See gap note on the UI layer. | **PASS** |
| 7 | NFT (both sides): two ERC-721 mints (`streamId`→recipient, `streamId\|SENDER_FLAG`→sender, both `Transfer(0x0,…)`); `supportsInterface(0x80ac58cd)`→true; `ownerOf` per side; `balanceOf` per party; transfer reverts ("soulbound"). | Integration `nft_two_tokens_owner_and_token_uri` (receipt has `StreamOpened`+2 `Transfer` mints; `ownerOf(streamId)`==recipient, `ownerOf(streamId\|FLAG)`==sender; `balanceOf`==1 each; write `transferFrom` reverts "soulbound") **+ NEW** `erc721_collection_metadata_and_eth_call_soulbound` (all 3 interface ids true, bogus false; `name()`="ubi2 Streams", `symbol()`="USTREAM"; `eth_call` transferFrom reverts "soulbound") **+** runtime `streams.rs` units (`token_id_roundtrip_and_flag`, `transfer_selectors_are_soulbound`). | **PASS** |
| 8 | On-chain card: `tokenURI(id)` → valid `data:application/json;base64` with `name`/`attributes`/`image`, image a `data:image/svg+xml` that parses as valid SVG and shows live streamed amount + progress + status. | Integration `nft_two_tokens_owner_and_token_uri` (decode JSON → `name` "ubi2 Stream #0", `attributes` array, `image` base64-SVG → `<svg…</svg>` containing "Active", "UBI", "Incoming"; decoded `Streamed`=`5.99 UBI`, `Progress`=24%) **+** `tokenURICall` determinism test `crates/rpc/tests/m2_tokenuri_determinism.rs` **+** streams.rs units (`svg_contains_live_values_and_status`, `token_uri_decodes_to_json_with_image_svg`). | **PASS** |

## Tests added by this gate

Appended to `crates/rpc/tests/m2_acceptance.rs` (the two pre-existing tests were left intact):

- **`ubi_get_streams_in_out_split_and_live_accrual`** (criterion 6) — boots the real `ubi2_rpc::serve`
  on `127.0.0.1:18557`, signs a real `openStream` dev→recipient mined ~2h in the past, then drives
  `ubi_getStreams(sender)` and `ubi_getStreams(recipient)` over the wire and asserts the same stream
  appears as the sender's sole *outgoing* and the recipient's sole *incoming*, with a non-zero live
  `accrued_now` bounded by the deposit cap and cross-checked against the runtime's own `accrued`.
  Also asserts `ubi_getStream(unknown)` → null. This was the criterion-6 RPC gap (the existing tests
  only called the single-id `ubi_getStream`).
- **`erc721_collection_metadata_and_eth_call_soulbound`** (criterion 7, completeness) — on
  `127.0.0.1:18558`: `supportsInterface` true for all three declared ids (ERC-165/721/721-Metadata)
  and false for a bogus id; `name()`/`symbol()` == the collection identity; and a `transferFrom`
  *simulated through `eth_call`* reverts "soulbound" (the pre-existing test only covered the write-tx
  soulbound path).

All txs are signed in-process with the public Hardhat/Anvil account-0 key via k256/alloy and driven
over a raw async HTTP/1.1 client — the same wire path a wallet uses. Non-default ports keep the gate
off `:8545`.

The runtime stream property suite (`property_streams_solvent_conserved_reproducible`) and the
reliability gate's `m2_stream_consistency.rs` / `m2_tokenuri_determinism.rs` are relied on for
criteria 3/5/8 and were not duplicated.

## Test-run summary (all green)

```
cargo test --workspace
  ubi2_rpc unit ................................ 13 passed
  rpc m1_acceptance ............................  3 passed
  rpc m2_acceptance (incl. 2 NEW) ..............  4 passed
  rpc m2_tokenuri_determinism .................  3 passed
  ubi2_runtime unit (incl. M2 stream tests) ... 22 passed
  runtime i2_determinism ......................  6 passed
  runtime m2_stream_consistency ...............  4 passed
  ---------------------------------------------------------
  TOTAL ....................................... 55 passed; 0 failed
```

Selected live evidence (from `--nocapture`):

```
[stream] deposit locked: sender spendable 50000000000000000000 -> 49999999999999985600 (Δ 14400)
[stream] accrual: +1000s = 1000, +2500s = 2500 base units (rate=1/s)
[stream] solvency: recipient balance a year past open = 14400 == deposit 14400
[stream] stop@+1h: recipient paid 3600, sender refunded 10800; conservation pre=51e18 post=51e18 OK
[reads] ubi_getStreams: sender out=1/in=0, recipient in=1/out=0; live accrued_now=7200 (≤ deposit 14400)
[nft] ownerOf(recipient_token)=0x…D2, ownerOf(sender_token)=0xf39F…2266
[nft] supportsInterface: ERC165/ERC721/ERC721Metadata = true, bogus = false
[nft] name()='ubi2 Streams', symbol()='USTREAM'
[nft] tokenURI attributes = [Status=Active, Side=Incoming, Rate=0.99 UBI/hr, Deposit=24.00 UBI,
       Streamed=5.99 UBI, Progress=24, …]   (image decodes to <svg…</svg>, shows "Active"/"UBI")
[nft] soulbound: transferFrom rejected with 'soulbound'  (both write-tx and eth_call paths)
```

## How to reproduce

```sh
# Port hygiene (a stale devnet node may hold :8545).
pkill -f 'target/.*ubi2-node' 2>/dev/null

# Full workspace suite (55 tests).
cargo test --workspace

# Just the M2 acceptance integration tests, with live evidence.
cargo test -p ubi2-rpc --test m2_acceptance -- --nocapture
```

All integration tests boot the server on non-default ports (18555–18558) and self-stop their server
handle; no external node is started, so `:8545` is untouched.

## Gaps & notes (none block PASS)

1. **No automated test runner for the TS layer.** The SDK (`packages/sdk/src/streaming.ts`,
   incl. `projectStreamAccrued` — the client-side per-frame "dripping" projection) and the wallet
   (`apps/wallet/app/streams.tsx` — Outgoing/Incoming lists, Stop button, `wallet_watchAsset`) have
   **no unit tests**: there is no vitest/jest configured and no `test` script in any `package.json`.
   Criterion 6's authoritative accrual math is fully covered in Rust (`accrued`/`ubi_getStreams`);
   `projectStreamAccrued` is a thin client mirror of that capped formula. The "wallet shows a stream
   dripping and lets the sender stop it" clause is therefore evidenced by the RPC surface + code
   review of the wallet wiring, not by an automated UI test. Recommend: a small vitest harness for the
   SDK encoders + `projectStreamAccrued` parity vs the on-chain cap (follow-up, not an M2 blocker).
2. **Workspace clippy is currently red — but not from this gate's code.** `cargo clippy
   --workspace --all-targets -- -D warnings` fails (exit 101) on a `clippy::absurd_extreme_comparisons`
   in the **reliability gate's** file `crates/runtime/tests/m2_stream_consistency.rs` (~line 287:
   `big.accrued(u64::MAX) <= u128::MAX`, an always-true assertion). This gate's own additions are
   clippy-clean: `cargo clippy -p ubi2-rpc --all-targets -- -D warnings` → exit 0. The lint is a
   test-quality issue in a GATE-2 file (the test still passes at runtime); it does not touch any M2
   acceptance criterion. Flagged for the owning gate to fix (background task spawned).
3. **`cargo fmt --all --check`** is clean after this gate's additions.

**Verdict: PASS.** Every M2 acceptance criterion (1–8) has at least one passing test; the two
coverage gaps that existed at criterion 6/7 (RPC `ubi_getStreams` in/out split + live accrual, and the
`eth_call` soulbound + collection-metadata path) are now closed with the new integration tests.
