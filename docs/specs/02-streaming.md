# 02 — Milestone 2: Streaming primitive (account-to-account)

**Status:** spec (architect, cycle 2).
**Goal:** an account can open a **continuous, real-time stream** of UBI to another account at a chosen
rate; the recipient's balance drips upward and the sender's locked deposit drips downward **live** (read
at wall-clock `now`, exactly like the protocol's 1-UBI/hour emission). Streams can be stopped early.
This extends the UBI drip from protocol→human into human→human — the "constantly rewarding" flow.

This builds directly on M1's deterministic, time-based balance model and its EIP-155 transaction path.

## Design decisions (the load-bearing ones)

### D1 — Streams are COLLATERALIZED (solvent by construction)
Opening a stream **locks a `deposit`** from the sender's spendable balance into the stream. The recipient
accrues `rate × elapsed`, **capped at `deposit`**. The stream auto-completes when the deposit is drained
at `t_end = started_at + deposit / rate`. This makes streams *solvent by construction* — a stream can
never pay out more than was locked, so there is no insolvency/over-draw attack and no need to predict the
sender's future balance. (Uncollateralized "stream-through" of live UBI inflow is a deferred follow-up.)

### D2 — Stream operations are EVM transactions to a system "StreamHub" address
To keep standard wallets (MetaMask) able to **sign** stream operations, an op is a normal EIP-155 tx sent
to the reserved system address **`0x0000000000000000000000000000000000005742`** ("StreamHub") with ABI-
encoded calldata. The node recognizes this address and parses the calldata; M1's "reject non-empty
calldata" rule is relaxed **only** for txs to StreamHub. No general EVM is introduced — the node decodes a
small fixed set of 4-byte selectors. `value` on these txs is 0 (the deposit is an argument, not msg.value,
so wallets needn't fund gas-vs-value confusion; see open question Q1).

Selectors (Solidity-style, so wallets/tooling can encode them):
- `openStream(address to, uint256 ratePerSec, uint256 deposit)` → selector `keccak("openStream(address,uint256,uint256)")[..4]`
- `stopStream(uint256 id)` → selector of `stopStream(uint256)`

The node assigns a sequential `id` and emits it (see RPC). Reads use custom `ubi_*` methods (below); balances
reflect streams through the standard `eth_getBalance`.

### D3 — Balances stay pure functions of (state, now) — invariant I2 holds
The live balance gains net stream flow, all integer math:
```
balance(a, now) = settled_balance(a)
                + emission_since_settle(a, now)                    # 1 UBI/hr if verified (M1)
                + Σ accrued(s, now)  for s in incoming_active(a)   # streams paying a
                                                                   # (sender's deposit already removed at open)
accrued(s, now) = min( s.rate * (min(now, s.end_or_stop) - s.started_at), s.deposit_remaining )
```
Two nodes computing `balance(a, now)` agree to the base unit. No floats.

### D4 — Each stream mints TWO ERC-721 NFTs — both wallet-visible (fully on-chain SVG)
Opening a stream mints **two** ERC-721 tokens so **both parties** see it in a standard wallet:
- the **recipient token** → `tokenId = streamId`, owner = `to` (the canonical "incoming stream" claim);
- the **sender receipt** → `tokenId = streamId | SENDER_FLAG` (top bit, `1 << 255`), owner = `from`.

This keeps ownership **stateless and deterministic** — `ownerOf(tokenId)` decodes the flag: high bit set
→ sender token of stream `tokenId & ~SENDER_FLAG`, owner `from`; else recipient token, owner `to`.
`balanceOf(addr)` = (# streams where `addr` is `to`) + (# where `addr` is `from`). `StreamHub`
(`0x…5742`) doubles as the ERC-721 collection **"ubi2 Streams" (USTREAM)**. The node answers the ERC-721
`view` methods as a **precompile inside `eth_call`** on StreamHub (M1's `eth_call → 0x` relaxed there
only): `supportsInterface`, `name`, `symbol`, `balanceOf(owner)`, `ownerOf(tokenId)`, `tokenURI(tokenId)`.
`tokenURI` returns a fully on-chain `data:application/json;base64,…` document whose `image` is an inline
`data:image/svg+xml;…` card (see "Streams as NFTs" below). Open emits two mints:
`Transfer(0x0, to, streamId)` and `Transfer(0x0, from, streamId|SENDER_FLAG)`. **Both tokens are soulbound
in M2** (transfer reverts); transferable streams where the *flow follows the NFT owner* are deferred.

## Data model (`crates/runtime`)
```
StreamId = u64                       // sequential, assigned at open
Stream {
  id: StreamId,
  from: Address,
  to: Address,
  rate: u128,            // base units per second
  deposit: u128,         // total locked at open
  drawn: u128,           // amount already settled to `to` (folded into to.settled_balance)
  started_at: u64,       // unix secs
  status: Active | Stopped(at: u64) | Completed,
}
```
State additions: a `streams: Map<StreamId, Stream>` registry + per-account indexes `outgoing: [StreamId]`,
`incoming: [StreamId]`, and a `next_stream_id` counter. `Account` keeps M1 fields.

## Operations (deterministic state transitions)

### openStream(from, to, rate, deposit) at `now`
1. Validate: `from != to`, `rate > 0`, `deposit > 0`, `deposit % rate == 0` recommended (clean `t_end`;
   else last tick is partial — allowed, capped by deposit), and `rate ≤ MAX_RATE` (anti-grief bound).
2. `settle(from, now)`; require `from.settled_balance ≥ deposit`; subtract `deposit` from
   `from.settled_balance` (lock it).
3. Create `Stream{ id: next_stream_id++, ..., drawn: 0, started_at: now, status: Active }`; index it.
4. Fail-closed: any error leaves state untouched (no partial writes).

### settle_stream(s, now) — internal, called on reads-that-commit and on stop/complete
- `owed = min(s.rate * (min(now, end_or_stop(s)) - s.started_at), s.deposit) - s.drawn`
- `settle(to, now)`; `to.settled_balance += owed`; `s.drawn += owed`.
- If `s.drawn == s.deposit` → `status = Completed`.

### stopStream(id, caller) at `now`
- Only `from` (or `to`?) may stop — **M2: only `from` may cancel; either party may let it run.** (Q2)
- `settle_stream(s, now)` to pay accrued; set `status = Stopped(now)`; **refund** `s.deposit - s.drawn`
  to `from.settled_balance` (after `settle(from, now)`).

### Auto-completion
A stream needs no tx to complete: once `now ≥ t_end`, `accrued` is capped at `deposit`, so reads already
show the final value. A lazy `settle_stream` on the next interaction (or block tick sweep) folds it in and
marks `Completed` + (no refund; fully drawn).

## RPC surface (`crates/rpc`)
- **Write** (via `eth_sendRawTransaction` to StreamHub, signed by the wallet): `openStream`, `stopStream`
  parsed from calldata. The tx receipt's logs include the assigned `id` (emit a `StreamOpened`/`StreamStopped`
  log so `eth_getTransactionReceipt` carries it; standard EVM log shape).
- **Read** (custom, for our SDK/wallet — third-party wallets only need balances):
  - `ubi_getStreams(address)` → `{ outgoing: [StreamView], incoming: [StreamView] }`
  - `ubi_getStream(id)` → `StreamView`
  - `StreamView` includes `id, from, to, rate, deposit, drawn, started_at, status, accrued_now, t_end`.
- `eth_getBalance` continues to reflect everything live (now including net streams).
- **ERC-721 view precompile in `eth_call`** (StreamHub only): decode the selector and return ABI-encoded
  results for `supportsInterface(bytes4)` (true for `0x01ffc9a7` ERC165 + `0x80ac58cd` ERC721 +
  `0x5b5e139f` ERC721Metadata), `name()`→"ubi2 Streams", `symbol()`→"USTREAM", `balanceOf(address)`
  (count of streams owned), `ownerOf(uint256)` (stream recipient; revert for unknown/none), and
  `tokenURI(uint256)` (the data-URI document below). These let MetaMask "Import NFT" (StreamHub + id) and
  render the card.

## Streams as NFTs (ERC-721) — the wallet-visible card

**Why:** a stream becomes a first-class object the user can see and inspect in any standard wallet, with
its live conditions rendered on the token itself. No external metadata host — everything is on-chain.

### `tokenURI(id)` → metadata document
`data:application/json;base64,<base64( json )>` where `json` is:
```jsonc
{
  "name": "ubi2 Stream #<id>",
  "description": "A real-time UBI stream from <from> to <to> at <rate> UBI/hr. Fully on-chain on ubi2.",
  "image": "data:image/svg+xml;base64,<base64( svg )>",
  "attributes": [
    { "trait_type": "Status",   "value": "Active|Stopped|Completed" },
    { "trait_type": "From",      "value": "0x…" },
    { "trait_type": "To",        "value": "0x…" },
    { "trait_type": "Rate",      "value": "1.00 UBI/hr" },
    { "trait_type": "Deposit",   "value": "24.00 UBI" },
    { "trait_type": "Streamed",  "value": "6.50 UBI" },
    { "display_type": "boost_percentage", "trait_type": "Progress", "value": 27 },
    { "display_type": "date", "trait_type": "Started", "value": <unix> },
    { "display_type": "date", "trait_type": "Ends",    "value": <unix> }
  ]
}
```
`attributes` give marketplaces/wallets structured traits; the `image` is the human-readable card.

### The SVG card (generated in Rust by string-templating; self-contained)
A 500×500 card using the ubi2 palette (bg `#0b0b0f`, panel `#14141b`, accent `#6ee7b7`, muted `#9a9aa6`),
system/monospace fonts only (no external fonts/images so it renders anywhere). Layout, top → bottom:
1. **Header** — "ubi2" wordmark (accent "2") + "STREAM" label; right-aligned **status pill** (green
   Active / amber Stopped / muted Completed) and `#<id>`.
2. **Flow row** — `from` (0xAB…12) → `to` (0xF3…66), truncated, with an arrow / drip-dots between them.
3. **Headline** — large mono **"<streamed> UBI"** streamed so far, sub-line "of <deposit> UBI".
4. **Progress bar** — filled to `drawn/deposit` (%), accent fill on a muted track.
5. **Stats row** — **Rate** "1.00 UBI / hr" · **Started** · **Ends** (or "ran dry"/"stopped").
6. **Footer** — "real-time stream · chain 21826".
Optional: a subtle SMIL `<animate>` drip accent that degrades gracefully where animation isn't rendered.
The template is a pure function of the stream's fields + the read-time `now` (so "streamed/progress"
reflect the moment `tokenURI` is called). Keep the SVG small and escaped/valid. The card takes a
**`side` param** (incoming vs outgoing, derived from the SENDER_FLAG): same data, with a small
"Incoming"/"Outgoing" badge and the viewer's own address emphasized — so each party's token reads naturally.

### Minting / ownership
- `open_stream` mints **two** tokens: `streamId` → `to`, and `streamId | SENDER_FLAG` → `from`; emit a
  `Transfer(0x0, owner, tokenId)` for each.
- `ownerOf(tokenId)` decodes the flag (sender token → `from`, recipient token → `to`); `balanceOf` counts
  both sides; `tokenURI` renders the card with the matching `side` badge.
- Soulbound in M2: no `transferFrom`/`approve` state; if called, the call/tx reverts with "soulbound".
- `stop`/`complete` do **not** burn either token (they stay as a record); the status on both cards flips.

## Wallet / SDK (`apps/wallet`, `packages/sdk`)
- **SDK:** `openStream({to, ratePerSec, deposit})` and `stopStream(id)` that build + send the StreamHub tx
  (encode selector + args; sign with the user's key/provider); `getStreams(address)`; reuse `projectBalance`
  so streamed balances also tick per-frame.
- **Wallet:** a "Send a stream" form (recipient, rate e.g. UBI/hour, and deposit or duration → deposit),
  plus **Active streams** lists (Outgoing / Incoming) with live-ticking accrued amounts and a Stop button on
  outgoing. The connected account's headline balance already reflects incoming streams.
- **NFT surfacing:** render the same on-chain card (fetch `tokenURI`, show the SVG) next to each stream,
  and an **"Add NFT to MetaMask"** helper (`wallet_watchAsset` with `type: ERC721`, StreamHub address + id)
  so the user one-clicks the stream into their standard wallet.

## Safety (whitepaper §4.3 — what's in M2 vs deferred)
- **Collateralization limit:** inherent (D1) — a stream can't exceed its deposit. ✅ M2
- **Rate control:** `MAX_RATE` bound + `rate > 0`. ✅ M2 (basic)
- **Circuit breakers / multi-sig / conditional streams:** deferred to a later milestone.

## Acceptance criteria (map 1:1 to tests)
1. Opening a stream locks the sender's deposit (sender spendable drops by `deposit` immediately) and is
   signable/sendable as an EVM tx to StreamHub by a standard signer.
2. The recipient's `eth_getBalance` **increases at `rate`** in real time while the stream is active, and the
   sender's spendable balance does not double-count the locked deposit.
3. A stream pays out **at most `deposit`** — after `t_end`, the recipient's accrued from the stream stops at
   exactly `deposit` (solvency; no over-draw).
4. `stopStream` by the sender pays the recipient the accrued-to-stop amount and **refunds the unused deposit**
   to the sender; totals are conserved (no UBI created or lost), to the base unit.
5. **Reproducibility (I2):** stream balances are identical across two nodes and across random timelines
   (property test over `(rate, deposit, started_at, now, stop?)`).
6. `ubi_getStreams` returns correct in/out streams with live `accrued_now`; the wallet shows a stream
   dripping and lets the sender stop it.
7. **NFT (both sides):** opening a stream mints two ERC-721s — `streamId`→recipient and
   `streamId|SENDER_FLAG`→sender (both `Transfer(0x0,…)` in the receipt); `supportsInterface(0x80ac58cd)`→
   true; `ownerOf(streamId)`→recipient and `ownerOf(streamId|SENDER_FLAG)`→sender; `balanceOf` counts the
   right side for each party; transfer attempts revert ("soulbound").
8. **On-chain card:** `tokenURI(id)` returns a valid `data:application/json;base64` doc whose decoded
   JSON has `name`, `attributes`, and an `image` `data:image/svg+xml` that parses as valid SVG and shows
   the live streamed amount + progress + status (verified by decoding in a test). MetaMask "Import NFT"
   (StreamHub + id) renders it.

## Open questions (resolve in M2-T1 finalization)
- **Q1:** deposit as a calldata arg vs. `msg.value`. *Decision:* **calldata arg** (D2) — keeps gas/value
  semantics simple on devnet where gas isn't charged; the node debits `deposit` from the sender on open.
- **Q2:** may the recipient also cancel? *Decision (M2):* **no — only the sender cancels;** either party may
  let it run to completion. Revisit with conditional streams.
- **Q3:** `StreamId` as `u64` vs `H256`. *Decision:* **`u64`** sequential — simpler, fits logs as a topic.

## Deferred to later cycles
1:many / many:1 fan-out, uncollateralized stream-through of live UBI inflow, conditional/programmable
streams, circuit breakers, stream composition (split/merge). Multi-node consensus arrives with M3.
