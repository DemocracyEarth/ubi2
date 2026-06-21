# ADR-0003 — Streaming: collateralized streams, a StreamHub precompile, and stream NFTs

- **Status:** accepted (M2)
- **Date:** 2026-06-21
- **Deciders:** architect + protocol-engineer (cycle 2), with product (Santiago) on the NFT model

## Context
M2 adds account-to-account real-time streams. Three decisions were load-bearing and costly to reverse,
so they are recorded here. Full design in [`../02-streaming.md`](../02-streaming.md).

## Decisions

### 1. Streams are collateralized (solvent by construction)
Opening a stream locks a `deposit`; the recipient accrues `rate × elapsed` **capped at `deposit`**, and the
stream auto-completes at `t_end = started_at + deposit/rate`. **Rejected:** uncollateralized streams that
draw from the sender's live balance — they require predicting future insolvency (interacting with UBI
inflow and other streams) and open over-draw/grief attacks. The cap makes a stream unable to ever pay out
more than was locked, so there is no insolvency path. Uncollateralized "stream-through" of live UBI inflow
is a deferred enhancement.

### 2. Stream operations are EVM transactions to a system address ("StreamHub" `0x…5742`)
An op is a normal EIP-155 tx to StreamHub with ABI calldata (`openStream`/`stopStream`); reads are custom
`ubi_*` methods. **Rejected:** bespoke `ubi_openStream` write RPCs — standard wallets (MetaMask) can't
sign those. By making ops ordinary signed txs, MetaMask signs them unchanged. No general EVM is
introduced; the node decodes a small fixed selector set ("precompile" pattern). M1's "reject calldata"
rule is relaxed for StreamHub only.

### 3. Each stream mints two soulbound ERC-721 NFTs (recipient + sender), with a fully on-chain SVG card
Both parties see the stream in any standard wallet. `tokenId = streamId` → recipient; `streamId | (1<<255)`
→ sender (the flag is decoded statelessly in `ownerOf`/`tokenURI`). StreamHub doubles as the ERC-721
collection and answers the view methods as a precompile inside `eth_call`; `tokenURI` returns a fully
on-chain `data:` URI (base64 JSON + inline SVG card). **Rejected:** off-chain metadata (IPFS/HTTP) — keeps
everything self-contained and verifiable. **M2 scope:** tokens are soulbound; **transferable streams**
(where the flow follows the NFT owner — a tradeable income stream) are a deliberate deferral, noted for a
later milestone.

## Consequences
- Streams are safe (solvent), wallet-native (signable + visible), and self-describing (on-chain card).
- The "StreamHub precompile" sets the pattern for future system contracts (e.g. governance in M5) without a
  general EVM. M4 prompt-contracts will revisit whether a general execution layer is warranted.
- Rate precision: `rate` is integer base-units/sec, so a "1 UBI/hr" stream actually flows at
  `floor(1e18/3600)/sec` ≈ 0.99999…/hr — the same bounded truncation as [ADR-0002](0002-emission-rounding-policy.md).
  The card currently *truncates* this in its 2-dp display; a display-rounding/`rate`-granularity revisit is a
  tracked follow-up (board).
