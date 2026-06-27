# Security gate — Proof-of-Humanity soulbound NFT (branch feat/poh-nft-branding @ 2bee8d2)

**Verdict: PASS** — no open High/Critical. PoCs: `crates/rpc/tests/security_poh_gate3.rs` (4, all green;
run live on :38545–:38548). *(Reconstructed by the orchestrator from the gate's structured result — the
gate's own file write did not land.)*

## Boundaries verified intact
- **Soulbound holds.** `transferFrom`, both `safeTransferFrom` overloads, `approve`, and `setApprovalForAll`
  all revert — over `eth_call` (`"soulbound"`) and over a real signed tx (`parse_humanity_calldata` →
  `UnknownSelector` → revert). There is no mint/transfer/delegate write entrypoint: a badge exists purely as a
  function of `ubi_getHuman.status == Verified` and cannot be moved or delegated. PoC: ownership unchanged
  after every attack; the attacker never acquires a badge.
- **View surface is panic-free.** `addr_of_token_id` rejects ids with bits above 160; `ownerOf`/`tokenURI`
  revert cleanly and `balanceOf` returns 0 for zero / max-uint256 / high-bits / Challenged / Revoked / unknown
  ids — no node panic / DoS.
- **No card injection.** The on-chain JSON+SVG card embeds only non-attacker-controlled fields (address hex,
  integers, dates) — nothing user-controlled reaches it, so no SVG/JSON break or script injection on-chain.
- **Ownership/log consistency.** The Transfer mint/burn stream agrees with `ownerOf`/`balanceOf` (token exists
  ⇔ `Verified`); no forged ownership; the `Verified→Challenged→Revoked` path does not double-burn.
- **No regression** in the cycle-5/6 defenses (oracle-admin, contract-text cap, fees).

## Findings (Low; non-blocking; tracked as follow-ups)
| # | Severity | Title |
|---|---|---|
| 1 | Low | **eth_call sim parity:** add the 4-arg `safeTransferFrom` selector (`0xb88d4fde`) to the soulbound-revert match in `poh_nft_call` AND the pre-existing StreamHub `erc721_call`, so `eth_call` simulation fails closed exactly like the real-tx revert path. Cosmetic only today (the real tx already reverts via `UnknownSelector` — not a bypass). → **FU-16**. |
| 2 | Low | **Defense-in-depth XSS:** `apps/wallet/app/humanity.tsx` (and the existing stream card) render the `tokenURI` SVG via `dangerouslySetInnerHTML`, trusting the configured RPC. The node card is clean (hex + integers, no script), but a hostile/compromised RPC could return a `<script>` SVG → XSS in the wallet origin. Render as `<img src=data:image/svg+xml;base64,…>` or run the SVG through DOMPurify (SVG profile). → **FU-17**. |
