# PoH NFT card — codegen & design source

- **poh-card.mjs** — the canonical PoH NFT card design (`renderCard(traits)` → SVG). The two
  on-chain renderers, `contracts/src/PoHCardRenderer.sol` and `crates/rpc/src/poh_nft.rs::render_svg`,
  are hand-ports of this file and are byte-verified against it. Change the design here first, then
  mirror into both renderers.
- **gen-countries.mjs** — regenerates the ISO 3166-1 alpha-3 → (flag, short name) tables
  `contracts/src/Countries.sol` and `crates/rpc/src/poh_countries.rs` from the canonical ISO source.
  Run: `npm i i18n-iso-countries && node scripts/gen-countries.mjs <repo-root>`
