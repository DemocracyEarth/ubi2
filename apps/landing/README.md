# ubi.eth — landing page

A self-contained, **zero-dependency static site** that introduces the UBI blockchain:
Proof of Humanity, Streaming UBI, Prompt Contracts, and how a node works. Built to be
pinned to **IPFS** and served at the ENS name **`ubi.eth`**.

```
apps/landing/
  index.html     # all 10 sections, semantic + accessible
  styles.css     # the obsidian-glass design system (no external fonts)
  app.js         # vanilla JS — canvas motion, live counter, fail-safe scroll reveal
  assets/        # the AI-generated video loops + poster frames (+ .gitkeep)
```

No build step. No CDN, no remote fonts/images, no `fetch()` — it renders fully offline,
which is exactly what IPFS needs.

## View it locally

```bash
cd apps/landing
python3 -m http.server 8080      # then open http://127.0.0.1:8080
# or just: open index.html
```

## Deploy to IPFS → ubi.eth

1. **Pin the folder** to IPFS and get its CID (any of these):
   ```bash
   # Local node
   ipfs add -r apps/landing
   # or a pinning service
   npx @web3-storage/w3cli up apps/landing      # web3.storage
   #  Pinata / Fleek / Filebase also work — upload the apps/landing/ directory
   ```
2. **Point `ubi.eth` at the CID.** In the ENS manager (app.ens.domains) for `ubi.eth`,
   set the **Content Hash** record to `ipfs://<CID>`. Gateways and ENS-aware browsers
   (Brave, or `https://ubi.eth.limo`) then resolve `ubi.eth` to this page.
3. Re-pin + update the Content Hash on each release (IPFS content is immutable per CID).

## Video slots (swap in new clips anytime)

Each `<video data-video-slot="...">` points at a clip in `assets/`. The clips here were
generated with **Higgsfield** (Kling 3.0 Turbo). To replace one, drop a new file in
`assets/` and update that slot's `<source>` (+ `poster`). An empty slot falls back to the
canvas/SVG animation automatically — nothing breaks.

| Slot | File |
|---|---|
| `hero-bg` | `assets/hero-bg.mp4` |
| `pillar-poh` | `assets/poh-pillar.mp4` |
| `pillar-streaming` | `assets/streaming-pillar.mp4` |
| `pillar-contracts` | `assets/contracts-pillar.mp4` |
| `pillar-network` | `assets/network-pillar.mp4` |

## Before you publish

- **"Open the App" link** currently points at `http://localhost:3000` — repoint it to the
  deployed wallet URL (or its own ENS/IPFS address) when there is one.
- **Whitepaper link** is `WHITEPAPER.md` (repo-relative). For IPFS, either copy
  `WHITEPAPER.md` into `apps/landing/` or point the link at the GitHub URL.
- **GitHub link** → confirm the final org/repo path.
