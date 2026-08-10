# Deploying proofofhumanity.org

`@ubi2/proofofhumanity` is a **Next.js 15 (App Router) SSR app**, not a static export.
The issuer API routes (`/api/self-verify`, `/api/predicate`, `/api/predicate/demo-credential`)
sign vouchers/attestations with `ISSUER_PRIVATE_KEY` **server-side**, so it must run on a
Node/serverless host (AWS Amplify SSR, Vercel, a container, or `next start`). A pure static
host (S3/CloudFront-only, IPFS/Pinata) can **not** serve the issuer — that only becomes an
option after the trustless v2 (holder-side ZK) removes the server signer.

Contract deployment is a separate release step. Complete the testnet-only
[`contracts/PHASE2.md`](../../contracts/PHASE2.md) gate before configuring any deployed addresses
here. Its deployer uses encrypted Foundry keystores; do not reuse the app's raw server-side issuer
secret for contract deployment.

## Pre-deploy checklist — v0.1.0 (verified 2026-08-09)

- [x] `pnpm --filter @ubi2/proofofhumanity build` — production build passes (9 routes; the 3
      API routes are `ƒ` server-rendered, `/` + icons static).
- [x] `pnpm --filter @ubi2/proofofhumanity typecheck` — clean.
- [x] Social card served: `/og.png` (1200×630, `image/png`); OG + Twitter
      `summary_large_image` tags with absolute URLs.
- [x] Favicon: `/icon.svg` + `/apple-icon.png` auto-wired; `theme-color` set.
- [ ] `ISSUER_PRIVATE_KEY` set to the production signer (its address must equal each chain's
      `ProofOfHumanity.issuer`) — **not** the dev Anvil default.
- [ ] `NEXT_PUBLIC_SELF_ENDPOINT` = the public HTTPS origin (Self rejects `localhost`).
- [ ] `NEXT_PUBLIC_SELF_ENV=production` once testing on real passports.
- [ ] Per-chain `ProofOfHumanity` addresses set for every chain you want mintable.
- [ ] `NEXT_PUBLIC_SITE_URL` = the canonical origin (drives OG absolute URLs).

## Environment variables

Client vars (`NEXT_PUBLIC_*`) are inlined into the browser bundle; server vars are not. Keep
`ISSUER_PRIVATE_KEY` server-only (no `NEXT_PUBLIC_` prefix) — Next strips it from the client.

| Variable | Scope | Required | Default (dev) | Notes |
|---|---|---|---|---|
| `ISSUER_PRIVATE_KEY` | server | **yes** (prod) | Anvil acct #1 (not secret) | Voucher/attestation signer; address must == `ProofOfHumanity.issuer`. Store in Amplify Secrets / SSM. |
| `NEXT_PUBLIC_SITE_URL` | client | recommended | `https://proofofhumanity.org` | Canonical origin for OG/Twitter absolute image URLs. |
| `NEXT_PUBLIC_SELF_ENDPOINT` | client | **yes** (real proofs) | `""` (QR disabled) | Public HTTPS URL of `/api/self-verify` as the Self app sees it. |
| `NEXT_PUBLIC_SELF_ENV` | client | no | `staging` | `staging` (mock passports) or `production` (real). Flips frontend `endpointType` **and** backend `mockPassport` in lockstep. |
| `NEXT_PUBLIC_BASE_RPC_URL` / `NEXT_PUBLIC_BASE_POH` | client | per chain | public RPC / `0x0…0` | Base RPC + deployed `ProofOfHumanity`. Zero address ⇒ chain shown but mint disabled. |
| `NEXT_PUBLIC_OP_RPC_URL` / `NEXT_PUBLIC_OP_POH` | client | per chain | public RPC / `0x0…0` | Optimism. |
| `NEXT_PUBLIC_CELO_RPC_URL` / `NEXT_PUBLIC_CELO_POH` | client | per chain | public RPC / `0x0…0` | Celo. |
| `NEXT_PUBLIC_LOCAL_CHAIN_ID` / `_NAME` / `_RPC_URL` / `_POH` | client | dev only | Anvil 31337 | Local mint target; drop or leave zero-addressed in prod. |

## Recommended: AWS Amplify Hosting (SSR, git-connected)

1. **Amplify → New app → Host web app** → connect the GitHub repo/branch.
2. Monorepo: set the **app root** to `apps/proofofhumanity`. Amplify detects Next.js SSR
   (the `WEB_COMPUTE` platform). Build spec (auto, or `amplify.yml`):
   ```yaml
   version: 1
   applications:
     - appRoot: apps/proofofhumanity
       frontend:
         phases:
           preBuild:
             commands:
               - corepack enable
               - pnpm install --frozen-lockfile
           build:
             commands:
               - pnpm --filter @ubi2/proofofhumanity build
         artifacts:
           baseDirectory: .next
           files: ['**/*']
         cache:
           paths: ['node_modules/**/*', '.next/cache/**/*']
   ```
3. **Environment variables**: add the table above. Put `ISSUER_PRIVATE_KEY` in **Secrets
   Manager / SSM** and reference it — do not paste the raw key into plaintext env.
4. Point `proofofhumanity.org` at the Amplify domain (Route 53 / custom domain).

## Alternatives

- **Any Node host / container**: `pnpm --filter @ubi2/proofofhumanity build` then
  `pnpm --filter @ubi2/proofofhumanity start` behind TLS. Set the same env vars.
- **Vercel**: import the repo, set root to `apps/proofofhumanity`, add env vars. Zero-config
  Next SSR + edge; OG image is a static asset (no runtime generation to configure).

## Post-deploy verification

- `curl -I https://<origin>/og.png` → `200 image/png`.
- Paste the URL into the Twitter/X card validator and Facebook sharing debugger; confirm the
  1200×630 card renders. WhatsApp/iMessage read the same OG tags.
- Load the site: favicon shows in the tab; the mint flow reaches "prove humanity with Self".
- Verify `ISSUER_PRIVATE_KEY`'s address matches `ProofOfHumanity.issuer()` on each live chain.

## Security

- The issuer key is the mint's trust anchor for v1 — treat it as a signing HSM/secret, rotate
  via `setIssuer(...)` on-chain if exposed. Never ship it with a `NEXT_PUBLIC_` prefix.
- Rate-limit `/api/self-verify` and `/api/predicate` per nullifier in production (the dev
  in-process store is not durable) — see the route handlers' TODOs.
