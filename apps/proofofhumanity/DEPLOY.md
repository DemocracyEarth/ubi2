# Deploying proofofhumanity.org

`@ubi2/proofofhumanity` is a **Next.js 15 (App Router) SSR app**, not a static export.
The issuer API routes (`/api/self-verify`, `/api/predicate`)
sign vouchers/attestations with `ISSUER_PRIVATE_KEY` **server-side**, so it must run on a
Node host (a container or `next start`). A pure static
host (S3/CloudFront-only, IPFS/Pinata) can **not** serve the issuer — that only becomes an
option after a holder-side ZK prover removes the v1 server signer.

The current Self callback handoff is an intentionally bounded, 10-minute, process-local store. A
first production release therefore runs **one sticky Node replica**. Do not deploy this version to
autoscaling/serverless multi-instance infrastructure: a phone callback and the browser poll may hit
different workers. Before horizontal scaling, select and review a shared encrypted store; derived
claims are sensitive data even though raw passport proofs are never stored.

Contract deployment is a separate release step. Complete the testnet-only
[`contracts/PHASE2.md`](../../contracts/PHASE2.md) gate before configuring any deployed addresses
here. Its deployer uses encrypted Foundry keystores; do not reuse the app's raw server-side issuer
secret for contract deployment.

The app ships verified contract pairs for all five Phase 2 targets—Base Sepolia, Ethereum Sepolia,
Celo Sepolia, World Chain Sepolia, and Robinhood Chain Testnet—as public defaults. They can be
overridden with `NEXT_PUBLIC_*` variables, but the server still fails closed unless its issuer
signer matches both live `issuer()` getters. Every mainnet remains zero-addressed and visibly
unavailable. See the public
[`contracts/DEPLOYMENTS.md`](../../contracts/DEPLOYMENTS.md) registry for addresses and transactions.

## Pre-deploy checklist — first mainnet release

- [ ] `pnpm --filter @ubi2/proofofhumanity typecheck`, `test:contracts`, and `build` pass on the release commit.
- [ ] `contracts/scripts/phase2-all.sh e2e` is green on Ethereum Sepolia, Base Sepolia, Celo Sepolia,
      World Chain Sepolia, and Robinhood Chain Testnet with verified source and a live mint.
- [ ] `ISSUER_PRIVATE_KEY` set to the production signer (its address must equal each chain's
      `ProofOfHumanity.issuer()` and `PredicateVerifier.issuer()`) — **not** the deployer or dev key.
- [ ] Contract owner is the intended production multisig on every chain; deployer, owner, and issuer
      roles have been recorded and checked independently.
- [ ] `NEXT_PUBLIC_SELF_ENDPOINT` = the public HTTPS origin (Self rejects `localhost`).
- [ ] `NEXT_PUBLIC_SELF_ENV=production` once testing on real passports.
- [ ] Paired `ProofOfHumanity` + `PredicateVerifier` addresses set for each enabled chain.
- [ ] One sticky Node replica, TLS, trusted proxy headers, restart monitoring, log redaction, and
      secrets injection are configured. Horizontal scaling is blocked until the shared-store design is approved.
- [ ] `NEXT_PUBLIC_SITE_URL` = the canonical origin (drives OG absolute URLs).
- [ ] Explicit human approval is recorded immediately before each individual mainnet broadcast.

## Environment variables

Client vars (`NEXT_PUBLIC_*`) are inlined into the browser bundle; server vars are not. Keep
`ISSUER_PRIVATE_KEY` server-only (no `NEXT_PUBLIC_` prefix) — Next strips it from the client.

| Variable | Scope | Required | Default (dev) | Notes |
|---|---|---|---|---|
| `ISSUER_PRIVATE_KEY` | server | **yes** (prod) | Anvil acct #1 (not secret) | Voucher/attestation signer; address must equal both contract issuers. Inject from a secret manager; never paste into chat or commit it. |
| `NEXT_PUBLIC_SITE_URL` | client | recommended | `https://proofofhumanity.org` | Canonical origin for OG/Twitter absolute image URLs. |
| `NEXT_PUBLIC_SELF_ENDPOINT` | client | **yes** (real proofs) | `""` (QR disabled) | Public HTTPS URL of `/api/self-verify` as the Self app sees it. |
| `NEXT_PUBLIC_SELF_ENV` | client | no | `staging` | `staging` (mock passports) or `production` (real). Flips frontend `endpointType` **and** backend `mockPassport` in lockstep. |
| `NEXT_PUBLIC_<NETWORK>_RPC_URL` | client | per chain | public endpoint | Use a production provider with capacity and monitoring. These URLs are public by design. |
| `NEXT_PUBLIC_<NETWORK>_POH` | client | per chain | `0x0…0` | Deployed `ProofOfHumanity`. Zero address disables mint and predicate issuance. |
| `NEXT_PUBLIC_<NETWORK>_PREDICATE` | client | per chain | `0x0…0` | Paired `PredicateVerifier`. Both addresses are required for predicates. |
| `NEXT_PUBLIC_LOCAL_CHAIN_ID` / `_NAME` / `_RPC_URL` / `_POH` / `_PREDICATE` | client | dev only | Anvil 31337 | Local target; leave zero-addressed in production. |

Supported prefixes are `ETHEREUM`, `BASE`, `CELO`, `WORLD`, `ROBINHOOD`, and `OP`, plus their
testnet forms shown in [`.env.example`](.env.example).

The checked-in nonzero testnet defaults are release registry entries, not secrets. Missing or empty
environment values keep those defaults; set the zero address to deliberately disable one of those
testnet targets in a deployment. A malformed address also fails closed to zero.

## Recommended first-release topology: one Node container

1. Build from the pinned lockfile: `corepack enable && pnpm install --frozen-lockfile`, then
   `pnpm --filter @ubi2/proofofhumanity build`.
2. Run `pnpm --filter @ubi2/proofofhumanity start` as a single Node process behind TLS.
3. Inject `ISSUER_PRIVATE_KEY` from the host secret manager. Never put it in a build argument,
   image layer, `NEXT_PUBLIC_*`, `.env` committed to git, or deployment logs.
4. Terminate untrusted direct traffic at a proxy that overwrites `X-Forwarded-For`; the route uses
   that value for callback rate limiting.
5. Health-check `/`, `/verify`, and `/developers`; alert on restarts and 5xx responses from both API routes.

Serverless and multi-replica targets become valid only after the callback handoff is moved to a
reviewed shared encrypted store. That is an application release gate, not a contract blocker.

## Post-deploy verification

- `curl -I https://<origin>/og.png` → `200 image/png`.
- Paste the URL into the Twitter/X card validator and Facebook sharing debugger; confirm the
  1200×630 card renders. WhatsApp/iMessage read the same OG tags.
- Load the site: favicon shows in the tab; the mint flow reaches "prove humanity with Self".
- Complete one real Self verification with each disclosure profile and confirm the browser session
  can produce age 18+, age 21+, nationality, and sanctions-clear attestations.
- Call `PredicateVerifier.check(...)` with the returned artifact and confirm consumer, context,
  subject, wrong-chain, wrong-verifier, stale, and wrong-signer failures all fail closed.
- Verify the signing address matches both `issuer()` getters on every live chain.

## Security

- The issuer key is the mint's trust anchor for v1 — treat it as a signing HSM/secret, rotate
  via `setIssuer(...)` on-chain if exposed. Never ship it with a `NEXT_PUBLIC_` prefix.
- The routes use bounded, process-local rate limits and a 10-minute callback handoff. They limit
  abuse on a single replica but are not distributed controls. Put edge rate limits at the trusted
  proxy and require a shared, reviewed limiter before horizontal scaling.
- v1 predicates are issuer-attested. The holder-side ZK prover is not implemented or deployed;
  `PredicateVerifier.prover()` must remain visibly zero until that separate release is audited.
- The currently recorded Phase 2 PredicateVerifier addresses predate the v2 consumer-forwarding and
  wallet-independent replay correction. They remain valid for v1 only and must not be configured with a prover;
  the v2 rehearsal requires a new versioned testnet host/registry/adapter/verifier stack.
