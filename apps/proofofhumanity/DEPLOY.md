# Deploying proofofhumanity.org

`@ubi2/proofofhumanity` is a **Next.js 15 (App Router) SSR app**, not a static export.
The issuer API routes (`/api/self-verify`, `/api/predicate`)
sign vouchers/attestations with `ISSUER_PRIVATE_KEY` **server-side**, so it must run on a
Node host (a container or `next start`). A pure static
host (S3/CloudFront-only, IPFS/Pinata) can **not** serve the issuer — that only becomes an
option after a holder-side ZK prover removes the v1 server signer.

The optional v2 Self issuance path uses a separate `ZK_SELF_ISSUANCE_AUTHORITY_PRIVATE_KEY`.
It authenticates a short-lived, proof-bound authorization for an immutable bridge; it is not the
deployer, v1 voucher issuer, private-credential issuer key, or registry owner. The raw Self
nullifier is transformed in memory into a registry-scoped duplicate key and is never returned in
the v2 response, logged, stored, or sent on-chain. This remains a transitional off-chain Self trust
boundary until the exact production passport proof can be verified on-chain.

The optional `/api/sponsored-mint` path is **testnet-only** and uses a third, isolated
`POH_SPONSOR_PRIVATE_KEY`. It pays gas but has no credential authority: recipient, nullifier,
epoch, contract and issuer signature are loaded from the short-lived address/session record created
by the verified Self callback. The request accepts only a chain id and no body. A configured public
testnet allowlist, live RPC chain/bytecode/issuer checks, separate-role checks, gas/fee/reserve caps,
per-source/account/capability limits, one in-flight transaction per chain, and a three-attempt ceiling
all fail closed before spending. Mainnet and local chain classifications are rejected even if an
operator puts their ids in the allowlist.

After submission the API returns either pending transaction evidence or a confirmed, versioned
receipt containing the chain, contract, proof-bound recipient, token id, transaction/block hashes,
and the matching `HumanityMinted`/`HumanityRefreshed` event. The server verifies those fields plus
`ownerOf`, `tokenOfNullifier`, `isValid`, and `locked` at the receipt block. The browser re-reads the
same ownership and soulbound state. Neither response contains the sponsor private key.

The current Self callback handoff is an intentionally bounded, 10-minute, process-local store. A
first production release therefore runs **one sticky Node replica**. Do not deploy this version to
autoscaling/serverless multi-instance infrastructure: a phone callback and the browser poll may hit
different workers. Before horizontal scaling, select and review a shared encrypted store; derived
claims are sensitive data even though raw passport proofs are never stored.
The same process-local record backs the v2 refresh endpoint. A `PATCH` may replace a stale
slot/epoch/deadline authorization but preserves the original record expiry; it cannot make a verified
grant live longer than ten minutes. The address plus 128-bit session header is a bearer capability.

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
- [ ] If v2 issuance is enabled, all six `ZK_SELF_ISSUANCE_*` values are set; the RPC chain,
      registry domain, active issuer key, bridge codehash/configuration, and isolated authority key
      are checked live by the callback before every signature.
- [ ] If testnet sponsorship is enabled, `POH_SPONSOR_PRIVATE_KEY` is a separately generated,
      low-balance hot account; `POH_SPONSOR_TESTNET_CHAIN_IDS` names only the intended public testnets;
      gas/fee/reserve caps and faucet budget alerts are configured. Never enable it for mainnet.
- [ ] Paired `ProofOfHumanity` + `PredicateVerifier` addresses set for each enabled chain.
- [ ] One sticky Node replica, TLS, trusted proxy headers, restart monitoring, log redaction, and
      secrets injection are configured. Horizontal scaling is blocked until the shared-store design is approved.
- [ ] `NEXT_PUBLIC_SITE_URL` = the canonical origin (drives OG absolute URLs).
- [ ] Explicit human approval is recorded immediately before each individual mainnet broadcast.

## Environment variables

Client vars (`NEXT_PUBLIC_*`) are inlined into the browser bundle; server vars are not. Keep
`ISSUER_PRIVATE_KEY`, `POH_SPONSOR_PRIVATE_KEY`, and the v2 authority server-only (no
`NEXT_PUBLIC_` prefix) — Next strips them from the client.

| Variable | Scope | Required | Default (dev) | Notes |
|---|---|---|---|---|
| `ISSUER_PRIVATE_KEY` | server | **yes** (prod) | Anvil acct #1 (not secret) | Voucher/attestation signer; address must equal both contract issuers. Inject from a secret manager; never paste into chat or commit it. |
| `POH_SPONSOR_PRIVATE_KEY` | server secret | optional testnet only | disabled | Isolated low-balance transaction signer. Must not be issuer, deployer, owner, or holder. No development fallback and never `NEXT_PUBLIC_`. |
| `POH_SPONSOR_TESTNET_CHAIN_IDS` | server | with sponsor key | disabled | Explicit comma-separated allowlist. Every id must resolve to a configured, deployed `network: "testnet"`; mainnet/local fail closed. |
| `POH_SPONSOR_MAX_GAS` | server | no | `350000` | Refuse an estimate above this per transaction. |
| `POH_SPONSOR_MAX_FEE_WEI` | server | no | `5000000000000000` | Refuse when estimated gas × current gas price exceeds this amount. |
| `POH_SPONSOR_MIN_RESERVE_WEI` | server | no | `1000000000000000` | Balance that must remain after the estimated fee. |
| `POH_SPONSOR_CONFIRMATIONS` | server | no | `1` | Required receipt confirmations, bounded to 1–12. |
| `POH_SPONSOR_RECEIPT_TIMEOUT_MS` | server | no | `90000` | Initial wait, bounded to 5–300 seconds. A timeout returns recoverable pending evidence rather than resubmitting. |
| `POH_SPONSOR_DAILY_TX_LIMIT` | server | no | `100` | Conservative process-local transaction-attempt ceiling per chain and UTC-aligned 24-hour window; put a matching distributed limit at ingress. |
| `ZK_SELF_ISSUANCE_CHAIN_ID` | server | v2 only | disabled | One canonical issuance chain. All six v2 variables must be present together. |
| `ZK_SELF_ISSUANCE_RPC_URL` | server | v2 only | disabled | Server RPC used to read one pinned block before authorizing a slot/epoch. |
| `ZK_SELF_ISSUANCE_REGISTRY` | server | v2 only | disabled | `ZkIdentityIssuanceRegistry` address. |
| `ZK_SELF_ISSUANCE_BRIDGE` | server | v2 only | disabled | Immutable `ZkIdentitySelfIssuanceBridge` authorized by the registry. |
| `ZK_SELF_ISSUER_KEY_ID` | server | v2 only | disabled | Active bytes32 issuer-key namespace; not a private key. |
| `ZK_SELF_ISSUANCE_AUTHORITY_PRIVATE_KEY` | server secret | v2 only | disabled | Separate EIP-712 Self-verification authority. Never reuse the deployer or v1 issuer. |
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
4. Terminate untrusted direct traffic at a proxy that overwrites `X-Forwarded-For`; the routes use
   that value for callback, v2-refresh, predicate, and sponsorship rate limiting.
5. Add edge quotas and a daily faucet-spend alarm for `/api/sponsored-mint`. Process-local quotas are
   defense in depth for the required single replica, not a substitute for ingress controls.
6. Health-check `/`, `/verify`, and `/developers`; alert on restarts and 5xx responses from the API routes.

The checked-in Base Sepolia staging profile, trusted-proxy example, spend/reserve monitor, and
secret-safe live rehearsal procedure are in
[`ops/proofofhumanity/SPONSORED_MINT_STAGING.md`](../../ops/proofofhumanity/SPONSORED_MINT_STAGING.md).

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
- If v2 is enabled, deliberately consume the observed next slot with a competing test issuance,
  confirm the stale authorization fails without consuming its key/commitment, PATCH with the original
  address/session, and confirm the refreshed authorization succeeds before the original ten-minute expiry.
- If sponsorship is enabled, mint once per allowlisted testnet from an unfunded dedicated credential
  account. Verify the transaction sender is the isolated sponsor, the token owner is the proof-bound
  account, the UI receipt links to the confirmed transaction, and a repeated POST returns the same
  evidence without a second transaction. Confirm a mainnet id, mismatched session, and body all fail.

## Security

- The issuer key is the mint's trust anchor for v1 — treat it as a signing HSM/secret, rotate
  via `setIssuer(...)` on-chain if exposed. Never ship it with a `NEXT_PUBLIC_` prefix.
- The v2 Self authority is a temporary issuance trust root. Its immutable bridge cannot rotate in
  place: deploy and governance-authorize a new bridge, retire the old authority, then update the
  server configuration. A production HSM adapter and independently reviewed proof service remain
  release gates; the current server variable is suitable for isolated testnet rehearsal.
- The routes use bounded, process-local rate limits and a 10-minute callback handoff. They limit
  abuse on a single replica but are not distributed controls. Put edge rate limits at the trusted
  proxy and require a shared, reviewed limiter before horizontal scaling.
- The sponsor is a deliberately lossy testnet hot wallet, not a trust root. Keep only a bounded faucet
  balance, alert on spend/low reserve, rotate it independently, and never reuse the issuer/deployer/owner.
  The route has per-request gas and fee caps, but distributed edge quotas and durable idempotency are
  required before any horizontally scaled or production-value sponsorship design.
- v1 predicates are issuer-attested. The holder-side ZK prover is not implemented or deployed;
  `PredicateVerifier.prover()` must remain visibly zero until that separate release is audited.
- The currently recorded Phase 2 PredicateVerifier addresses predate the v2 consumer-forwarding and
  wallet-independent replay correction. They remain valid for v1 only and must not be configured with a prover;
  the v2 rehearsal requires a new versioned testnet host/registry/adapter/verifier stack.
