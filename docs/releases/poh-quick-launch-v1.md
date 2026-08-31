# PoH Quick Launch v1 — scope reset, audit, and 14-day cut

- **Baseline:** `ac4e0b3ecf1f7d14bb85293508c5482809e879d2` (merged PR #112)
- **Release target:** Base Sepolia (`84532`)
- **Status:** testable release candidate work; no live-readiness or mainnet claim
- **User outcomes:** Self proof → soulbound PoH mint; age/nationality/sanctions-clear Boolean presentation

## Release contract

Quick Launch ships exactly these product paths:

1. A wallet-bound Self verification produces one issuer-signed humanity voucher.
2. The holder or isolated testnet sponsor redeems that voucher for one ERC-5192 soulbound token on
   Base Sepolia.
3. The same verified browser session may request `age>=18`, `age>=21`, `nationality=<A3>`, and
   `sanctions-clear` v1 attestations.
4. The app verifies each attestation locally and through the pinned Base Sepolia `PredicateVerifier`.

The release does not include another network, mainnet, the ubi2 native chain, consensus, custom
circuits, Phase 2 ceremony work, portable credentials, status operators, a custom prover, or DAO/UBI
features.

## Existing-path audit

| Component | Finding | Release decision |
|---|---|---|
| `ProofOfHumanity` | Real ERC-5192 contract, EIP-712 voucher, one-nullifier mapping, refresh, expiry, and transfer rejection are tested. | Keep. Pin to reviewed Base Sepolia address. |
| `/api/self-verify` | Real `SelfBackendVerifier` path exists and binds the proof to the wallet and disclosure/session request. It previously signed every configured chain and also exposed a v2 issuance branch. | Keep v1; sign Base Sepolia only; reject v2 requests. |
| Sponsored mint | Real testnet transaction executor verifies live chain, bytecode, issuer, roles, budgets, receipt event, ownership, validity, and lock. | Keep, but allow only `84532`; a synthetic rehearsal is not Self evidence. |
| Held predicates | Age flags, nationality and OFAC-clear are derived from the selected Self disclosures and signed as a private v1 credential. | Keep with explicit issuer trust and session-only limitation. |
| `/api/predicate` | Checks credential signature/freshness, live SBT ownership, paired contracts and issuers, then signs and contract-checks a bound Boolean. | Keep, Base Sepolia only. |
| V2 policy lab | Builds deterministic policy hashes but generates no proof. | Remove from `/verify`. Research source stays unreferenced. |
| Holder vault panel | Stores an empty synthetic, production-ineligible payload; browser evidence uses a deterministic PRF API double and no physical authenticator. | Remove from the product route. Do not reuse as passkey production evidence. |
| Demo credential API | Fabricates adult, ARG, sanctions-clear attributes and signs them. A production environment override could enable it. | Delete the route. |
| V2 Self issuance refresh | Transitional bridge authorization requiring separate unaudited release inputs. | Remove POST branch and PATCH method from the release API. |
| Multi-chain UI/config | The page marketed mainnets/ubi2 and the API issued vouchers for five testnets. | Enforce one executable Base Sepolia release profile. |
| Predicate privacy copy | Artifacts are consumer-bound, but expose the same subject wallet and therefore are linkable across consumers using that wallet. | Correct the claim before release; do not promise unlinkability. |

## Rehearsal and mock inventory

These remain useful engineering evidence but are not proof of the real user journey:

- Self `staging` accepts test/mock passports; it proves staging plumbing, not a real-passport launch.
- Voucher and predicate cross-stack tests construct a nullifier and use known Anvil keys.
- Phase 2 deployment e2e signs a deterministic voucher and predicate without a phone/Self callback.
- The checked-in Base Sepolia sponsored-mint evidence uses a synthetic staging voucher and explicitly
  makes no passport claim.
- Solidity `MockPredicateProver` and research Groth16 fixtures test the future prover seam; the reviewed
  Base Sepolia `prover()` is zero and must stay zero.
- `SybilResistantVote` is a sample consumer used for cross-stack contract behavior; it is not a
  production relying-party integration or evidence that an external consumer completed the flow.
- V2 policy hashes, synthetic holder payloads, emulated-mobile Chromium, passkey PRF doubles, status
  fleets, audit packages, and ceremony records are R&D evidence, not Quick Launch evidence.

## Concrete production blockers

### Application/infrastructure

- No approved public HTTPS Quick Launch deployment or exact Self callback URL is present in this
  worktree.
- The ten-minute verification handoff and quotas are process-local, requiring one sticky Node replica.
- Trusted-proxy overwriting, ingress limits, TLS, restart/5xx monitoring, and log redaction need observed
  host evidence.
- A monitored Base Sepolia RPC/provider and outage behavior need a recorded choice.

### Public trust bindings

- Read-only RPC evidence on 2026-08-30 confirmed chain `84532`, bytecode at both addresses, owner
  `0x26250e47500943464290A77ae3508a3001d9B69d`, issuer
  `0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe`, and zero predicate prover.
- That does not establish control of the corresponding issuer secret or sponsor account. An approved
  secret-manager path and matching public address are required; secret values must never enter evidence.
- The current owner and issuer are documented disposable testnet roles. They are sufficient only for the
  testnet release candidate, never for mainnet.

### Real user evidence

- No observed public-host Self staging callback → voucher → sponsored mint → predicate sequence is
  present.
- No separately observed Self production/real-passport sequence is present.
- Physical mobile handoff, tab closure, callback timeout, wallet switch, duplicate human, replay,
  wrong-binding, RPC outage, and sponsor depletion need recorded outcomes.

### Product/security decisions

- V1 predicates are issuer-attested, not holder-generated ZK proofs.
- Predicate artifacts expose the subject wallet and are not cross-consumer unlinkable.
- The private v1 credential is currently in `sessionStorage`, not passkey-encrypted.
- The current profile requires sanctions clearance for the Self verification/mint. Product must confirm
  that policy before calling the release complete.

## Dependency-ordered 14-day cut

| Days | Owner | Deliverable | Acceptance gate | Completion milestone |
|---:|---|---|---|---:|
| 1–2 | product + architect + interface | Merge the executable Quick Launch scope: Base Sepolia only; remove demo/V2 routes and UI; publish this audit. | Source tests prove no mainnet/non-Base chain, fabricated credential, V2 issuance, holder vault, or prover enters the release path. | 15% |
| 2–3 | release + security | Provision one HTTPS/sticky Node candidate and inject approved issuer/sponsor secret paths. | Public preflight green; secrets absent from build, logs and evidence; public signer roles match contracts. | 25% |
| 3–4 | interface + QA | Run Self staging on a physical phone through callback, voucher and wallet mint. | Observed wallet-bound voucher and confirmed locked/valid token; duplicate/replay/wallet-switch failures pass. | 40% |
| 4–5 | release + reliability | Run sponsored mint from an unfunded dedicated account. | Isolated sponsor, bounded spend, correct recipient/event/state, idempotent retry, depletion and cap failures observed. | 50% |
| 5–6 | interface + QA | Exercise all v1 predicates from the same real staging session. | 18+/21+/nationality true+false/sanctions clear contract-check; wrong bindings and stale inputs reject. | 60% |
| 6–8 | interface + security | Add a narrow passkey protection slice for the v1 held credential, not a new passport proof system. Loss/recovery re-runs Self. | User verification required; no password fallback; no plaintext durable storage; logout/tab/account invalidation; physical-device tests. | 72% |
| 8–9 | privacy + product | Correct final privacy/trust language and decide mandatory-sanctions policy. | UI, API docs and consent describe issuer visibility, wallet linkability, storage lifetime, and sanctions behavior accurately. | 78% |
| 9–10 | reliability | Exercise callback timeout, restart, RPC outage, sponsor outage, rate limits and recovery. | No false success, duplicate transaction, leaked attribute, or stuck session. | 84% |
| 10–11 | security | Focused threat model and adversarial review of the release diff and deployed configuration. | Zero open Critical/High; Mediums explicitly accepted or fixed. | 90% |
| 11–12 | QA | Cross-browser/mobile usability with several external testers. | Complete physical-phone journey, clear failure recovery, accessibility smoke, no demo/V2 surface. | 94% |
| 12–13 | release | Run the complete repository and Quick Launch gates on the release commit; archive redacted evidence. | Every required check green and reproducible; public artifact links recorded. | 97% |
| 14 | product + release | Go/no-go for the Base Sepolia public candidate. | All blockers checked, observed evidence reviewed, rollback/disable procedure rehearsed. | 100% |

The percentages are completion of the **Quick Launch Base Sepolia candidate**, not the broader ubi2,
portable-v2, or mainnet roadmap.

### Days 2–3 observed status — 2026-08-30

The automatic `main` deployment now serves the Quick Launch/Base Sepolia UI at
`https://proofofhumanity.org`; the demo credential route is absent and the transaction-free public
chain/callback preflight is green. That advances public byte delivery, but not the 25% host gate.

CloudFront is observable, but origin topology is not. This worktree has no AWS credentials, GitHub has
no deployment record for the host, and the repository contains no approved issuer/sponsor secret-manager
reference or immutable injection attestation. A strict runtime readiness record and external evidence
verifier are therefore being added, with the observed record pinned at
[`../../ops/proofofhumanity/evidence/quick-launch-host-preflight-2026-08-30.json`](../../ops/proofofhumanity/evidence/quick-launch-host-preflight-2026-08-30.json).
It is explicitly `ready: false`; completion remains **15%** until topology and both secret-provenance
chains are independently supplied and match the deployed runtime.

## First-PR acceptance criteria

- The executable release chain set contains exactly Base Sepolia and rejects network misclassification
  or duplicates; public preflight rejects any override of the reviewed contract pair.
- Self callback signs only the Base Sepolia voucher and rejects a v2 disclosure request.
- Predicate and sponsored-mint APIs reject every non-release chain.
- `/verify` has no policy lab, the mint flow has no holder-vault rehearsal, and the fabricated credential
  route no longer exists.
- Public preflight is transaction-free and fails on wrong chain, missing bytecode, owner/issuer mismatch,
  nonzero prover, invalid Self mode, or unsafe callback URL.
- Product, PWA, typecheck, build, cross-stack, Solidity, Rust, SDK, operator, reliability, and security
  validation gates are green before merge.
