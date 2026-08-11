# Changelog

All notable changes to **proofofhumanity.org** (the `@ubi2/proofofhumanity` app) are
documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add a deterministic contract CI gate covering formatting, optimized bytecode size, the complete
  Forge suite, target-contract line/branch coverage, gas regression, Solidity/TypeScript EIP-712
  parity, and an encrypted-keystore deployment rehearsal on Anvil.
- Add a testnet-only Phase 2 deployment wrapper for Base Sepolia, Ethereum Sepolia, Celo Sepolia,
  Robinhood Chain Testnet, and World Chain Sepolia, including chain/signer checks, explicit broadcast
  confirmation, manifest validation, source verification, and a post-deploy mint/replay/soulbound
  e2e check.
- Add the production-shaped predicate center for age 18+, age 21+, ISO alpha-3 nationality, and
  sanctions-clear attestations, with optional disclosure selection during the Self flow.
- Add `/verify` and `/developers`, a public `@ubi2/sdk` predicate API, canonical descriptor vectors,
  Solidity/TypeScript integration examples, and `PREDICATES.md`.
- Add Ethereum, Base, Celo, Optimism, World Chain, and Robinhood Chain mainnet configuration pairs,
  plus all five Phase 2 testnets. Predicate issuance stays disabled until both deployment addresses exist.
- Publish the verified Base Sepolia, Ethereum Sepolia, Celo Sepolia, and Robinhood Chain Testnet
  contract pairs, explorer links, deployment transactions, and live-gate evidence in the app and
  contract registry.

### Changed

- Reject exact same-epoch humanity voucher replays while preserving strictly newer in-place refreshes.
- Run predicate cross-stack parity against the production `PredicateVerifier` and
  `SybilResistantVote` artifacts instead of mirrored fixture implementations.
- Make `Deploy.s.sol` derive ownership from Foundry's active broadcast caller so named encrypted
  keystores wire the deployed stack to the actual deployer.
- Bind predicate issuance to a configured chain/verifier pair and verify the subject's live SBT
  ownership plus both on-chain issuer addresses before signing.
- Require successful OFAC and requested minimum-age checks from Self, keep optional private claims
  in session storage, fail closed on a missing production issuer key, and add bounded rate limits.
- Replace the fabricated age-only demo and inaccurate trustless-ZK copy with the real issuer-attested
  v1 flow and an explicit unshipped holder-ZK status.
- Make Phase 2 live probes repeatable, include a signed predicate negative-space check, tolerate only
  public Foundry broadcast manifests in an otherwise clean tree, and forbid aggregate broadcasts.

## [0.1.0] — 2026-08-09

First public release — a deployable, end-to-end proof-of-humanity credential.

### Added

**Credential & contracts**

- Minimal soulbound **Proof-of-Humanity** token: ERC-721 + **ERC-5192** (non-transferable).
  Each token stores only a `nullifier` (one unique human) and a coarse **~90-day validity
  epoch** — no name, birthdate, nationality, or passport data on-chain (invariant: no PII).
- `currentEpoch()` / `isValid()` freshness with monotonic refresh (`EpochDowngrade` guard).
- **Self (self.xyz) ZK passport** verification via `@selfxyz/core`; the issuer signs a slim
  **EIP-712 humanity voucher** (`HumanityVoucher(address to,uint256 nullifier,uint32 epoch)`)
  the contract verifies before minting. Distinct EIP-712 domain per chain.
- **Multi-chain mint**: the same credential mints on any EVM chain and on **UBI Chain**
  (ubi2 native) — Ethereum, Base, Optimism, Celo wired in the UI.
- **Predicate layer v1** (issuer-attested): prove a yes/no fact (`age>=18`, nationality,
  sanctions-clear) revealing only the boolean, bound to one consumer and context. `PredicateVerifier`
  + `SybilResistantVote` demo consumer; `IPredicateProver` seam reserved for the trustless
  v2 (holder-side ZK proof).

**App & landing**

- Multi-chain mint flow: connect wallet → prove humanity with Self → pick a chain in step 3
  → mint. On-chain SVG credential card preview.
- In-browser **live predicate demo** ("prove you're 18+") — private credential kept in the
  browser, only the boolean reaches the consumer, with client-side digest/signature parity checks.
- Landing sections: hero, why it matters, **how it works** (animated four-step flow rail),
  **the app** (mint), privacy model, for builders & DAOs (tabbed Solidity + TypeScript
  gating examples), under-the-hood (clickable primitives with canonical links), and
  **Universal Basic Income** (linked to https://ubi.eth.limo/, minted under `ubi.eth`).
- Brand system in `globals.css`: warm gradient, mint-green "verified"/UBI affordances,
  scroll-reveal, ambient aurora — dark theme, reduced-motion aware.

**Deploy & discoverability**

- **Social preview card** `public/og.png` (1200×630) for Twitter/X, WhatsApp, etc., plus
  Open Graph + `summary_large_image` Twitter metadata with absolute URLs via `metadataBase`.
- **Favicon** from the logo emblem: `app/icon.svg` + `app/apple-icon.png` (auto-wired by
  Next's file conventions); `theme-color` and `color-scheme` set.
- Deploy guide (`DEPLOY.md`) with the environment-variable matrix and an SSR host checklist.

### Notes

- This build is **SSR** (not a static export): the issuer API routes
  (`/api/self-verify`, `/api/predicate`) hold `ISSUER_PRIVATE_KEY` server-side and must run
  on a Node host. The first release uses a bounded process-local callback handoff and therefore
  requires one sticky replica; see `DEPLOY.md`.
- Predicate proofs are **v1 (issuer-attested)**; the trustless holder-side ZK path (v2) is a
  documented follow-on (`IPredicateProver`).

[Unreleased]: https://github.com/DemocracyEarth/ubi2/compare/poh-v0.1.0...HEAD
[0.1.0]: https://github.com/DemocracyEarth/ubi2/releases/tag/poh-v0.1.0
