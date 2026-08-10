# Proof of Humanity Contract Release — Phase 1 QA Report

**Date:** 2026-08-09

**Scope:** `contracts/` and the `apps/proofofhumanity` Solidity/TypeScript boundary

**Decision:** **PASS for Phase 2 testnet dry-runs**

**Mainnet status:** **BLOCKED** until Phase 2 is green and a human explicitly approves each chain

This is an internal release-engineering review, not an independent third-party audit. Slither is not
installed on the machine, so the required fallback manual review was performed and is recorded below.
No testnet or mainnet transaction was submitted during this phase.

## Release gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Optimized build and size limit | PASS | `forge build --sizes`; every runtime is below 24,576 bytes |
| Solidity formatting | PASS | `forge fmt --check` |
| Solidity tests | PASS | 108 passed, 0 failed, 0 skipped |
| Fuzz | PASS | 256 cases for nullifier uniqueness / second-mint resistance |
| Stateful invariants | PASS | 3 invariants × 64 runs × 64 calls; 12,288 calls, 0 reverts |
| Target contract coverage | PASS | ProofOfHumanity and PredicateVerifier each at 100% lines and branches |
| Voucher cross-stack parity | PASS | 21 assertions, 0 failures, production ProofOfHumanity artifact |
| Predicate cross-stack parity | PASS | 29 assertions, 0 failures, production verifier and vote artifacts |
| Isolated gas snapshot | PASS | `.gas-snapshot` generated and committed with four target calls |
| Static/manual security review | PASS with documented trust assumptions | Slither unavailable; manual review below |

## Coverage

Command: `forge coverage --report summary`

| Contract | Lines | Statements | Branches | Functions |
| --- | ---: | ---: | ---: | ---: |
| `ProofOfHumanity.sol` | 100% (67/67) | 100% (76/76) | 100% (10/10) | 100% (17/17) |
| `PredicateVerifier.sol` | 100% (66/66) | 100% (70/70) | 100% (12/12) | 100% (18/18) |

The whole-package line percentage is lower because `script/Deploy.s.sol` and the inlined
`Countries.sol` source are outside this phase's target-contract threshold. Foundry emitted source-anchor
warnings while instrumenting unoptimized coverage bytecode; the target-contract summary still reports
every line and branch covered.

## Test coverage added or strengthened

- Exact voucher replay now reverts `VoucherReplayed`; strictly newer epochs refresh the same token and
  older epochs still revert `EpochDowngrade`.
- A reused nullifier cannot allocate or remap a second token, including attempts from another wallet.
- EIP-712 vouchers and predicate attestations signed for one chain are rejected on another chain.
- Predicate, context, epoch, result, consumer, subject, signature, freshness, and nonce bindings are
  exercised explicitly.
- The proof path covers owner-only prover configuration, set/swap/unset, happy paths, false results,
  unset prover, wrong predicate, subject mismatch, stale epoch, bad proof, replay, independent consumer
  and context replay domains, and stateless repeated `checkProof` calls.
- SybilResistantVote covers valid yes/no votes, one-human-one-vote, invalid or absent SBTs, expired SBTs,
  predicate/context/consumer/subject mismatch, false predicates, bad signatures, replay, and double vote.
- Privacy tests use `vm.record`, `vm.recordLogs`, `vm.accesses`, and `vm.load` to assert representative
  exact age, date of birth, and nationality values do not appear in valid attestation/proof calldata,
  logs, accessed storage slots, or stored values. Only the derived boolean is revealed.
- The predicate cross-stack test now loads the production `PredicateVerifier` and
  `SybilResistantVote` artifacts. The remaining fixture is only a minimal consumer probe.

## Cross-stack parity

| Test | Result | Key evidence |
| --- | --- | --- |
| `voucher.crossstack.ts` | 21/21 | SDK digest equals `hashVoucher`; mint succeeds; replay, wrong signer, and wrong-chain signature revert; newer epoch refreshes in place |
| `predicate.crossstack.ts` | 29/29 | SDK digest equals production `hashAttestation`; signature recovers to issuer; production vote succeeds; replay/binding/freshness/signature negatives revert |

The tests use only published Anvil development accounts. No production secret is read or stored.

## Isolated gas snapshot

Setup, hashing, and signing are excluded with Foundry gas-meter controls. Values measure the target
external call against the configured optimizer (`runs = 200`). They are regression benchmarks, not
chain-specific fee estimates.

| Operation | Gas |
| --- | ---: |
| New `mintWithVoucher` | 134,448 |
| In-place newer-epoch refresh | 13,813 |
| Issuer path `consume` | 39,833 |
| Mock proof path `consumeWithProof` | 34,385 |

The proof-path number uses the deterministic mock prover and does not estimate a future Groth16 prover.

## Runtime sizes

| Production contract | Runtime bytes | Margin to 24,576 |
| --- | ---: | ---: |
| `PoHCardRenderer` | 10,569 | 14,007 |
| `ProofOfHumanity` | 9,048 | 15,528 |
| `PredicateVerifier` | 5,368 | 19,208 |
| `SybilResistantVote` (demo only) | 1,879 | 22,697 |

`SybilResistantVote` remains demo-only and must not be deployed to production.

## Findings and resolutions

### P1-QA-01 — Same-epoch voucher replay was accepted (resolved)

An identical signed voucher previously emitted a no-op refresh repeatedly. It could not mint a second
token or redirect ownership, but it violated the requested single-use behavior and enabled redundant log
and gas consumption. Equal epochs now revert `VoucherReplayed`; the downgrade and strictly newer refresh
paths remain distinct and tested.

### P1-QA-02 — Predicate cross-stack test used mirrored contracts (resolved)

The TypeScript test deployed a duplicate fixture verifier and vote contract, allowing the test lane to
drift from production while remaining green. It now builds and deploys the production Foundry artifacts;
only the consumer probe remains a fixture.

### P1-QA-03 — Contract README described obsolete public attributes (resolved)

The README claimed nationality, age flags, gender, and sanctions status were stored publicly. The deployed
surface stores only nullifier and coarse epoch. Documentation now matches the no-PII implementation.

No open High or Critical finding remains from this phase.

## Manual security review

| Area | Assessment |
| --- | --- |
| Access control | `setIssuer`, `setCardRenderer`, and `setPredicateProver` are `onlyOwner`; unauthorized and zero-issuer paths are tested. Deployment must transfer ownership to the intended multisig. |
| Reentrancy | Mint uses `_mint`, not `_safeMint`, so there is no receiver callback. Issuer consume has no external call. Proof verification is a `view` interface call before replay-state writes. Renderer access occurs only in `tokenURI` through a view call. |
| Low-level/unchecked calls | No `delegatecall`, `selfdestruct`, `tx.origin`, unrestricted low-level call, unchecked block, or ignored boolean return exists in the production contracts. |
| Signature malleability | OpenZeppelin 5.7 `ECDSA.recover` provides canonical signature checks. EIP-712 domains bind chain ID and verifying contract; wrong signer, field tampering, rotation, and wrong-chain tests fail closed. |
| Voucher front-running | Anyone may relay a voucher, but `to` is signed and the token always mints to that address. A relayer cannot redirect it. Exact replay is rejected. |
| Replay domains | Voucher epochs are strictly monotonic. Issuer attestations key `(subject, consumer, context, nonce)`. Proofs key `(subject, consumer, keccak256(context))`; different consumer/context values are independent. |
| Privacy | SBT state is nullifier + epoch. Predicate tests assert exact private attribute values are absent from calldata, logs, and storage. `tokenURI` tests assert no PII fields. |
| Issuer blast radius | The v1 issuer can authorize SBTs and arbitrary predicate booleans, including future epochs. This is an explicit v1 trust assumption. Protect it as a production signing secret, monitor it, and retain rapid owner/multisig rotation. |
| Owner/prover blast radius | The owner can rotate issuer, renderer, and predicate prover. A malicious prover can mislead consumers that opt into the proof path, but cannot alter SBT/nullifier state or UBI eligibility. Launch with prover unset and use a multisig owner. |
| Prover context binding | Privacy and consumer binding depend on the future prover cryptographically binding the opaque context. The prover is unset at launch; any real prover requires its own audit before activation. |

Foundry lint emitted only advisory items: deliberate narrowing for epoch/display values, hashing-efficiency
suggestions, naming style, and test-only base64 arithmetic. None changes the release decision. The epoch
cast remains within `uint32` for any realistic timestamp; renderer truncation intentionally selects four
display hex digits.

## Commands executed

```text
forge fmt --check
forge build --sizes
forge test
forge coverage --report summary
forge snapshot
pnpm --filter @ubi2/proofofhumanity typecheck
pnpm --filter @ubi2/proofofhumanity test:crossstack
pnpm --filter @ubi2/proofofhumanity test:predicate
```

## Phase 2 entry condition

Phase 1 is green. Phase 2 may begin with throwaway test credentials and testnet-only funds. Production
deployer or issuer secrets are not required and must not be supplied. Mainnet broadcasting remains
prohibited until every required testnet deployment, explorer verification, and end-to-end mint passes.
