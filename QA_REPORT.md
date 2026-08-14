# Proof of Humanity Contract Release — Phase 1 QA Report

**Date:** 2026-08-14

**Scope:** `contracts/` and the `apps/proofofhumanity` Solidity/TypeScript boundary

**Decision:** **PASS for the v1 Phase 2 stack; v2 adapter remains pre-deployment**

**Mainnet status:** **BLOCKED** pending the applicable audits and explicit human approval for each chain

This is an internal release-engineering review, not an independent third-party audit. Slither is not
installed on the machine, so the required fallback manual review was performed and is recorded below.
No testnet or mainnet transaction was submitted during this phase.

## Release gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Optimized build and size limit | PASS | `forge build --sizes`; every runtime is below 24,576 bytes |
| Solidity formatting | PASS | `forge fmt --check` |
| Solidity tests | PASS | 154 passed, 0 failed, 0 skipped |
| Fuzz | PASS | 256 cases for nullifier uniqueness / second-mint resistance |
| Stateful invariants | PASS | 3 invariants × 64 runs × 64 calls; 12,288 calls, 0 reverts |
| Target contract coverage | PASS | ProofOfHumanity and PredicateVerifier each at 100% lines and branches |
| Voucher cross-stack parity | PASS | 21 assertions, 0 failures, production ProofOfHumanity artifact |
| Predicate cross-stack parity | PASS | 29 assertions, 0 failures, production verifier and vote artifacts |
| Isolated gas snapshot | PASS | `.gas-snapshot` generated and committed with seven target calls |
| Static/manual security review | PASS with documented trust assumptions | Slither unavailable; manual review below |

## Coverage

Command: `forge coverage --report summary`

| Contract | Lines | Statements | Branches | Functions |
| --- | ---: | ---: | ---: | ---: |
| `ProofOfHumanity.sol` | 100% (67/67) | 100% (76/76) | 100% (10/10) | 100% (17/17) |
| `PredicateVerifier.sol` | 100% (79/79) | 100% (84/84) | 100% (16/16) | 100% (21/21) |

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
  and context replay domains, stateless repeated `checkProof` calls, explicit-consumer read checks, missing/zero
  replay identifiers, and wallet changes that must not bypass one-per-scope replay.
- The governed v2 adapter covers exact 18-signal/eight-word decoding, host-only calls, chain/host/consumer/subject/
  context/challenge/policy/nullifier-mode binding, verifier-codehash/issuer/root governance, invalid proofs,
  revoked roots, and governed dynamic-status registration, exact publication-time binding, inclusive freshness,
  stale-by-one-second rejection, unknown/zero/mismatch/future rejection and irreversible retirement.
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
| Issuer path `consume` | 39,855 |
| Mock proof path `consumeWithProof` | 36,159 |
| V2 static policy host + adapter + registry + replay write (stub raw verifier) | 89,885 |
| V2 fresh dynamic status host + adapter + registry + replay write (stub raw verifier) | 90,173 |
| Research five-input BN254 raw verifier | 230,657 |

The adapter numbers isolate integration overhead with a stub raw verifier. The five-input verifier uses public
deterministic setup material. None estimates the final production 18-input end-to-end call, and the measurements
must not be added mechanically.

## Runtime sizes

| Production contract | Runtime bytes | Margin to 24,576 |
| --- | ---: | ---: |
| `PoHCardRenderer` | 11,714 | 12,862 |
| `ProofOfHumanity` | 9,048 | 15,528 |
| `PredicateVerifier` | 6,236 | 18,340 |
| `SybilResistantVote` (demo only) | 1,879 | 22,697 |
| `ZkIdentityPredicateProver` (pre-deployment) | 4,957 | 19,619 |
| `ZkIdentityVersionRegistry` (pre-deployment) | 5,497 | 19,079 |
| `V2PackedStatusGroth16Verifier` (research only) | 2,211 | 22,365 |

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

### V2-SEC-01 — Nested consumer and wallet-change replay were not enforceable (resolved pre-mainnet)

The original proof seam passed presenter-controlled context through a nested call, where the prover could see only
`PredicateVerifier` as `msg.sender`. Its replay key also included `subject`, allowing a portable credential to reuse
the same scoped nullifier after changing wallets. The host now constructs the consumer envelope itself and spends a
prover-authenticated replay identifier independent of subject. The five existing testnet hosts predate this change,
remain v1-only with prover unset, and require a versioned redeploy before v2 testing. No mainnet host exists.

### V2-SEC-02 — Dynamic-status time and root relationship was undefined (resolved in proposed ADR-0011)

Signal 17 had no pinned unit or authority, so accepting it could let an old sanctions root be relabeled with a
fresh holder/issuer timestamp. The canonical policy hash now commits to provider, list version, root and maximum
age; governance registers that exact hash with the snapshot's Unix publication time; and the adapter requires exact
timestamp equality before applying the inclusive age window. Unknown, retired, future, mismatched and stale
snapshots fail closed. Production activation still requires the final circuit to prove the policy-kind zero/non-zero
rule and status-root relation, plus independent review.

No open High or Critical finding remains from this phase.

## Manual security review

| Area | Assessment |
| --- | --- |
| Access control | `setIssuer`, `setCardRenderer`, and `setPredicateProver` are `onlyOwner`; unauthorized and zero-issuer paths are tested. Deployment must transfer ownership to the intended multisig. |
| Reentrancy | Mint uses `_mint`, not `_safeMint`, so there is no receiver callback. Issuer consume has no external call. Proof verification is a `view` interface call before replay-state writes. Renderer access occurs only in `tokenURI` through a view call. |
| Low-level/unchecked calls | No `delegatecall`, `selfdestruct`, `tx.origin`, unrestricted low-level call, unchecked block, or ignored boolean return exists in the production contracts. |
| Signature malleability | OpenZeppelin 5.7 `ECDSA.recover` provides canonical signature checks. EIP-712 domains bind chain ID and verifying contract; wrong signer, field tampering, rotation, and wrong-chain tests fail closed. |
| Voucher front-running | Anyone may relay a voucher, but `to` is signed and the token always mints to that address. A relayer cannot redirect it. Exact replay is rejected. |
| Replay domains | Voucher epochs are strictly monotonic. Issuer attestations key `(subject, consumer, context, nonce)`. Stateful proofs spend a prover-authenticated, domain-separated `(consumer, scoped identifier)` key; wallet/challenge changes cannot reset it, while different consumer/context/policy scopes remain independent. |
| Privacy | SBT state is nullifier + epoch. Predicate tests assert exact private attribute values are absent from calldata, logs, and storage. `tokenURI` tests assert no PII fields. |
| Issuer blast radius | The v1 issuer can authorize SBTs and arbitrary predicate booleans, including future epochs. This is an explicit v1 trust assumption. Protect it as a production signing secret, monitor it, and retain rapid owner/multisig rotation. |
| Owner/prover blast radius | The owner can rotate issuer, renderer, and predicate prover. A malicious prover can mislead consumers that opt into the proof path, but cannot alter SBT/nullifier state or UBI eligibility. Launch with prover unset and use a multisig owner. |
| Prover context binding | The host constructs `abi.encode(actualConsumer, applicationContext)` before the nested call. The v2 adapter recomputes every pinned presentation/nullifier binding and resolves codehash-pinned governance. Proposed ADR-0011 additionally binds dynamic status to an exact registered snapshot publication time and maximum age. Any real prover still requires circuit/Solidity review before activation. |

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
