# EC-C7 findings — the real staging proof is captured & the production VK is proven

**Status (2026-07-12): GO.** A genuine Self staging mock-passport proof was captured through the C1 relay
and **verifies TRUE against our extracted production VK** through the real `Groth16Verifier` at 21 signals
(`crates/zkpoh/tests/ec_c7_gonogo.rs`, G2 ordering `swap_b=false`). This is the definitive validation that
the on-chain-extracted VK (`self_prod_vkey.json`) is correct and matches the staging ceremony — the crypto
core of EC-C7 is done. Fixtures committed: `crates/zkpoh/fixtures/self_staging_{proof,public}.json`.

## What the real proof carries (from the capture)

| Slot | Value |
|---|---|
| `attestation_id@8` | `1` (E_PASSPORT) ✓ |
| `merkle_root@9` | `0x0c3b9b6e4ebbf32e675ccb318ea3a3ec94ac0b0f3d33768f8b24d0015eb836e5` (real staging registry root) |
| `current_date@10..15` | `[2,6,0,7,3,1]` → 2026-07-31 |
| `ofac@16` | `3401417420280718516738171609390626784619095029610962469425010828214197157747` |
| `ofac@17` | `6227060330278404862591977884131255780942563186873190571034622155790997155169` |
| `ofac@18` | `21056015788554834534165942295360655227086483475348760845000192264553821912934` |
| `scope@19` | `0x297ac5681a5a5d1a555e177be0f852a684a6fa91e6063e28b828e90f569669d6` |
| `user_identifier@20` | `0x28edff481a0eca85f9d91287153aefee1f78a031` (userId was `0xf39Fd6…92266`) |

## The three reconciliation gaps the real proof exposed

Capturing a real proof was meant to surface where our C1 assumptions diverge from Self's production
encoding — it found three. All must be reconciled before the value-minting verifier can be flipped on.
None affects the crypto GO above (the proof verifies); they are runtime-binding corrections.

1. **Proof wire format — `a/b/c`, not `pi_a/pi_b/pi_c`.** The Self V2 app POSTs an affine Groth16 proof
   `{a:[x,y], b:[[..],[..]], c:[x,y], protocol:"groth16"}`. Our C1 relay validator/encoder
   (`packages/sdk` `validateProofBundle`/`encodeSelfRelayPayload`, used by `apps/wallet/app/api/self-verify`)
   require snarkjs `pi_a/pi_b/pi_c`, so the real payload is rejected before submission. **Fix:** accept the
   `a/b/c` shape (map `a→pi_a`, `b→pi_b`, `c→pi_c`; append the projective `z`); no G2 swap (`swap_b=false`).

2. **`current_date` — raw digits, not ASCII.** Self emits the six date signals as raw integers `0–9`
   (`[2,6,0,7,3,1]`), but `crates/runtime/src/zkpoh.rs::current_date_to_epoch` requires ASCII digit codes
   (`is_ascii_digit()`, `b - b'0'`) and returns `None` for the real values → the freshness bind would fail.
   **Fix:** decode raw digits `0–9` (drop the ASCII assumption); update the SDK's `dateToSelfSignals` and the
   dev-mock (`buildDevMockSubmission`) + the `m6_zkpoh` runtime test to match.

3. **`user_identifier` — a Self derivation, not our padded address.** `crates/runtime/src/zkpoh.rs::
   address_to_hash` left-pads the 20-byte address to 32 bytes, so the submitter bind expects
   `0x000…f39fd6…92266`. But the captured `user_identifier@20` is `0x28edff48…a031`, and it is **not**
   `keccak256`/`sha256` of the `userContextData` (checked) — Self derives it via a circuit-level formula
   (likely Poseidon, defined in `@selfxyz/core`/the circuits, not in the installed frontend packages).
   **Fix (needs Self's exact derivation identified first):** make the SDK compute the same
   `user_identifier` from the sender address and have the runtime bind against it, preserving the
   anti-replay property (proof for address A can't be submitted by B).

## Remaining work to flip the minting default
Reconcile the three above → then the mechanical pin+flip (`docs/ec-c7-capture-runbook.md`): pin
`self_prod_vkey.json` (regen the `.bin`), set `UBI2_SELF_SCOPE = scope@19` and seed the captured
`merkle_root`/OFAC roots at genesis, keep `ec_c7_gonogo.rs` as the verify gate, and switch `crates/node`
to `Chain::with_verifier(Groth16Verifier::from_pinned())`. This changes genesis `state_root` — a
coordinated consensus migration, not a silent swap.
