# EC-C7 — Capture a genuine Self staging proof & flip on the real verifier

**Status (2026-07-12).** EC-C7 is *one human action* from done.

| Deliverable | State |
|---|---|
| **1. Production `vc_and_disclose` VK** | ✅ **DONE + adversarially verified.** Extracted from Self's on-chain Groth16 verifier, cross-checked **byte-identical** across two independent primary sources (GitHub generated `Verifier_vc_and_disclose.sol` + the Celoscan-verified live Celo-mainnet deployment `0x0A57C317800865194496763377d25CA2082DB649`). G2 c0/c1 swap **proven** against the canonical BN254 generator; all 4 fixed points + 22 IC points pass on-curve/subgroup. Proven to load through our pin pipeline at arity-21 (`crates/zkpoh/tests/self_prod_vk_derisk.rs`). Lives at `crates/zkpoh/fixtures/self_prod_vkey.json`. |
| **2. A genuine staging proof** | ⏳ **Needs one human scan.** Self's mock-passport registration runs client-side in a phone TEE — it cannot be scripted headlessly. Everything to *capture* it is wired (see below). |

The VK matches ceremony `0x0A57C317…` (mainnet), reported **byte-identical** to the Celo-Sepolia staging verifier `0x7C2FBA7F…` — so one VK should verify both. **This is confirmed for real only by step 6's off-chain check**, which is the GO/NO-GO gate before anything is pinned.

---

## What you need
- The **Self mobile app** (iOS/Android).
- A public **tunnel** to your laptop — the Self app runs on a phone and `SelfAppBuilder` refuses `localhost` endpoints. `ngrok http 3000` or `cloudflared tunnel --url http://localhost:3000`.
- A fresh **ubi2 devnet** + the **C1 wallet** running locally.
- `@selfxyz/core >= 1.1.0-beta.1` in the wallet (mock passports register on **Celo Sepolia**, chainId `11142220` — not the deprecated Alfajores `44787`).

## Steps

1. **Start a tunnel** to the wallet and note the public URL, e.g. `https://abcd.ngrok-free.app`.

2. **Boot a fresh devnet + the wallet in capture mode.** The `UBI2_SELF_CAPTURE_DIR` env turns on the raw-bundle capture side-channel in `apps/wallet/app/api/self-verify/route.ts` (a no-op otherwise):
   ```bash
   # terminal 1 — fresh devnet
   UBI2_RPC_ADDR=127.0.0.1:8545 UBI2_DATA_DIR=.devnet-ecc7 ./target/debug/ubi2-node

   # terminal 2 — wallet: capture ON, endpoint = the PUBLIC tunnel URL + /api/self-verify
   UBI2_SELF_CAPTURE_DIR=$PWD/crates/zkpoh/fixtures \
   NEXT_PUBLIC_SELF_ENDPOINT=https://abcd.ngrok-free.app/api/self-verify \
   NEXT_PUBLIC_RPC_URL=http://127.0.0.1:8545 \
     pnpm --filter @ubi2/wallet dev
   ```

3. **Create a mock passport in the Self app.** On the first screen tap the **Passport** button **5 times** with one finger to open “create a mock passport”, and create it. (Same TEE registration + client-side proving pipeline as a real passport — no hardware, no physical document.)

4. **Register it on staging** and wait for the on-chain identity commitment to settle on Celo Sepolia — the proof’s `merkle_root` is only valid once the commitment is in the registry tree. Staging `IdentityVerificationHubV2` routes `E_PASSPORT` (`attestation_id = 1`) to the disclose verifier.

5. **Scan the wallet QR** (Identity tab → ZK-passport panel → the live Self QR / universal link). Connect your ubi2 dev address first so `userId` binds to it. The Self app produces a **genuine 21-signal `vc_and_disclose` Groth16 proof** and POSTs `{attestationId, proof, publicSignals, userContextData}` to the relay. Capture mode writes three files into `crates/zkpoh/fixtures/`:
   - `self_staging_proof.json` — the verbatim snarkjs proof,
   - `self_staging_public.json` — the 21-element publicSignals array,
   - `self_staging_meta.json` — every reconciliation slot decoded as decimal **and** as a 0x-padded 32-byte scalar (scope@19, merkle_root@9, ofac@16/17/18, attestation@8, user_identifier@20, nullifier@7, current_date@10–15).

6. **🚦 GO/NO-GO — verify the captured proof off-chain against our pinned VK.** This is the definitive check that our extracted VK matches the ceremony the staging proof came from:
   ```bash
   node -e '
     const {groth16}=require("snarkjs");
     const vk=require("./crates/zkpoh/fixtures/self_prod_vkey.json");
     const pub=require("./crates/zkpoh/fixtures/self_staging_public.json");
     const proof=require("./crates/zkpoh/fixtures/self_staging_proof.json");
     groth16.verify(vk,pub,proof).then(ok=>{console.log("verify:",ok);process.exit(ok?0:1)});'
   ```
   - **TRUE** → the pin is correct; proceed to the code changes.
   - **FALSE** → the staging deployment uses a *different* random ceremony than mainnet. Fix: extract that specific staging verifier's VK from its Celoscan-verified source the same way (`.sol` constants → snarkjs `vkey.json`, G2 c0/c1 swap), replace `self_prod_vkey.json`, re-run. Do **not** pin a VK the captured proof doesn't satisfy.

## Then — the four mechanical edits (each low-risk once step 6 is TRUE)

1. **Pin the VK.** Rename `self_prod_vkey.json` → the pinned fixture, regenerate the canonical `.bin` (`cargo test -p ubi2-zkpoh regen_pinned_synthetic_vk -- --ignored`), and rewrite `crates/zkpoh/src/genesis_vk.rs` docs from “SYNTHETIC layout-lock” to “real production VK” (mechanics unchanged — still `include_bytes!` + `Validate::Yes`).
2. **Reconcile the runtime bindings** to the captured values (`self_staging_meta.json`): set `UBI2_SELF_SCOPE` (`crates/runtime/src/zkpoh.rs`) = scope@19; seed the accepted identity root = merkle_root@9 and OFAC roots (kinds 0/1/2) = @16/17/18 at genesis (`crates/node` + `lifecycle::seed_self_identity_root` / `seed_self_ofac_root`); confirm attestation@8 == `E_PASSPORT`(1) and the date/root freshness windows admit the capture.
3. **Add the real end-to-end test** `crates/zkpoh/tests/self_staging_real.rs`: `include_str!` the captured fixtures, assert `Groth16Verifier::from_pinned().verify_passport(...) == TRUE` at 21 signals, and that a tampered proof / flipped nullifier fails closed.
4. **Flip the consensus default** in `crates/node/src/lib.rs` (~line 381): `chain.with_verifier(Groth16Verifier::from_pinned(...))` instead of the `MockZkVerifier` default.

> ⚠️ **Consensus migration.** Steps 1–2 change the genesis `state_root` (new VK + scope + seeded roots). Roll out as a coordinated fresh genesis, never a silent swap. The captured `merkle_root`/OFAC roots are point-in-time — Self rotates staging registry roots, so a stale capture will fail the on-chain `merkle_root` bind; keep within `SELF_ROOT_WINDOW_BLOCKS` or repin via a governance op.
>
> ⚠️ **Ceremony coupling.** Self can redeploy a new random-ceremony verifier at any time. Re-confirm at capture time (step 6) that the Hub still routes `E_PASSPORT` to a verifier whose VK equals our pin.
