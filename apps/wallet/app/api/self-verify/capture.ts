/**
 * EC-C7 capture side-channel (DEV-ONLY, spec 06b §4.1 VK-status / EC-C7).
 *
 * The relay (`route.ts`) is a thin UNTRUSTED encoder — it normally keeps only the derived calldata +
 * nullifier in an in-memory store. EC-C7 needs the *raw* `{proof, publicSignals}` a genuine Self
 * STAGING mock-passport scan produces, persisted to disk as a reusable test vector so we can (a) replay
 * it against the real `Groth16Verifier` + the pinned production VK, and (b) read the real scope /
 * merkle_root / OFAC-root / attestation VALUES to reconcile the runtime bindings.
 *
 * This is a pure SIDE EFFECT that changes nothing about validity: it is a NO-OP unless
 * `UBI2_SELF_CAPTURE_DIR` is set, and even when set it only writes files — the relay's response and its
 * trust boundary are untouched. Never enable it in production.
 *
 * When enabled, on a well-formed POST it writes into `$UBI2_SELF_CAPTURE_DIR`:
 *   - `self_staging_proof.json`  — the verbatim snarkjs proof object ({pi_a, pi_b, pi_c, ...}).
 *   - `self_staging_public.json` — the verbatim 21-element decimal-string publicSignals array.
 *   - `self_staging_meta.json`   — decoded reconciliation values (each public slot as decimal AND as a
 *                                  0x-padded 32-byte big-endian scalar, ready to drop into the Rust
 *                                  constants: scope@19, merkle_root@9, ofac@16/17/18, attestation@8,
 *                                  user_identifier@20, nullifier@7, current_date@10..15).
 */

import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// The confirmed vc_and_disclose 21-signal slot indices (spec 06b §4.1) — kept local so this dev-only
// module has no import coupling to the trust path.
const SLOT = {
  nullifier: 7,
  attestationId: 8,
  merkleRoot: 9,
  currentDate: [10, 11, 12, 13, 14, 15] as const,
  ofacPassportNo: 16,
  ofacNameDob: 17,
  ofacNameYob: 18,
  scope: 19,
  userIdentifier: 20,
} as const;

/** Decimal field-element string -> 0x-prefixed, 32-byte big-endian hex (the on-chain bytes32 form). */
function decToBytes32Hex(dec: string): string {
  let hex = BigInt(dec).toString(16);
  if (hex.length > 64) throw new Error(`slot value exceeds 32 bytes: ${dec}`);
  return "0x" + hex.padStart(64, "0");
}

/**
 * Persist the VERBATIM request body BEFORE any validation (a no-op unless capture mode is on). This is
 * the diagnostic escape hatch: the real Self V2 app may POST a proof shape our validator/encoder does not
 * yet accept — this saves exactly what arrived so we can adapt the encoder to the real format. Returns
 * the directory written to, or null.
 */
export function captureRawRequestBody(body: unknown): string | null {
  const dir = process.env.UBI2_SELF_CAPTURE_DIR;
  if (!dir) return null;
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "self_raw_body.json"), JSON.stringify(body, null, 2) + "\n");
    return dir;
  } catch (e) {
    console.error("[self-verify capture] raw body persist failed:", e);
    return null;
  }
}

interface CapturePayload {
  attestationId: number | string;
  proof: unknown;
  publicSignals: string[];
  userContextData?: string;
}

/**
 * Persist a captured staging bundle if capture mode is on. Returns the directory written to (for the
 * relay to surface in its response), or `null` if capture is disabled / failed (never throws into the
 * request path — a capture failure must not break the relay).
 */
export function captureRawBundle(payload: CapturePayload, submitter: string): string | null {
  const dir = process.env.UBI2_SELF_CAPTURE_DIR;
  if (!dir) return null;
  try {
    mkdirSync(dir, { recursive: true });
    const ps = payload.publicSignals;

    writeFileSync(join(dir, "self_staging_proof.json"), JSON.stringify(payload.proof, null, 2) + "\n");
    writeFileSync(join(dir, "self_staging_public.json"), JSON.stringify(ps, null, 2) + "\n");

    const slotView = (i: number) => ({ index: i, dec: ps[i], hex: decToBytes32Hex(ps[i]) });
    const meta = {
      capturedAt: new Date().toISOString(),
      submitter,
      attestationId: payload.attestationId,
      note: "EC-C7 genuine Self STAGING capture. hex = 0x-padded 32-byte big-endian, ready for the Rust pins.",
      reconciliation: {
        scope: slotView(SLOT.scope), // -> crates/runtime/src/zkpoh.rs UBI2_SELF_SCOPE
        merkle_root: slotView(SLOT.merkleRoot), // -> seed_self_identity_root(...)
        ofac_passportno: slotView(SLOT.ofacPassportNo), // -> seed_self_ofac_root(kind 0, ...)
        ofac_namedob: slotView(SLOT.ofacNameDob), //  -> seed_self_ofac_root(kind 1, ...)
        ofac_nameyob: slotView(SLOT.ofacNameYob), //  -> seed_self_ofac_root(kind 2, ...)
        attestation_id: slotView(SLOT.attestationId), // expect E_PASSPORT (1)
        user_identifier: slotView(SLOT.userIdentifier), // must equal address_to_hash(submitter)
        nullifier: slotView(SLOT.nullifier),
        current_date: SLOT.currentDate.map(slotView),
      },
    };
    writeFileSync(join(dir, "self_staging_meta.json"), JSON.stringify(meta, null, 2) + "\n");
    return dir;
  } catch (e) {
    // Never let a capture side-effect break the relay; just log server-side.
    console.error("[self-verify capture] failed to persist bundle:", e);
    return null;
  }
}
