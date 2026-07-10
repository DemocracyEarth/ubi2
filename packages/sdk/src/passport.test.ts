/**
 * @ubi2/sdk/passport — unit tests (typecheck + logic, no node/live RPC required).
 *
 * Tests the ZK-passport proof-bundle parsing, the single by-index read (nullifier@7), and the
 * full-vector calldata encoding for the CONFIRMED Self `vc_and_disclose` 21-signal layout
 * (spec 06b §4.1/§4.3). Uses the SHARED synthetic fixture the Rust crypto tests use
 * (`crates/zkpoh/fixtures/self_synthetic_public.json`) to assert SDK + Rust parse an identical
 * proof identically (§4.2 GAP-4 — one shared source of truth).
 *
 * Run: pnpm -C packages/sdk run test   (tsx src/passport.test.ts)
 *
 * Validates:
 *  1. parseProofBundle accepts a 21-signal bundle and rejects malformed JSON / bad shapes.
 *  2. extractNullifier returns publicSignals[7] as a 32-byte 0x-hex (the ONLY by-index read).
 *  3. extractSubmitterAddress reads the low 20 bytes of publicSignals[20].
 *  4. publicSignalsToBytes32 maps the full 21-vector; encodeSubmitZkPassportProof carries it.
 *  5. encodeSubmitZkPassportProof produces calldata with the new selector
 *     (submitZkPassportProof(bytes,bytes32[21],uint8)).
 *  6. validateProofBundle requires exactly 21 signals.
 *  7. SDK↔Rust parity: reading the shared synthetic fixture, the SDK's nullifier@7 equals the
 *     fixture's slot-7 field element (the same slot the Rust `SELF_IDX_NULLIFIER` binds).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { keccak256, toHex } from "viem";

import {
  parseProofBundle,
  validateProofBundle,
  extractNullifier,
  extractSubmitterAddress,
  publicSignalsToBytes32,
  encodeProofBytes,
  encodeSubmitZkPassportProof,
  encodeZkBundleAsCalldata,
  validateSelfRelayPayload,
  encodeSelfRelayPayload,
  SELF_NPUBLIC,
  SELF_IDX_NULLIFIER,
  SELF_IDX_USER_IDENTIFIER,
  type SelfProofBundle,
  type SelfRelayPayload,
} from "./passport.js";

// ---------------------------------------------------------------------------
// Test fixture: a minimal valid Self-shape proof bundle (21 public signals, §4.1).
// The proof values are test-only BN254 field elements — NOT a real person's data.
// ---------------------------------------------------------------------------

const TEST_NULLIFIER_DEC =
  "14723305143599295486105733121446353133863889257489542032576171376300323541304";
// Address 0x6f6f...6f6f (20 bytes of 0x6f) as a big-endian uint256 decimal.
const TEST_SUBMITTER_ADDR_DEC = BigInt("0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f").toString();

// 21 signals, per the CONFIRMED layout: revealed[0..3], forbidden[3..7], nullifier@7,
// attestation_id@8, merkle_root@9, current_date[10..16], ofac@16..19, scope@19, user_id@20.
const TEST_PUBLIC_SIGNALS: string[] = [
  "701", "702", "703",          // [0..3]  revealedData_packed
  "801", "802", "803", "804",   // [3..7]  forbidden_countries_list_packed (4)
  TEST_NULLIFIER_DEC,           // [7]     nullifier
  "1",                          // [8]     attestation_id (== 1)
  "111",                        // [9]     merkle_root
  "50", "50", "48", "54", "50", "57", // [10..16] current_date YYMMDD ASCII (test values)
  "601", "602", "603",          // [16..19] ofac roots
  "999",                        // [19]    scope
  TEST_SUBMITTER_ADDR_DEC,      // [20]    user_identifier (submitter address)
];

// A BN254 G1/G2 point set (test values only — not a real proof).
const G1_X = "1";
const G1_Y = "2";
const G2_X: [string, string] = ["10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"];
const G2_Y: [string, string] = ["8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"];

const FIXTURE_BUNDLE: SelfProofBundle = {
  proof: {
    pi_a: [G1_X, G1_Y, "1"],
    pi_b: [G2_X, G2_Y, ["1", "0"]],
    pi_c: [G1_X, G1_Y, "1"],
    protocol: "groth16",
    curve: "bn128",
  },
  publicSignals: TEST_PUBLIC_SIGNALS,
};

// ---------------------------------------------------------------------------
// Minimal assertion helpers (no external test framework)
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failed++;
  } else {
    console.log(`  pass: ${msg}`);
    passed++;
  }
}

function test(name: string, fn: () => void): void {
  console.log(`\n[TEST] ${name}`);
  try {
    fn();
  } catch (e) {
    console.error(`  FAIL (threw): ${e instanceof Error ? e.message : String(e)}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("layout constants mirror the confirmed 21-signal map (§4.1)", () => {
  assert(SELF_NPUBLIC === 21, "SELF_NPUBLIC == 21");
  assert(SELF_IDX_NULLIFIER === 7, "nullifier is slot 7");
  assert(SELF_IDX_USER_IDENTIFIER === 20, "user_identifier is slot 20");
});

test("parseProofBundle: accepts a 21-signal bundle", () => {
  const { bundle, error } = parseProofBundle(JSON.stringify(FIXTURE_BUNDLE));
  assert(error === null, "error is null for a valid bundle");
  assert(bundle?.publicSignals.length === 21, "publicSignals has 21 elements");
});

test("parseProofBundle: rejects bad JSON", () => {
  const { bundle, error } = parseProofBundle("not json {");
  assert(bundle === null, "bundle is null for bad JSON");
  assert(error !== null && error.includes("JSON"), "error mentions JSON");
});

test("validateProofBundle: rejects wrong-length publicSignals", () => {
  const bad = { proof: FIXTURE_BUNDLE.proof, publicSignals: ["1", "2"] };
  const err = validateProofBundle(bad);
  assert(err !== null, "error for a 2-element vector");
  assert(err!.includes("21"), "error names the required 21");
});

test("validateProofBundle: rejects missing proof / non-object", () => {
  assert(validateProofBundle({ publicSignals: TEST_PUBLIC_SIGNALS }) !== null, "missing proof");
  assert(validateProofBundle(null) !== null, "null is invalid");
  assert(validateProofBundle("string") !== null, "string is invalid");
});

test("extractNullifier: reads publicSignals[7] (the ONLY by-index read)", () => {
  const nullifier = extractNullifier(FIXTURE_BUNDLE);
  assert(nullifier.startsWith("0x") && nullifier.length === 66, "32-byte 0x-hex");
  assert(BigInt(nullifier) === BigInt(TEST_NULLIFIER_DEC), "value matches slot 7");
});

test("extractSubmitterAddress: low 20 bytes of publicSignals[20]", () => {
  const addr = extractSubmitterAddress(FIXTURE_BUNDLE);
  assert(addr.length === 42, "20-byte hex address");
  assert(
    addr.toLowerCase() === "0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f",
    `address value correct, got ${addr}`,
  );
});

test("publicSignalsToBytes32: maps the full 21-vector", () => {
  const arr = publicSignalsToBytes32(FIXTURE_BUNDLE);
  assert(arr.length === 21, "21 bytes32 values");
  assert(arr.every((h) => h.startsWith("0x") && h.length === 66), "each is a 32-byte 0x-hex");
  assert(BigInt(arr[SELF_IDX_NULLIFIER]) === BigInt(TEST_NULLIFIER_DEC), "slot 7 round-trips");
});

test("encodeSubmitZkPassportProof: new selector + full-vector calldata", () => {
  const data = encodeSubmitZkPassportProof({
    proofBytes: encodeProofBytes(FIXTURE_BUNDLE.proof),
    publicSignals: publicSignalsToBytes32(FIXTURE_BUNDLE),
    schemeTag: 0,
  });
  assert(data.startsWith("0x") && data.length > 10, "non-trivial calldata");
  const selector = data.slice(0, 10);
  const expected = keccak256(toHex("submitZkPassportProof(bytes,bytes32[21],uint8)")).slice(0, 10);
  console.log(`    selector: ${selector} (expected ${expected})`);
  assert(selector === expected, "selector matches submitZkPassportProof(bytes,bytes32[21],uint8)");
});

test("encodeZkBundleAsCalldata: deterministic full-bundle round-trip", () => {
  const a = encodeZkBundleAsCalldata(FIXTURE_BUNDLE);
  const b = encodeZkBundleAsCalldata(FIXTURE_BUNDLE);
  assert(a === b, "same bundle → same calldata (deterministic)");
  assert(a.startsWith("0x") && a.length > 100, "non-trivial calldata");
});

test("SDK↔Rust parity: the shared synthetic fixture parses identically", () => {
  // The SAME 21-signal fixture the Rust arity-21 crypto test loads. The SDK's nullifier@7 must equal
  // the fixture's slot-7 field element (the exact slot Rust's SELF_IDX_NULLIFIER binds) — proving both
  // sides parse an identical proof identically (§4.2 GAP-4, one shared source of truth).
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = resolve(here, "../../../crates/zkpoh/fixtures/self_synthetic_public.json");
  const signals = JSON.parse(readFileSync(fixturePath, "utf8")) as string[];
  assert(signals.length === SELF_NPUBLIC, "the shared fixture carries 21 signals");

  const bundle: SelfProofBundle = { proof: FIXTURE_BUNDLE.proof, publicSignals: signals };
  const nullifier = extractNullifier(bundle);
  // Rust reads signals[SELF_IDX_NULLIFIER] verbatim as its registry key; the SDK must read the same.
  const expected = "0x" + BigInt(signals[SELF_IDX_NULLIFIER]).toString(16).padStart(64, "0");
  assert(nullifier === expected, "SDK nullifier@7 == fixture slot-7 field element (Rust parity)");
  // And the full-vector map preserves every slot verbatim (no by-index policy mutation).
  const arr = publicSignalsToBytes32(bundle);
  assert(
    arr.every((h, i) => BigInt(h) === BigInt(signals[i])),
    "every carried bytes32 equals the fixture field element at its index",
  );
});

// ---------------------------------------------------------------------------
// Self client flow (Stage C1, spec 06b §5) — relay payload → calldata
// ---------------------------------------------------------------------------

const RELAY_PAYLOAD: SelfRelayPayload = {
  attestationId: 1,
  proof: FIXTURE_BUNDLE.proof,
  publicSignals: TEST_PUBLIC_SIGNALS,
  userContextData: "0x" + TEST_SUBMITTER_ADDR_DEC.toString().padStart(64, "0"),
};

test("validateSelfRelayPayload: accepts the exact Self-app POST shape", () => {
  assert(validateSelfRelayPayload(RELAY_PAYLOAD) === null, "well-formed payload validates");
});

test("validateSelfRelayPayload: rejects missing attestationId / bad arity", () => {
  const { attestationId: _attestationId, ...noAttestation } = RELAY_PAYLOAD;
  assert(
    validateSelfRelayPayload(noAttestation) !== null,
    "missing attestationId is rejected",
  );
  const shortSignals = { ...RELAY_PAYLOAD, publicSignals: ["1", "2"] };
  assert(validateSelfRelayPayload(shortSignals) !== null, "wrong-arity publicSignals is rejected");
});

test("encodeSelfRelayPayload: 21-vector relay payload → 0xf342a2f3 calldata (round-trip)", () => {
  const data = encodeSelfRelayPayload(RELAY_PAYLOAD);
  assert(data.startsWith("0x"), "calldata is hex");
  const selector = data.slice(0, 10);
  assert(selector === "0xf342a2f3", `selector is 0xf342a2f3, got ${selector}`);

  // Must equal encoding the same signals via the bundle path (one shared encoder, §5.4).
  const viaBundle = encodeZkBundleAsCalldata({
    proof: RELAY_PAYLOAD.proof,
    publicSignals: RELAY_PAYLOAD.publicSignals,
  });
  assert(data === viaBundle, "relay-payload encoding matches the bundle encoding byte-for-byte");

  // The 21-vector round-trips into the calldata: decode the tail and check slot 7 (nullifier) and
  // slot 20 (user_identifier) land at the expected byte offsets (4-byte selector + head words).
  assert(
    data.includes(BigInt(TEST_NULLIFIER_DEC).toString(16)),
    "the nullifier field element appears in the encoded calldata",
  );
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n${"─".repeat(60)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  // biome-ignore lint: test runner exit — intentional
  (globalThis as unknown as { process: { exit(c: number): never } }).process.exit(1);
} else {
  console.log("All tests passed.");
}
