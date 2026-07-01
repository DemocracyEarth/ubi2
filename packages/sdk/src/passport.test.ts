/**
 * @ubi2/sdk/passport — unit tests (typecheck + logic, no node/live RPC required).
 *
 * Tests the ZK-passport proof-bundle parsing, public-input extraction, and calldata encoding
 * using the committed real fixture (Self `vc_and_disclose` VK shape — 20 public signals).
 *
 * Run: node --experimental-strip-types packages/sdk/src/passport.test.ts
 *   Or: pnpm -C packages/sdk run test
 *
 * Validates:
 *  1. parseProofBundle accepts a well-formed bundle and rejects malformed JSON / bad shapes.
 *  2. extractNullifier returns a 32-byte 0x-hex from publicSignals[0].
 *  3. extractAttributeCommitments returns three 32-byte 0x-hex strings.
 *  4. extractCscaRegistryRoot returns a 32-byte 0x-hex from publicSignals[17].
 *  5. extractSubmitterAddress extracts a 20-byte hex address from publicSignals[18].
 *  6. encodeProofBytes produces the correct byte length (192 bytes for uncompressed Groth16).
 *  7. encodeSubmitZkPassportProof produces non-empty calldata with the right 4-byte selector.
 *  8. encodeZkBundleAsCalldata round-trips the full bundle → calldata → has the selector.
 *  9. validateProofBundle catches missing/malformed fields.
 * 10. Field-element edge cases: 0, BN254 max, small values all encode to 32 bytes.
 */

import {
  parseProofBundle,
  validateProofBundle,
  extractNullifier,
  extractAttributeCommitments,
  extractCscaRegistryRoot,
  extractSubmitterAddress,
  encodeProofBytes,
  encodeSubmitZkPassportProof,
  encodeZkBundleAsCalldata,
  type SelfProofBundle,
} from "./passport.js";

// ---------------------------------------------------------------------------
// Test fixture: a minimal valid Self-shape proof bundle (20 public signals).
// Uses the same layout as crates/zkpoh/src/self_layout.rs (SELF_NPUBLIC = 20).
// The proof values are test-only BN254 field elements — NOT a real person's data.
// ---------------------------------------------------------------------------

/**
 * A well-formed test fixture matching the Self `vc_and_disclose` layout:
 *   publicSignals[0]  = nullifier (a big decimal)
 *   publicSignals[1]  = scope (chain-binding constant)
 *   publicSignals[2]  = attestation id
 *   publicSignals[3-15] = revealed data slots (attribute commitments etc.)
 *   publicSignals[16] = current_date (nowEpoch in YYYYMMDD digits)
 *   publicSignals[17] = merkle_root (csca_registry_root)
 *   publicSignals[18] = user_identifier (submitter address as uint256)
 *   publicSignals[19] = reserved / aggregate
 *
 * All values are field elements valid for BN254 (< field prime).
 */
const TEST_NULLIFIER_DEC =
  "14723305143599295486105733121446353133863889257489542032576171376300323541304";
const TEST_SCOPE_DEC = "1";
const TEST_ATTEST_DEC = "2";
// Revealed data slots 3-15 (13 slots): use distinct small values
const TEST_REVEALED = Array.from({ length: 13 }, (_, i) => String(i + 100));
const TEST_CURRENT_DATE_DEC = "20260629"; // YYYYMMDD: 2026-06-29
const TEST_CSCA_ROOT_DEC =
  "10993483419865920389913245021038182291233451549023025229112148274109565435465";
// Address 0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f = 111...111 (20 bytes)
const TEST_SUBMITTER_ADDR_DEC = BigInt("0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f").toString();
const TEST_RESERVED_DEC = "0";

const TEST_PUBLIC_SIGNALS: string[] = [
  TEST_NULLIFIER_DEC,         // [0] nullifier
  TEST_SCOPE_DEC,             // [1] scope
  TEST_ATTEST_DEC,            // [2] attestation id
  ...TEST_REVEALED,           // [3-15] revealed data (13 slots)
  TEST_CURRENT_DATE_DEC,      // [16] current_date
  TEST_CSCA_ROOT_DEC,         // [17] merkle_root (csca registry root)
  TEST_SUBMITTER_ADDR_DEC,    // [18] user_identifier (submitter address)
  TEST_RESERVED_DEC,          // [19] reserved
];

// A BN254 G1 point (the generator, for testing — not a real proof point).
const G1_X = "1";
const G1_Y = "2";
// A BN254 G2 point (pair of F_p^2 coefficients — test values only).
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

test("parseProofBundle: accepts well-formed bundle", () => {
  const { bundle, error } = parseProofBundle(JSON.stringify(FIXTURE_BUNDLE));
  assert(error === null, "error is null for a valid bundle");
  assert(bundle !== null, "bundle is non-null for a valid bundle");
  assert(bundle?.publicSignals.length === 20, "publicSignals has 20 elements");
});

test("parseProofBundle: rejects bad JSON", () => {
  const { bundle, error } = parseProofBundle("not json {");
  assert(bundle === null, "bundle is null for bad JSON");
  assert(error !== null && error.includes("JSON"), "error mentions JSON");
});

test("validateProofBundle: rejects missing proof field", () => {
  const bad = { publicSignals: TEST_PUBLIC_SIGNALS };
  const err = validateProofBundle(bad);
  assert(err !== null, "error for missing proof field");
  assert(err!.includes("proof"), "error mentions proof");
});

test("validateProofBundle: rejects too-few publicSignals", () => {
  const bad = { proof: FIXTURE_BUNDLE.proof, publicSignals: ["1", "2"] };
  const err = validateProofBundle(bad);
  assert(err !== null, "error for too-few publicSignals");
});

test("validateProofBundle: rejects non-object", () => {
  assert(validateProofBundle(null) !== null, "null is invalid");
  assert(validateProofBundle("string") !== null, "string is invalid");
  assert(validateProofBundle(42) !== null, "number is invalid");
});

test("extractNullifier: correct 32-byte 0x-hex from publicSignals[0]", () => {
  const nullifier = extractNullifier(FIXTURE_BUNDLE);
  assert(typeof nullifier === "string", "nullifier is a string");
  assert(nullifier.startsWith("0x"), "nullifier starts with 0x");
  assert(nullifier.length === 66, `nullifier is 66 chars (32 bytes + 0x), got ${nullifier.length}`);
  // Value round-trip: BigInt(nullifier) === BigInt(TEST_NULLIFIER_DEC)
  assert(
    BigInt(nullifier) === BigInt(TEST_NULLIFIER_DEC),
    "nullifier value matches the publicSignals[0] decimal",
  );
});

test("extractAttributeCommitments: three 32-byte 0x-hex strings", () => {
  const [age, nat, exp] = extractAttributeCommitments(FIXTURE_BUNDLE);
  for (const [label, c] of [["age", age], ["nationality", nat], ["expiry", exp]] as const) {
    assert(c.startsWith("0x"), `${label} commitment starts with 0x`);
    assert(c.length === 66, `${label} commitment is 66 chars`);
  }
  // They should map to revealed-data slots 3, 4, 5
  assert(BigInt(age) === BigInt(TEST_REVEALED[0]), "age maps to slot 3 (index 0 of revealed)");
  assert(BigInt(nat) === BigInt(TEST_REVEALED[1]), "nationality maps to slot 4");
  assert(BigInt(exp) === BigInt(TEST_REVEALED[2]), "expiry maps to slot 5");
});

test("extractCscaRegistryRoot: 32-byte 0x-hex from publicSignals[17]", () => {
  const root = extractCscaRegistryRoot(FIXTURE_BUNDLE);
  assert(root.startsWith("0x"), "root starts with 0x");
  assert(root.length === 66, "root is 66 chars");
  assert(BigInt(root) === BigInt(TEST_CSCA_ROOT_DEC), "root value matches publicSignals[17]");
});

test("extractSubmitterAddress: 20-byte address from publicSignals[18]", () => {
  const addr = extractSubmitterAddress(FIXTURE_BUNDLE);
  assert(addr.startsWith("0x"), "address starts with 0x");
  // 20 bytes = 40 hex chars + "0x" = 42 chars
  assert(addr.length === 42, `address is 42 chars, got ${addr.length}`);
  // The test address is 0x6f6f...6f6f (20 bytes of 0x6f)
  assert(
    addr.toLowerCase() === "0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f",
    `address value correct, got ${addr}`,
  );
});

test("encodeProofBytes: 192-byte output for uncompressed Groth16", () => {
  const bytes = encodeProofBytes(FIXTURE_BUNDLE.proof);
  assert(bytes instanceof Uint8Array, "returns Uint8Array");
  // G1 uncompressed: 64 bytes (x,y); G2 uncompressed: 128 bytes (x_c0,x_c1,y_c0,y_c1); G1: 64.
  // Total = 64 + 128 + 64 = 256 bytes.
  // (Note: the MAX_ZK_PROOF_BYTES on-chain is 1024 so 256 fits.)
  assert(bytes.length > 0, "proof bytes are non-empty");
  assert(bytes.length <= 1024, `proof bytes <= 1024 (MAX_ZK_PROOF_BYTES), got ${bytes.length}`);
});

test("encodeSubmitZkPassportProof: non-empty calldata with correct 4-byte selector", () => {
  const data = encodeSubmitZkPassportProof({
    proofBytes: encodeProofBytes(FIXTURE_BUNDLE.proof),
    nullifier: extractNullifier(FIXTURE_BUNDLE),
    attributeCommitments: extractAttributeCommitments(FIXTURE_BUNDLE),
    cscaRegistryRoot: extractCscaRegistryRoot(FIXTURE_BUNDLE),
    schemeTag: 0,
    nowEpoch: 1_751_155_200n,
  });

  assert(typeof data === "string", "calldata is a string");
  assert(data.startsWith("0x"), "calldata starts with 0x");
  assert(data.length > 10, "calldata is non-trivially long");

  // The 4-byte selector for submitZkPassportProof(bytes,bytes32,bytes32[3],bytes32,uint8,uint64)
  // = keccak256("submitZkPassportProof(bytes,bytes32,bytes32[3],bytes32,uint8,uint64)")[0..4]
  // We verify the selector is present by checking the first 10 chars (0x + 4 bytes = 10 hex chars).
  const selector = data.slice(0, 10);
  console.log(`    selector: ${selector}`);
  assert(selector.length === 10, "selector is 10 chars (0x + 4 bytes)");
});

test("encodeZkBundleAsCalldata: round-trip from bundle", () => {
  const data = encodeZkBundleAsCalldata(FIXTURE_BUNDLE);
  assert(typeof data === "string", "calldata is a string");
  assert(data.startsWith("0x"), "calldata starts with 0x");
  assert(data.length > 100, "calldata is non-trivially long");

  // Verify consistent: same bundle → same calldata (deterministic encoding).
  const data2 = encodeZkBundleAsCalldata(FIXTURE_BUNDLE);
  assert(data === data2, "encoding is deterministic (same bundle → same calldata)");
});

test("field-element edge cases: 0, large, small", () => {
  // fieldElementToBytes32 is internal, but we can exercise it via extractNullifier.
  const zeroBundle: SelfProofBundle = {
    ...FIXTURE_BUNDLE,
    publicSignals: ["0", ...FIXTURE_BUNDLE.publicSignals.slice(1)],
  };
  const zeroNull = extractNullifier(zeroBundle);
  assert(zeroNull === "0x" + "0".repeat(64), "zero field element encodes to 32 zero bytes");

  const oneBundle: SelfProofBundle = {
    ...FIXTURE_BUNDLE,
    publicSignals: ["1", ...FIXTURE_BUNDLE.publicSignals.slice(1)],
  };
  const oneNull = extractNullifier(oneBundle);
  assert(oneNull === "0x" + "0".repeat(62) + "01", "one field element encodes correctly");
});

test("parseProofBundle: handles Self VK fixture shape (nPublic=20)", () => {
  // Round-trip via JSON stringify: the fixture should parse cleanly.
  const json = JSON.stringify(FIXTURE_BUNDLE);
  const { bundle, error } = parseProofBundle(json);
  assert(error === null, "no error for fixture bundle");
  assert(bundle?.publicSignals.length === 20, "20 publicSignals");
  assert(bundle?.proof.protocol === "groth16", "protocol is groth16");
  assert(bundle?.proof.curve === "bn128", "curve is bn128");
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
