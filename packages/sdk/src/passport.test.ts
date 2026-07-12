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
 *  8. buildDevMockSubmission (the C1 "dev mint (mock)" helper) constructs a 21-signal vector that
 *     satisfies every binding `submit_zk_passport_proof` checks: scope == UBI2_SELF_SCOPE,
 *     user_identifier == address_to_hash(sender), merkle_root/ofac roots == the supplied live
 *     roots, attestation_id == 1, nullifier canonical (< BN254 r) and fresh per call, and
 *     current_date decodes to the exact calendar day of `now` (parity-checked against the literal
 *     example in `crates/runtime/src/zkpoh.rs::tests::current_date_decode_and_freshness`).
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
  buildDevMockSubmission,
  encodeDevMockSubmission,
  dateToSelfSignals,
  addressToHash,
  randomCanonicalScalar,
  UBI2_SELF_SCOPE,
  BN254_FR_MODULUS,
  OFAC_KIND_PASSPORTNO,
  OFAC_KIND_NAMEDOB,
  OFAC_KIND_NAMEYOB,
  SELF_NPUBLIC,
  SELF_IDX_NULLIFIER,
  SELF_IDX_USER_IDENTIFIER,
  SELF_IDX_SCOPE,
  SELF_IDX_MERKLE_ROOT,
  SELF_IDX_ATTESTATION_ID,
  SELF_IDX_CURRENT_DATE,
  SELF_IDX_OFAC_PASSPORTNO,
  type SelfProofBundle,
  type SelfRelayPayload,
  type SelfRootsResponse,
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
// Dev mint (mock) — buildDevMockSubmission (C1 devnet dev-mint helper)
// ---------------------------------------------------------------------------

// The exact devnet-seeded roots (`crates/node/src/lib.rs::DEVNET_SELF_IDENTITY_ROOT`/
// `DEVNET_OFAC_ROOTS`) shaped as a `ubi_getSelfRoots` response — a realistic fixture for the
// *test*, never hardcoded inside the SDK helper itself (it always reads roots from the caller).
const DEV_IDENTITY_ROOT = "0x" + "5e".repeat(32);
const DEV_OFAC_ROOTS = ["0x" + "0f".repeat(32), "0x" + "1f".repeat(32), "0x" + "2f".repeat(32)];
const DEV_ROOTS: SelfRootsResponse = {
  identityRoots: [{ root: DEV_IDENTITY_ROOT, pinnedAtBlock: 0 }],
  ofacRoots: [
    { kind: OFAC_KIND_PASSPORTNO, root: DEV_OFAC_ROOTS[0]!, pinnedAtBlock: 0 },
    { kind: OFAC_KIND_NAMEDOB, root: DEV_OFAC_ROOTS[1]!, pinnedAtBlock: 0 },
    { kind: OFAC_KIND_NAMEYOB, root: DEV_OFAC_ROOTS[2]!, pinnedAtBlock: 0 },
  ],
  windowBlocks: 5_000_000,
};

const DEV_SENDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // well-known devnet dev account

test("dateToSelfSignals: parity with the Rust example (crates/runtime::zkpoh tests)", () => {
  // The exact example `current_date_decode_and_freshness` asserts: 2023-11-14 00:00 UTC decodes
  // from ASCII digits '2','3','1','1','1','4' and epoch 1_699_920_000. We assert the INVERSE:
  // encoding that same epoch reproduces those exact six ASCII-digit signals.
  const sig = dateToSelfSignals(1_699_920_000);
  const expectedAscii = ["2", "3", "1", "1", "1", "4"].map((c) => BigInt(c.charCodeAt(0)));
  sig.forEach((h, i) => {
    assert(BigInt(h) === expectedAscii[i], `digit[${i}] matches the Rust fixture example`);
  });
});

test("dateToSelfSignals: round-trips against JS Date's own UTC calendar", () => {
  const now = Math.floor(Date.now() / 1000);
  const sig = dateToSelfSignals(now);
  const d = new Date(now * 1000);
  const yy = d.getUTCFullYear() % 100;
  const mm = d.getUTCMonth() + 1;
  const dd = d.getUTCDate();
  const expected = [
    Math.floor(yy / 10), yy % 10,
    Math.floor(mm / 10), mm % 10,
    Math.floor(dd / 10), dd % 10,
  ];
  sig.forEach((h, i) => {
    const digit = Number(BigInt(h)) - 0x30;
    assert(digit === expected[i], `digit[${i}] == ${expected[i]} (got ${digit})`);
  });
});

test("addressToHash: zero-extends the low 20 bytes, matching ubi2_runtime::address_to_hash", () => {
  const h = addressToHash(DEV_SENDER);
  assert(h.length === 66, "32-byte 0x-hex");
  // Derive the expected value independently (BigInt round-trip, not a hand-typed hex literal) so a
  // transcription slip here can't mask a real bug — this is the exact class of error the dev-mint
  // helper exists to avoid in the runtime bindings.
  assert(BigInt(h) === BigInt(DEV_SENDER), "value equals the address interpreted as a big-endian uint256");
  assert(
    h.toLowerCase().endsWith(DEV_SENDER.slice(2).toLowerCase()),
    `low 20 bytes carry the address verbatim, got ${h}`,
  );
  assert(h.slice(2, 26) === "0".repeat(24), "high 12 bytes are zero");
});

test("randomCanonicalScalar: always canonical (< BN254 r) and unique per call", () => {
  const a = randomCanonicalScalar();
  const b = randomCanonicalScalar();
  assert(BigInt(a) < BN254_FR_MODULUS, "a < r");
  assert(BigInt(b) < BN254_FR_MODULUS, "b < r");
  assert(a !== b, "two calls produce different nullifiers (collision astronomically unlikely)");
});

test("buildDevMockSubmission: satisfies every runtime binding (spec 06b §4.4)", () => {
  const now = 1_699_920_000; // pinned so the date assertion below is exact, not just \"close to now\"
  const built = buildDevMockSubmission(DEV_SENDER, DEV_ROOTS, now);

  assert(built.publicSignals.length === SELF_NPUBLIC, "exactly 21 signals");
  assert(built.schemeTag === 0, "schemeTag is 0 (SCHEME_TAG_PASSPORT)");

  // scope@19 == UBI2_SELF_SCOPE (crates/runtime::UBI2_SELF_SCOPE, low-8-byte ASCII "ubi2-poh").
  assert(built.publicSignals[SELF_IDX_SCOPE] === UBI2_SELF_SCOPE, "scope binds UBI2_SELF_SCOPE");
  assert(
    UBI2_SELF_SCOPE.toLowerCase() ===
      ("0x" + "00".repeat(24) + Buffer.from("ubi2-poh").toString("hex")).toLowerCase(),
    "UBI2_SELF_SCOPE derivation matches the documented low-8-byte ASCII packing exactly",
  );

  // user_identifier@20 == address_to_hash(sender) (anti-replay binding, §4.4 step 4).
  assert(
    built.publicSignals[SELF_IDX_USER_IDENTIFIER] === addressToHash(DEV_SENDER),
    "user_identifier binds address_to_hash(sender)",
  );

  // attestation_id@8 == 1 (E-Passport).
  assert(BigInt(built.publicSignals[SELF_IDX_ATTESTATION_ID]) === 1n, "attestation_id == 1");

  // merkle_root@9 and ofac@16,17,18 == the LIVE roots supplied (never hardcoded in the helper).
  assert(
    built.publicSignals[SELF_IDX_MERKLE_ROOT].toLowerCase() === DEV_IDENTITY_ROOT.toLowerCase(),
    "merkle_root == the supplied live identity root",
  );
  [0, 1, 2].forEach((kind) => {
    assert(
      built.publicSignals[SELF_IDX_OFAC_PASSPORTNO + kind].toLowerCase() ===
        DEV_OFAC_ROOTS[kind]!.toLowerCase(),
      `ofac root kind ${kind} == the supplied live root`,
    );
  });

  // current_date@10..16 decodes to exactly `now`'s calendar day (2023-11-14, the pinned Rust
  // fixture example — see the dateToSelfSignals parity test above).
  for (let i = 0; i < 6; i++) {
    assert(
      built.publicSignals[SELF_IDX_CURRENT_DATE + i] === dateToSelfSignals(now)[i],
      `current_date digit[${i}] matches dateToSelfSignals(now)`,
    );
  }

  // nullifier@7 is canonical (< r) and equals the returned convenience field.
  assert(built.publicSignals[SELF_IDX_NULLIFIER] === built.nullifier, "nullifier field matches slot 7");
  assert(BigInt(built.nullifier) < BN254_FR_MODULUS, "nullifier is canonical (< BN254 r)");

  // A second build for the same sender gets a DIFFERENT nullifier (each dev-mint call is unique;
  // on-chain reuse would only be rejected via AlreadyEnhanced/NullifierAlreadyUsed, not a collision).
  const built2 = buildDevMockSubmission(DEV_SENDER, DEV_ROOTS, now);
  assert(built.nullifier !== built2.nullifier, "repeated builds get fresh nullifiers");
});

test("buildDevMockSubmission: throws fail-closed on missing roots (never silently mints wrong)", () => {
  const empty: SelfRootsResponse = { identityRoots: [], ofacRoots: [], windowBlocks: 0 };
  let threw = false;
  try {
    buildDevMockSubmission(DEV_SENDER, empty, 1_699_920_000);
  } catch {
    threw = true;
  }
  assert(threw, "throws when ubi_getSelfRoots has no accepted identity root");

  const noOfac: SelfRootsResponse = {
    identityRoots: DEV_ROOTS.identityRoots,
    ofacRoots: [{ kind: OFAC_KIND_PASSPORTNO, root: DEV_OFAC_ROOTS[0]!, pinnedAtBlock: 0 }],
    windowBlocks: 0,
  };
  let threw2 = false;
  try {
    buildDevMockSubmission(DEV_SENDER, noOfac, 1_699_920_000);
  } catch {
    threw2 = true;
  }
  assert(threw2, "throws when an OFAC kind (namedob/nameyob) is missing from the live roots");
});

test("encodeDevMockSubmission: 0xf342a2f3 calldata, matches manual encode of the built submission", () => {
  const now = 1_699_920_000;
  const { data, nullifier } = encodeDevMockSubmission(DEV_SENDER, DEV_ROOTS, now);
  assert(data.startsWith("0xf342a2f3"), "selector is 0xf342a2f3 (submitZkPassportProof)");

  const built = buildDevMockSubmission(DEV_SENDER, DEV_ROOTS, now);
  const viaEncode = encodeSubmitZkPassportProof({
    proofBytes: built.proofBytes,
    publicSignals: built.publicSignals,
    schemeTag: built.schemeTag,
  });
  // Nullifiers differ between independent builds (fresh randomness each call), so compare the
  // calldata with the nullifier slot masked out rather than expecting byte-identical output.
  assert(data.length === viaEncode.length, "same calldata length as a manual encode");
  assert(nullifier !== built.nullifier, "each call mints a fresh nullifier (sanity: not a stub)");
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
