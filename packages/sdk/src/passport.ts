/**
 * @ubi2/sdk/passport — M6 ZK-passport proof-of-humanity client.
 *
 * Implements the client side of the `submitZkPassportProof` flow (spec §4.1, §9):
 *  - A typed encoder for the `submitZkPassportProof` HumanityHub op (ABI-encoded calldata the
 *    same way the Rust `sol!` block decodes it, so the bytes match byte-for-byte).
 *  - A `sendZkPassportProof` helper: proof bundle (snarkjs JSON) → ABI-encoded calldata →
 *    submit via an injected EIP-1193 provider or a local private key.
 *  - Typed reads: assurance level, Pedersen attribute commitments, nullifier-used, CSCA registry.
 *
 * PRIVACY INVARIANT (spec I6, docs §"Hard Constraints"):
 *   Only opaque proof bundles and 32-byte commitments cross this module.  No raw passport
 *   field — document number, date of birth, nationality string — ever appears here.  The
 *   proof bundle itself (from the Self app or a test fixture) is the only personal-data
 *   artifact handled, and this module treats it as an opaque byte array.
 *
 * STAGE NOTE (Stage 2 / spec §12.2):
 *   The live in-app NFC scan (Stage C) depends on the Light-Node WASM prover and is out of
 *   scope here.  This module implements the "paste/upload a proof bundle" path: the user
 *   obtains a Self-app proof JSON, this module encodes + submits it, and reads back the
 *   resulting on-chain assurance level.
 */

import {
  createWalletClient,
  http,
  defineChain,
  encodeFunctionData,
  type Chain,
  type EIP1193Provider,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { HUMANITY_HUB } from "./humanity";

// ---------------------------------------------------------------------------
// Assurance level (spec §5.1)
// ---------------------------------------------------------------------------

/**
 * On-chain assurance level for a verified human.
 *
 *   STD   — verified via M3 social vouching / AI-jury path only.
 *   ENH   — verified via ZK-passport proof alone (no prior vouching).
 *   DUAL  — verified via M3 vouching AND subsequently upgraded with a ZK-passport proof.
 *
 * Level is METADATA — it never gates UBI accrual (spec inclusion constraint, §5.1):
 * STD and ENH/DUAL humans are first-class and both stream UBI identically.
 */
export type AssuranceLevel = "STD" | "ENH" | "DUAL";

/** Human-readable label for an assurance level. */
export function assuranceLevelLabel(level: AssuranceLevel): string {
  const map: Record<AssuranceLevel, string> = {
    STD: "Standard (social vouching)",
    ENH: "Enhanced (ZK-passport)",
    DUAL: "Dual (vouching + ZK-passport)",
  };
  return map[level] ?? level;
}

/** Short badge text for the PoH card. */
export function assuranceLevelBadge(level: AssuranceLevel): string {
  return { STD: "STD", ENH: "ENH", DUAL: "DUAL" }[level] ?? level;
}

// ---------------------------------------------------------------------------
// Proof bundle shape (snarkjs JSON output from the Self app — opaque inputs)
// ---------------------------------------------------------------------------

/**
 * A ZK-passport proof bundle in snarkjs Groth16 JSON format.
 *
 * This is the JSON the Self mobile app (or any OpenPassport-compatible prover) exports.
 * We treat it as an opaque byte carrier — we do not inspect or interpret proof internals.
 *
 * Fields:
 *   proof        — The Groth16 proof: { pi_a, pi_b, pi_c } BN254 group elements (string arrays).
 *   publicSignals — The public inputs vector (ordered per spec §3.5 / Self layout): an array of
 *                   decimal-string field elements, exactly matching the VK's `nPublic`.
 *
 * The `nullifier` and `attributeCommitments` we extract from `publicSignals` are always the
 * same field elements that go on-chain — we never decode what they represent.
 */
export interface SelfProofBundle {
  proof: {
    pi_a: [string, string, string];
    pi_b: [[string, string], [string, string], [string, string]];
    pi_c: [string, string, string];
    protocol?: string;
    curve?: string;
  };
  publicSignals: string[];
}

// ---------------------------------------------------------------------------
// Public-input layout — the CONFIRMED Self `vc_and_disclose` 21-signal layout
// (spec 06b §4.1; SELF_NPUBLIC = 21, VK IC.len() == 22).
// ---------------------------------------------------------------------------

/**
 * The number of public signals the real Self `vc_and_disclose` statement carries (spec 06b §4.1).
 * Mirrors `ubi2_runtime::SELF_NPUBLIC` (= 21). The full vector is carried on-chain verbatim
 * (`bytes32[21]`, §4.3) and the runtime binds the policy slots BY INDEX — the SDK no longer
 * extracts policy fields; it passes the whole vector.
 */
export const SELF_NPUBLIC = 21;

/**
 * The canonical public-input slot indices (spec 06b §4.1, CONFIRMED). These constants mirror
 * `crates/runtime::SELF_IDX_*` / `crates/zkpoh::self_layout` exactly — the single shared source of
 * truth (§4.2 GAP-4). circom orders public signals as OUTPUTS (declaration order) then public
 * INPUTS in DECLARATION order, and `forbidden_countries_list_packed` is 4 elements.
 *
 *   0,1,2   revealedData_packed[3]                (opaque attribute commitments — I6)
 *   3,4,5,6 forbidden_countries_list_packed[4]    (pass-through)
 *   7       nullifier            = Poseidon(secret, scope)   ← the ONLY slot the SDK reads
 *   8       attestation_id       (== 1 for E-Passport)
 *   9       merkle_root          (∈ accepted Self identity roots)
 *  10..15   current_date[6]      (YYMMDD ASCII)
 *  16,17,18 ofac_*_smt_root
 *  19       scope                (== UBI2_SELF_SCOPE)
 *  20       user_identifier      (== submitter address)
 */
export const SELF_IDX_REVEALED_DATA = 0;
export const SELF_IDX_FORBIDDEN_COUNTRIES = 3;
export const SELF_IDX_NULLIFIER = 7;
export const SELF_IDX_ATTESTATION_ID = 8;
export const SELF_IDX_MERKLE_ROOT = 9;
export const SELF_IDX_CURRENT_DATE = 10;
export const SELF_IDX_OFAC_PASSPORTNO = 16;
export const SELF_IDX_OFAC_NAMEDOB = 17;
export const SELF_IDX_OFAC_NAMEYOB = 18;
export const SELF_IDX_SCOPE = 19;
export const SELF_IDX_USER_IDENTIFIER = 20;

/**
 * Extract the `nullifier` (bytes32) from a Self proof bundle's publicSignals — slot 7 (§4.1).
 *
 * This is the ONLY by-index read the SDK performs, and it is for the `ubi_isNullifierUsed`
 * pre-check display ONLY (§4.2 GAP-4): the on-chain policy binding derives every slot itself from
 * the full carried vector, so the SDK never extracts attribute-commitments / merkle-root / OFAC
 * roots by index anymore. Returns the field element as a big-endian 32-byte hex string.
 */
export function extractNullifier(bundle: SelfProofBundle): Hex {
  return fieldElementToBytes32(bundle.publicSignals[SELF_IDX_NULLIFIER]);
}

/**
 * Extract the submitter address bound into a Self proof bundle — `user_identifier` slot 20 (§4.1).
 * The proof binds to this address; the tx sender must match on-chain (anti-replay, §4.4). This is a
 * display / pre-check read only — the runtime re-binds `signals[20] == tx sender` itself.
 * Returns a 0x-hex string (40 hex chars, 20 bytes).
 */
export function extractSubmitterAddress(bundle: SelfProofBundle): string {
  const raw = bundle.publicSignals[SELF_IDX_USER_IDENTIFIER];
  // The field element is the address as a big-endian uint256; take the low 20 bytes.
  const hex32 = fieldElementToBytes32(raw);
  return "0x" + hex32.slice(2 + 24); // drop 0x + 24 leading zero nibbles = 20 bytes
}

/**
 * Convert a proof bundle's full `publicSignals` vector to the `bytes32[21]` array the on-chain op
 * carries (spec 06b §4.3). Each decimal field element → a big-endian 32-byte hex string, in order.
 * Throws if the vector is not exactly [`SELF_NPUBLIC`] long (fail-closed shape check).
 */
export function publicSignalsToBytes32(bundle: SelfProofBundle): Hex[] {
  if (bundle.publicSignals.length !== SELF_NPUBLIC) {
    throw new Error(
      `publicSignals has ${bundle.publicSignals.length} elements; the Self layout requires exactly ${SELF_NPUBLIC}.`,
    );
  }
  return bundle.publicSignals.map(fieldElementToBytes32);
}

/**
 * Convert a decimal-string BN254 field element to a 32-byte (bytes32) 0x-hex string.
 * Used for all proof bundle → calldata conversions.
 */
function fieldElementToBytes32(decimal: string): Hex {
  let n = BigInt(decimal);
  const hex = n.toString(16).padStart(64, "0");
  return `0x${hex}` as Hex;
}

// ---------------------------------------------------------------------------
// Proof bytes encoder (snarkjs JSON → Groth16 canonical bytes)
// ---------------------------------------------------------------------------

/**
 * Encode a snarkjs Groth16 proof JSON into the canonical byte encoding the runtime expects.
 *
 * The Rust verifier (`crates/zkpoh`) expects the proof as 3 BN254 group-element pairs:
 *   [32 bytes A_x][32 bytes A_y][64 bytes B (4×32)][32 bytes C_x][32 bytes C_y] = 192 bytes
 *
 * snarkjs `pi_b` is [ [x_high, x_low], [y_high, y_low], [1, 0] ] (G2, reverse of arkworks).
 * We encode in the order the arkworks Groth16 deserializer expects: A, B, C.
 *
 * PRIVACY: proof bytes are opaque group elements — no document data, no personal information.
 */
export function encodeProofBytes(proof: SelfProofBundle["proof"]): Uint8Array {
  const enc = (s: string) => fieldElementToU8Array32(s);

  // G1 element (x, y) = 64 bytes each; uncompressed encoding.
  const A = new Uint8Array([...enc(proof.pi_a[0]), ...enc(proof.pi_a[1])]);

  // G2 element: pi_b[0] = x coefficients [high, low], pi_b[1] = y coefficients [high, low].
  // arkworks G2Affine uncompressed: (x_c0, x_c1, y_c0, y_c1) = 128 bytes.
  // snarkjs stores as [[x_c1, x_c0], [y_c1, y_c0], ...] (reversed order).
  const B = new Uint8Array([
    ...enc(proof.pi_b[0][1]), // x_c0
    ...enc(proof.pi_b[0][0]), // x_c1
    ...enc(proof.pi_b[1][1]), // y_c0
    ...enc(proof.pi_b[1][0]), // y_c1
  ]);

  const C = new Uint8Array([...enc(proof.pi_c[0]), ...enc(proof.pi_c[1])]);

  const out = new Uint8Array(A.length + B.length + C.length);
  out.set(A, 0);
  out.set(B, A.length);
  out.set(C, A.length + B.length);
  return out;
}

function fieldElementToU8Array32(decimal: string): Uint8Array {
  const hex = BigInt(decimal).toString(16).padStart(64, "0");
  const buf = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

// ---------------------------------------------------------------------------
// ABI: submitZkPassportProof calldata encoder
// ---------------------------------------------------------------------------

// The Stage-C op ABI (spec 06b §4.3): the FULL 21-element public vector is carried on-chain; the
// runtime derives + binds every policy slot by index. Selector must match the Rust `sol!` decode:
// keccak256("submitZkPassportProof(bytes,bytes32[21],uint8)")[0..4].
const SUBMIT_ZK_PASSPORT_PROOF_ABI = [
  {
    type: "function",
    name: "submitZkPassportProof",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicSignals", type: "bytes32[21]" },
      { name: "schemeTag", type: "uint8" },
    ],
    outputs: [],
  },
] as const;

/** A fixed 21-element `bytes32` tuple — the exact shape viem's `bytes32[21]` ABI arg expects. */
type Bytes32x21 = readonly [
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
];

/** Parameters for `encodeSubmitZkPassportProof` (spec 06b §4.3). */
export interface ZkPassportProofParams {
  /** ABI-encoded proof bytes (use `encodeProofBytes` to convert a snarkjs JSON proof). */
  proofBytes: Uint8Array;
  /**
   * The FULL Self `vc_and_disclose` public vector as `bytes32[21]` (snarkjs order, §4.1). Use
   * `publicSignalsToBytes32(bundle)`. The runtime binds every policy slot itself — no by-index
   * extraction here (§4.2 GAP-4).
   */
  publicSignals: Hex[];
  /** Scheme tag (0 = Self e-passport; the runtime binds `attestation_id == 1` for tag 0). */
  schemeTag?: number;
}

/**
 * ABI-encode a `submitZkPassportProof(proof, publicSignals[21], schemeTag)` calldata for HumanityHub
 * (spec 06b §4.3).
 *
 * Pass this as `data` to `sendHumanityTx` or `eth_sendTransaction`. The submitter address is NOT in
 * calldata — it is the tx sender, bound against `publicSignals[20]` on-chain (anti-replay, §4.4).
 */
export function encodeSubmitZkPassportProof(params: ZkPassportProofParams): Hex {
  const schemeTag = params.schemeTag ?? 0;
  if (params.publicSignals.length !== SELF_NPUBLIC) {
    throw new Error(
      `encodeSubmitZkPassportProof: publicSignals must be exactly ${SELF_NPUBLIC} bytes32 values, got ${params.publicSignals.length}.`,
    );
  }
  // viem encodeFunctionData for `bytes` type expects a 0x-prefixed hex string.
  const proofHex = u8ArrayToHex(params.proofBytes);

  // viem types the arg as a fixed 21-tuple; we validated the length above, so the cast is safe.
  const signals = params.publicSignals as unknown as Bytes32x21;
  return encodeFunctionData({
    abi: SUBMIT_ZK_PASSPORT_PROOF_ABI,
    functionName: "submitZkPassportProof",
    args: [proofHex, signals, schemeTag],
  });
}

/** Convert a Uint8Array to a 0x-prefixed hex string (for viem `bytes` ABI encoding). */
function u8ArrayToHex(arr: Uint8Array): Hex {
  const hex = Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `0x${hex}` as Hex;
}

/**
 * One-shot helper: encode a Self proof bundle into `submitZkPassportProof` calldata (spec 06b §4.3).
 *
 * Encodes the proof bytes and passes the FULL 21-element public vector through unmodified — no
 * by-index policy extraction (the runtime binds every slot itself). The submitter address is the tx
 * sender, bound against `publicSignals[20]` on-chain.
 */
export function encodeZkBundleAsCalldata(bundle: SelfProofBundle): Hex {
  return encodeSubmitZkPassportProof({
    proofBytes: encodeProofBytes(bundle.proof),
    publicSignals: publicSignalsToBytes32(bundle),
    schemeTag: 0,
  });
}

// ---------------------------------------------------------------------------
// Send helper (mirrors sendHumanityTx)
// ---------------------------------------------------------------------------

/** The minimal ubi2 viem Chain definition. */
function ubi2PassportChain(rpcUrl: string): Chain {
  return defineChain({
    id: 0x5542,
    name: "ubi2 devnet",
    nativeCurrency: { name: "UBI", symbol: "UBI", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

/** Options for `sendZkPassportProof`. Provide exactly one signer. */
export interface SendZkPassportOptions {
  /** ABI-encoded calldata from `encodeSubmitZkPassportProof` or `encodeZkBundleAsCalldata`. */
  data: Hex;
  /** Sender address — required for injected-provider path. */
  from?: string;
  /** Injected EIP-1193 provider (e.g. `window.ethereum`). */
  provider?: EIP1193Provider;
  /** Local private key (devnet/tests). */
  privateKey?: Hex;
  /** RPC URL (required for the private-key path). */
  rpcUrl?: string;
}

/** Result of submitting a ZK passport proof. */
export interface ZkPassportTxResult {
  hash: Hex;
}

/**
 * Submit a `submitZkPassportProof` transaction to HumanityHub via an injected provider or a
 * local private key. Returns the transaction hash.
 *
 * After mining, call `ZkPassportReader.getHuman(address)` to read back the resulting
 * assurance level (ENH for a new address, DUAL for an existing STD-Verified address).
 */
export async function sendZkPassportProof(
  opts: SendZkPassportOptions,
): Promise<ZkPassportTxResult> {
  if (opts.provider) {
    if (!opts.from)
      throw new Error("sendZkPassportProof: `from` is required with an injected provider");
    const hash = (await opts.provider.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: opts.from as Hex,
          to: HUMANITY_HUB,
          value: "0x0",
          data: opts.data,
        },
      ],
    })) as Hex;
    return { hash };
  }

  if (opts.privateKey) {
    if (!opts.rpcUrl)
      throw new Error("sendZkPassportProof: `rpcUrl` is required with a private key");
    const account = privateKeyToAccount(opts.privateKey);
    const chain = ubi2PassportChain(opts.rpcUrl);
    const wallet = createWalletClient({ account, chain, transport: http(opts.rpcUrl) });
    const hash = await wallet.sendTransaction({
      to: HUMANITY_HUB,
      value: 0n,
      data: opts.data,
      gas: 800000n, // GAS_ZKPOH is the heaviest op; supply explicitly.
      gasPrice: 0n,
    });
    return { hash };
  }

  throw new Error("sendZkPassportProof: provide either `provider` or `privateKey`");
}

// ---------------------------------------------------------------------------
// Typed reads (spec §9: ubi_getAttributes, ubi_isNullifierUsed, ubi_getCscaRegistry)
// ---------------------------------------------------------------------------

/** The three opaque Pedersen attribute commitments returned by `ubi_getAttributes`. */
export interface AttributeCommitments {
  /** Age-threshold commitment (opaque 32-byte hex; no DOB — I6). */
  ageCommitment: string | null;
  /** Nationality-bucket commitment (opaque 32-byte hex; no country code — I6). */
  nationalityCommitment: string | null;
  /** Document-expiry commitment (opaque 32-byte hex; no exact date — I6). */
  expiryCommitment: string | null;
}

/** A single CSCA trust-anchor entry (sovereign signing key, no PII). */
export interface CscaEntry {
  /** ICAO 3-letter country code (e.g. `"USA"`). */
  country_code: string;
  /** 32-byte hex fingerprint of the CSCA public key. */
  key_id: string;
  /** Raw CSCA public key bytes (0x-hex). */
  pubkey: string;
  /** Unix seconds when this entry was registered. */
  added_at: number;
  /** `"Active"` or `"Revoked"`. */
  status: "Active" | "Revoked";
}

/** Response from `ubi_getCscaRegistry`. */
export interface CscaRegistry {
  /** 32-byte hex commitment over the sorted Active CSCA entries (spec §7.2). */
  root: string;
  /** Sorted Active CSCA entries (Revoked entries excluded). */
  entries: CscaEntry[];
}

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * ZK-passport reads layered over any object that exposes a JSON-RPC `call`
 * (the existing `Ubi2Client` qualifies). All returns are opaque — no PII (I6).
 */
export class ZkPassportReader {
  private readonly rpc: JsonRpcCaller;
  constructor(rpc: JsonRpcCaller) {
    this.rpc = rpc;
  }

  /**
   * `ubi_getAttributes(address)` — the three opaque Pedersen attribute commitments for an
   * ENH/DUAL-verified human, or nulls for an STD-only / unverified human.
   *
   * The commitments are perfectly hiding (Pedersen with per-attribute blinding) — revealing them
   * here reveals nothing about the underlying attributes (spec §3.4 / EC-8 / I6).
   */
  async getAttributes(address: string): Promise<AttributeCommitments> {
    return this.rpc.call<AttributeCommitments>("ubi_getAttributes", [address]);
  }

  /**
   * `ubi_isNullifierUsed(nullifier)` — check if a nullifier is already spent.
   * A client should call this before starting proof generation to give early feedback.
   * The nullifier itself reveals nothing beyond its spent/unspent status.
   */
  async isNullifierUsed(nullifier: Hex): Promise<boolean> {
    return this.rpc.call<boolean>("ubi_isNullifierUsed", [nullifier]);
  }

  /**
   * `ubi_getCscaRegistry()` — the sorted Active CSCA trust-anchor entries + the current
   * registry root. A prover needs the current root to build a proof against the live trust set.
   * CSCA entries are sovereign public keys, not personal data.
   */
  async getCscaRegistry(): Promise<CscaRegistry> {
    return this.rpc.call<CscaRegistry>("ubi_getCscaRegistry");
  }
}

// ---------------------------------------------------------------------------
// Proof-bundle validation (client-side, no crypto — shape check only)
// ---------------------------------------------------------------------------

/**
 * Validate the shape of a parsed proof bundle (before attempting to submit).
 * Does NOT verify the cryptographic proof — only checks that the JSON has the expected fields
 * and the publicSignals vector is non-empty.
 *
 * Returns an error message string if invalid, or `null` if the shape looks correct.
 */
export function validateProofBundle(parsed: unknown): string | null {
  if (!parsed || typeof parsed !== "object") return "Proof bundle must be a JSON object.";
  const p = parsed as Record<string, unknown>;

  if (!p.proof || typeof p.proof !== "object")
    return "Missing `proof` field (expected Groth16 proof object).";

  const proof = p.proof as Record<string, unknown>;
  if (!Array.isArray(proof.pi_a) || proof.pi_a.length < 2)
    return "proof.pi_a must be an array of at least 2 elements.";
  if (!Array.isArray(proof.pi_b) || proof.pi_b.length < 2)
    return "proof.pi_b must be an array of at least 2 elements.";
  if (!Array.isArray(proof.pi_c) || proof.pi_c.length < 2)
    return "proof.pi_c must be an array of at least 2 elements.";

  if (!Array.isArray(p.publicSignals) || (p.publicSignals as unknown[]).length === 0)
    return "Missing `publicSignals` array (public inputs vector).";

  const signals = p.publicSignals as unknown[];
  if (signals.length !== SELF_NPUBLIC)
    return `publicSignals has ${signals.length} elements; the confirmed Self layout requires exactly ${SELF_NPUBLIC}.`;

  return null; // valid shape
}

/**
 * Parse and validate a proof bundle from a JSON string.
 * Returns `{bundle, error}` — if `error` is non-null, `bundle` is null.
 */
export function parseProofBundle(json: string): { bundle: SelfProofBundle | null; error: string | null } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    return { bundle: null, error: `Invalid JSON: ${e instanceof Error ? e.message : String(e)}` };
  }
  const err = validateProofBundle(parsed);
  if (err) return { bundle: null, error: err };
  return { bundle: parsed as SelfProofBundle, error: null };
}
