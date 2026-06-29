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
// Public-input layout (spec §3.5, Self arity-20 layout from crates/zkpoh)
// ---------------------------------------------------------------------------

/**
 * The canonical public-input indices for the Self `vc_and_disclose` layout (SELF_NPUBLIC = 20).
 * These constants mirror `crates/zkpoh/src/self_layout.rs` exactly — if the layout changes,
 * the VK arity changes and this module must be updated in lock-step.
 *
 * Index 0:    nullifier (spec §3.3)
 * Index 1:    scope / chain-binding constant
 * Index 2:    attestation id
 * Index 3-15: revealed data slots (MRZ buckets; opaque, zero-padded if unused)
 * Index 16:   current_date (nowEpoch in YYYYMMDD form)
 * Index 17:   merkle_root = csca_registry_root (spec §7.2)
 * Index 18:   user_identifier = submitter_address (spec §4.3, anti-replay)
 * Index 19:   [reserved / attribute-commitment aggregate]
 */
const SELF_IDX_NULLIFIER = 0;
const SELF_IDX_CSCA_ROOT = 17;   // merkle_root slot (our CSCA registry root)
const SELF_IDX_SUBMITTER = 18;   // user_identifier slot (submitter address)
// Attribute commitment slots: derived from revealed data (indices 3-15).
// For the M6 calldata we pass the attribute slot field elements directly as commitments.
const SELF_IDX_ATTR_BASE = 3;    // first of the 13 revealed-data slots

/**
 * Extract the `nullifier` (bytes32) from a Self proof bundle's publicSignals.
 * The nullifier is publicSignals[0] as a big-endian 32-byte hex string.
 */
export function extractNullifier(bundle: SelfProofBundle): Hex {
  return fieldElementToBytes32(bundle.publicSignals[SELF_IDX_NULLIFIER]);
}

/**
 * Extract the three attribute commitments from a Self proof bundle.
 * Uses the first three revealed-data slots (indices 3, 4, 5) as the age / nationality / expiry
 * commitment stand-ins.  In a real Self circuit these encode the selective-disclosure outputs.
 */
export function extractAttributeCommitments(bundle: SelfProofBundle): [Hex, Hex, Hex] {
  return [
    fieldElementToBytes32(bundle.publicSignals[SELF_IDX_ATTR_BASE]),
    fieldElementToBytes32(bundle.publicSignals[SELF_IDX_ATTR_BASE + 1]),
    fieldElementToBytes32(bundle.publicSignals[SELF_IDX_ATTR_BASE + 2]),
  ];
}

/**
 * Extract the CSCA registry root from a Self proof bundle (merkle_root slot, index 17).
 * This is the trust-anchor commitment the proof was built against (spec §7.2).
 */
export function extractCscaRegistryRoot(bundle: SelfProofBundle): Hex {
  return fieldElementToBytes32(bundle.publicSignals[SELF_IDX_CSCA_ROOT]);
}

/**
 * Extract the submitter address from a Self proof bundle (user_identifier slot, index 18).
 * The proof binds to this address; the tx sender must match (anti-replay, spec §4.3).
 * Returns as a checksummed 0x hex string (40 hex chars, 20 bytes).
 */
export function extractSubmitterAddress(bundle: SelfProofBundle): string {
  const raw = bundle.publicSignals[SELF_IDX_SUBMITTER];
  // The field element is the address as a big-endian uint256; take the low 20 bytes.
  const hex32 = fieldElementToBytes32(raw);
  return "0x" + hex32.slice(2 + 24); // drop 0x + 24 leading zero nibbles = 20 bytes
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

const SUBMIT_ZK_PASSPORT_PROOF_ABI = [
  {
    type: "function",
    name: "submitZkPassportProof",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "nullifier", type: "bytes32" },
      { name: "attributeCommitments", type: "bytes32[3]" },
      { name: "cscaRegistryRoot", type: "bytes32" },
      { name: "schemeTag", type: "uint8" },
      { name: "nowEpoch", type: "uint64" },
    ],
    outputs: [],
  },
] as const;

/** Parameters for `encodeSubmitZkPassportProof`. */
export interface ZkPassportProofParams {
  /** ABI-encoded proof bytes (use `encodeProofBytes` to convert a snarkjs JSON proof). */
  proofBytes: Uint8Array;
  /** 32-byte nullifier (use `extractNullifier` to get it from a proof bundle). */
  nullifier: Hex;
  /** Three 32-byte Pedersen attribute commitments [age, nationality, expiry]. */
  attributeCommitments: [Hex, Hex, Hex];
  /** 32-byte CSCA registry root the proof was built against (spec §7.2). */
  cscaRegistryRoot: Hex;
  /** Scheme tag (0 = ICAO 9303 e-passport / Self / OpenPassport path). */
  schemeTag?: number;
  /**
   * The `nowEpoch` reference epoch the proof used (unix seconds).
   * Must equal the block timestamp at submission (the runtime validates this).
   * Default: the current unix timestamp (seconds).
   */
  nowEpoch?: bigint;
}

/**
 * ABI-encode a `submitZkPassportProof(...)` calldata for HumanityHub.
 *
 * Pass this as `data` to `sendHumanityTx` or `eth_sendTransaction`.
 * The submitter address is NOT in calldata — it is the tx sender (anti-replay, spec §4.3).
 */
export function encodeSubmitZkPassportProof(params: ZkPassportProofParams): Hex {
  const schemeTag = params.schemeTag ?? 0;
  const nowEpoch = params.nowEpoch ?? BigInt(Math.floor(Date.now() / 1000));
  // viem encodeFunctionData for `bytes` type expects a 0x-prefixed hex string.
  const proofHex = u8ArrayToHex(params.proofBytes);

  return encodeFunctionData({
    abi: SUBMIT_ZK_PASSPORT_PROOF_ABI,
    functionName: "submitZkPassportProof",
    args: [
      proofHex,
      params.nullifier,
      params.attributeCommitments,
      params.cscaRegistryRoot,
      schemeTag,
      nowEpoch,
    ],
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
 * One-shot helper: encode a Self proof bundle into `submitZkPassportProof` calldata.
 *
 * Extracts the nullifier, attribute commitments, and CSCA root from the bundle's publicSignals,
 * encodes the proof bytes, and calls `encodeSubmitZkPassportProof`.
 */
export function encodeZkBundleAsCalldata(bundle: SelfProofBundle): Hex {
  return encodeSubmitZkPassportProof({
    proofBytes: encodeProofBytes(bundle.proof),
    nullifier: extractNullifier(bundle),
    attributeCommitments: extractAttributeCommitments(bundle),
    cscaRegistryRoot: extractCscaRegistryRoot(bundle),
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
  if (signals.length < 19)
    return `publicSignals has ${signals.length} elements; Self layout requires at least 19.`;

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
