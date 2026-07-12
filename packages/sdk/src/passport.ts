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

/** A single accepted Self identity-commitment root entry (spec 06b §2.2). */
export interface SelfIdentityRootEntry {
  /** The Poseidon Lean-IMT root (32-byte hex). */
  root: string;
  /** Block height governance pinned it at (the freshness-window clock). */
  pinnedAtBlock: number;
}

/** A single accepted Self OFAC SMT root entry (spec 06b §2.2). */
export interface SelfOfacRootEntry {
  /** `0 = passportno`, `1 = namedob`, `2 = nameyob` (mirrors `SELF_IDX_OFAC_*` slot order). */
  kind: number;
  /** The OFAC SMT root (32-byte hex). */
  root: string;
  /** Block height governance pinned it at. */
  pinnedAtBlock: number;
}

/** Response from `ubi_getSelfRoots` — the LIVE accepted trust anchors a proof must bind against. */
export interface SelfRootsResponse {
  /** The accepted Self identity-commitment roots (`merkle_root` slot 9 must be a member). */
  identityRoots: SelfIdentityRootEntry[];
  /** The accepted OFAC SMT roots, one set per kind (slots 16/17/18 must each be a member). */
  ofacRoots: SelfOfacRootEntry[];
  /** The freshness window (in blocks) a pinned root stays valid for (spec 06b §2.2). */
  windowBlocks: number;
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

  /**
   * `ubi_getSelfRoots()` — the LIVE accepted Self identity + OFAC roots (spec 06b §2.2/§8). A
   * client (real prover or [`buildDevMockSubmission`]) reads this to know which `merkle_root` /
   * `ofac_*_root` values the runtime currently binds against, rather than hardcoding a devnet
   * constant that could drift from the live chain.
   */
  async getSelfRoots(): Promise<SelfRootsResponse> {
    return this.rpc.call<SelfRootsResponse>("ubi_getSelfRoots");
  }
}

// ---------------------------------------------------------------------------
// Dev mint (mock) — a BINDING-CORRECT submission for devnets running the MockZkVerifier
// (spec 06b §6.3; `crates/runtime::MockZkVerifier`, the devnet consensus default).
//
// The dev-fixture (`/api/self-dev-fixture`) and the raw synthetic fixture
// (`crates/zkpoh/fixtures/self_synthetic_public.json`) both carry ARBITRARY de-risk values for
// the policy-bound slots (scope@19, merkle_root@9, current_date@10..16, user_identifier@20) —
// values the C0 crypto tests use to exercise ARITY, not the C1 runtime's on-chain BINDING checks
// (`submit_zk_passport_proof`, `crates/runtime/src/lifecycle.rs`). Submitting that fixture as-is
// on a devnet is rejected at the FIRST binding (`WrongScope`) and never mints a human.
//
// `buildDevMockSubmission` instead constructs the full 21-signal vector so every binding the
// runtime checks (spec 06b §4.4) passes:
//   * scope@19            == UBI2_SELF_SCOPE (the exact 32 bytes `crates/runtime/src/zkpoh.rs`
//                            pins — low 8 bytes ASCII "ubi2-poh", rest zero);
//   * user_identifier@20  == address_to_hash(sender) (the low 20 bytes hold `sender`, matching
//                            `crates/runtime::address_to_hash` exactly);
//   * merkle_root@9        an accepted Self identity root, read LIVE via `ubi_getSelfRoots`
//                            (never hardcoded — the devnet seed is a documented constant but this
//                            helper stays correct even if governance repins it);
//   * ofac@16,17,18        the accepted OFAC roots (kinds 0/1/2), also read live;
//   * current_date@10..16  TODAY as six YYMMDD ASCII-digit field elements, encoded by the exact
//                            inverse-civil-calendar algorithm `crates/runtime::current_date_to_epoch`
//                            decodes (Howard Hinnant days-from-civil) — so it decodes inside
//                            `block.timestamp`'s `SELF_DATE_WINDOW_SECS` freshness window;
//   * attestation_id@8     == 1 (E-Passport);
//   * nullifier@7           a fresh random CANONICAL BN254 scalar (< r) — unique per call, so
//                            repeated dev-mints for the same address don't collide (they'd hit
//                            `AlreadyEnhanced` on-chain anyway, since one address ⇒ one human);
//   * slots 0..7 (revealedData[0..3] + forbidden_countries[3..7])  arbitrary canonical field
//                            elements — pass-through, never bound by the runtime.
//
// The `proof` bytes are NEVER inspected by `MockZkVerifier::verify_passport` — it keys purely on
// `(nullifier@7, submitter_address)` — so any well-formed non-empty byte string (≤
// `MAX_ZK_PROOF_BYTES` = 1024, `crates/rpc/src/humanity.rs`) is accepted. This is why the mock
// path is dev-only: it produces a real on-chain mint with NO cryptographic proof of humanity
// behind it. It exists so the plumbing (encode → sign → submit → mint) is exercisable and
// demonstrable on a devnet without a real Self phone flow, clearly labeled as a mock everywhere
// it is surfaced in the UI.
// ---------------------------------------------------------------------------

/** The pinned canonical ubi2 Self scope seed (spec 06b §3) — mirrors `UBI2_SELF_SCOPE_SEED` in
 *  `crates/runtime/src/zkpoh.rs`. One scope network-wide ⇒ one-passport-one-human. */
export const UBI2_SELF_SCOPE_SEED = "ubi2-poh";

/**
 * The pinned canonical ubi2 scope scalar the runtime binds `signals[19]` against — mirrors
 * `ubi2_runtime::UBI2_SELF_SCOPE` (`crates/runtime/src/zkpoh.rs` ~line 99) EXACTLY: the low 8
 * bytes are the ASCII encoding of [`UBI2_SELF_SCOPE_SEED`], the remaining 24 bytes are zero.
 * Derived here (rather than hand-copied as a hex literal) so the derivation is self-evidently the
 * same rule the Rust doc comment states.
 */
export const UBI2_SELF_SCOPE: Hex = (() => {
  const seed = new TextEncoder().encode(UBI2_SELF_SCOPE_SEED); // 8 ASCII bytes
  const buf = new Uint8Array(32);
  buf.set(seed, 32 - seed.length); // low 8 bytes = seed ASCII, high 24 bytes = zero
  return u8ArrayToHex(buf);
})();

/** The `attestation_id` value a Self E-Passport disclosure proof carries (slot 8, bound `== 1`). */
export const SELF_ATTESTATION_ID_EPASSPORT = 1;

/** OFAC root kinds (spec 06b §2.2) — mirror `ubi2_runtime::OFAC_KIND_*` (slots 16/17/18). */
export const OFAC_KIND_PASSPORTNO = 0;
export const OFAC_KIND_NAMEDOB = 1;
export const OFAC_KIND_NAMEYOB = 2;

/** The BN254 scalar-field order `r` — mirrors `ubi2_runtime::BN254_FR_MODULUS_BE` exactly. A
 *  canonical nullifier must be strictly `< r` (the malleability guard, spec 06b §3.5). */
export const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Zero-extend a 20-byte ubi2 address to a 32-byte big-endian [`Hex`] — mirrors
 * `ubi2_runtime::address_to_hash` EXACTLY (the low 20 bytes hold the address, the high 12 bytes
 * are zero). This is the `user_identifier` slot (20) form the runtime binds the tx sender against.
 */
export function addressToHash(address: string): Hex {
  const clean = address.toLowerCase().replace(/^0x/, "");
  if (clean.length !== 40) {
    throw new Error(`addressToHash: expected a 20-byte (40 hex-char) address, got "${address}"`);
  }
  return `0x${"0".repeat(24)}${clean}` as Hex;
}

/**
 * A cryptographically-sourced (where available) random 32-byte buffer. Falls back to `Math.random`
 * only if no `crypto.getRandomValues` is present (never the case in a browser or Node ≥19) — the
 * nullifier only needs to be unpredictable-enough-to-be-unique for a devnet dev tool, not a
 * security boundary (the mock verifier provides none regardless).
 */
function randomBytes32(): Uint8Array {
  const buf = new Uint8Array(32);
  const g = globalThis as { crypto?: { getRandomValues?: (b: Uint8Array) => Uint8Array } };
  if (g.crypto?.getRandomValues) {
    g.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < 32; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return buf;
}

/**
 * A fresh random CANONICAL BN254 scalar (`< r`, spec 06b §3.5's round-trip obligation) — the
 * `nullifier` slot (7) for a dev-mock submission. Reducing a full 256-bit random value mod `r`
 * (rather than rejection-sampling) always yields a value `< r`, so [`is_canonical_scalar`]'s Rust
 * twin (`crates/runtime::is_canonical_scalar`) always accepts it.
 */
export function randomCanonicalScalar(): Hex {
  const bytes = randomBytes32();
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  n = n % BN254_FR_MODULUS;
  return `0x${n.toString(16).padStart(64, "0")}` as Hex;
}

/**
 * Encode a unix-seconds timestamp as the six `current_date` YYMMDD ASCII-digit field elements
 * (slots 10..16) — the EXACT inverse of `ubi2_runtime::current_date_to_epoch` (Howard Hinnant
 * civil-from-days), matching `crates/runtime/tests/m6_zkpoh.rs::date_signals` byte-for-byte so the
 * decoded epoch lands within `block.timestamp`'s freshness window (spec 06b §4.4 step 5).
 */
export function dateToSelfSignals(nowSecs: number): [Hex, Hex, Hex, Hex, Hex, Hex] {
  const days = Math.floor(nowSecs / 86_400);
  const z = days + 719_468;
  const era = Math.floor(z / 146_097); // z is always positive for any realistic `nowSecs` (post-1970)
  const doe = z - era * 146_097; // [0, 146096]
  const yoe = Math.floor(
    (doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365,
  ); // [0, 399]
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100)); // [0, 365]
  const mp = Math.floor((5 * doy + 2) / 153); // [0, 11]
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1; // [1, 31]
  const m = mp < 10 ? mp + 3 : mp - 9; // [1, 12]
  const year = m <= 2 ? y + 1 : y;
  const yy = ((year % 100) + 100) % 100;
  const digits = [Math.floor(yy / 10), yy % 10, Math.floor(m / 10), m % 10, Math.floor(d / 10), d % 10];
  return digits.map((dg) => numberToBytes32(0x30 + dg)) as [Hex, Hex, Hex, Hex, Hex, Hex]; // 0x30 = ASCII '0'
}

/** A small non-negative integer → 32-byte big-endian [`Hex`] (canonical — always `< r`). */
function numberToBytes32(n: number): Hex {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex;
}

/** The fixed dev-mock proof payload — `MockZkVerifier::verify_passport` never inspects proof
 *  bytes, only `(nullifier, submitter)`, so any well-formed non-empty blob is accepted. 192 bytes
 *  (matching the shape of `crates/runtime/tests/m6_zkpoh.rs`'s `vec![0xAB; 192]` test proof). */
const DEV_MOCK_PROOF_BYTES = new Uint8Array(192).fill(0xab);

/** The result of [`buildDevMockSubmission`] — ready to pass straight to
 *  `encodeSubmitZkPassportProof` (or `.publicSignals`/`.proofBytes` individually). */
export interface DevMockSubmission {
  /** The dev-mock proof bytes (opaque to `MockZkVerifier`; see [`DEV_MOCK_PROOF_BYTES`]). */
  proofBytes: Uint8Array;
  /** The full 21-element `bytes32` public-signal vector (spec 06b §4.1), every policy slot bound
   *  correctly for `sender` against the LIVE roots supplied. Exactly `SELF_NPUBLIC` (21) elements —
   *  typed as `Hex[]` (matching [`ZkPassportProofParams.publicSignals`]) rather than the fixed
   *  21-tuple so it passes straight to `encodeSubmitZkPassportProof` with no cast. */
  publicSignals: Hex[];
  /** Always `0` (Self e-passport, `SCHEME_TAG_PASSPORT`). */
  schemeTag: 0;
  /** The nullifier (slot 7) this submission will register — convenience for a pre-check /
   *  post-submit `ubi_isNullifierUsed` display. */
  nullifier: Hex;
}

/**
 * Build a BINDING-CORRECT `submitZkPassportProof` submission for `sender` that the C1 runtime
 * ACCEPTS on a devnet running `MockZkVerifier` (spec 06b §6.3) — a real on-chain mint, with every
 * policy binding (`crates/runtime/src/lifecycle.rs::submit_zk_passport_proof`) satisfied, but with
 * NO actual proof of humanity behind it (the "proof" bytes are inert; see the module doc above).
 *
 * **DEV-ONLY.** Never wire this to a path a user could reach outside an explicitly-labeled devnet
 * "dev mint (mock)" affordance — it demonstrates the mint mechanics, not proof-of-humanity.
 *
 * @param sender  The tx sender / subject address (20-byte hex, `0x`-prefixed or not) — bound into
 *                `user_identifier@20` via [`addressToHash`]. The caller MUST sign+send the
 *                resulting calldata FROM this exact address (anti-replay, spec §4.4 step 4).
 * @param roots   The LIVE accepted Self roots from `ubi_getSelfRoots` ([`ZkPassportReader.getSelfRoots`]).
 *                Never hardcode a root — a governance repin would silently break a hardcoded value.
 * @param now     Unix seconds to encode as `current_date` (defaults to `Date.now()/1000`). Must be
 *                within `SELF_DATE_WINDOW_SECS` (±2 days) of the block that mines the tx.
 */
export function buildDevMockSubmission(
  sender: string,
  roots: SelfRootsResponse,
  now: number = Math.floor(Date.now() / 1000),
): DevMockSubmission {
  if (roots.identityRoots.length === 0) {
    throw new Error(
      "buildDevMockSubmission: ubi_getSelfRoots returned no accepted Self identity root — the devnet has not seeded one.",
    );
  }
  const identityRoot = roots.identityRoots[0]!.root as Hex;

  const ofacByKind = new Map(roots.ofacRoots.map((r) => [r.kind, r.root as Hex]));
  const ofacRoot = (kind: number): Hex => {
    const r = ofacByKind.get(kind);
    if (!r) {
      throw new Error(
        `buildDevMockSubmission: ubi_getSelfRoots returned no accepted OFAC root of kind ${kind}.`,
      );
    }
    return r;
  };

  const nullifier = randomCanonicalScalar();
  const date = dateToSelfSignals(now);

  // Slots 0..7 (revealedData_packed[0..3] + forbidden_countries_list_packed[3..7]): pass-through,
  // never bound by the runtime — small arbitrary canonical field elements.
  const passthrough = [1, 2, 3, 4, 5, 6, 7].map(numberToBytes32);

  const signals: Hex[] = [
    ...passthrough, // 0..7  revealedData[0..3] + forbidden_countries[3..7]
    nullifier, // 7      nullifier
    numberToBytes32(SELF_ATTESTATION_ID_EPASSPORT), // 8      attestation_id
    identityRoot, // 9      merkle_root
    ...date, // 10..16 current_date (6 signals)
    ofacRoot(OFAC_KIND_PASSPORTNO), // 16
    ofacRoot(OFAC_KIND_NAMEDOB), // 17
    ofacRoot(OFAC_KIND_NAMEYOB), // 18
    UBI2_SELF_SCOPE, // 19     scope
    addressToHash(sender), // 20     user_identifier
  ];

  if (signals.length !== SELF_NPUBLIC) {
    // Defensive — a slot-count bug here would silently misalign the vector.
    throw new Error(`buildDevMockSubmission: built ${signals.length} signals, expected ${SELF_NPUBLIC}.`);
  }

  return {
    proofBytes: DEV_MOCK_PROOF_BYTES,
    publicSignals: signals,
    schemeTag: 0,
    nullifier,
  };
}

/**
 * One-shot helper: [`buildDevMockSubmission`] → `submitZkPassportProof` calldata, ready for
 * `sendZkPassportProof`. DEV-ONLY (see [`buildDevMockSubmission`]'s doc).
 */
export function encodeDevMockSubmission(
  sender: string,
  roots: SelfRootsResponse,
  now?: number,
): { data: Hex; nullifier: Hex } {
  const built = buildDevMockSubmission(sender, roots, now);
  const data = encodeSubmitZkPassportProof({
    proofBytes: built.proofBytes,
    publicSignals: built.publicSignals,
    schemeTag: built.schemeTag,
  });
  return { data, nullifier: built.nullifier };
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

// ---------------------------------------------------------------------------
// Self client flow (Stage C1, spec 06b §5) — the relay wire payload
// ---------------------------------------------------------------------------

/**
 * The exact wire shape the Self mobile app POSTs to the ubi2 relay endpoint after a user
 * completes an in-app verification (spec 06b §5.2): `{ attestationId, proof, publicSignals,
 * userContextData }`. `userContextData` echoes the `userDefinedData` the wallet passed into
 * `SelfAppBuilder` (here, the connected ubi2 address) — an advisory cross-check only; the
 * authoritative binding is on-chain (`publicSignals[20] == tx sender`, spec §4.4 step 4).
 */
export interface SelfRelayPayload {
  attestationId: number | string;
  proof: SelfProofBundle["proof"];
  publicSignals: string[];
  userContextData?: string;
}

/**
 * Validate the shape of a Self relay payload (spec 06b §5.2 step 1) BEFORE encoding it.
 * This is a shape check only — no cryptography — exactly like `validateProofBundle`. The relay
 * is untrusted by design (§5.2): the runtime re-verifies the proof and re-binds every slot, so a
 * relay that lies here can at worst produce a tx the chain rejects fail-closed.
 */
export function validateSelfRelayPayload(parsed: unknown): string | null {
  if (!parsed || typeof parsed !== "object") return "Relay payload must be a JSON object.";
  const p = parsed as Record<string, unknown>;
  if (p.attestationId === undefined || p.attestationId === null)
    return "Missing `attestationId`.";
  return validateProofBundle({ proof: p.proof, publicSignals: p.publicSignals });
}

/**
 * Encode a Self relay payload (the exact POST body the Self app sends, spec 06b §5.2) directly
 * into `submitZkPassportProof` calldata — the ONE function the relay endpoint calls. It never
 * inspects proof internals beyond arity/shape; cryptographic validity is decided exclusively by
 * the runtime's re-verify (spec §5.2 "the relay is not trusted").
 */
export function encodeSelfRelayPayload(payload: SelfRelayPayload): Hex {
  const bundle: SelfProofBundle = { proof: payload.proof, publicSignals: payload.publicSignals };
  return encodeZkBundleAsCalldata(bundle);
}
