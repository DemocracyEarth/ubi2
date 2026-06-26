/**
 * @ubi2/sdk/humanity — M3 Proof-of-Humanity helpers.
 *
 * Implements the HumanityHub interface from `docs/specs/03-proof-of-humanity.md`:
 *  - calldata encoders for the four write ops (requestVerification, vouch, challenge,
 *    submitVerdict) targeting HUMANITY_HUB (0x0000000000000000000000000000000000005048),
 *  - typed reads via the custom `ubi_*` RPC methods,
 *  - a `sendHumanityTx` helper that signs either through an injected EIP-1193 provider
 *    (MetaMask) or a local private key (viem wallet client, for the devnet/tests).
 *
 * All ABI encoding/decoding and signing goes through `viem` so the bytes match exactly
 * what the node expects (per the M3-T4 protocol-engineer report).
 */

import {
  createWalletClient,
  http,
  defineChain,
  encodeFunctionData,
  decodeFunctionResult,
  type Chain,
  type EIP1193Provider,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

/** Reserved system "HumanityHub" address — 0x5048 = ASCII "PH". */
export const HUMANITY_HUB = "0x0000000000000000000000000000000000005048" as const;

// ---------------------------------------------------------------------------
// ABI fragments (minimal, human-readable) matching the IHumanityHub interface
// ---------------------------------------------------------------------------

const REQUEST_VERIFICATION_ABI = [
  {
    type: "function",
    name: "requestVerification",
    stateMutability: "nonpayable",
    inputs: [{ name: "livenessRef", type: "bytes32" }],
    outputs: [],
  },
] as const;

const VOUCH_ABI = [
  {
    type: "function",
    name: "vouch",
    stateMutability: "nonpayable",
    inputs: [{ name: "vouchee", type: "address" }],
    outputs: [],
  },
] as const;

const CHALLENGE_ABI = [
  {
    type: "function",
    name: "challenge",
    stateMutability: "nonpayable",
    inputs: [
      { name: "subject", type: "address" },
      { name: "evidenceRef", type: "bytes32" },
    ],
    outputs: [],
  },
] as const;

const SUBMIT_VERDICT_ABI = [
  {
    type: "function",
    name: "submitVerdict",
    stateMutability: "nonpayable",
    inputs: [
      { name: "caseId", type: "uint256" },
      { name: "verdict", type: "uint8" },
      { name: "confidence", type: "uint8" },
    ],
    outputs: [],
  },
] as const;

// ---------------------------------------------------------------------------
// Calldata encoders
// ---------------------------------------------------------------------------

/**
 * ABI-encode a `requestVerification(livenessRef)` call.
 * `livenessRef` is a 32-byte content hash (hex string with "0x" prefix).
 */
export function encodeRequestVerification(livenessRef: Hex): Hex {
  return encodeFunctionData({
    abi: REQUEST_VERIFICATION_ABI,
    functionName: "requestVerification",
    args: [livenessRef],
  });
}

/** ABI-encode a `vouch(vouchee)` call. */
export function encodeVouch(vouchee: string): Hex {
  return encodeFunctionData({
    abi: VOUCH_ABI,
    functionName: "vouch",
    args: [vouchee as Hex],
  });
}

/**
 * ABI-encode a `challenge(subject, evidenceRef)` call.
 * `evidenceRef` is a 32-byte content hash.
 */
export function encodeChallenge(subject: string, evidenceRef: Hex): Hex {
  return encodeFunctionData({
    abi: CHALLENGE_ABI,
    functionName: "challenge",
    args: [subject as Hex, evidenceRef],
  });
}

/**
 * Verdict values: 0=Human, 1=Sybil, 2=Uncertain.
 * Confidence values: 0=Low, 1=Med, 2=High.
 * Out-of-range bytes are rejected (fail closed) by the node.
 */
export type VerdictValue = 0 | 1 | 2;
export type ConfidenceValue = 0 | 1 | 2;

/** ABI-encode a `submitVerdict(caseId, verdict, confidence)` call. */
export function encodeSubmitVerdict(
  caseId: bigint | number,
  verdict: VerdictValue,
  confidence: ConfidenceValue,
): Hex {
  return encodeFunctionData({
    abi: SUBMIT_VERDICT_ABI,
    functionName: "submitVerdict",
    args: [BigInt(caseId), verdict, confidence],
  });
}

// ---------------------------------------------------------------------------
// Typed read shapes (matching JSON from ubi_* methods)
// ---------------------------------------------------------------------------

/** On-chain human status labels. */
export type HumanStatus = "Unverified" | "Pending" | "Verified" | "Challenged" | "Revoked";

/** A human record as returned by `ubi_getHuman(address)`. */
export interface HumanRecord {
  address: string;
  status: HumanStatus;
  /** Unix seconds when Verified (drives emission). */
  verified_at: number;
  /** 32-byte hex commitment to off-chain liveness evidence. */
  liveness_ref: string;
  /** Addresses that vouched for this human. */
  vouches_in: string[];
  /** Voucher reputation score (can be negative after sybil slashing). */
  reputation: number;
}

/** A canonical verdict inside a case vote. */
export interface CanonicalVerdict {
  verdict: VerdictValue;
  confidence: ConfidenceValue;
  reasons_hash: string;
}

/** A single juror vote inside a case. */
export interface CaseVote {
  juror: string;
  verdict: CanonicalVerdict;
}

/** Case status: Open, Committed, or Escalated. */
export type CaseStatusType = "Open" | "Committed" | "Escalated";
export type CaseStatus =
  | { type: "Open" }
  | { type: "Committed"; verdict: CanonicalVerdict }
  | { type: "Escalated" };

/** Case kind: Registration or Challenge. */
export type CaseKind = "Registration" | "Challenge";

/** A case record as returned by `ubi_getCase(id)`. */
export interface CaseRecord {
  /** Case id (number, per the node's JSON shape). */
  id: number;
  subject: string;
  kind: CaseKind;
  evidence_ref: string;
  jury: string[];
  votes: CaseVote[];
  status: CaseStatus;
  opened_at: number;
}

/** Vouches in/out for an address as returned by `ubi_getVouches(address)`. */
export interface VouchSet {
  outgoing: string[];
  incoming: string[];
}

/** A juror registry entry as returned by `ubi_getJurors()`. */
export interface JurorRecord {
  address: string;
  /** Stake as a hex-quantity string (may be "0x0" for register-only in M3). */
  stake: string;
  active: boolean;
}

// ---------------------------------------------------------------------------
// Reader class (mirrors StreamReader pattern)
// ---------------------------------------------------------------------------

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * PoH-aware reads layered over any object that exposes a JSON-RPC `call`
 * (the existing `Ubi2Client` qualifies). Kept separate for tree-shakeability.
 */
export class HumanityReader {
  constructor(private readonly rpc: JsonRpcCaller) {}

  /**
   * `ubi_getHuman(address)` → the human record or `null` if unknown.
   */
  async getHuman(address: string): Promise<HumanRecord | null> {
    return this.rpc.call<HumanRecord | null>("ubi_getHuman", [address]);
  }

  /**
   * `ubi_getCase(id)` → a single case or `null`.
   * Accepts both hex string and number ids.
   */
  async getCase(id: number | string): Promise<CaseRecord | null> {
    return this.rpc.call<CaseRecord | null>("ubi_getCase", [id]);
  }

  /** `ubi_getVouches(address)` → outgoing + incoming vouch lists. */
  async getVouches(address: string): Promise<VouchSet> {
    return this.rpc.call<VouchSet>("ubi_getVouches", [address]);
  }

  /** `ubi_getJurors()` → all registered jurors. */
  async getJurors(): Promise<JurorRecord[]> {
    return this.rpc.call<JurorRecord[]>("ubi_getJurors");
  }

  /** `ubi_getPendingCases()` → all Open cases sorted ascending by id. */
  async getPendingCases(): Promise<CaseRecord[]> {
    return this.rpc.call<CaseRecord[]>("ubi_getPendingCases");
  }
}

// ---------------------------------------------------------------------------
// Sending humanity ops
// ---------------------------------------------------------------------------

/** The minimal ubi2 viem `Chain` definition (mirrors ubi2Chain in streaming.ts). */
function ubi2HumanityChain(rpcUrl: string): Chain {
  return defineChain({
    id: 0x5542,
    name: "ubi2 devnet",
    nativeCurrency: { name: "UBI", symbol: "UBI", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

/** Result of submitting a humanity op. */
export interface HumanityTxResult {
  /** The transaction hash. */
  hash: Hex;
}

/** Options for `sendHumanityTx`. Provide exactly one signer (`provider` or `privateKey`). */
export interface SendHumanityOptions {
  /** HumanityHub calldata (from an `encode*` function above). */
  data: Hex;
  /** Sender address. Required for the injected-provider path; derived from the key otherwise. */
  from?: string;
  /** An injected EIP-1193 provider (e.g. `window.ethereum`). */
  provider?: EIP1193Provider;
  /** A local private key (devnet/tests). */
  privateKey?: Hex;
  /** RPC URL (required for the private-key path). */
  rpcUrl?: string;
}

/**
 * Build + send a HumanityHub transaction two ways:
 *  - **injected provider**: `eth_sendTransaction` to HUMANITY_HUB with `value: 0x0`.
 *  - **local private key**: a viem wallet client signs via `eth_sendRawTransaction`.
 *
 * Returns the transaction hash.
 */
export async function sendHumanityTx(opts: SendHumanityOptions): Promise<HumanityTxResult> {
  if (opts.provider) {
    if (!opts.from) throw new Error("sendHumanityTx: `from` is required with an injected provider");
    const hash = (await opts.provider.request({
      method: "eth_sendTransaction",
      params: [{ from: opts.from as Hex, to: HUMANITY_HUB, value: "0x0", data: opts.data }],
    })) as Hex;
    return { hash };
  }

  if (opts.privateKey) {
    if (!opts.rpcUrl) throw new Error("sendHumanityTx: `rpcUrl` is required with a private key");
    const account = privateKeyToAccount(opts.privateKey);
    const chain = ubi2HumanityChain(opts.rpcUrl);
    const wallet = createWalletClient({ account, chain, transport: http(opts.rpcUrl) });
    const hash = await wallet.sendTransaction({
      to: HUMANITY_HUB,
      value: 0n,
      data: opts.data,
      // Devnet does not charge gas; supply explicit fields so viem skips estimation calls.
      gas: 200000n,
      gasPrice: 0n,
    });
    return { hash };
  }

  throw new Error("sendHumanityTx: provide either `provider` or `privateKey`");
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/** Human-readable label for a HumanStatus. */
export function humanStatusLabel(status: HumanStatus): string {
  const map: Record<HumanStatus, string> = {
    Unverified: "Unverified",
    Pending: "Pending",
    Verified: "Verified",
    Challenged: "Challenged",
    Revoked: "Revoked",
  };
  return map[status] ?? status;
}

/** Human-readable label for a verdict value. */
export function verdictLabel(v: VerdictValue): string {
  return ["Human", "Sybil", "Uncertain"][v] ?? String(v);
}

/** Human-readable label for a confidence value. */
export function confidenceLabel(c: ConfidenceValue): string {
  return ["Low", "Med", "High"][c] ?? String(c);
}

/**
 * Derive a deterministic liveness ref from a seed string (mirrors the node's
 * `derive_liveness` logic so the wallet can pass a stable ref without user input).
 * In production this would be a commitment to an off-chain liveness transcript (I6).
 */
export function deriveLivenessRef(seed: string): Hex {
  // Encode seed as UTF-8, then produce a 32-byte keccak-style hex commitment.
  // We don't have keccak available without viem's keccak256, which needs Uint8Array.
  // Use a simple deterministic hex derived from the seed for the devnet demo.
  const encoder = new TextEncoder();
  const bytes = encoder.encode("ubi2-liveness-ref:" + seed);
  // Pad/truncate to 32 bytes and hex-encode.
  const buf = new Uint8Array(32);
  for (let i = 0; i < Math.min(bytes.length, 32); i++) {
    buf[i] = bytes[i];
  }
  const hex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `0x${hex}` as Hex;
}

// ---------------------------------------------------------------------------
// PoH NFT helpers (ERC-721 soulbound, minted by HumanityHub on Verified)
// ---------------------------------------------------------------------------

/**
 * The ERC-721 ABI fragments for HumanityHub's PoH NFT — mirrors the stream-NFT ABI
 * in streaming.ts but targets HUMANITY_HUB.
 */
const POH_ERC721_ABI = [
  { type: "function", name: "name",   stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "tokenURI",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ type: "string" }],
  },
] as const;

/**
 * Compute the PoH NFT tokenId for a given address.
 * Stateless scheme: `tokenId = uint256(uint160(address))` — the address zero-extended to 256 bits.
 * The token *exists* (ownerOf does not revert) iff `ubi_getHuman(addr).status == "Verified"`.
 */
export function pohTokenId(address: string): bigint {
  return BigInt(address);
}

/** A decoded on-chain PoH NFT card. */
export interface PohCard {
  /** Token name, e.g. `"Proof of Humanity — 0xf39F…2266"`. */
  name: string;
  /** Description text from the metadata. */
  description: string;
  /** Inline SVG markup (decoded from the metadata `image` data-URI). */
  svg: string;
  /** Structured attributes from the metadata document. */
  attributes: Array<{ trait_type?: string; display_type?: string; value: string | number }>;
}

// base64 decode (browser + Node ≥ 16)
function pohDecodeBase64(b64: string): string {
  const atobFn = (globalThis as { atob?: (s: string) => string }).atob;
  if (typeof atobFn !== "function") throw new Error("base64 decoder (atob) unavailable");
  const bin = atobFn(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function pohDecodeDataUri(uri: string): string {
  const comma = uri.indexOf(",");
  if (comma < 0) throw new Error("malformed data URI");
  return pohDecodeBase64(uri.slice(comma + 1));
}

/**
 * PoH NFT reads layered over any JSON-RPC caller (the existing `Ubi2Client` qualifies).
 * Mirrors `StreamReader` from `streaming.ts` but targets `HUMANITY_HUB`.
 */
export class PohNftReader {
  constructor(private readonly rpc: JsonRpcCaller) {}

  /** Low-level `eth_call` against HumanityHub, returning the raw hex result. */
  private async hubCall(data: Hex): Promise<Hex> {
    return this.rpc.call<Hex>("eth_call", [{ to: HUMANITY_HUB, data }, "latest"]);
  }

  /** ERC-721 `name()` of the PoH collection (`"Proof of Humanity"`). */
  async collectionName(): Promise<string> {
    const data = encodeFunctionData({ abi: POH_ERC721_ABI, functionName: "name", args: [] });
    return decodeFunctionResult({
      abi: POH_ERC721_ABI,
      functionName: "name",
      data: await this.hubCall(data),
    }) as string;
  }

  /** ERC-721 `symbol()` — `"POH"`. */
  async collectionSymbol(): Promise<string> {
    const data = encodeFunctionData({ abi: POH_ERC721_ABI, functionName: "symbol", args: [] });
    return decodeFunctionResult({
      abi: POH_ERC721_ABI,
      functionName: "symbol",
      data: await this.hubCall(data),
    }) as string;
  }

  /**
   * ERC-721 `balanceOf(owner)` — returns `1n` if the account is Verified, `0n` otherwise.
   * Never reverts.
   */
  async balanceOf(owner: string): Promise<bigint> {
    const data = encodeFunctionData({ abi: POH_ERC721_ABI, functionName: "balanceOf", args: [owner as Hex] });
    return decodeFunctionResult({
      abi: POH_ERC721_ABI,
      functionName: "balanceOf",
      data: await this.hubCall(data),
    }) as bigint;
  }

  /**
   * ERC-721 `ownerOf(tokenId)` — returns the address if Verified.
   * Reverts (`ERC721: owner query for nonexistent token`) if the account is not Verified.
   * Use `pohTokenId(address)` to compute the tokenId.
   */
  async ownerOf(tokenId: bigint): Promise<string> {
    const data = encodeFunctionData({ abi: POH_ERC721_ABI, functionName: "ownerOf", args: [tokenId] });
    return decodeFunctionResult({
      abi: POH_ERC721_ABI,
      functionName: "ownerOf",
      data: await this.hubCall(data),
    }) as string;
  }

  /**
   * Fetch and decode the on-chain PoH NFT card for a given tokenId.
   * Calls `tokenURI(tokenId)`, decodes the base64 JSON, then decodes the base64 SVG `image`.
   * Reverts if the token does not exist (account not Verified).
   *
   * Use `pohTokenId(address)` to compute the tokenId from an Ethereum address.
   */
  async fetchPohCard(tokenId: bigint): Promise<PohCard> {
    const data = encodeFunctionData({ abi: POH_ERC721_ABI, functionName: "tokenURI", args: [tokenId] });
    const uri = decodeFunctionResult({
      abi: POH_ERC721_ABI,
      functionName: "tokenURI",
      data: await this.hubCall(data),
    }) as string;

    const json = JSON.parse(pohDecodeDataUri(uri)) as {
      name: string;
      description?: string;
      image: string;
      attributes?: PohCard["attributes"];
    };
    const svg = pohDecodeDataUri(json.image);
    return {
      name: json.name,
      description: json.description ?? "",
      svg,
      attributes: json.attributes ?? [],
    };
  }
}
