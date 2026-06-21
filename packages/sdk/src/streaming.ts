/**
 * @ubi2/sdk/streaming — M2 streaming primitive + stream-NFT helpers.
 *
 * Implements the interface contract from `docs/specs/02-streaming.md`:
 *  - calldata encoders for the two StreamHub write ops (`openStream`, `stopStream`),
 *  - typed reads via the custom `ubi_getStreams` / `ubi_getStream` RPC methods,
 *  - stream-NFT helpers: deterministic token ids per side + on-chain card decoding,
 *  - a `sendStreamTx` helper that signs either through an injected EIP-1193 provider
 *    (MetaMask) or a local private key (viem wallet client, for the devnet/tests).
 *
 * All ABI encoding/decoding and signing goes through `viem` so the bytes are exactly what a
 * standard wallet would produce.
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

// Defined locally (not imported from ./index) to avoid a circular module-init dependency:
// index re-exports this file, so importing values back from it would hit a temporal-dead-zone
// under strict ESM evaluation order. These mirror the constants in ./index by construction.
const UBI = 10n ** 18n;
const EMISSION_PERIOD_SECS = 3600n;

/** Reserved system "StreamHub" address — the ERC-721 collection + write-op target. */
export const STREAM_HUB = "0x0000000000000000000000000000000000005742" as const;

/** Top-bit flag distinguishing the sender receipt token from the recipient token. */
export const SENDER_FLAG = 1n << 255n;

/** Devnet chain id as the canonical hex string (`0x5542`). */
export const DEVNET_CHAIN_ID_HEX = "0x5542";

/**
 * Streaming rate for "1 UBI / hour" expressed in base units per second (`10**18 / 3600`).
 * Streams are denominated in base-units-per-second; this is the natural unit for the form.
 */
export const RATE_1_UBI_PER_HOUR = UBI / EMISSION_PERIOD_SECS;

// --- ABI fragments (minimal, human-readable) ----------------------------------------------

const OPEN_STREAM_ABI = [
  {
    type: "function",
    name: "openStream",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "ratePerSec", type: "uint256" },
      { name: "deposit", type: "uint256" },
    ],
    outputs: [],
  },
] as const;

const STOP_STREAM_ABI = [
  {
    type: "function",
    name: "stopStream",
    stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "uint256" }],
    outputs: [],
  },
] as const;

const ERC721_VIEW_ABI = [
  { type: "function", name: "name", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
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

/** ABI-encode an `openStream(to, ratePerSec, deposit)` call into StreamHub calldata. */
export function encodeOpenStream(to: string, ratePerSec: bigint, deposit: bigint): Hex {
  return encodeFunctionData({
    abi: OPEN_STREAM_ABI,
    functionName: "openStream",
    args: [to as Hex, ratePerSec, deposit],
  });
}

/** ABI-encode a `stopStream(id)` call into StreamHub calldata. */
export function encodeStopStream(id: bigint | number): Hex {
  return encodeFunctionData({
    abi: STOP_STREAM_ABI,
    functionName: "stopStream",
    args: [BigInt(id)],
  });
}

// --- Stream views -------------------------------------------------------------------------

/** Stream lifecycle status as returned by the node (tagged union). */
export type StreamStatus =
  | { type: "Active" }
  | { type: "Stopped"; at: number }
  | { type: "Completed" };

/** Raw `StreamView` as returned over JSON-RPC (numeric fields are hex strings). */
export interface RawStreamView {
  id: number;
  from: string;
  to: string;
  rate: string;
  deposit: string;
  drawn: string;
  started_at: number;
  accrued_now: string;
  t_end: number;
  status: StreamStatus;
}

/** A stream with hex amount fields parsed to `bigint` for client-side math. */
export interface StreamView {
  id: number;
  from: string;
  to: string;
  /** Base units per second. */
  rate: bigint;
  /** Total locked at open, in base units. */
  deposit: bigint;
  /** Amount already settled to `to`, in base units. */
  drawn: bigint;
  /** Unix seconds the stream started. */
  startedAt: number;
  /** Node-computed accrued amount at read time, in base units. */
  accruedNow: bigint;
  /** Unix seconds the deposit drains (`startedAt + deposit/rate`). */
  tEnd: number;
  status: StreamStatus;
}

function parseStreamView(raw: RawStreamView): StreamView {
  return {
    id: raw.id,
    from: raw.from,
    to: raw.to,
    rate: BigInt(raw.rate),
    deposit: BigInt(raw.deposit),
    drawn: BigInt(raw.drawn),
    startedAt: raw.started_at,
    accruedNow: BigInt(raw.accrued_now),
    tEnd: raw.t_end,
    status: raw.status,
  };
}

/** The two sides of a stream's NFT pair. */
export type StreamSide = "recipient" | "sender";

/**
 * Deterministic ERC-721 token id for a stream side: recipient token = `streamId`,
 * sender receipt = `streamId | SENDER_FLAG`.
 */
export function streamNftTokenId(streamId: number | bigint, side: StreamSide): bigint {
  const id = BigInt(streamId);
  return side === "sender" ? id | SENDER_FLAG : id;
}

/** A decoded on-chain stream NFT card. */
export interface StreamCard {
  /** Token name, e.g. `"ubi2 Stream #0"`. */
  name: string;
  /** Inline SVG markup (decoded from the metadata `image` data-URI). */
  svg: string;
  /** Structured attributes from the metadata document. */
  attributes: Array<{ trait_type?: string; display_type?: string; value: string | number }>;
}

// --- base64 (works in Node and browsers) --------------------------------------------------

function decodeBase64(b64: string): string {
  // Node ≥ 16 exposes a global `atob`, as do browsers — so this single path covers both
  // without needing @types/node. atob → binary string → UTF-8 decode (handles multi-byte SVG).
  const atobFn = (globalThis as { atob?: (s: string) => string }).atob;
  if (typeof atobFn !== "function") throw new Error("base64 decoder (atob) unavailable");
  const bin = atobFn(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Split a `data:...;base64,<payload>` URI and decode the payload to a UTF-8 string. */
function decodeDataUri(uri: string): string {
  const comma = uri.indexOf(",");
  if (comma < 0) throw new Error("malformed data URI");
  return decodeBase64(uri.slice(comma + 1));
}

// --- RPC reads ----------------------------------------------------------------------------

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * Stream-aware reads layered over any object exposing a JSON-RPC `call`
 * (the existing `Ubi2Client` qualifies). Kept separate from the client so it stays a thin,
 * tree-shakeable add-on.
 */
export class StreamReader {
  constructor(private readonly rpc: JsonRpcCaller) {}

  /** `ubi_getStreams(address)` → parsed outgoing + incoming streams for an account. */
  async getStreams(address: string): Promise<{ outgoing: StreamView[]; incoming: StreamView[] }> {
    const res = await this.rpc.call<{ outgoing: RawStreamView[]; incoming: RawStreamView[] }>(
      "ubi_getStreams",
      [address],
    );
    return {
      outgoing: res.outgoing.map(parseStreamView),
      incoming: res.incoming.map(parseStreamView),
    };
  }

  /** `ubi_getStream(id)` → a single parsed stream. */
  async getStream(id: number | bigint): Promise<StreamView> {
    const raw = await this.rpc.call<RawStreamView>("ubi_getStream", [Number(id)]);
    return parseStreamView(raw);
  }

  /** Low-level `eth_call` against StreamHub, returning the raw hex result. */
  private async hubCall(data: Hex): Promise<Hex> {
    return this.rpc.call<Hex>("eth_call", [{ to: STREAM_HUB, data }, "latest"]);
  }

  /** ERC-721 `name()` of the StreamHub collection (`"ubi2 Streams"`). */
  async collectionName(): Promise<string> {
    const data = encodeFunctionData({ abi: ERC721_VIEW_ABI, functionName: "name", args: [] });
    return decodeFunctionResult({
      abi: ERC721_VIEW_ABI,
      functionName: "name",
      data: await this.hubCall(data),
    }) as string;
  }

  /** ERC-721 `ownerOf(tokenId)`. */
  async ownerOf(tokenId: bigint): Promise<string> {
    const data = encodeFunctionData({ abi: ERC721_VIEW_ABI, functionName: "ownerOf", args: [tokenId] });
    return decodeFunctionResult({
      abi: ERC721_VIEW_ABI,
      functionName: "ownerOf",
      data: await this.hubCall(data),
    }) as string;
  }

  /** ERC-721 `balanceOf(owner)` — number of stream tokens the account holds. */
  async tokenBalanceOf(owner: string): Promise<bigint> {
    const data = encodeFunctionData({
      abi: ERC721_VIEW_ABI,
      functionName: "balanceOf",
      args: [owner as Hex],
    });
    return decodeFunctionResult({
      abi: ERC721_VIEW_ABI,
      functionName: "balanceOf",
      data: await this.hubCall(data),
    }) as bigint;
  }

  /**
   * Fetch and decode an on-chain stream NFT card: calls `tokenURI(tokenId)`, decodes the
   * base64 JSON document, then decodes its base64 SVG `image` into inline markup.
   */
  async fetchStreamCard(tokenId: bigint): Promise<StreamCard> {
    const data = encodeFunctionData({ abi: ERC721_VIEW_ABI, functionName: "tokenURI", args: [tokenId] });
    const uri = decodeFunctionResult({
      abi: ERC721_VIEW_ABI,
      functionName: "tokenURI",
      data: await this.hubCall(data),
    }) as string;

    const json = JSON.parse(decodeDataUri(uri)) as {
      name: string;
      image: string;
      attributes?: StreamCard["attributes"];
    };
    const svg = decodeDataUri(json.image);
    return { name: json.name, svg, attributes: json.attributes ?? [] };
  }
}

// --- Sending stream ops -------------------------------------------------------------------

/** The minimal ubi2 viem `Chain` definition (gas/value are free on devnet). */
export function ubi2Chain(rpcUrl: string): Chain {
  return defineChain({
    id: 0x5542,
    name: "ubi2 devnet",
    nativeCurrency: { name: "UBI", symbol: "UBI", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

/** Result of submitting a stream op. */
export interface SendResult {
  /** The transaction hash. */
  hash: Hex;
}

/** Options for `sendStreamTx`. Provide exactly one signer (`provider` or `privateKey`). */
export interface SendStreamOptions {
  /** StreamHub calldata (from `encodeOpenStream` / `encodeStopStream`). */
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
 * Build + send a StreamHub transaction two ways:
 *  - **injected provider**: `eth_sendTransaction` to StreamHub with `value: 0x0` and the data
 *    (MetaMask signs); the wallet manages nonce/gas.
 *  - **local private key**: a viem wallet client signs and submits via `eth_sendRawTransaction`.
 *
 * Returns the transaction hash. The deposit is a calldata argument, so `value` is always 0.
 */
export async function sendStreamTx(opts: SendStreamOptions): Promise<SendResult> {
  if (opts.provider) {
    if (!opts.from) throw new Error("sendStreamTx: `from` is required with an injected provider");
    const hash = (await opts.provider.request({
      method: "eth_sendTransaction",
      params: [{ from: opts.from as Hex, to: STREAM_HUB, value: "0x0", data: opts.data }],
    })) as Hex;
    return { hash };
  }

  if (opts.privateKey) {
    if (!opts.rpcUrl) throw new Error("sendStreamTx: `rpcUrl` is required with a private key");
    const account = privateKeyToAccount(opts.privateKey);
    const chain = ubi2Chain(opts.rpcUrl);
    const wallet = createWalletClient({ account, chain, transport: http(opts.rpcUrl) });
    const hash = await wallet.sendTransaction({
      to: STREAM_HUB,
      value: 0n,
      data: opts.data,
      // Devnet does not charge gas; supply explicit fields so viem skips estimation calls.
      gas: 200000n,
      gasPrice: 0n,
    });
    return { hash };
  }

  throw new Error("sendStreamTx: provide either `provider` or `privateKey`");
}

// --- Convenience: rate / deposit conversions for the UI -----------------------------------

/** Convert a "UBI per hour" rate (as a decimal string or number) to base-units-per-second. */
export function ratePerHourToBaseUnitsPerSec(ubiPerHour: string | number): bigint {
  // rate_per_sec = ubiPerHour * 1e18 / 3600, kept as exact integer math via a scaled numerator.
  const scaled = parseUbiToBaseUnits(String(ubiPerHour));
  return scaled / EMISSION_PERIOD_SECS;
}

/** Parse a human UBI decimal string (e.g. "1.5") into base units (1e18). */
export function parseUbiToBaseUnits(ubi: string): bigint {
  const trimmed = ubi.trim();
  if (trimmed === "" || !/^\d*\.?\d*$/.test(trimmed)) throw new Error(`invalid UBI amount: ${ubi}`);
  const [whole = "0", frac = ""] = trimmed.split(".");
  const fracPadded = (frac + "0".repeat(18)).slice(0, 18);
  return BigInt(whole || "0") * UBI + BigInt(fracPadded || "0");
}

/**
 * Project a stream's accrued amount forward to `nowMs` for smooth client-side ticking.
 * Interpolates `rate * elapsed` from `startedAt`, capped at `deposit`, and frozen at the
 * stop/complete time for non-active streams (matching the on-chain `accrued` cap).
 */
export function projectStreamAccrued(s: StreamView, nowMs: number = Date.now()): bigint {
  // Determine the effective "now" in seconds, capped at the stream's settled endpoint.
  let endSec: number;
  if (s.status.type === "Stopped") endSec = s.status.at;
  else if (s.status.type === "Completed") endSec = s.tEnd;
  else endSec = s.tEnd; // Active: cap at t_end (deposit drained).

  const nowSec = Math.floor(nowMs / 1000);
  const effectiveSec = Math.min(nowSec, endSec);
  const elapsed = BigInt(Math.max(0, effectiveSec - s.startedAt));
  const accrued = s.rate * elapsed;
  return accrued > s.deposit ? s.deposit : accrued;
}
