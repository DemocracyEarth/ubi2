/**
 * Canonical wire encoding/decoding for the ubi2/sync/1 protocol (spec 05 §3.1, §4.1, §4.2).
 *
 * Byte-for-byte compatible with `crates/network::wire` Rust implementation:
 *  - Fixed-width integers: big-endian.
 *  - Variable-length byte fields: u32 big-endian length prefix.
 *  - WireBlock: number(u64) | parent_hash(32) | timestamp(u64) | txs_root(32) | state_root(32)
 *               | proposer(20) | proposer_sig(u32-prefixed) | tx_count(u32) | [tx(u32-prefixed)]
 *  - Hello: genesis_hash(32) | chain_id(u64) | tip_height(u64) | tip_hash(32)
 *           | validator_tag(u8) [+ addr(20)] | peer_proof(u32-prefixed) | protocol_ver(u16)
 *  - SyncRequest/SyncResponse: tag(u8=0 Hello / 1 Blocks) | payload
 *  - GetBlocks: from(u64) | to(u64)
 *  - Blocks: count(u32) | [block_len(u32) | block_bytes]
 */

// ---------------------------------------------------------------------------
// Low-level read/write helpers
// ---------------------------------------------------------------------------

class Writer {
  private chunks: Uint8Array[] = [];
  private _len = 0;

  u8(v: number): this {
    const b = new Uint8Array(1);
    b[0] = v & 0xff;
    this.chunks.push(b);
    this._len += 1;
    return this;
  }
  u16(v: number): this {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, false);
    this.chunks.push(b);
    this._len += 2;
    return this;
  }
  u32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v, false);
    this.chunks.push(b);
    this._len += 4;
    return this;
  }
  u64(v: bigint): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v, false);
    this.chunks.push(b);
    this._len += 8;
    return this;
  }
  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    this._len += b.length;
    return this;
  }
  /** Write a u32-length-prefixed blob. */
  blob(b: Uint8Array): this {
    this.u32(b.length);
    this.bytes(b);
    return this;
  }
  finish(): Uint8Array {
    const out = new Uint8Array(this._len);
    let offset = 0;
    for (const c of this.chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }
}

class Reader {
  private pos = 0;
  constructor(private buf: Uint8Array) {}

  u8(): number {
    if (this.pos >= this.buf.length) throw new Error("wire: truncated");
    return this.buf[this.pos++]!;
  }
  u16(): number {
    if (this.pos + 2 > this.buf.length) throw new Error("wire: truncated");
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 2).getUint16(0, false);
    this.pos += 2;
    return v;
  }
  u32(): number {
    if (this.pos + 4 > this.buf.length) throw new Error("wire: truncated");
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 4).getUint32(0, false);
    this.pos += 4;
    return v;
  }
  u64(): bigint {
    if (this.pos + 8 > this.buf.length) throw new Error("wire: truncated");
    const v = new DataView(
      this.buf.buffer,
      this.buf.byteOffset + this.pos,
      8,
    ).getBigUint64(0, false);
    this.pos += 8;
    return v;
  }
  take(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error("wire: truncated");
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  /** Read a u32-length-prefixed blob bounded by `max`. */
  blob(max: number): Uint8Array {
    const n = this.u32();
    if (n > max) throw new Error(`wire: blob too long (${n} > ${max})`);
    return this.take(n);
  }
  finish(): void {
    if (this.pos !== this.buf.length) throw new Error("wire: trailing bytes");
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WireBlock {
  number: bigint;
  parentHash: Uint8Array; // 32 bytes
  timestamp: bigint;
  txsRoot: Uint8Array; // 32 bytes
  stateRoot: Uint8Array; // 32 bytes
  proposer: Uint8Array; // 20 bytes
  proposerSig: Uint8Array; // 65 bytes or empty
  txs: Uint8Array[]; // raw EIP-155 tx bytes
}

export interface Hello {
  genesisHash: Uint8Array; // 32 bytes
  chainId: bigint;
  tipHeight: bigint;
  tipHash: Uint8Array; // 32 bytes
  validator: Uint8Array | null; // 20 bytes or null
  peerProof: Uint8Array;
  protocolVer: number;
}

export interface GetBlocks {
  from: bigint;
  to: bigint;
}

export interface Blocks {
  blocks: Uint8Array[]; // canonical-encoded WireBlock bytes (pass directly to WASM applyBlock)
}

/**
 * The seeded genesis anchor the gateway serves to a light client (spec 07 §3.4 — the
 * `ln-trust-1/2/3` fix).  The client checks `genesisHash`/`stateRoot`/`chainId`/`proposer` against its
 * PINNED constants (it NEVER adopts the gateway's), then imports `snapshot` and re-derives its state_root
 * locally, rejecting unless it equals the pinned root.
 */
export interface Genesis {
  genesisHash: Uint8Array; // 32 bytes
  chainId: bigint;
  stateRoot: Uint8Array; // 32 bytes — the SEEDED genesis state_root (re-derived + checked vs pinned)
  genesisTime: bigint;
  proposer: Uint8Array; // 20 bytes — the authorized PoA proposer
  snapshot: Uint8Array; // the genesis state snapshot bytes (imported into the WASM kernel)
}

export type SyncRequest =
  | { tag: "Hello"; hello: Hello }
  | { tag: "GetBlocks"; getBlocks: GetBlocks }
  | { tag: "GetGenesis" };

export type SyncResponse =
  | { tag: "Hello"; hello: Hello }
  | { tag: "Blocks"; blocks: Blocks }
  | { tag: "Genesis"; genesis: Genesis };

// ---------------------------------------------------------------------------
// WireBlock encode/decode
// ---------------------------------------------------------------------------

const MAX_TX_BYTES = 128 * 1024;
const MAX_BLOCK_BYTES = 8 * 1024 * 1024;
const SYNC_MAX_BATCH = 128;

export function encodeWireBlock(b: WireBlock): Uint8Array {
  const w = new Writer();
  w.u64(b.number);
  w.bytes(b.parentHash);
  w.u64(b.timestamp);
  w.bytes(b.txsRoot);
  w.bytes(b.stateRoot);
  w.bytes(b.proposer);
  w.blob(b.proposerSig);
  w.u32(b.txs.length);
  for (const tx of b.txs) {
    w.blob(tx);
  }
  return w.finish();
}

export function decodeWireBlock(buf: Uint8Array): WireBlock {
  const r = new Reader(buf);
  const number = r.u64();
  const parentHash = r.take(32);
  const timestamp = r.u64();
  const txsRoot = r.take(32);
  const stateRoot = r.take(32);
  const proposer = r.take(20);
  const proposerSig = r.blob(65);
  const count = r.u32();
  if (count > MAX_BLOCK_BYTES / 4) throw new Error("wire: too many txs");
  const txs: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    txs.push(r.blob(MAX_TX_BYTES));
  }
  r.finish();
  return { number, parentHash, timestamp, txsRoot, stateRoot, proposer, proposerSig, txs };
}

// ---------------------------------------------------------------------------
// Hello encode/decode
// ---------------------------------------------------------------------------

export function encodeHello(h: Hello): Uint8Array {
  const w = new Writer();
  w.bytes(h.genesisHash);
  w.u64(h.chainId);
  w.u64(h.tipHeight);
  w.bytes(h.tipHash);
  if (h.validator) {
    w.u8(1);
    w.bytes(h.validator);
  } else {
    w.u8(0);
  }
  w.blob(h.peerProof);
  w.u16(h.protocolVer);
  return w.finish();
}

export function decodeHello(buf: Uint8Array): Hello {
  const r = new Reader(buf);
  const genesisHash = r.take(32);
  const chainId = r.u64();
  const tipHeight = r.u64();
  const tipHash = r.take(32);
  const tag = r.u8();
  let validator: Uint8Array | null = null;
  if (tag === 1) {
    validator = r.take(20);
  } else if (tag !== 0) {
    throw new Error("wire: bad validator tag");
  }
  const peerProof = r.blob(65);
  const protocolVer = r.u16();
  r.finish();
  return { genesisHash, chainId, tipHeight, tipHash, validator, peerProof, protocolVer };
}

// ---------------------------------------------------------------------------
// GetBlocks encode/decode
// ---------------------------------------------------------------------------

export function encodeGetBlocks(g: GetBlocks): Uint8Array {
  const w = new Writer();
  w.u64(g.from);
  w.u64(g.to);
  return w.finish();
}

export function decodeGetBlocks(buf: Uint8Array): GetBlocks {
  const r = new Reader(buf);
  const from = r.u64();
  const to = r.u64();
  r.finish();
  return { from, to };
}

// ---------------------------------------------------------------------------
// Blocks encode/decode
// ---------------------------------------------------------------------------

export function encodeBlocks(b: Blocks): Uint8Array {
  const w = new Writer();
  w.u32(b.blocks.length);
  for (const raw of b.blocks) {
    w.blob(raw);
  }
  return w.finish();
}

export function decodeBlocks(buf: Uint8Array): Blocks {
  const r = new Reader(buf);
  const count = r.u32();
  if (count > SYNC_MAX_BATCH) throw new Error(`wire: too many blocks in response (${count})`);
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    blocks.push(r.blob(MAX_BLOCK_BYTES));
  }
  r.finish();
  return { blocks };
}

// ---------------------------------------------------------------------------
// Genesis encode/decode (spec 07 §3.4 — the verifiable genesis anchor)
// ---------------------------------------------------------------------------

export function encodeGenesis(g: Genesis): Uint8Array {
  const w = new Writer();
  w.bytes(g.genesisHash);
  w.u64(g.chainId);
  w.bytes(g.stateRoot);
  w.u64(g.genesisTime);
  w.bytes(g.proposer);
  w.blob(g.snapshot);
  return w.finish();
}

export function decodeGenesis(buf: Uint8Array): Genesis {
  const r = new Reader(buf);
  const genesisHash = r.take(32);
  const chainId = r.u64();
  const stateRoot = r.take(32);
  const genesisTime = r.u64();
  const proposer = r.take(20);
  const snapshot = r.blob(MAX_BLOCK_BYTES);
  r.finish();
  return { genesisHash, chainId, stateRoot, genesisTime, proposer, snapshot };
}

// ---------------------------------------------------------------------------
// SyncRequest encode/decode
// ---------------------------------------------------------------------------

const SYNC_TAG_HELLO = 0;
const SYNC_TAG_BLOCKS = 1;
const SYNC_TAG_GENESIS = 2;

export function encodeSyncRequest(req: SyncRequest): Uint8Array {
  const w = new Writer();
  if (req.tag === "Hello") {
    w.u8(SYNC_TAG_HELLO);
    w.bytes(encodeHello(req.hello));
  } else if (req.tag === "GetBlocks") {
    w.u8(SYNC_TAG_BLOCKS);
    w.bytes(encodeGetBlocks(req.getBlocks));
  } else {
    // GetGenesis carries no body.
    w.u8(SYNC_TAG_GENESIS);
  }
  return w.finish();
}

export function decodeSyncResponse(buf: Uint8Array): SyncResponse {
  if (buf.length === 0) throw new Error("wire: empty SyncResponse");
  const tag = buf[0]!;
  const rest = buf.slice(1);
  if (tag === SYNC_TAG_HELLO) {
    return { tag: "Hello", hello: decodeHello(rest) };
  } else if (tag === SYNC_TAG_BLOCKS) {
    return { tag: "Blocks", blocks: decodeBlocks(rest) };
  } else if (tag === SYNC_TAG_GENESIS) {
    return { tag: "Genesis", genesis: decodeGenesis(rest) };
  }
  throw new Error(`wire: unknown SyncResponse tag ${tag}`);
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

export function toHex(bytes: Uint8Array): string {
  let s = "0x";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

export function fromHex(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
