/**
 * @ubi2/light-client — sync race regression tests (issue #37).
 *
 * Proves the browser sync driver's request/response correlation + strict in-order application close the
 * race between the gateway's live block pushes and its request replies. Runs the REAL {@link LightClient}
 * against an in-process mock gateway injected via the `wsFactory` seam (no socket, no WASM) with a fake
 * `ILightState` shim that enforces the "trust no server" ordering invariants: a block only applies when
 * its number is exactly `tip + 1` AND its parent-hash links to the current tip — otherwise it throws,
 * exactly as the real WASM kernel would. So if the client ever applied a block out of order, these tests
 * would surface a thrown VerificationError instead of a clean, contiguous apply sequence.
 *
 * Run: pnpm -C packages/light-client run test   (tsx src/sync.test.ts)
 *
 * Scenarios (from issue #37):
 *   1. A live block pushed DURING the GetGenesis window is buffered (req_id 0), not consumed as the
 *      Genesis reply; Genesis still resolves and the client reaches the correct tip.
 *   2. A live block pushed DURING a GetBlocks window does not corrupt the batch; the client ends at the
 *      correct tip having applied every block exactly once, in order.
 *   3. Blocks mined between the first Hello and going live are fetched via the tip re-query (even when
 *      their live pushes were never delivered — the "never catches up" case).
 *   4. An out-of-order / burst live push applies in order (gap-fill), never a parent-hash abort.
 * Plus a cross-language wire vector matching the Rust `sync_frame_cross_lang_vector` test.
 */

import { LightClient } from "./client.js";
import {
  decodeGetBlocks,
  decodeHello,
  decodeSyncFrame,
  encodeBlocks,
  encodeGenesis,
  encodeHello,
  encodeSyncRequest,
  fromHex,
  toHex,
  wireBlockNumber,
} from "./wire.js";
import type { SyncRequest } from "./wire.js";
import type { BlockOutcome, ILightState, TipInfo } from "./wasm-types.js";
import type { WebSocketLike } from "./client.js";

// ─── tiny test harness ─────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;
async function test(name: string, fn: () => Promise<void> | void): Promise<void> {
  try {
    await fn();
    console.log(`  ok    ${name}`);
    passed++;
  } catch (e) {
    console.error(`  FAIL  ${name}\n        ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    failed++;
  }
}
function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(msg);
}
function assertEq(a: unknown, b: unknown, msg: string): void {
  if (a !== b) throw new Error(`${msg}: ${String(a)} !== ${String(b)}`);
}
function waitFor(cond: () => boolean, ms: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = (): void => {
      if (cond()) return resolve();
      if (Date.now() - start > ms) return reject(new Error("waitFor: timed out"));
      setTimeout(tick, 2);
    };
    tick();
  });
}

// ─── pinned constants the mock serves + the client pins ──────────────────────────
const CHAIN_ID = 21826;
const GENESIS_HASH = "0x" + "11".repeat(32);
const GENESIS_STATE_ROOT = "0x" + "22".repeat(32);
const PROPOSER = "0x" + "33".repeat(20);
const GENESIS_TIME = 1_700_000_000;

// ─── deterministic fake block hash (no crypto): number encoded in the low 8 bytes ─
function fakeHash(n: number): Uint8Array {
  const h = new Uint8Array(32);
  new DataView(h.buffer).setBigUint64(24, BigInt(n), false);
  return h;
}
const fakeHashHex = (n: number): string => toHex(fakeHash(n));

/** Build a 40-byte block blob: `number(u64 BE) ‖ parent_hash(32)` — all the shim + client read. */
function buildBlock(n: number): Uint8Array {
  const b = new Uint8Array(40);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  b.set(fakeHash(n - 1), 8);
  return b;
}

/**
 * A fake `ILightState` that enforces the ordering + parent-hash invariants the real WASM kernel does.
 * It records every applied block number so a test can assert a strictly-contiguous apply sequence.
 */
class FakeState implements ILightState {
  private tipNum = 0;
  private tipHashHex = fakeHashHex(0);
  readonly applied: number[] = [];

  applyBlock(wire: Uint8Array, _expectedProposer?: string): BlockOutcome {
    const num = Number(wireBlockNumber(wire));
    const parentHex = toHex(wire.subarray(8, 40));
    if (num !== this.tipNum + 1) {
      throw new Error(`non-contiguous block: got ${num}, tip ${this.tipNum}`);
    }
    if (parentHex !== this.tipHashHex) {
      throw new Error(`parent-hash mismatch at block ${num}`);
    }
    this.tipNum = num;
    this.tipHashHex = fakeHashHex(num);
    this.applied.push(num);
    return { number: num, hash: this.tipHashHex, stateRoot: GENESIS_STATE_ROOT, timestamp: 0 };
  }
  stateRoot(): string {
    return GENESIS_STATE_ROOT;
  }
  tip(): TipInfo {
    return { number: this.tipNum, hash: this.tipHashHex, stateRoot: GENESIS_STATE_ROOT, timestamp: 0 };
  }
  balanceOf(_addr: string, _now: bigint): string {
    return "0";
  }
  nonceOf(_addr: string): number {
    return 0;
  }
  humanStatus(_addr: string): number {
    return 0;
  }
  serialize(): Uint8Array {
    return new Uint8Array(0);
  }
}

// ─── the in-process mock gateway (a WebSocketLike + a scripted responder) ────────
interface MockConfig {
  /** Highest block that EXISTS (GetBlocks serves up to this; live pushes bump it). */
  maxHeight: number;
  /** Tip the gateway ADVERTISES on the n-th Hello (default: current maxHeight). */
  advertisedTip?: (helloCount: number) => number;
  /** Hook fired right before the Genesis reply — inject a live push here. */
  onGetGenesis?: (gw: MockGateway) => void;
  /** Hook fired right before each GetBlocks reply — inject a live push here. */
  onGetBlocks?: (gw: MockGateway, from: bigint, to: bigint) => void;
}

type Listener = (ev: { data: Uint8Array } | Event) => void;

class MockGateway {
  private listeners: Record<string, Listener[]> = { open: [], message: [], close: [], error: [] };
  private helloCount = 0;
  private openScheduled = false;
  maxHeight: number;
  readonly socket: WebSocketLike;

  constructor(private cfg: MockConfig) {
    this.maxHeight = cfg.maxHeight;
    const self = this;
    // A minimal WebSocket-shaped object; cast at the seam (the client only uses this subset).
    this.socket = {
      binaryType: "arraybuffer",
      addEventListener(type: string, l: Listener): void {
        (self.listeners[type] ??= []).push(l);
        // Fire "open" once, on a microtask AFTER the client has attached its listener (the client
        // registers open→message→close→error synchronously, so all are present when this runs).
        if (type === "open" && !self.openScheduled) {
          self.openScheduled = true;
          queueMicrotask(() => self.dispatch("open", new Event("open")));
        }
      },
      removeEventListener(type: string, l: Listener): void {
        self.listeners[type] = (self.listeners[type] ?? []).filter((x) => x !== l);
      },
      send(data: Uint8Array): void {
        self.handleSend(data);
      },
      close(): void {
        self.dispatch("close", new Event("close"));
      },
    } as unknown as WebSocketLike;
  }

  private dispatch(type: string, ev: { data: Uint8Array } | Event): void {
    for (const l of this.listeners[type] ?? []) l(ev);
  }

  /** Deliver a framed response to the client on the next microtask (FIFO order preserved). */
  private deliver(bytes: Uint8Array): void {
    queueMicrotask(() => this.dispatch("message", { data: bytes }));
  }

  /** Simulate a live-block push: the gateway mines block `n` and pushes it with req_id 0. */
  pushLive(n: number): void {
    this.maxHeight = Math.max(this.maxHeight, n);
    this.deliver(respFrame(0n, TAG_BLOCKS, encodeBlocks({ blocks: [buildBlock(n)] })));
  }

  private serveBlocks(from: bigint, to: bigint): Uint8Array[] {
    const blobs: Uint8Array[] = [];
    const hi = to < BigInt(this.maxHeight) ? to : BigInt(this.maxHeight);
    for (let n = from; n <= hi; n++) blobs.push(buildBlock(Number(n)));
    return blobs;
  }

  private handleSend(frameBytes: Uint8Array): void {
    const { reqId, req } = decodeReqFrame(frameBytes);
    if (req.tag === "Hello") {
      this.helloCount++;
      const tip = this.cfg.advertisedTip ? this.cfg.advertisedTip(this.helloCount) : this.maxHeight;
      const body = encodeHello({
        genesisHash: fromHex(GENESIS_HASH),
        chainId: BigInt(CHAIN_ID),
        tipHeight: BigInt(tip),
        tipHash: new Uint8Array(32),
        validator: null,
        peerProof: new Uint8Array(0),
        protocolVer: 1,
      });
      this.deliver(respFrame(reqId, TAG_HELLO, body));
    } else if (req.tag === "GetGenesis") {
      this.cfg.onGetGenesis?.(this);
      const body = encodeGenesis({
        genesisHash: fromHex(GENESIS_HASH),
        chainId: BigInt(CHAIN_ID),
        stateRoot: fromHex(GENESIS_STATE_ROOT),
        genesisTime: BigInt(GENESIS_TIME),
        proposer: fromHex(PROPOSER),
        snapshot: new Uint8Array([1, 2, 3]),
      });
      this.deliver(respFrame(reqId, TAG_GENESIS, body));
    } else {
      const { from, to } = req.getBlocks;
      this.cfg.onGetBlocks?.(this, from, to);
      const body = encodeBlocks({ blocks: this.serveBlocks(from, to) });
      this.deliver(respFrame(reqId, TAG_BLOCKS, body));
    }
  }
}

// ─── frame helpers (request decode + response encode, mirroring wire.ts) ──────────
const TAG_HELLO = 0;
const TAG_BLOCKS = 1;
const TAG_GENESIS = 2;

function decodeReqFrame(buf: Uint8Array): { reqId: bigint; req: SyncRequest } {
  const reqId = new DataView(buf.buffer, buf.byteOffset, 8).getBigUint64(0, false);
  const tag = buf[8]!;
  const rest = buf.subarray(9);
  if (tag === TAG_HELLO) return { reqId, req: { tag: "Hello", hello: decodeHello(rest) } };
  if (tag === TAG_BLOCKS) return { reqId, req: { tag: "GetBlocks", getBlocks: decodeGetBlocks(rest) } };
  if (tag === TAG_GENESIS) return { reqId, req: { tag: "GetGenesis" } };
  throw new Error(`mock: bad request tag ${tag}`);
}

function respFrame(reqId: bigint, tag: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + 1 + body.length);
  new DataView(out.buffer).setBigUint64(0, reqId, false);
  out[8] = tag;
  out.set(body, 9);
  return out;
}

function newClient(gw: MockGateway): LightClient {
  return new LightClient({
    gatewayUrl: "ws://mock",
    chainId: CHAIN_ID,
    genesisHash: GENESIS_HASH,
    genesisStateRoot: GENESIS_STATE_ROOT,
    genesisTime: GENESIS_TIME,
    validatorSet: [PROPOSER],
    lightStateGenesisFactory: () => new FakeState(),
    wsFactory: () => gw.socket,
  });
}

// ─── the tests ───────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  await test("cross-language wire vector: GetGenesis @ req_id 1 == 00..01 02", () => {
    const enc = encodeSyncRequest(1n, { tag: "GetGenesis" });
    assertEq(toHex(enc), "0x000000000000000102", "GetGenesis frame bytes");
    // Body is unchanged by framing: byte 8 is the tag, prefix is the big-endian req_id.
    const gb = encodeSyncRequest(0x0102030405060708n, { tag: "GetBlocks", getBlocks: { from: 1n, to: 5n } });
    assertEq(toHex(gb.subarray(0, 8)), "0x0102030405060708", "req_id prefix is big-endian");
    assertEq(gb[8], TAG_BLOCKS, "byte after prefix is the body tag");
    // A live push (req_id 0) decodes as an empty Blocks body and round-trips through decodeSyncFrame.
    const push = respFrame(0n, TAG_BLOCKS, encodeBlocks({ blocks: [] }));
    const { reqId, resp } = decodeSyncFrame(push);
    assertEq(reqId, 0n, "live-push req_id is 0");
    assertEq(resp.tag, "Blocks", "live-push body tag");
  });

  await test("scenario 1: live push DURING GetGenesis is not mis-consumed as the Genesis reply", async () => {
    let pushed = false;
    const gw = new MockGateway({
      maxHeight: 3,
      onGetGenesis: (g) => {
        if (!pushed) {
          pushed = true;
          g.pushLive(4); // a block mined exactly in the GetGenesis window
        }
      },
    });
    const lc = newClient(gw);
    await lc.sync(); // before the fix this threw "expected Genesis response to GetGenesis"
    const state = (lc as unknown as { state: FakeState }).state;
    assert(pushed, "the live push was injected during the GetGenesis window");
    assertEq(lc.tip?.number, 4, "client reached the correct tip");
    assertEq(JSON.stringify(state.applied), JSON.stringify([1, 2, 3, 4]), "applied contiguous + in order");
    assertEq(lc.badge, "verified", "badge verified");
    lc.close();
  });

  await test("scenario 2: live push DURING a GetBlocks batch does not corrupt the batch", async () => {
    let injected = false;
    const gw = new MockGateway({
      maxHeight: 5,
      onGetBlocks: (g, _from, _to) => {
        if (!injected) {
          injected = true;
          g.pushLive(6); // races the [1..5] batch reply
        }
      },
    });
    const lc = newClient(gw);
    await lc.sync();
    const state = (lc as unknown as { state: FakeState }).state;
    assert(injected, "a live push was injected during a GetBlocks window");
    assertEq(lc.tip?.number, 6, "client ends at the correct tip");
    assertEq(
      JSON.stringify(state.applied),
      JSON.stringify([1, 2, 3, 4, 5, 6]),
      "every block applied exactly once, in order — the batch was not corrupted",
    );
    lc.close();
  });

  await test("scenario 3: blocks mined between Hello and going-live are fetched via tip re-query", async () => {
    // First Hello advertises 3; the re-query Hello advertises 6 (blocks 4,5,6 'mined' during handshake).
    // No live pushes are delivered for 4,5,6 — proving the re-query alone closes the gap.
    const gw = new MockGateway({
      maxHeight: 6,
      advertisedTip: (helloCount) => (helloCount === 1 ? 3 : 6),
    });
    const lc = newClient(gw);
    await lc.sync();
    const state = (lc as unknown as { state: FakeState }).state;
    assertEq(lc.tip?.number, 6, "client caught up to the real tip via the re-query");
    assertEq(
      JSON.stringify(state.applied),
      JSON.stringify([1, 2, 3, 4, 5, 6]),
      "handshake-gap blocks fetched + applied in order",
    );
    lc.close();
  });

  await test("scenario 4: an out-of-order / burst live push applies in order (gap-fill), no parent abort", async () => {
    // The gateway advertises tip 0 (no pull catch-up), then bursts live pushes OUT OF ORDER: block 3
    // then block 2 — block 1 is never pushed. The in-order applier must gap-fill [1] and apply 1,2,3.
    const gw = new MockGateway({
      maxHeight: 3,
      advertisedTip: () => 0,
    });
    const lc = newClient(gw);
    await lc.sync(); // goes live at tip 0
    const state = (lc as unknown as { state: FakeState }).state;
    // Burst, out of order, with a hole at 1:
    gw.pushLive(3);
    gw.pushLive(2);
    await waitFor(() => lc.tip?.number === 3, 1000);
    assertEq(lc.tip?.number, 3, "applier reached tip 3");
    assertEq(
      JSON.stringify(state.applied),
      JSON.stringify([1, 2, 3]),
      "strict in-order apply despite an out-of-order burst (gap-filled block 1)",
    );
    assertEq(lc.badge, "verified", "no parent-hash abort — badge stayed verified");
    lc.close();
  });
}

await main();
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  throw new Error(`${failed} light-client sync test(s) failed`);
}
