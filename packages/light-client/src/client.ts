/**
 * LightClient — the ubi2 browser/Node light node (spec 07 §3.2, ADR-0006).
 *
 * Connects to a WS sync gateway, handshakes (Hello exchange), requests blocks in batches of
 * SYNC_MAX_BATCH, drives the `LightCore` WASM kernel to re-execute each block and assert a
 * byte-identical `state_root`, stays live via pushed new-block frames, and exposes verified reads.
 *
 * Trust model (spec §3.4): full re-execution from genesis (or a restored IndexedDB snapshot).
 * The gateway is trusted only for availability — a forged block fails re-execution and is caught.
 * A tampered state_root, reordered txs, or forged proposer all produce a `VerificationError`.
 *
 * verifyMode: "full" is the only mode that satisfies the spec's LC-2/LC-5 exit criteria.
 * Header-only is a documented degraded mode (never auto-selected).
 */

import {
  bytesEqual,
  decodeSyncFrame,
  encodeSyncRequest,
  fromHex,
  toHex,
  wireBlockNumber,
  SYNC_LIVE_PUSH_ID,
} from "./wire.js";
import type { SyncRequest, SyncResponse } from "./wire.js";
import type {
  ILightState,
  LightStateFactory,
  LightStateGenesisFactory,
  TipInfo,
} from "./wasm-types.js";
import type { SnapshotStore } from "./store.js";
import { defaultStore } from "./store.js";

// Constants matching crates/network/src/consts.rs
const SYNC_MAX_BATCH = 128n;
const FINALITY_DEPTH = 6n;
const PROTOCOL_VERSION = 1;

/**
 * How many times, after the initial catch-up to the Hello tip, we RE-QUERY the gateway's current tip
 * and fetch the gap before going live (issue #37 handshake gap). Bounded so steady block production
 * cannot spin this loop forever — once live, buffered pushes + gap-fill keep the client at the tip.
 */
const HANDSHAKE_CATCHUP_ROUNDS = 8;

/** Default per-request timeout (ms). A reply that never arrives rejects the request instead of hanging. */
const DEFAULT_REQUEST_TIMEOUT_MS = 20_000;

/**
 * The subset of the WHATWG `WebSocket` API the client uses. Declared as a seam so tests can inject a
 * deterministic in-process mock gateway (issue #37 race tests) without a real socket; production passes
 * the global `WebSocket`.
 */
export type WebSocketLike = Pick<
  WebSocket,
  "binaryType" | "send" | "close" | "addEventListener" | "removeEventListener"
>;

export type VerifyMode = "full"; // "header" is a backlog degraded mode (never auto-selected)

/** Emitted when a block fails verification (forged block, wrong root, unsigned proposer, etc.). */
export class VerificationError extends Error {
  constructor(
    message: string,
    public readonly blockNumber: bigint,
    public readonly detail: string,
  ) {
    super(message);
    this.name = "VerificationError";
  }
}

/** Emitted when the gateway advertises the wrong network (genesis hash / chain id mismatch). */
export class WrongNetworkError extends Error {
  constructor(detail: string) {
    super(`wrong network: ${detail}`);
    this.name = "WrongNetworkError";
  }
}

/** Emitted when the gateway fails to serve a requested block range (availability fault). */
export class GatewayError extends Error {
  constructor(detail: string) {
    super(`gateway error: ${detail}`);
    this.name = "GatewayError";
  }
}

export interface LightClientOptions {
  /** ws:// or wss:// URL of the sync gateway endpoint (e.g. ws://127.0.0.1:8546). */
  gatewayUrl: string;
  /**
   * Expected chain id (0x5542 = 21826 for the devnet).  The Hello exchange rejects a gateway
   * with a different chain id (AC-F-LN4).
   */
  chainId: number;
  /**
   * PINNED genesis block hash (0x-hex, 32 bytes) — a REQUIRED hard-coded constant of the shipped app
   * (`ln-trust-1`).  The client REJECTS (`WrongNetworkError`) any gateway whose advertised genesis hash
   * differs; it NEVER adopts the gateway's.
   */
  genesisHash: string;
  /**
   * PINNED **seeded** genesis state_root (0x-hex, 32 bytes) — a REQUIRED hard-coded constant
   * (`ln-trust-2`/`ln-trust-3`).  The client fetches the gateway's genesis snapshot, re-derives its
   * state_root in the WASM kernel, and REJECTS unless it equals this pinned value.  This is the seeded
   * root (over the genesis accounts/jurors/CSCA/governance), NOT the genesis block header's zero root.
   */
  genesisStateRoot: string;
  /** Genesis unix time (seconds) — pinned; cross-checked against the gateway's served anchor. */
  genesisTime?: number;
  /**
   * PINNED PoA validator/proposer set (0x-hex 20-byte addresses) — a REQUIRED hard-coded constant
   * (`ln-trust-1`).  The kernel enforces `block.proposer ∈ this set` on EVERY block (no None-skip).  On
   * the single-proposer devnet this is `[expectedProposer]`.
   */
  validatorSet: string[];
  /**
   * Factory that constructs a WASM LightState from the PINNED, verified seeded-genesis snapshot
   * (`genesisImport`).  This is the shipped path.  Supplied by the caller (browser: the wasm-bindgen
   * `LightState.genesisImport`; tests: a native shim).
   */
  lightStateGenesisFactory: LightStateGenesisFactory;
  /**
   * Legacy empty-state factory (the pre-pin `new LightState(...)` path).  Optional + retained for
   * back-compat; the shipped client uses {@link lightStateGenesisFactory}.  The empty-state import is
   * non-functional on a real seeded chain (`ln-trust-2`).
   */
  lightStateFactory?: LightStateFactory;
  /** Persistence store for verified snapshots (default: IndexedDB in browser, in-memory in Node). */
  store?: SnapshotStore;
  /**
   * The scheduled proposer address (0x-hex 20 bytes).  ALWAYS passed to `applyBlock` so the kernel pins
   * the scheduled proposer on every block (`ln-trust-1`).  Defaults to the sole `validatorSet` entry.
   */
  expectedProposer?: string;
  /** Verification mode (only "full" satisfies LC-2/LC-5; kept for forward-compat). */
  verifyMode?: VerifyMode;
  /** Emit log messages (optional; defaults to console.error for errors, silent otherwise). */
  logger?: (level: "info" | "warn" | "error", msg: string) => void;
  /**
   * Factory for the WebSocket (test seam, issue #37). Defaults to the global `WebSocket`. Tests inject
   * an in-process mock gateway to drive the request/response + live-push race deterministically.
   */
  wsFactory?: (url: string) => WebSocketLike;
  /** Per-request reply timeout in ms (default {@link DEFAULT_REQUEST_TIMEOUT_MS}). */
  requestTimeoutMs?: number;
}

export interface VerifiedBalanceSample {
  /** Balance in base units at `now` (unix seconds), as a decimal string (never a float). */
  balance: string;
  /** The unix second at which the balance was sampled. */
  now: number;
  /** Whether the balance is from a fully-verified (re-executed) block or a live-push. */
  verified: boolean;
  /** The verified tip height at the time of the sample. */
  tipHeight: bigint;
}

/**
 * LightClient: connects to a WS sync gateway and maintains a locally-verified chain state.
 *
 * Usage:
 * ```ts
 * const lc = new LightClient({ gatewayUrl: "ws://127.0.0.1:8546", chainId: 0x5542,
 *                               lightStateFactory: (cid, gh, gr, gt) => new LightState(...) });
 * await lc.sync(); // sync genesis→tip, then stays live until lc.close()
 * const bal = lc.balanceOf("0x...", BigInt(Math.floor(Date.now()/1000)));
 * ```
 */
export class LightClient {
  private readonly gatewayUrl: string;
  private readonly chainId: number;
  private readonly genesisHash: string;
  private readonly genesisStateRoot: string;
  private readonly genesisTime: number | undefined;
  private readonly validatorSet: string[];
  private readonly lightStateGenesisFactory: LightStateGenesisFactory;
  private readonly expectedProposer: string;
  private readonly verifyMode: VerifyMode;
  private readonly log: (level: "info" | "warn" | "error", msg: string) => void;

  private state: ILightState | null = null;
  private ws: WebSocketLike | null = null;
  private closed = false;
  private verificationBadge: "unverified" | "verified" | "error" = "unverified";
  private lastVerificationError: string | null = null;
  private gatewayTip: bigint = 0n;
  private store: SnapshotStore;
  private readonly wsFactory: (url: string) => WebSocketLike;
  private readonly requestTimeoutMs: number;

  // ---- issue #37: request/response correlation + strict in-order application ----
  /** In-flight requests keyed by their client-assigned `req_id`; resolved by the single message handler. */
  private readonly pending = new Map<
    bigint,
    { resolve: (r: SyncResponse) => void; reject: (e: Error) => void }
  >();
  /** Next correlation id to assign. Starts at 1 — `0` is reserved for unsolicited live pushes. */
  private nextReqId = 1n;
  /** Live-pushed (and gap-filled) blocks awaiting strict in-order application, keyed by block number. */
  private readonly liveBuffer = new Map<bigint, Uint8Array>();
  /** The last block number applied to the kernel — the SINGLE source of truth for ordering. */
  private localTip = 0n;
  /** Serialize the applier: `true` while `drain()` runs; `drainQueued` re-runs it for a late enqueue. */
  private draining = false;
  private drainQueued = false;
  /** After initial sync we go "live": the message handler then kicks `drain()` on every push. */
  private live = false;
  private snapKey = "";

  constructor(opts: LightClientOptions) {
    this.gatewayUrl = opts.gatewayUrl;
    this.chainId = opts.chainId;
    // ln-trust-1/2/3: the pinned anchor constants are REQUIRED — there is no "accept any genesis" path.
    if (!opts.genesisHash) {
      throw new Error("LightClient: genesisHash is required (pinned anchor, ln-trust-1)");
    }
    if (!opts.genesisStateRoot) {
      throw new Error(
        "LightClient: genesisStateRoot is required (pinned seeded root, ln-trust-2)",
      );
    }
    if (!opts.validatorSet || opts.validatorSet.length === 0) {
      throw new Error(
        "LightClient: validatorSet must pin at least one PoA proposer (ln-trust-1)",
      );
    }
    if (!opts.lightStateGenesisFactory) {
      throw new Error("LightClient: lightStateGenesisFactory is required (pinned-snapshot import)");
    }
    this.genesisHash = opts.genesisHash;
    this.genesisStateRoot = opts.genesisStateRoot;
    this.genesisTime = opts.genesisTime;
    this.validatorSet = opts.validatorSet.map((v) => v.toLowerCase());
    this.lightStateGenesisFactory = opts.lightStateGenesisFactory;
    // Always have an expected (scheduled) proposer to pass to applyBlock — default to the sole pinned
    // validator (the single-proposer devnet). The kernel ALSO enforces membership in the pinned set.
    this.expectedProposer = (opts.expectedProposer ?? opts.validatorSet[0]!).toLowerCase();
    this.verifyMode = opts.verifyMode ?? "full";
    this.log = opts.logger ?? (() => {});
    this.store = opts.store ?? defaultStore();
    this.wsFactory = opts.wsFactory ?? ((url: string) => new WebSocket(url));
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  /** The current verification badge (`"unverified"` / `"verified"` / `"error"`). */
  get badge(): "unverified" | "verified" | "error" {
    return this.verificationBadge;
  }

  /** The last verification error message, if any. */
  get lastError(): string | null {
    return this.lastVerificationError;
  }

  /** The verified tip info (or null before any block is applied). */
  get tip(): TipInfo | null {
    return this.state?.tip() ?? null;
  }

  /**
   * The streaming balance of `addr` at unix-second `now`, as a **decimal string** of base units.
   * Returns null if the state has not been initialised (no blocks applied yet).
   *
   * IMPORTANT: `now` is a unix second (not ms) supplied by the caller.  The value projects the
   * stream forward exactly as `Account::balance(now)` does — the same integer formula the chain
   * commits.  No float, ever (spec §2.2, I2).
   */
  balanceOf(addr: string, now: bigint): string | null {
    return this.state?.balanceOf(addr, now) ?? null;
  }

  /** PoH status of `addr` (0=Unverified…4=Revoked), or 0 if state not yet initialised. */
  humanStatus(addr: string): number {
    return this.state?.humanStatus(addr) ?? 0;
  }

  /**
   * Connect to the sync gateway, handshake, sync all blocks from genesis (or last snapshot) to
   * the gateway's tip, and stay live.  Resolves once the initial sync is complete.
   *
   * Throws `WrongNetworkError` if the gateway is on a different network.
   * Throws `GatewayError` on connection/protocol failures.
   */
  async sync(): Promise<void> {
    const log = this.log;

    // ---- Persisted-snapshot handling ----
    // We always re-sync from the PINNED, verified genesis anchor (spec §3.3 — always safe). A future
    // snapshot-restore fast path would `deserialize` the stored state THEN re-pin the validator set via
    // `setValidatorSet` and re-verify the restored root against the pinned tip before trusting it; until
    // then re-syncing from the verified seeded genesis is the correct, trust-preserving default.
    const snapKey = `lightState:${this.chainId}`;
    this.snapKey = snapKey;
    const snapBytes = await this.store.load(snapKey);
    if (snapBytes) {
      log("info", `snapshot found (${snapBytes.length} bytes); re-syncing from the pinned genesis anchor`);
    }

    // ---- Open WebSocket + install the SINGLE persistent frame handler ----
    // From the very first byte, every inbound frame is demultiplexed by its `req_id` (issue #37): a
    // correlated reply resolves its pending request; an unsolicited live push (`req_id = 0`) is buffered.
    // So a block mined during ANY request window can never be consumed as that request's response.
    const ws = await this.openSocket();
    this.ws = ws;

    // ---- Hello handshake ----
    // We always send our PINNED genesis hash. The gateway closes on a mismatch, AND we re-check the
    // gateway's advertised hash below — we NEVER adopt the gateway's genesis (ln-trust-1).
    const helloResp = await this.request({
      tag: "Hello",
      hello: {
        genesisHash: fromHex(this.genesisHash),
        chainId: BigInt(this.chainId),
        tipHeight: 0n,
        tipHash: new Uint8Array(32),
        validator: null,
        peerProof: new Uint8Array(0),
        protocolVer: PROTOCOL_VERSION,
      },
    });
    if (helloResp.tag !== "Hello") {
      throw new GatewayError("expected Hello response");
    }
    const gwHello = helloResp.hello;

    // Validate chain id + genesis hash against the PINNED constants (AC-F-LN4, ln-trust-1).
    if (gwHello.chainId !== BigInt(this.chainId)) {
      throw new WrongNetworkError(
        `chainId mismatch: expected ${this.chainId}, got ${gwHello.chainId}`,
      );
    }
    if (!bytesEqual(gwHello.genesisHash, fromHex(this.genesisHash))) {
      throw new WrongNetworkError(
        `genesisHash mismatch: pinned ${this.genesisHash}, gateway ${toHex(gwHello.genesisHash)}`,
      );
    }

    this.gatewayTip = gwHello.tipHeight;
    log("info", `gateway tip: block ${gwHello.tipHeight}`);

    // ---- Fetch the seeded genesis anchor and verify it against the PINNED constants ----
    // (ln-trust-2/3): the gateway serves the seeded genesis snapshot; the WASM kernel re-derives its
    // state_root LOCALLY and throws unless it equals the pinned root. A lying gateway is CAUGHT here.
    // A live block pushed DURING this window carries `req_id = 0` → it is buffered, never taken as the
    // Genesis reply (the original issue #37 abort).
    const genesisResp = await this.request({ tag: "GetGenesis" });
    if (genesisResp.tag !== "Genesis") {
      throw new GatewayError("expected Genesis response to GetGenesis");
    }
    const anchor = genesisResp.genesis;

    // Re-check every served anchor field against the pinned constants (NEVER adopt the gateway's).
    if (!bytesEqual(anchor.genesisHash, fromHex(this.genesisHash))) {
      throw new WrongNetworkError(
        `genesis anchor hash mismatch: pinned ${this.genesisHash}, gateway ${toHex(anchor.genesisHash)}`,
      );
    }
    if (!bytesEqual(anchor.stateRoot, fromHex(this.genesisStateRoot))) {
      throw new WrongNetworkError(
        `genesis state_root mismatch: pinned ${this.genesisStateRoot}, gateway ${toHex(anchor.stateRoot)}`,
      );
    }
    if (anchor.chainId !== BigInt(this.chainId)) {
      throw new WrongNetworkError(
        `genesis anchor chainId mismatch: expected ${this.chainId}, got ${anchor.chainId}`,
      );
    }
    // The served proposer must be in the pinned validator set.
    if (!this.validatorSet.includes(toHex(anchor.proposer).toLowerCase())) {
      throw new WrongNetworkError(
        `genesis proposer ${toHex(anchor.proposer)} is not in the pinned validator set`,
      );
    }
    const resolvedGenesisTime = this.genesisTime ?? Number(anchor.genesisTime);

    // ---- Initialise the WASM state from the PINNED, verified genesis snapshot ----
    // `genesisImport` re-derives the snapshot's state_root and THROWS (WrongNetwork) unless it equals
    // the pinned root — so the snapshot is untrusted DATA verified against the hard-coded anchor.
    try {
      this.state = this.lightStateGenesisFactory(
        this.chainId,
        this.genesisHash,
        this.genesisStateRoot,
        resolvedGenesisTime,
        anchor.snapshot,
        this.validatorSet,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // A snapshot whose re-derived root != pinned is the gateway lying about the seeded genesis.
      throw new WrongNetworkError(`genesis snapshot failed pinned-root verification: ${msg}`);
    }

    // The applied tip starts wherever the imported verified state sits (genesis import → 0).
    this.localTip = BigInt(this.state.tip().number);

    // ---- Catch up to the Hello tip (in-order, via the shared applier) ----
    await this.catchUpTo(this.gatewayTip);

    // ---- Close the handshake gap (issue #37) ----
    // Blocks mined between the first Hello and now must be fetched, or the light node stays behind the
    // real tip forever. RE-QUERY the gateway's CURRENT tip and GetBlocks the gap, repeating until the
    // tip stops advancing (bounded). Live pushes buffered during the handshake are also applied here.
    for (let round = 0; round < HANDSHAKE_CATCHUP_ROUNDS; round++) {
      const currentTip = await this.requestTip();
      if (currentTip <= this.localTip) break;
      await this.catchUpTo(currentTip);
    }

    log("info", `initial sync complete at block ${this.localTip}`);

    // ---- Go live: flush buffered pushes, then apply every future push in strict order ----
    // Marking `live` makes the message handler kick `drain()` on each push; the explicit drain here
    // flushes anything buffered during the handshake/catch-up.
    this.live = true;
    await this.drain();
  }

  /**
   * Fetch and apply blocks in contiguous `SYNC_MAX_BATCH` batches until the applied tip reaches
   * `target`. Each batch is enqueued and applied through the SINGLE in-order applier ({@link drain}),
   * so a live push interleaved during a batch window is ordered correctly, never applied out of turn.
   */
  private async catchUpTo(target: bigint): Promise<void> {
    while (this.localTip < target) {
      const from = this.localTip + 1n;
      const to = from + SYNC_MAX_BATCH - 1n <= target ? from + SYNC_MAX_BATCH - 1n : target;
      const blocks = await this.requestBlocks(from, to);
      if (blocks.length === 0) break; // gateway has no more — stop (avoid a spin)
      this.enqueueBlocks(blocks);
      await this.drain();
    }
  }

  /** Apply a single wire-encoded block to the WASM kernel.  Throws `VerificationError` on failure. */
  private async applyWireBlock(wireBlockBytes: Uint8Array): Promise<bigint> {
    if (!this.state) throw new Error("state not initialised");

    try {
      // ln-trust-1: ALWAYS pass the scheduled proposer so the kernel pins it on every block (no
      // None-skip). The kernel ALSO enforces `proposer ∈ pinned validator set` independently.
      const outcome = this.state.applyBlock(wireBlockBytes, this.expectedProposer);
      this.verificationBadge = "verified";
      this.lastVerificationError = null;
      return BigInt(outcome.number);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      this.verificationBadge = "error";
      this.lastVerificationError = msg;
      // Determine block number for the error (best-effort from tip+1).
      const tipNum = this.state.tip().number;
      throw new VerificationError(
        `block verification failed: ${msg}`,
        BigInt(tipNum + 1),
        msg,
      );
    }
  }

  /**
   * Buffer live-pushed / gap-filled block blobs for strict in-order application, keyed by block number.
   * Blocks at or below the applied tip (or already buffered) are ignored — dedup is by number.
   */
  private enqueueBlocks(blocks: Uint8Array[]): void {
    for (const b of blocks) {
      const n = wireBlockNumber(b);
      if (n > this.localTip && !this.liveBuffer.has(n)) {
        this.liveBuffer.set(n, b);
      }
    }
  }

  /**
   * The SINGLE in-order applier (issue #37). Applies a buffered block ONLY when its number is exactly
   * `localTip + 1`; on a gap (a buffered block sits above a missing height) it `GetBlocks` the missing
   * range and applies in order. Serialized by `draining`/`drainQueued` so no two applications ever race
   * — the parent-hash chain in `applyWireBlock` therefore never sees an out-of-order block. Fail-closed:
   * a block that fails verification stops application and surfaces the error (never a wrong balance).
   */
  private async drain(): Promise<void> {
    if (this.draining) {
      // Another drain is running — ask it to re-scan the buffer after its current pass (no lost wakeup).
      this.drainQueued = true;
      return;
    }
    this.draining = true;
    try {
      do {
        this.drainQueued = false;
        for (;;) {
          const next = this.localTip + 1n;
          const bytes = this.liveBuffer.get(next);
          if (bytes) {
            this.liveBuffer.delete(next);
            try {
              this.localTip = await this.applyWireBlock(bytes);
            } catch (e) {
              // Fail-closed: stop applying; the badge is already "error". Do NOT advance the tip.
              if (e instanceof VerificationError) {
                this.log("error", e.message);
                return;
              }
              throw e;
            }
            continue;
          }
          // `next` is missing. If a HIGHER block is buffered we missed a push → fetch the gap.
          let lowestHigher: bigint | null = null;
          for (const k of this.liveBuffer.keys()) {
            if (k > next && (lowestHigher === null || k < lowestHigher)) lowestHigher = k;
          }
          if (lowestHigher === null) break; // nothing applicable right now
          const cap = next + SYNC_MAX_BATCH - 1n;
          const to = cap < lowestHigher - 1n ? cap : lowestHigher - 1n;
          const fetched = await this.requestBlocks(next, to);
          if (fetched.length === 0) break; // gateway can't serve the gap yet — stop (avoid a spin)
          this.enqueueBlocks(fetched);
        }
      } while (this.drainQueued);
      await this.persist(this.snapKey);
    } finally {
      this.draining = false;
    }
  }

  /** Persist the current verified state to the store. */
  private async persist(key: string): Promise<void> {
    if (!this.state) return;
    try {
      const bytes = this.state.serialize();
      await this.store.save(key, bytes);
    } catch (_) {
      // Persistence failure is non-fatal (a restart will re-sync).
    }
  }

  /** Whether a block at `height` is below the finality depth (provisional). */
  isProvisional(height: bigint): boolean {
    const tip = this.state?.tip();
    if (!tip) return true;
    return height > BigInt(tip.number) - FINALITY_DEPTH;
  }

  /** Close the WS connection and mark the client as closed. */
  close(): void {
    this.closed = true;
    this.rejectAllPending(new GatewayError("client closed"));
    this.ws?.close();
    this.ws = null;
  }

  // ---------------------------------------------------------------------------
  // WebSocket helpers — request/response correlation + live-push demux (issue #37)
  // ---------------------------------------------------------------------------

  /**
   * Open the socket and install the SINGLE persistent frame handler. Resolves on `open`. From this
   * point every inbound frame flows through {@link onMessage}, which demultiplexes by `req_id`.
   */
  private openSocket(): Promise<WebSocketLike> {
    return new Promise((resolve, reject) => {
      let opened = false;
      const ws = this.wsFactory(this.gatewayUrl);
      ws.binaryType = "arraybuffer";
      ws.addEventListener("open", () => {
        opened = true;
        resolve(ws);
      });
      ws.addEventListener("message", (event: MessageEvent) => this.onMessage(event));
      ws.addEventListener("close", () => {
        // Reject any in-flight requests so awaiters fail instead of hanging.
        this.rejectAllPending(new GatewayError("connection closed"));
        if (!this.closed) this.log("warn", "sync gateway connection closed");
      });
      ws.addEventListener("error", (e: Event) => {
        if (!opened) reject(new GatewayError(`connect failed: ${String(e)}`));
        this.rejectAllPending(new GatewayError(`WebSocket error: ${String(e)}`));
        this.log("error", `sync gateway error: ${String(e)}`);
      });
    });
  }

  /**
   * The single message handler. Demultiplexes every frame by its `req_id` (issue #37):
   *  - `req_id != 0` → resolve the matching pending request (never mis-consumed by a live push);
   *  - `req_id == 0` → an unsolicited live-block push: buffer the block(s) and, once live, kick the
   *    strict in-order applier.
   */
  private onMessage(event: MessageEvent): void {
    if (this.closed) return;
    let reqId: bigint;
    let resp: SyncResponse;
    try {
      const raw = event.data as ArrayBuffer | Uint8Array;
      const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer);
      ({ reqId, resp } = decodeSyncFrame(bytes));
    } catch (e) {
      // A malformed frame is dropped — it must not crash the socket handler.
      this.log("warn", `dropping undecodable frame: ${String(e)}`);
      return;
    }

    if (reqId !== SYNC_LIVE_PUSH_ID) {
      const pend = this.pending.get(reqId);
      if (pend) {
        this.pending.delete(reqId);
        pend.resolve(resp);
      } else {
        this.log("warn", `unmatched response req_id ${reqId} (dropped)`);
      }
      return;
    }

    // Unsolicited live push (req_id 0): buffer for strict in-order application.
    if (resp.tag === "Blocks") {
      this.enqueueBlocks(resp.blocks.blocks);
      if (this.live) void this.drain();
    }
  }

  /**
   * Send a correlated request and await the matching reply. Assigns the next `req_id`, sends the framed
   * request, and resolves when {@link onMessage} routes the echoed-id reply back — so a live push can
   * NEVER be consumed in place of this response. Rejects on timeout / socket close.
   */
  private request(req: SyncRequest): Promise<SyncResponse> {
    const ws = this.ws;
    if (!ws) return Promise.reject(new GatewayError("socket not open"));
    const reqId = this.nextReqId++;
    return new Promise<SyncResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(reqId)) {
          reject(new GatewayError(`request ${reqId} timed out after ${this.requestTimeoutMs}ms`));
        }
      }, this.requestTimeoutMs);
      this.pending.set(reqId, {
        resolve: (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      try {
        ws.send(encodeSyncRequest(reqId, req));
      } catch (e) {
        this.pending.delete(reqId);
        clearTimeout(timer);
        reject(new GatewayError(`send failed: ${String(e)}`));
      }
    });
  }

  /** Request a block range, returning the raw (opaque) block blobs. Throws if the reply is not `Blocks`. */
  private async requestBlocks(from: bigint, to: bigint): Promise<Uint8Array[]> {
    const resp = await this.request({ tag: "GetBlocks", getBlocks: { from, to } });
    if (resp.tag !== "Blocks") {
      throw new GatewayError(`expected Blocks response, got ${resp.tag}`);
    }
    return resp.blocks.blocks;
  }

  /**
   * Re-query the gateway's CURRENT tip (issue #37 handshake gap). A re-sent Hello is answered by the
   * gateway with a fresh Hello carrying its live tip; we read the height off the correlated reply.
   */
  private async requestTip(): Promise<bigint> {
    const resp = await this.request({
      tag: "Hello",
      hello: {
        genesisHash: fromHex(this.genesisHash),
        chainId: BigInt(this.chainId),
        tipHeight: this.localTip,
        tipHash: new Uint8Array(32),
        validator: null,
        peerProof: new Uint8Array(0),
        protocolVer: PROTOCOL_VERSION,
      },
    });
    if (resp.tag !== "Hello") {
      throw new GatewayError(`expected Hello (tip re-query), got ${resp.tag}`);
    }
    return resp.hello.tipHeight;
  }

  /** Reject and clear every in-flight request (on socket close / client close). */
  private rejectAllPending(err: Error): void {
    for (const pend of this.pending.values()) pend.reject(err);
    this.pending.clear();
  }
}
