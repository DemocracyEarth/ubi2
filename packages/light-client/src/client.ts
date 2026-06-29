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
  decodeBlocks,
  decodeHello,
  decodeSyncResponse,
  encodeGetBlocks,
  encodeHello,
  encodeSyncRequest,
  fromHex,
  toHex,
} from "./wire.js";
import type { ILightState, LightStateFactory, TipInfo } from "./wasm-types.js";
import type { SnapshotStore } from "./store.js";
import { defaultStore } from "./store.js";

// Constants matching crates/network/src/consts.rs
const SYNC_MAX_BATCH = 128n;
const FINALITY_DEPTH = 6n;
const PROTOCOL_VERSION = 1;

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
   * Expected genesis block hash (0x-hex, 32 bytes).  Rejects a gateway on a different network.
   * If omitted, the light client accepts any genesis and records the gateway's (useful for first
   * start with an unknown genesis).
   */
  genesisHash?: string;
  /** Expected genesis state root (0x-hex, 32 bytes). Used to initialise the WASM state. */
  genesisStateRoot?: string;
  /** Expected genesis unix time (seconds). */
  genesisTime?: number;
  /** Factory that constructs a WASM LightState handle.  Supplied by the caller. */
  lightStateFactory: LightStateFactory;
  /** Persistence store for verified snapshots (default: IndexedDB in browser, in-memory in Node). */
  store?: SnapshotStore;
  /** Optional scheduled proposer address (0x-hex 20 bytes).  Passed to `applyBlock`. */
  expectedProposer?: string;
  /** Verification mode (only "full" satisfies LC-2/LC-5; kept for forward-compat). */
  verifyMode?: VerifyMode;
  /** Emit log messages (optional; defaults to console.error for errors, silent otherwise). */
  logger?: (level: "info" | "warn" | "error", msg: string) => void;
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
  private readonly genesisHash: string | undefined;
  private readonly genesisStateRoot: string | undefined;
  private readonly genesisTime: number | undefined;
  private readonly lightStateFactory: LightStateFactory;
  private readonly expectedProposer: string | undefined;
  private readonly verifyMode: VerifyMode;
  private readonly log: (level: "info" | "warn" | "error", msg: string) => void;

  private state: ILightState | null = null;
  private ws: WebSocket | null = null;
  private closed = false;
  private verificationBadge: "unverified" | "verified" | "error" = "unverified";
  private lastVerificationError: string | null = null;
  private gatewayTip: bigint = 0n;
  private store: SnapshotStore;

  constructor(opts: LightClientOptions) {
    this.gatewayUrl = opts.gatewayUrl;
    this.chainId = opts.chainId;
    this.genesisHash = opts.genesisHash;
    this.genesisStateRoot = opts.genesisStateRoot;
    this.genesisTime = opts.genesisTime;
    this.lightStateFactory = opts.lightStateFactory;
    this.expectedProposer = opts.expectedProposer;
    this.verifyMode = opts.verifyMode ?? "full";
    this.log = opts.logger ?? (() => {});
    this.store = opts.store ?? defaultStore();
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

    // ---- Try to restore from a persisted snapshot ----
    const snapKey = `lightState:${this.chainId}`;
    const snapBytes = await this.store.load(snapKey);
    if (snapBytes) {
      // For now we skip snapshot restoration and re-sync from genesis (always safe, spec §3.3).
      // Full snapshot restore requires the WASM LightState.deserialize static method which is
      // provided by the caller's factory; that integration is a follow-up.
      log("info", `snapshot found (${snapBytes.length} bytes) but re-syncing from genesis`);
    }

    // ---- Open WebSocket ----
    const ws = await this.connect();
    this.ws = ws;

    // ---- Hello handshake ----
    const genesisHashBytes = this.genesisHash
      ? fromHex(this.genesisHash)
      : new Uint8Array(32); // zero hash accepted if genesis unknown

    const helloMsg = encodeSyncRequest({
      tag: "Hello",
      hello: {
        genesisHash: genesisHashBytes,
        chainId: BigInt(this.chainId),
        tipHeight: 0n,
        tipHash: new Uint8Array(32),
        validator: null,
        peerProof: new Uint8Array(0),
        protocolVer: PROTOCOL_VERSION,
      },
    });
    ws.send(helloMsg);

    // Wait for the gateway's Hello response.
    const gatewayHelloBytes = await this.recv(ws);
    const gatewayResp = decodeSyncResponse(gatewayHelloBytes);
    if (gatewayResp.tag !== "Hello") {
      throw new GatewayError("expected Hello response, got Blocks");
    }
    const gwHello = gatewayResp.hello;

    // Validate chain id + genesis hash (AC-F-LN4).
    if (gwHello.chainId !== BigInt(this.chainId)) {
      throw new WrongNetworkError(
        `chainId mismatch: expected ${this.chainId}, got ${gwHello.chainId}`,
      );
    }
    if (this.genesisHash) {
      const ourGenesis = fromHex(this.genesisHash);
      if (!bytesEqual(gwHello.genesisHash, ourGenesis)) {
        throw new WrongNetworkError(
          `genesisHash mismatch: expected ${this.genesisHash}, got ${toHex(gwHello.genesisHash)}`,
        );
      }
    }

    // If we didn't know the genesis hash before, record it now.
    const resolvedGenesisHash = this.genesisHash ?? toHex(gwHello.genesisHash);
    const resolvedGenesisRoot = this.genesisStateRoot ?? "0x" + "00".repeat(32);
    const resolvedGenesisTime = this.genesisTime ?? 0;

    this.gatewayTip = gwHello.tipHeight;
    log("info", `gateway tip: block ${gwHello.tipHeight}`);

    // ---- Initialise the WASM state ----
    this.state = this.lightStateFactory(
      this.chainId,
      resolvedGenesisHash,
      resolvedGenesisRoot,
      resolvedGenesisTime,
    );

    // ---- Sync loop: fetch blocks genesis→tip in SYNC_MAX_BATCH batches ----
    let localTip = 0n; // we always start from genesis in this implementation
    while (localTip < this.gatewayTip) {
      const from = localTip + 1n;
      const to = localTip + SYNC_MAX_BATCH < this.gatewayTip
        ? localTip + SYNC_MAX_BATCH
        : this.gatewayTip;

      const getBlocksMsg = encodeSyncRequest({
        tag: "GetBlocks",
        getBlocks: { from, to },
      });
      ws.send(getBlocksMsg);

      const blocksBytes = await this.recv(ws);
      const blocksResp = decodeSyncResponse(blocksBytes);
      if (blocksResp.tag !== "Blocks") {
        throw new GatewayError("expected Blocks response, got Hello");
      }

      const { blocks } = blocksResp.blocks;
      if (blocks.length === 0) {
        // Gateway has no more blocks — break.
        break;
      }

      for (const wireBlockBytes of blocks) {
        localTip = await this.applyWireBlock(wireBlockBytes);
      }

      // Persist snapshot after each batch.
      await this.persist(snapKey);
    }

    log("info", `initial sync complete at block ${localTip}`);

    // ---- Stay live: the gateway pushes new blocks as SyncResponse::Blocks(count=1) ----
    this.listenLive(ws, snapKey);
  }

  /** Apply a single wire-encoded block to the WASM kernel.  Throws `VerificationError` on failure. */
  private async applyWireBlock(wireBlockBytes: Uint8Array): Promise<bigint> {
    if (!this.state) throw new Error("state not initialised");

    try {
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

  /** Listen for live pushed blocks after initial sync completes. */
  private listenLive(ws: WebSocket, snapKey: string): void {
    const log = this.log;
    ws.addEventListener("message", async (event: MessageEvent) => {
      if (this.closed) return;
      try {
        const raw = event.data as ArrayBuffer | Uint8Array;
        const bytes =
          raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer);
        const resp = decodeSyncResponse(bytes);
        if (resp.tag !== "Blocks") return;
        for (const wireBlockBytes of resp.blocks.blocks) {
          await this.applyWireBlock(wireBlockBytes);
        }
        await this.persist(snapKey);
      } catch (e) {
        if (e instanceof VerificationError) {
          log("error", e.message);
        }
        // Other decode errors: log + continue (don't crash the live listener).
      }
    });

    ws.addEventListener("close", () => {
      if (!this.closed) {
        log("warn", "sync gateway connection closed");
      }
    });

    ws.addEventListener("error", (e: Event) => {
      log("error", `sync gateway error: ${String(e)}`);
    });
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
    this.ws?.close();
    this.ws = null;
  }

  // ---------------------------------------------------------------------------
  // WebSocket helpers
  // ---------------------------------------------------------------------------

  private connect(): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.gatewayUrl);
      ws.binaryType = "arraybuffer";
      ws.addEventListener("open", () => resolve(ws));
      ws.addEventListener("error", (e) => reject(new GatewayError(`connect failed: ${String(e)}`)));
    });
  }

  /**
   * Receive the next binary message from the WebSocket.  Rejects on close or error.
   * Used only during the sequential handshake + sync-loop phases.
   */
  private recv(ws: WebSocket): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const onMessage = (event: MessageEvent) => {
        ws.removeEventListener("message", onMessage);
        ws.removeEventListener("close", onClose);
        ws.removeEventListener("error", onError);
        const raw = event.data as ArrayBuffer | Uint8Array;
        resolve(raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer));
      };
      const onClose = () => {
        ws.removeEventListener("message", onMessage);
        ws.removeEventListener("error", onError);
        reject(new GatewayError("connection closed before response"));
      };
      const onError = (e: Event) => {
        ws.removeEventListener("message", onMessage);
        ws.removeEventListener("close", onClose);
        reject(new GatewayError(`WebSocket error: ${String(e)}`));
      };
      ws.addEventListener("message", onMessage);
      ws.addEventListener("close", onClose);
      ws.addEventListener("error", onError);
    });
  }
}
