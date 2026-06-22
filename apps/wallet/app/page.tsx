"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  formatUbi,
  projectBalance,
  DEVNET_CHAIN_ID,
  type BalanceSample,
  type Block,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, NETWORK } from "./config";
import { Streams } from "./streams";
import { Humanity } from "./humanity";

type Conn = "connecting" | "ok" | "bad";

const POLL_MS = 4000;
const MAX_BLOCKS = 6;

const client = new Ubi2Client({ url: RPC_URL });

function shortHash(hash: string): string {
  if (!hash || hash.length < 14) return hash;
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
}

function fmtTs(hexSecs: string): string {
  const secs = parseInt(hexSecs, 16);
  if (!Number.isFinite(secs)) return "—";
  const d = new Date(secs * 1000);
  return d.toLocaleTimeString();
}

function Copy({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="copy"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

export default function Home() {
  const [conn, setConn] = useState<Conn>("connecting");
  const [chainId, setChainId] = useState<number | null>(null);
  const [display, setDisplay] = useState<string>("—");
  const [latest, setLatest] = useState<number | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Latest balance sample, read by the rAF loop without re-rendering on every poll.
  const sampleRef = useRef<BalanceSample | null>(null);
  const rafRef = useRef<number | null>(null);

  // Check connection + chain id.
  const checkConn = useCallback(async () => {
    try {
      const id = await client.chainId();
      setChainId(id);
      if (id === DEVNET_CHAIN_ID) {
        setConn("ok");
        setError(null);
      } else {
        setConn("bad");
        setError(`Wrong chain id: got ${id}, expected ${DEVNET_CHAIN_ID}`);
      }
      return id === DEVNET_CHAIN_ID;
    } catch (e) {
      setConn("bad");
      setError(e instanceof Error ? e.message : "node unreachable");
      sampleRef.current = null;
      return false;
    }
  }, []);

  // Poll: re-anchor the balance sample + refresh explorer.
  const poll = useCallback(async () => {
    const live = await checkConn();
    if (!live) return;
    try {
      const sample = await client.sampleBalance(DEV_ACCOUNT);
      sampleRef.current = sample;

      const head = await client.blockNumber();
      setLatest(head);

      const start = Math.max(0, head - (MAX_BLOCKS - 1));
      const nums: number[] = [];
      for (let n = head; n >= start; n--) nums.push(n);
      const fetched = await Promise.all(nums.map((n) => client.getBlockByNumber(n)));
      setBlocks(fetched.filter((b): b is Block => b != null));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [checkConn]);

  // Polling loop.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      await poll();
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [poll]);

  // Animation loop: interpolate the balance forward between polls for a smooth tick.
  useEffect(() => {
    const frame = () => {
      const s = sampleRef.current;
      // 8 decimals so the streaming drip is visibly moving frame-to-frame (>= the 2-dp floor).
      if (s) setDisplay(formatUbi(projectBalance(s), 8));
      rafRef.current = requestAnimationFrame(frame);
    };
    rafRef.current = requestAnimationFrame(frame);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  const statusClass = conn === "ok" ? "status ok" : conn === "bad" ? "status bad" : "status warn";
  const statusText =
    conn === "ok"
      ? `Connected · chain ${chainId}`
      : conn === "connecting"
        ? "Connecting…"
        : "Disconnected";

  return (
    <main>
      <div className="header">
        <div>
          <h1>
            <span style={{ color: "var(--accent)" }}>UBI</span>
          </h1>
          <p className="tagline">wallet &amp; block explorer · devnet</p>
        </div>
        <span className={statusClass}>
          <span className="dot" />
          {statusText}
        </span>
      </div>

      {/* Streaming balance */}
      <section className="card">
        <h2>Verified account balance</h2>
        <div className="balance">{display}</div>
        <div className="balance-sub">
          Streaming live
          <span className="rate-badge">1 UBI / hr</span>
        </div>
        <div className="mt">
          <div className="label">Account</div>
          <div className="row">
            <span className="addr">{DEV_ACCOUNT}</span>
            <Copy value={DEV_ACCOUNT} />
          </div>
        </div>
        {conn === "bad" && error && (
          <p className="small mt" style={{ color: "var(--danger)" }}>
            {error} — is the devnet node running on {RPC_URL}?
          </p>
        )}
      </section>

      {/* M3: Proof of Humanity */}
      <Humanity account={DEV_ACCOUNT} />

      {/* M2: streaming */}
      <Streams account={DEV_ACCOUNT} />

      <div className="grid-2">
        {/* Explorer */}
        <section className="card">
          <h2>Explorer · latest blocks</h2>
          <div className="row" style={{ marginBottom: "0.75rem" }}>
            <span className="muted small">Height</span>
            <span className="block-num">{latest != null ? `#${latest}` : "—"}</span>
          </div>
          <div className="blocks">
            {blocks.length === 0 && <p className="muted small">No blocks yet.</p>}
            {blocks.map((b) => (
              <div className="block-row" key={b.hash || b.number}>
                <span className="block-num">#{parseInt(b.number, 16)}</span>
                <span className="block-hash">{shortHash(b.hash)}</span>
                <span className="block-ts">{fmtTs(b.timestamp)}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Add to MetaMask */}
        <section className="card">
          <h2>Add to MetaMask</h2>
          <dl className="kv">
            <dt>Network name</dt>
            <dd>{NETWORK.chainName}</dd>
            <dt>RPC URL</dt>
            <dd>{NETWORK.rpcUrl}</dd>
            <dt>Chain ID</dt>
            <dd>{NETWORK.chainIdDec}</dd>
            <dt>Symbol</dt>
            <dd>{NETWORK.symbol}</dd>
          </dl>
          <div className="row mt">
            <span className="muted small">Add this network manually in MetaMask.</span>
            <Copy value={NETWORK.rpcUrl} />
          </div>
        </section>
      </div>
    </main>
  );
}
