"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  formatUbi,
  projectBalance,
  DEVNET_CHAIN_ID,
  type BalanceSample,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, NETWORK } from "./config";
import { Nav, type Section } from "./nav";
import { Streams } from "./streams";
import { Humanity } from "./humanity";
import { Explorer } from "./explorer";
import { Contracts } from "./contracts";

type Conn = "connecting" | "ok" | "bad";

const POLL_MS = 4000;

const client = new Ubi2Client({ url: RPC_URL });

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
        } catch { /* clipboard unavailable */ }
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

export default function Home() {
  const [section, setSection] = useState<Section>("wallet");
  const [conn, setConn] = useState<Conn>("connecting");
  const [chainId, setChainId] = useState<number | null>(null);
  const [display, setDisplay] = useState<string>("—");
  const [error, setError] = useState<string | null>(null);

  // Latest balance sample — read by rAF loop without re-rendering on every poll.
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

  // Poll: re-anchor the balance sample.
  const poll = useCallback(async () => {
    const live = await checkConn();
    if (!live) return;
    try {
      const sample = await client.sampleBalance(DEV_ACCOUNT);
      sampleRef.current = sample;
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

  // Animation loop: interpolate balance forward between polls for a smooth tick.
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

  return (
    <>
      <Nav active={section} onSelect={setSection} conn={conn} chainId={chainId} />

      <main className="app-main">
        {/* ------------------------------------------------------------------ */}
        {/* WALLET section                                                       */}
        {/* ------------------------------------------------------------------ */}
        {section === "wallet" && (
          <div>
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

            {/* M2: streaming */}
            <Streams account={DEV_ACCOUNT} />
          </div>
        )}

        {/* ------------------------------------------------------------------ */}
        {/* EXPLORER section                                                     */}
        {/* ------------------------------------------------------------------ */}
        {section === "explorer" && <Explorer />}

        {/* ------------------------------------------------------------------ */}
        {/* IDENTITY section (Proof of Humanity)                                */}
        {/* ------------------------------------------------------------------ */}
        {section === "identity" && <Humanity account={DEV_ACCOUNT} />}

        {/* ------------------------------------------------------------------ */}
        {/* CONTRACTS section                                                   */}
        {/* ------------------------------------------------------------------ */}
        {section === "contracts" && <Contracts account={DEV_ACCOUNT} />}
      </main>
    </>
  );
}
