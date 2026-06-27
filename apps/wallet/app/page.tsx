"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ExplorerReader,
  formatUbi,
  projectBalance,
  sendTransferTx,
  DEVNET_CHAIN_ID,
  type BalanceSample,
  type ActivityRow,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY, NETWORK, getExplorerUrl } from "./config";
import { Nav, type Section } from "./nav";
import { Streams } from "./streams";
import { Humanity } from "./humanity";
import { Explorer } from "./explorer";
import { Contracts } from "./contracts";
import { AiSection } from "./ai-section";

type Conn = "connecting" | "ok" | "bad";

const POLL_MS = 4000;

const client = new Ubi2Client({ url: RPC_URL });
const explorerReader = new ExplorerReader(client);

// UBI fee constants (gas * 1 gwei) for display in transfer preview
const TRANSFER_FEE_BASE = 21_000n * 1_000_000_000n;   // 0.000021 UBI

function short(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function shortHash(h: string): string {
  if (!h || h.length < 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-6)}`;
}

function hexToUbi(hex: string, frac = 4): string {
  try { return formatUbi(BigInt(hex), frac); } catch { return "0 UBI"; }
}

function fmtTs(hexSecs: string): string {
  const secs = parseInt(hexSecs, 16);
  if (!Number.isFinite(secs)) return "—";
  return new Date(secs * 1000).toLocaleTimeString();
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
        } catch { /* clipboard unavailable */ }
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function kindBadgeCls(kind: string): string {
  if (kind === "Transfer") return "kind-badge k-transfer";
  if (kind.includes("Stream")) return "kind-badge k-stream";
  if (kind === "Vouch" || kind.includes("Verification") || kind.includes("Verdict") || kind === "Challenge") return "kind-badge k-vouch";
  if (kind.includes("Deploy") || kind.includes("Contract")) return "kind-badge k-deploy";
  if (kind.includes("Invoke") || kind.includes("Fund") || kind.includes("Effect")) return "kind-badge k-invoke";
  return "kind-badge k-system";
}

function kindLabel(kind: string): string {
  const map: Record<string, string> = {
    Transfer: "transfer", OpenStream: "open stream", StopStream: "stop stream",
    RequestVerification: "apply PoH", Vouch: "vouch", Challenge: "challenge",
    SubmitVerdict: "verdict", DeployContract: "deploy", FundContract: "fund",
    InvokeContract: "invoke", SubmitEffect: "effect",
  };
  return map[kind] ?? kind.toLowerCase();
}

// ---- Transfer form ---------------------------------------------------------------

interface Injected {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

function getInjected(): Injected | null {
  if (typeof window === "undefined") return null;
  const eth = (window as unknown as { ethereum?: Injected }).ethereum;
  return eth ?? null;
}

function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const o = e as Record<string, unknown>;
    const nested = (o.data as { message?: string } | undefined)?.message;
    const msg = (o.shortMessage ?? o.message ?? nested) as string | undefined;
    if (msg) return typeof o.code === "number" ? `${msg} (code ${o.code})` : msg;
    try { return JSON.stringify(e); } catch { /* fall through */ }
  }
  return String(e);
}

function TransferForm() {
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  useEffect(() => setInjected(getInjected()), []);

  const connect = useCallback(async () => {
    if (!injected) { setNote({ kind: "err", text: "No injected wallet — install MetaMask." }); return; }
    try {
      const accounts = (await injected.request({ method: "eth_requestAccounts" })) as string[];
      setConnected(accounts[0] ?? DEV_ACCOUNT);
      setNote(null);
    } catch (e) { setNote({ kind: "err", text: errMessage(e) }); }
  }, [injected]);

  const send = useCallback(async () => {
    if (!/^0x[0-9a-fA-F]{40}$/.test(to)) {
      setNote({ kind: "err", text: "Recipient must be a 0x address (42 chars)." });
      return;
    }
    let valueBase: bigint;
    try {
      const trimmed = amount.trim();
      const [whole = "0", frac = ""] = trimmed.split(".");
      const fracPadded = (frac + "0".repeat(18)).slice(0, 18);
      valueBase = BigInt(whole || "0") * (10n ** 18n) + BigInt(fracPadded || "0");
      if (valueBase <= 0n) throw new Error("amount must be > 0");
    } catch {
      setNote({ kind: "err", text: "Invalid amount." });
      return;
    }
    setBusy(true);
    setNote(null);
    try {
      const from = connected ?? DEV_ACCOUNT;
      let hash: string;
      if (injected) {
        const res = await sendTransferTx({
          to, value: valueBase, from,
          provider: injected as Parameters<typeof sendTransferTx>[0]["provider"],
        });
        hash = res.hash;
      } else {
        const res = await sendTransferTx({ to, value: valueBase, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
        hash = res.hash;
      }
      setNote({
        kind: "ok",
        text: `Sent · ${shortHash(hash)} · fee ${formatUbi(TRANSFER_FEE_BASE, 6)}`,
      });
      setTo(""); setAmount("");
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(false);
    }
  }, [to, amount, injected, connected]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected ? "MetaMask (not connected)" : "devnet dev key";

  return (
    <div className="card">
      <div className="card-header">
        <h3>Send UBI</h3>
        <span className="tag green">native transfer</span>
      </div>

      <div className="field">
        <label>Recipient address</label>
        <input placeholder="0x…" value={to} onChange={(e) => setTo(e.target.value.trim())} spellCheck={false} />
      </div>

      <div className="field">
        <label>Amount (UBI)</label>
        <input inputMode="decimal" placeholder="e.g. 1.0" value={amount} onChange={(e) => setAmount(e.target.value)} />
      </div>

      {/* Fee preview */}
      <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: ".75rem", flexWrap: "wrap" }}>
        <span className="muted small">
          fee: <span style={{ fontFamily: "var(--mono)", color: "var(--warn)" }}>{formatUbi(TRANSFER_FEE_BASE, 6)}</span>
        </span>
        <span className="muted small" style={{ fontSize: ".72rem" }}>gas 21000 × 1 gwei</span>
      </div>

      <button className="primary" onClick={send} disabled={busy}>{busy ? "Sending…" : "Send"}</button>

      <div className="signer" style={{ marginTop: ".5rem" }}>
        signing with <b>{signerLabel}</b>
        {injected && !connected && (
          <button className="ghost" style={{ marginLeft: ".5rem" }} onClick={connect}>Connect MetaMask</button>
        )}
      </div>

      {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
    </div>
  );
}

// ---- Add to MetaMask button -------------------------------------------------------

function AddToMetaMaskButton() {
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const addNetwork = useCallback(async () => {
    const eth = (window as unknown as { ethereum?: { request: (a: unknown) => Promise<unknown> } }).ethereum;
    if (!eth) {
      setNote({ kind: "err", text: "MetaMask not detected — install it first." });
      return;
    }
    setBusy(true);
    setNote(null);
    try {
      const explorerUrl = getExplorerUrl();
      await eth.request({
        method: "wallet_addEthereumChain",
        params: [
          {
            chainId: NETWORK.chainIdHex,
            chainName: NETWORK.chainName,
            nativeCurrency: {
              name: "UBI",
              symbol: NETWORK.symbol,
              decimals: NETWORK.decimals,
            },
            rpcUrls: [NETWORK.rpcUrl],
            blockExplorerUrls: [explorerUrl],
          },
        ],
      });
      setNote({ kind: "ok", text: "Network added — MetaMask will show ubi2 devnet as a custom network with block explorer links." });
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(false);
    }
  }, []);

  return (
    <div style={{ marginTop: "1rem" }}>
      <button className="primary" onClick={addNetwork} disabled={busy} style={{ marginBottom: "0.5rem" }}>
        {busy ? "Adding…" : "Add ubi2 devnet to MetaMask"}
      </button>
      <div className="muted small" style={{ marginTop: "0.25rem", lineHeight: 1.5 }}>
        Adds the network with block-explorer URLs pointing to this wallet app — MetaMask will
        show &quot;View on explorer&quot; links for transactions and accounts.
      </div>
      {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
    </div>
  );
}

// ---- Activity Feed ---------------------------------------------------------------

function ActivityFeed({ account }: { account: string }) {
  const [rows, setRows] = useState<ActivityRow[]>([]);
  const [blockNum, setBlockNum] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const [activity, head] = await Promise.all([
          explorerReader.getAddressActivity(account, 10),
          client.blockNumber(),
        ]);
        if (alive) { setRows(activity); setBlockNum(head); }
      } catch { /* node down */ }
    };
    poll();
    const id = setInterval(poll, POLL_MS);
    return () => { alive = false; clearInterval(id); };
  }, [account]);

  if (rows.length === 0) return null;

  return (
    <div className="card">
      <div className="card-header">
        <h3>Latest activity</h3>
        {blockNum != null && <span className="faint small" style={{ fontFamily: "var(--mono)" }}>block #{blockNum}</span>}
      </div>
      <div>
        {rows.map((row, i) => {
          const blockN = parseInt(row.blockNumber, 16);
          const feeUbi = row.fee ? hexToUbi(row.fee, 6) : null;
          return (
            <div
              key={`${row.hash}-${i}`}
              style={{
                display: "grid",
                gridTemplateColumns: "7rem 1fr auto",
                gap: ".6rem",
                alignItems: "center",
                padding: ".55rem 0",
                borderTop: i === 0 ? "none" : "1px solid var(--line)",
                fontSize: ".82rem",
              }}
            >
              <span className={kindBadgeCls(row.kind)}>{kindLabel(row.kind)}</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontFamily: "var(--mono)", color: "var(--muted)", fontSize: ".72rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {shortHash(row.hash)}
                  {row.counterparty && (
                    <span style={{ color: "var(--faint)", marginLeft: ".4rem" }}>→ {short(row.counterparty)}</span>
                  )}
                </div>
              </div>
              <span style={{ fontFamily: "var(--mono)", color: "var(--faint)", fontSize: ".72rem", textAlign: "right", whiteSpace: "nowrap" }}>
                #{blockN}
                {feeUbi && <span style={{ color: "var(--warn)", marginLeft: ".4rem" }}>· {feeUbi}</span>}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---- Home page ---------------------------------------------------------------

export default function Home() {
  const [section, setSection] = useState<Section>("wallet");
  const [conn, setConn] = useState<Conn>("connecting");
  const [chainId, setChainId] = useState<number | null>(null);
  const [display, setDisplay] = useState<string>("—");
  const [error, setError] = useState<string | null>(null);
  const [isVerified, setIsVerified] = useState(false);

  // Explorer deep-link state: when a contract detail links into the explorer
  const [explorerBlockTarget, setExplorerBlockTarget] = useState<number | null>(null);
  const [explorerTxTarget, setExplorerTxTarget] = useState<string | null>(null);

  const sampleRef = useRef<BalanceSample | null>(null);
  const rafRef = useRef<number | null>(null);

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

  const poll = useCallback(async () => {
    const live = await checkConn();
    if (!live) return;
    try {
      const sample = await client.sampleBalance(DEV_ACCOUNT);
      sampleRef.current = sample;
      try {
        const acct = await explorerReader.getAccount(DEV_ACCOUNT);
        setIsVerified(acct.human_status === "Verified");
      } catch { /* ignore */ }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [checkConn]);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      await poll();
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [poll]);

  useEffect(() => {
    const frame = () => {
      const s = sampleRef.current;
      if (s) setDisplay(formatUbi(projectBalance(s), 8));
      rafRef.current = requestAnimationFrame(frame);
    };
    rafRef.current = requestAnimationFrame(frame);
    return () => { if (rafRef.current != null) cancelAnimationFrame(rafRef.current); };
  }, []);

  const balanceNum = display.replace(" UBI", "").replace("—", "");

  // Navigate to explorer with a specific block or tx pre-selected
  const openExplorerBlock = useCallback((n: number) => {
    setExplorerBlockTarget(n);
    setExplorerTxTarget(null);
    setSection("explorer");
  }, []);

  const openExplorerTx = useCallback((hash: string) => {
    setExplorerTxTarget(hash);
    setExplorerBlockTarget(null);
    setSection("explorer");
  }, []);

  // Clear targets once consumed (the Explorer component reads these once on mount)
  const consumeExplorerTarget = useCallback(() => {
    setExplorerBlockTarget(null);
    setExplorerTxTarget(null);
  }, []);

  return (
    <>
      <Nav
        active={section}
        onSelect={setSection}
        conn={conn}
        chainId={chainId}
        onSettings={() => setSection("ai")}
        settingsOpen={section === "ai"}
      />

      <main className="app-main">
        {/* ------------------------------------------------------------------ */}
        {/* WALLET                                                               */}
        {/* ------------------------------------------------------------------ */}
        {section === "wallet" && (
          <div>
            {/* Hero grid */}
            <div className="hero-grid">
              {/* Main balance card */}
              <div className="card">
                <div className="label">Streaming balance</div>
                <div className="hero-bal">
                  {balanceNum || "—"}
                  <span className="hero-unit">UBI</span>
                </div>
                <div>
                  <span className="rate-badge">
                    <span className="drip" />
                    +1 UBI / hour · live
                  </span>
                </div>
                <div className="acct-row">
                  {isVerified && (
                    <span className="verified-badge poh">&#9679; Verified human</span>
                  )}
                  <span className="addr-chip">{short(DEV_ACCOUNT)}</span>
                  <Copy value={DEV_ACCOUNT} />
                </div>
                {error && conn === "bad" && (
                  <p className="small mt" style={{ color: "var(--danger)", margin: "1rem 0 0" }}>
                    {error} — is the devnet node running on {RPC_URL}?
                  </p>
                )}
              </div>

              {/* Mini stat card */}
              <div className="card mini-stats">
                <div className="mini-stat">
                  <div className="label">Network</div>
                  <div className="v">
                    <span style={{ fontFamily: "var(--mono)", fontSize: "14px", color: "var(--ink)" }}>
                      {NETWORK.chainName}
                    </span>
                  </div>
                </div>
                <div className="mini-stat">
                  <div className="label">Chain ID</div>
                  <div className="v">
                    <span className="green" style={{ fontFamily: "var(--mono)", fontSize: "22px", fontWeight: 600 }}>
                      {NETWORK.chainIdDec}
                    </span>
                  </div>
                </div>
                <div className="mini-stat">
                  <div className="label">Symbol</div>
                  <div className="v violet">{NETWORK.symbol}</div>
                </div>
              </div>
            </div>

            {/* Add to MetaMask — now includes blockExplorerUrls */}
            <div className="card">
              <div className="card-header">
                <h3>Add to MetaMask</h3>
                <Copy value={NETWORK.rpcUrl} />
              </div>
              <dl className="kv">
                <dt>Network name</dt>
                <dd>{NETWORK.chainName}</dd>
                <dt>RPC URL</dt>
                <dd>{NETWORK.rpcUrl}</dd>
                <dt>Chain ID</dt>
                <dd>{NETWORK.chainIdDec} (0x{DEVNET_CHAIN_ID.toString(16)})</dd>
                <dt>Symbol</dt>
                <dd>{NETWORK.symbol}</dd>
                <dt>Decimals</dt>
                <dd>{NETWORK.decimals}</dd>
                <dt>Block explorer</dt>
                <dd style={{ color: "var(--accent)", fontSize: "0.75rem" }}>
                  This wallet (set on add — MetaMask shows &quot;View on explorer&quot; links)
                </dd>
              </dl>
              <AddToMetaMaskButton />
            </div>

            {/* Transfer form — shows UBI fee */}
            <TransferForm />

            {/* Recent activity with fees */}
            <ActivityFeed account={DEV_ACCOUNT} />

            {/* Streams */}
            <Streams account={DEV_ACCOUNT} />
          </div>
        )}

        {/* ------------------------------------------------------------------ */}
        {/* EXPLORER                                                             */}
        {/* ------------------------------------------------------------------ */}
        {section === "explorer" && (
          <Explorer
            initialBlockTarget={explorerBlockTarget}
            initialTxTarget={explorerTxTarget}
            onConsumeTarget={consumeExplorerTarget}
          />
        )}

        {/* ------------------------------------------------------------------ */}
        {/* IDENTITY                                                             */}
        {/* ------------------------------------------------------------------ */}
        {section === "identity" && (
          <Humanity
            account={DEV_ACCOUNT}
            onSettings={() => setSection("ai")}
          />
        )}

        {/* ------------------------------------------------------------------ */}
        {/* CONTRACTS                                                            */}
        {/* ------------------------------------------------------------------ */}
        {section === "contracts" && (
          <Contracts
            account={DEV_ACCOUNT}
            onOpenExplorerBlock={openExplorerBlock}
            onOpenExplorerTx={openExplorerTx}
            onSettings={() => setSection("ai")}
          />
        )}

        {/* ------------------------------------------------------------------ */}
        {/* AI / SETTINGS                                                        */}
        {/* ------------------------------------------------------------------ */}
        {section === "ai" && (
          <AiSection />
        )}
      </main>
    </>
  );
}
