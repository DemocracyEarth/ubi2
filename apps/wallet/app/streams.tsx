"use client";

/**
 * M2 streaming UI — obsidian-glass reskin.
 * Logic unchanged: dual-signer, live-ticking stream rows, NFT cards, stop/add.
 * Shows UBI fee on open-stream form.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  StreamReader,
  formatUbi,
  encodeOpenStream,
  encodeStopStream,
  sendStreamTx,
  streamNftTokenId,
  projectStreamAccrued,
  parseUbiToBaseUnits,
  ratePerHourToBaseUnitsPerSec,
  STREAM_HUB,
  type StreamView,
  type StreamCard,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY } from "./config";
import { svgImageSrc } from "./svg-image";

const client = new Ubi2Client({ url: RPC_URL });
const reader = new StreamReader(client);

// UBI fee for a stream tx: GAS_STREAM (60 000) * 1 gwei = 60 000e9 base units
const STREAM_FEE_BASE = 60_000n * 1_000_000_000n;

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

async function requestFrom(injected: Injected, fallback: string): Promise<string> {
  const accounts = (await injected.request({ method: "eth_requestAccounts" })) as string[] | undefined;
  return accounts?.[0] ?? fallback;
}

function short(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function statusLabel(s: StreamView): { text: string; cls: string } {
  if (s.status.type === "Active") return { text: "Active", cls: "active" };
  if (s.status.type === "Stopped") return { text: "Stopped", cls: "stopped" };
  return { text: "Completed", cls: "completed" };
}

function StreamRow({
  stream, side, account, injected, onStopped,
}: {
  stream: StreamView;
  side: "incoming" | "outgoing";
  account: string;
  injected: Injected | null;
  onStopped: () => void;
}) {
  const [accrued, setAccrued] = useState<string>(() =>
    formatUbi(projectStreamAccrued(stream), 8),
  );
  const [card, setCard] = useState<StreamCard | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    let raf = 0;
    const frame = () => {
      setAccrued(formatUbi(projectStreamAccrued(stream), 8));
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [stream]);

  const tokenId = streamNftTokenId(stream.id, side === "incoming" ? "recipient" : "sender");
  useEffect(() => {
    let alive = true;
    reader.fetchStreamCard(tokenId).then((c) => alive && setCard(c)).catch(() => {});
    return () => { alive = false; };
  }, [tokenId, stream.status.type]);

  const stop = useCallback(async () => {
    setBusy(true); setNote(null);
    try {
      const data = encodeStopStream(stream.id);
      const res = injected
        ? await sendStreamTx({ data, from: await requestFrom(injected, account), provider: injected as never })
        : await sendStreamTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote(`stopStream sent · ${res.hash.slice(0, 10)}… · fee ${formatUbi(STREAM_FEE_BASE, 6)}`);
      setTimeout(onStopped, 2200);
    } catch (e) { setNote(errMessage(e)); }
    finally { setBusy(false); }
  }, [stream.id, injected, account, onStopped]);

  const addNft = useCallback(async () => {
    const eth = injected ?? getInjected();
    if (!eth) { setNote("No injected wallet — connect MetaMask."); return; }
    try {
      await eth.request({
        method: "wallet_watchAsset",
        params: { type: "ERC721", options: { address: STREAM_HUB, tokenId: tokenId.toString() } } as unknown as unknown[],
      });
      setNote("Requested NFT import in wallet.");
    } catch (e) { setNote(errMessage(e)); }
  }, [injected, tokenId]);

  const st = statusLabel(stream);
  const counterparty = side === "incoming" ? stream.from : stream.to;
  const ratePerHr = formatUbi(stream.rate * 3600n, 2).replace(" UBI", "");
  const canStop = side === "outgoing" && stream.status.type === "Active";

  return (
    <div className="stream">
      {/* NFT card thumbnail */}
      <div className="stream-card-img" aria-label={`Stream #${stream.id} NFT`}>
        {card ? (
          // issue #38: render the untrusted on-chain SVG as an inert <img>, never live DOM.
          <img
            src={svgImageSrc(card.svg)}
            alt={`Stream #${stream.id} card`}
            style={{ width: "100%", display: "block" }}
          />
        ) : (
          <div style={{ padding: "1rem", color: "var(--faint)", fontSize: ".72rem" }}>
            loading card…
          </div>
        )}
      </div>

      <div className="stream-body">
        <div className="stream-head">
          {/* Animated flow */}
          <div className="stream-flow" style={{ flex: 1, marginBottom: 0, marginRight: "1rem" }}>
            <span style={{ color: "var(--muted)", fontSize: ".75rem" }}>
              {side === "incoming" ? "from" : "to"}
            </span>
            <span className="stream-arrow" />
            <span style={{ fontFamily: "var(--mono)", fontSize: ".75rem", color: "var(--muted)" }}>
              {short(counterparty)}
            </span>
          </div>
          <span className={`pill ${st.cls}`}>{st.text}</span>
        </div>

        <div className="stream-live">{accrued}</div>
        <div className="stream-meta">
          {side === "incoming" ? "received" : "streamed"} · of {formatUbi(stream.deposit, 2)} ·{" "}
          {ratePerHr} UBI/hr
        </div>
        <div className="stream-meta">
          stream #{stream.id}
        </div>

        <div className="stream-actions">
          {canStop && (
            <button className="ghost danger" onClick={stop} disabled={busy}>
              {busy ? "Stopping…" : "Stop stream"}
            </button>
          )}
          <button className="ghost" onClick={addNft}>Add NFT</button>
        </div>

        {note && (
          <div className={`notice ${note.includes("sent") || note.includes("Requested") ? "ok" : "err"}`}>
            {note}
          </div>
        )}
      </div>
    </div>
  );
}

export function Streams({ account }: { account: string }) {
  const [outgoing, setOutgoing] = useState<StreamView[]>([]);
  const [incoming, setIncoming] = useState<StreamView[]>([]);
  const [tab, setTab] = useState<"incoming" | "outgoing">("incoming");
  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  const [to, setTo] = useState("");
  const [ratePerHr, setRatePerHr] = useState("1");
  const [deposit, setDeposit] = useState("");
  const [duration, setDuration] = useState("60");
  const [mode, setMode] = useState<"deposit" | "duration">("duration");
  const [submitting, setSubmitting] = useState(false);
  const [formNote, setFormNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const pollRef = useRef<() => void>(() => {});

  useEffect(() => setInjected(getInjected()), []);

  const refresh = useCallback(async () => {
    try {
      const res = await reader.getStreams(account);
      setOutgoing(res.outgoing);
      setIncoming(res.incoming);
    } catch { /* node may be down */ }
  }, [account]);
  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    const id = setInterval(() => pollRef.current(), 4000);
    return () => clearInterval(id);
  }, [refresh]);

  // Compute fee + deposit preview
  let depositPreview = "";
  try {
    const ratePerSec = ratePerHourToBaseUnitsPerSec(ratePerHr);
    if (ratePerSec > 0n) {
      const d = mode === "deposit"
        ? parseUbiToBaseUnits(deposit || "0")
        : ratePerSec * BigInt(Math.max(0, Math.floor(Number(duration) || 0))) * 60n;
      depositPreview = formatUbi(d, 4);
    }
  } catch { /* ignore */ }

  const submit = useCallback(async () => {
    setSubmitting(true); setFormNote(null);
    try {
      const ratePerSec = ratePerHourToBaseUnitsPerSec(ratePerHr);
      if (ratePerSec <= 0n) throw new Error("rate must be > 0");
      let depositBase: bigint;
      if (mode === "deposit") {
        depositBase = parseUbiToBaseUnits(deposit || "0");
      } else {
        const mins = BigInt(Math.max(0, Math.floor(Number(duration) || 0)));
        depositBase = ratePerSec * mins * 60n;
      }
      if (depositBase <= 0n) throw new Error("deposit must be > 0");
      if (!/^0x[0-9a-fA-F]{40}$/.test(to)) throw new Error("recipient must be a 0x address");

      const data = encodeOpenStream(to, ratePerSec, depositBase);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendStreamTx({ data, from, provider: injected as never })
        : await sendStreamTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });

      setFormNote({
        kind: "ok",
        text: `openStream sent · ${res.hash} — locking ${formatUbi(depositBase, 4)} · fee ${formatUbi(STREAM_FEE_BASE, 6)}`,
      });
      setTo(""); setDeposit("");
      setTimeout(refresh, 2400);
    } catch (e) { setFormNote({ kind: "err", text: errMessage(e) }); }
    finally { setSubmitting(false); }
  }, [to, ratePerHr, deposit, duration, mode, injected, account, refresh]);

  const connect = useCallback(async () => {
    if (!injected) { setFormNote({ kind: "err", text: "No injected wallet — install MetaMask." }); return; }
    try {
      setConnected(await requestFrom(injected, account));
      setFormNote(null);
    } catch (e) { setFormNote({ kind: "err", text: errMessage(e) }); }
  }, [injected, account]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected ? "MetaMask (not connected)" : "devnet dev key";

  return (
    <>
      {/* Open stream form */}
      <div className="card">
        <div className="card-header">
          <h3>Send a stream</h3>
          <span className="tag green">live</span>
        </div>

        <div className="field">
          <label>Recipient address</label>
          <input
            placeholder="0x…"
            value={to}
            onChange={(e) => setTo(e.target.value.trim())}
            spellCheck={false}
          />
        </div>

        <div className="field-row">
          <div className="field">
            <label>Rate (UBI / hour)</label>
            <input
              inputMode="decimal"
              value={ratePerHr}
              onChange={(e) => setRatePerHr(e.target.value)}
            />
          </div>
          <div className="field">
            <label>Fund by</label>
            <select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
              <option value="duration">Duration → deposit</option>
              <option value="deposit">Deposit amount</option>
            </select>
          </div>
        </div>

        <div className="field">
          {mode === "duration" ? (
            <>
              <label>Duration (minutes)</label>
              <input inputMode="numeric" value={duration} onChange={(e) => setDuration(e.target.value)} />
            </>
          ) : (
            <>
              <label>Deposit (UBI)</label>
              <input inputMode="decimal" value={deposit} onChange={(e) => setDeposit(e.target.value)} placeholder="e.g. 1.0" />
            </>
          )}
        </div>

        {/* Fee preview */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          marginBottom: ".75rem",
          flexWrap: "wrap",
        }}>
          {depositPreview && (
            <span className="muted small">
              deposit: <span style={{ fontFamily: "var(--mono)", color: "var(--accent)" }}>{depositPreview}</span>
            </span>
          )}
          <span className="muted small">
            fee: <span style={{ fontFamily: "var(--mono)", color: "var(--warn)" }}>{formatUbi(STREAM_FEE_BASE, 6)}</span>
          </span>
        </div>

        <button className="primary" onClick={submit} disabled={submitting}>
          {submitting ? "Sending…" : "Open stream"}
        </button>

        <div className="signer">
          signing with <b>{signerLabel}</b>
          {injected && !connected && (
            <button className="ghost" style={{ marginLeft: ".5rem" }} onClick={connect}>
              Connect MetaMask
            </button>
          )}
        </div>

        {formNote && <div className={`notice ${formNote.kind}`}>{formNote.text}</div>}
      </div>

      {/* Stream list */}
      <div className="card">
        <div className="card-header">
          <h3>Active streams</h3>
        </div>
        <div className="tabs">
          <button className={`tab ${tab === "incoming" ? "active" : ""}`} onClick={() => setTab("incoming")}>
            Incoming ({incoming.length})
          </button>
          <button className={`tab ${tab === "outgoing" ? "active" : ""}`} onClick={() => setTab("outgoing")}>
            Outgoing ({outgoing.length})
          </button>
        </div>

        {tab === "incoming" && (
          incoming.length === 0
            ? <p className="muted small">No incoming streams.</p>
            : incoming.map((s) => (
              <StreamRow key={`in-${s.id}`} stream={s} side="incoming" account={account} injected={injected} onStopped={refresh} />
            ))
        )}

        {tab === "outgoing" && (
          outgoing.length === 0
            ? <p className="muted small">No outgoing streams.</p>
            : outgoing.map((s) => (
              <StreamRow key={`out-${s.id}`} stream={s} side="outgoing" account={account} injected={injected} onStopped={refresh} />
            ))
        )}
      </div>
    </>
  );
}
