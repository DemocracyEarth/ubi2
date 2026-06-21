"use client";

/**
 * M2 streaming UI: a "Send a stream" form, live-ticking Outgoing/Incoming lists, on-chain
 * stream-NFT cards, Stop (sender), and "Add NFT to MetaMask". Signs through an injected
 * provider when one is connected, otherwise the devnet dev key for the local demo.
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

const client = new Ubi2Client({ url: RPC_URL });
const reader = new StreamReader(client);

interface Injected {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

function getInjected(): Injected | null {
  if (typeof window === "undefined") return null;
  const eth = (window as unknown as { ethereum?: Injected }).ethereum;
  return eth ?? null;
}

/**
 * Extract a human-readable message from any thrown value. MetaMask/EIP-1193 and viem reject with
 * plain *objects* (`{ code, message }`, `{ shortMessage }`), not `Error`s — so the old
 * `String(e)` rendered them as "[object Object]". Dig out the real message instead.
 */
function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const o = e as Record<string, unknown>;
    const nested = (o.data as { message?: string } | undefined)?.message;
    const msg = (o.shortMessage ?? o.message ?? nested) as string | undefined;
    if (msg) return typeof o.code === "number" ? `${msg} (code ${o.code})` : msg;
    try {
      return JSON.stringify(e);
    } catch {
      /* fall through */
    }
  }
  return String(e);
}

/**
 * Ensure the injected wallet has authorized this dapp and return the account to send from.
 * `eth_requestAccounts` is what triggers MetaMask's connect prompt — without it, `eth_sendTransaction`
 * rejects ("unauthorized"), which is the root of the "not connected" / "[object Object]" bug. The call
 * is idempotent: once connected, it returns the accounts without re-prompting.
 */
async function requestFrom(injected: Injected, fallback: string): Promise<string> {
  const accounts = (await injected.request({ method: "eth_requestAccounts" })) as
    | string[]
    | undefined;
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

/** A single stream row with a live-ticking accrued figure + on-chain NFT card. */
function StreamRow({
  stream,
  side,
  account,
  injected,
  onStopped,
}: {
  stream: StreamView;
  side: "incoming" | "outgoing";
  account: string;
  injected: Injected | null;
  onStopped: () => void;
}) {
  const [accrued, setAccrued] = useState<string>(() =>
    formatUbi(projectStreamAccrued(stream)),
  );
  const [card, setCard] = useState<StreamCard | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  // Live tick (only meaningful while Active; frozen otherwise by projectStreamAccrued).
  useEffect(() => {
    let raf = 0;
    const frame = () => {
      setAccrued(formatUbi(projectStreamAccrued(stream)));
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [stream]);

  // Fetch the on-chain NFT card for this side. Re-fetch when status changes so the card flips.
  const tokenId = streamNftTokenId(stream.id, side === "incoming" ? "recipient" : "sender");
  useEffect(() => {
    let alive = true;
    reader
      .fetchStreamCard(tokenId)
      .then((c) => alive && setCard(c))
      .catch(() => {});
    return () => {
      alive = false;
    };
    // refetch on status change to flip the pill on the card
  }, [tokenId, stream.status.type]);

  const stop = useCallback(async () => {
    setBusy(true);
    setNote(null);
    try {
      const data = encodeStopStream(stream.id);
      const res = injected
        ? await sendStreamTx({
            data,
            from: await requestFrom(injected, account),
            provider: injected as never,
          })
        : await sendStreamTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote(`stopStream sent · ${res.hash.slice(0, 10)}…`);
      setTimeout(onStopped, 2200);
    } catch (e) {
      setNote(errMessage(e));
    } finally {
      setBusy(false);
    }
  }, [stream.id, injected, account, onStopped]);

  const addNft = useCallback(async () => {
    const eth = injected ?? getInjected();
    if (!eth) {
      setNote("No injected wallet — connect MetaMask to import the NFT.");
      return;
    }
    try {
      await eth.request({
        method: "wallet_watchAsset",
        params: {
          type: "ERC721",
          options: { address: STREAM_HUB, tokenId: tokenId.toString() },
        } as unknown as unknown[],
      });
      setNote("Requested NFT import in wallet.");
    } catch (e) {
      setNote(errMessage(e));
    }
  }, [injected, tokenId]);

  const st = statusLabel(stream);
  const counterparty = side === "incoming" ? stream.from : stream.to;
  const ratePerHr = formatUbi(stream.rate * 3600n, 2).replace(" UBI", "");
  const canStop = side === "outgoing" && stream.status.type === "Active";

  return (
    <div className="stream">
      <div className="stream-card-img" aria-label={`Stream #${stream.id} NFT card`}>
        {card ? (
          <div dangerouslySetInnerHTML={{ __html: card.svg }} />
        ) : (
          <div style={{ padding: "1rem", color: "var(--muted)", fontSize: "0.75rem" }}>
            loading card…
          </div>
        )}
      </div>

      <div className="stream-body">
        <div className="stream-head">
          <span className="stream-counter">
            {side === "incoming" ? "from" : "to"}{" "}
            <span className="arrow">{short(counterparty)}</span>
          </span>
          <span className={`pill ${st.cls}`}>{st.text}</span>
        </div>

        <div className="stream-accrued">{accrued}</div>
        <div className="stream-meta">
          {side === "incoming" ? "received" : "streamed"} · of {formatUbi(stream.deposit, 2)} ·{" "}
          {ratePerHr} UBI/hr
        </div>
        <div className="stream-meta">
          stream #{stream.id} · token {tokenId.toString().length > 12 ? "…(sender)" : tokenId.toString()}
        </div>

        <div className="stream-actions">
          {canStop && (
            <button className="ghost danger" onClick={stop} disabled={busy}>
              {busy ? "Stopping…" : "Stop stream"}
            </button>
          )}
          <button className="ghost" onClick={addNft}>
            Add NFT to MetaMask
          </button>
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

  // form state
  const [to, setTo] = useState("");
  const [ratePerHr, setRatePerHr] = useState("1");
  const [deposit, setDeposit] = useState("");
  const [duration, setDuration] = useState("60"); // minutes
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
    } catch {
      /* node may be down; the parent page surfaces connection errors */
    }
  }, [account]);
  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    const id = setInterval(() => pollRef.current(), 4000);
    return () => clearInterval(id);
  }, [refresh]);

  const submit = useCallback(async () => {
    setSubmitting(true);
    setFormNote(null);
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
        text: `openStream sent · ${res.hash} — locking ${formatUbi(depositBase, 4)}`,
      });
      setTo("");
      setDeposit("");
      // give the node a tick to mine, then refresh.
      setTimeout(refresh, 2400);
    } catch (e) {
      setFormNote({ kind: "err", text: errMessage(e) });
    } finally {
      setSubmitting(false);
    }
  }, [to, ratePerHr, deposit, duration, mode, injected, account, refresh]);

  const connect = useCallback(async () => {
    if (!injected) {
      setFormNote({ kind: "err", text: "No injected wallet detected — install MetaMask." });
      return;
    }
    try {
      setConnected(await requestFrom(injected, account));
      setFormNote(null);
    } catch (e) {
      setFormNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected, account]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  return (
    <>
      {/* Send a stream */}
      <section className="card">
        <h2>Send a stream</h2>
        <div className="field">
          <label htmlFor="to">Recipient address</label>
          <input
            id="to"
            placeholder="0x…"
            value={to}
            onChange={(e) => setTo(e.target.value.trim())}
            spellCheck={false}
          />
        </div>
        <div className="field-row">
          <div className="field">
            <label htmlFor="rate">Rate (UBI / hour)</label>
            <input
              id="rate"
              inputMode="decimal"
              value={ratePerHr}
              onChange={(e) => setRatePerHr(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="mode">Fund by</label>
            <select id="mode" value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
              <option value="duration">Duration → deposit</option>
              <option value="deposit">Deposit amount</option>
            </select>
          </div>
        </div>
        <div className="field">
          {mode === "duration" ? (
            <>
              <label htmlFor="dur">Duration (minutes)</label>
              <input
                id="dur"
                inputMode="numeric"
                value={duration}
                onChange={(e) => setDuration(e.target.value)}
              />
            </>
          ) : (
            <>
              <label htmlFor="dep">Deposit (UBI)</label>
              <input
                id="dep"
                inputMode="decimal"
                value={deposit}
                onChange={(e) => setDeposit(e.target.value)}
                placeholder="e.g. 1.0"
              />
            </>
          )}
        </div>
        <button className="primary" onClick={submit} disabled={submitting}>
          {submitting ? "Sending…" : "Open stream"}
        </button>
        <div className="signer">
          signing with <b>{signerLabel}</b>
          {injected && !connected && (
            <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
              Connect MetaMask
            </button>
          )}
        </div>
        {formNote && <div className={`notice ${formNote.kind}`}>{formNote.text}</div>}
      </section>

      {/* Active streams */}
      <section className="card">
        <h2>Active streams</h2>
        <div className="tabs">
          <button
            className={`tab ${tab === "incoming" ? "active" : ""}`}
            onClick={() => setTab("incoming")}
          >
            Incoming ({incoming.length})
          </button>
          <button
            className={`tab ${tab === "outgoing" ? "active" : ""}`}
            onClick={() => setTab("outgoing")}
          >
            Outgoing ({outgoing.length})
          </button>
        </div>

        {tab === "incoming" &&
          (incoming.length === 0 ? (
            <p className="muted small">No incoming streams yet.</p>
          ) : (
            incoming.map((s) => (
              <StreamRow
                key={`in-${s.id}`}
                stream={s}
                side="incoming"
                account={account}
                injected={injected}
                onStopped={refresh}
              />
            ))
          ))}

        {tab === "outgoing" &&
          (outgoing.length === 0 ? (
            <p className="muted small">No outgoing streams yet.</p>
          ) : (
            outgoing.map((s) => (
              <StreamRow
                key={`out-${s.id}`}
                stream={s}
                side="outgoing"
                account={account}
                injected={injected}
                onStopped={refresh}
              />
            ))
          ))}
      </section>
    </>
  );
}
