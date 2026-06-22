"use client";

/**
 * M3 Proof-of-Humanity UI: shows the connected account's human status, vouches,
 * lets the user apply for verification, vouch for an address, challenge an address,
 * and lists all pending cases. Signs through the dual-signer pattern from streams.tsx.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  HumanityReader,
  sendHumanityTx,
  encodeRequestVerification,
  encodeVouch,
  encodeChallenge,
  deriveLivenessRef,
  humanStatusLabel,
  verdictLabel,
  confidenceLabel,
  HUMANITY_HUB,
  type HumanRecord,
  type CaseRecord,
  type JurorRecord,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const reader = new HumanityReader(client);

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
  const accounts = (await injected.request({ method: "eth_requestAccounts" })) as
    | string[]
    | undefined;
  return accounts?.[0] ?? fallback;
}

function short(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

/** Status pill with color coding. */
function StatusPill({ status }: { status: string }) {
  const cls =
    status === "Verified"
      ? "pill active"
      : status === "Pending"
        ? "pill poh-pending"
        : status === "Challenged"
          ? "pill poh-challenged"
          : status === "Revoked"
            ? "pill stopped"
            : "pill completed";
  return <span className={cls}>{humanStatusLabel(status as never)}</span>;
}

/** A single pending case row. */
function CaseRow({ c }: { c: CaseRecord }) {
  const statusText =
    c.status.type === "Committed"
      ? `Committed · ${verdictLabel(c.status.verdict.verdict)} (${confidenceLabel(c.status.verdict.confidence)})`
      : c.status.type === "Escalated"
        ? "Escalated"
        : "Open";

  const kindCls = c.kind === "Registration" ? "pill active" : "pill poh-challenged";

  return (
    <div className="poh-case-row">
      <span className="poh-case-id">#{c.id}</span>
      <span className="addr" style={{ fontSize: "0.78rem" }}>{short(c.subject)}</span>
      <span className={kindCls} style={{ fontSize: "0.66rem" }}>{c.kind}</span>
      <span className="muted small">{statusText}</span>
      <span className="muted small">jury: {c.jury.length}</span>
    </div>
  );
}

export function Humanity({ account }: { account: string }) {
  const [human, setHuman] = useState<HumanRecord | null>(null);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [jurors, setJurors] = useState<JurorRecord[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  // Form state
  const [vouchTo, setVouchTo] = useState("");
  const [challengeTarget, setChallengeTarget] = useState("");
  const [challengeRef, setChallengeRef] = useState("");

  // Async op state
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const pollRef = useRef<() => void>(() => {});

  useEffect(() => setInjected(getInjected()), []);

  const refresh = useCallback(async () => {
    try {
      const [h, c, j] = await Promise.all([
        reader.getHuman(account),
        reader.getPendingCases(),
        reader.getJurors(),
      ]);
      setHuman(h);
      setCases(c);
      setJurors(j);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(errMessage(e));
    }
  }, [account]);
  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    const id = setInterval(() => pollRef.current(), 5000);
    return () => clearInterval(id);
  }, [refresh]);

  // Determine the actual signer address
  const signerAddr = connected ?? account;

  // --- Actions ---

  const applyVerification = useCallback(async () => {
    setBusy("apply");
    setNote(null);
    try {
      const livenessRef = deriveLivenessRef(signerAddr + Date.now());
      const data = encodeRequestVerification(livenessRef);
      const res = injected
        ? await sendHumanityTx({
            data,
            from: await requestFrom(injected, signerAddr),
            provider: injected as never,
          })
        : await sendHumanityTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote({ kind: "ok", text: `requestVerification sent · ${res.hash.slice(0, 14)}…` });
      setTimeout(refresh, 2500);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [injected, signerAddr, refresh]);

  const submitVouch = useCallback(async () => {
    if (!/^0x[0-9a-fA-F]{40}$/.test(vouchTo)) {
      setNote({ kind: "err", text: "Vouchee must be a valid 0x address." });
      return;
    }
    setBusy("vouch");
    setNote(null);
    try {
      const data = encodeVouch(vouchTo);
      const res = injected
        ? await sendHumanityTx({
            data,
            from: await requestFrom(injected, signerAddr),
            provider: injected as never,
          })
        : await sendHumanityTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote({ kind: "ok", text: `vouch sent · ${res.hash.slice(0, 14)}…` });
      setVouchTo("");
      setTimeout(refresh, 2500);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [vouchTo, injected, signerAddr, refresh]);

  const submitChallenge = useCallback(async () => {
    if (!/^0x[0-9a-fA-F]{40}$/.test(challengeTarget)) {
      setNote({ kind: "err", text: "Subject must be a valid 0x address." });
      return;
    }
    setBusy("challenge");
    setNote(null);
    try {
      // evidenceRef: pad user input to bytes32, or derive a stub ref
      const raw = challengeRef.trim();
      let evidenceRef: `0x${string}`;
      if (/^0x[0-9a-fA-F]{64}$/.test(raw)) {
        evidenceRef = raw as `0x${string}`;
      } else {
        evidenceRef = deriveLivenessRef(raw || "challenge-" + challengeTarget);
      }
      const data = encodeChallenge(challengeTarget, evidenceRef);
      const res = injected
        ? await sendHumanityTx({
            data,
            from: await requestFrom(injected, signerAddr),
            provider: injected as never,
          })
        : await sendHumanityTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote({ kind: "ok", text: `challenge sent · ${res.hash.slice(0, 14)}…` });
      setChallengeTarget("");
      setChallengeRef("");
      setTimeout(refresh, 2500);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [challengeTarget, challengeRef, injected, signerAddr, refresh]);

  const connect = useCallback(async () => {
    if (!injected) {
      setNote({ kind: "err", text: "No injected wallet detected — install MetaMask." });
      return;
    }
    try {
      setConnected(await requestFrom(injected, account));
      setNote(null);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected, account]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  const canApply = !human || human.status === "Unverified" || human.status === "Revoked";
  const canVouch = human?.status === "Verified";

  return (
    <>
      {/* Human status card */}
      <section className="card">
        <h2>Proof of Humanity</h2>

        {loadErr && (
          <p className="small" style={{ color: "var(--danger)", marginBottom: "0.75rem" }}>
            {loadErr}
          </p>
        )}

        <div className="poh-status-row">
          <div>
            <div className="label">Account</div>
            <div className="addr" style={{ fontSize: "0.82rem" }}>{short(account)}</div>
          </div>
          <div>
            <div className="label">Status</div>
            {human ? (
              <StatusPill status={human.status} />
            ) : (
              <span className="muted small">loading…</span>
            )}
          </div>
          {human && human.status === "Verified" && (
            <div>
              <div className="label">Verified at</div>
              <div className="muted small">
                {human.verified_at
                  ? new Date(human.verified_at * 1000).toLocaleString()
                  : "—"}
              </div>
            </div>
          )}
          {human && (
            <div>
              <div className="label">Vouches in</div>
              <div className="muted small">{human.vouches_in.length}</div>
            </div>
          )}
        </div>

        {human && human.vouches_in.length > 0 && (
          <div className="poh-vouchers">
            <div className="label" style={{ marginBottom: "0.35rem" }}>Vouched by</div>
            <div className="poh-addr-list">
              {human.vouches_in.map((a) => (
                <span key={a} className="addr" style={{ fontSize: "0.75rem" }}>{short(a)}</span>
              ))}
            </div>
          </div>
        )}

        {/* Apply for verification */}
        {canApply && (
          <div className="poh-action-block">
            <button
              className="primary"
              onClick={applyVerification}
              disabled={busy === "apply"}
              style={{ marginTop: "0.5rem" }}
            >
              {busy === "apply" ? "Sending…" : "Apply for verification"}
            </button>
            <div className="muted small" style={{ marginTop: "0.4rem" }}>
              Submits a liveness commitment to HumanityHub ({short(HUMANITY_HUB)}) to open a
              Registration case. After the challenge window (5 blocks) clears, you become Verified.
            </div>
          </div>
        )}

        {/* Signer row */}
        <div className="signer" style={{ marginTop: "0.75rem" }}>
          signing with <b>{signerLabel}</b>
          {injected && !connected && (
            <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
              Connect MetaMask
            </button>
          )}
        </div>

        {note && (
          <div className={`notice ${note.kind}`}>{note.text}</div>
        )}
      </section>

      {/* Vouch action */}
      <section className="card">
        <h2>Vouch for address</h2>
        {!canVouch && (
          <p className="muted small" style={{ marginBottom: "0.75rem" }}>
            Only Verified accounts can vouch. Current status:{" "}
            <b>{human?.status ?? "unknown"}</b>.
          </p>
        )}
        <div className="field">
          <label htmlFor="vouch-addr">Address to vouch for</label>
          <input
            id="vouch-addr"
            placeholder="0x…"
            value={vouchTo}
            onChange={(e) => setVouchTo(e.target.value.trim())}
            spellCheck={false}
            disabled={!canVouch}
          />
        </div>
        <button
          className="primary"
          onClick={submitVouch}
          disabled={!canVouch || busy === "vouch"}
        >
          {busy === "vouch" ? "Vouching…" : "Vouch"}
        </button>
        {!note && (
          <div className="signer" style={{ marginTop: "0.5rem" }}>
            signing with <b>{signerLabel}</b>
          </div>
        )}
        {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
      </section>

      {/* Challenge action */}
      <section className="card">
        <h2>Challenge address</h2>
        <div className="field">
          <label htmlFor="challenge-addr">Subject address</label>
          <input
            id="challenge-addr"
            placeholder="0x…"
            value={challengeTarget}
            onChange={(e) => setChallengeTarget(e.target.value.trim())}
            spellCheck={false}
          />
        </div>
        <div className="field">
          <label htmlFor="evidence-ref">Evidence ref (bytes32 hex, or a free-text label)</label>
          <input
            id="evidence-ref"
            placeholder="e.g. duplicate-cluster-A (or 0x…64 hex)"
            value={challengeRef}
            onChange={(e) => setChallengeRef(e.target.value)}
            spellCheck={false}
          />
        </div>
        <button
          className="primary"
          onClick={submitChallenge}
          disabled={busy === "challenge"}
        >
          {busy === "challenge" ? "Challenging…" : "Challenge"}
        </button>
        {!note && (
          <div className="signer" style={{ marginTop: "0.5rem" }}>
            signing with <b>{signerLabel}</b>
          </div>
        )}
        {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
      </section>

      {/* Pending cases */}
      <section className="card">
        <h2>Pending cases ({cases.length})</h2>
        {cases.length === 0 ? (
          <p className="muted small">No open cases.</p>
        ) : (
          <div className="poh-cases">
            {cases.map((c) => (
              <CaseRow key={c.id} c={c} />
            ))}
          </div>
        )}

        {jurors.length > 0 && (
          <div style={{ marginTop: "1rem" }}>
            <div className="label" style={{ marginBottom: "0.4rem" }}>
              Registered jurors ({jurors.length})
            </div>
            <div className="poh-addr-list">
              {jurors.map((j) => (
                <span key={j.address} className="addr" style={{ fontSize: "0.75rem" }}>
                  {short(j.address)}
                  {j.active && (
                    <span className="pill active" style={{ marginLeft: "0.35rem", fontSize: "0.6rem" }}>
                      active
                    </span>
                  )}
                </span>
              ))}
            </div>
          </div>
        )}
      </section>
    </>
  );
}
