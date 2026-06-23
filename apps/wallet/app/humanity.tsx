"use client";

/**
 * M3 Proof-of-Humanity UI — cycle 6.
 *
 * Changes:
 *  - Vouch UX: surfaces ubi_getPendingCases so the user can pick a valid target
 *    (only accounts with an OPEN Registration case can be vouched for). Shows
 *    the failed-tx reason inline (e.g. "vouchee has no open registration").
 *  - AI mock banner in the Identity section.
 *  - Challenge UX mirrors the vouch improvement.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  HumanityReader,
  OracleAdminClient,
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
const oracle = new OracleAdminClient(client);

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

// ---- AI Mock Banner ---------------------------------------------------------------

function MockAiBanner({ onSettings }: { onSettings?: () => void }) {
  return (
    <div
      style={{
        background: "rgba(251,191,92,.07)",
        border: "1px solid rgba(251,191,92,.28)",
        borderRadius: "12px",
        padding: "0.85rem 1rem",
        marginBottom: "1.1rem",
        display: "flex",
        alignItems: "flex-start",
        gap: "0.75rem",
      }}
    >
      <span style={{ fontSize: "1.1rem", lineHeight: 1, marginTop: "0.05rem" }}>◈</span>
      <div style={{ flex: 1 }}>
        <div
          style={{
            fontWeight: 700,
            fontSize: "0.82rem",
            color: "var(--warn)",
            marginBottom: "0.3rem",
          }}
        >
          Mock AI active — proof-of-humanity verdicts are stubbed
        </div>
        <div style={{ fontSize: "0.77rem", color: "var(--muted)", lineHeight: 1.55 }}>
          Your node is running a deterministic mock AI. Proof-of-humanity verdicts are
          pre-scripted (the MockJury always commits a deterministic verdict). To use real
          AI-based verification, configure a local Ollama model or a cloud API key in{" "}
          {onSettings ? (
            <button
              onClick={onSettings}
              style={{
                background: "none",
                border: "none",
                color: "var(--accent-2)",
                cursor: "pointer",
                fontWeight: 700,
                fontSize: "inherit",
                padding: 0,
                fontFamily: "inherit",
              }}
            >
              Settings
            </button>
          ) : (
            <b style={{ color: "var(--accent-2)" }}>Settings</b>
          )}.
        </div>
      </div>
    </div>
  );
}

// ---- Status pill -----------------------------------------------------------------

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

// ---- Pending case row (for picking vouch target) ---------------------------------

function PendingCasePickerRow({
  c,
  onPick,
}: {
  c: CaseRecord;
  onPick: (addr: string) => void;
}) {
  const isOpen = c.status.type === "Open";
  const isRegistration = c.kind === "Registration";

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "2.5rem 7rem auto 1fr auto",
        gap: "0.6rem",
        alignItems: "center",
        padding: "0.55rem 0.5rem",
        borderTop: "1px solid var(--line)",
        fontSize: "0.82rem",
        background: isOpen && isRegistration ? "rgba(79,231,168,.03)" : "transparent",
      }}
    >
      <span
        style={{
          fontFamily: "var(--mono)",
          color: "var(--accent)",
          fontWeight: 600,
          fontSize: "0.8rem",
        }}
      >
        #{c.id}
      </span>
      <span className="addr" style={{ fontSize: "0.78rem" }}>{short(c.subject)}</span>
      <span
        className={c.kind === "Registration" ? "pill active" : "pill poh-challenged"}
        style={{ fontSize: "0.62rem" }}
      >
        {c.kind}
      </span>
      <span className="muted small">
        {c.status.type === "Open"
          ? "open"
          : c.status.type === "Committed"
            ? `committed · ${verdictLabel(c.status.verdict.verdict)} (${confidenceLabel(c.status.verdict.confidence)})`
            : "escalated"}
      </span>
      {isOpen && isRegistration && (
        <button
          className="ghost"
          style={{ fontSize: "0.7rem", padding: "0.2rem 0.55rem" }}
          onClick={() => onPick(c.subject)}
          title={`Vouch for ${c.subject}`}
        >
          Vouch
        </button>
      )}
    </div>
  );
}

// ---- Main case row ---------------------------------------------------------------

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

// ---- Main component -------------------------------------------------------------

export function Humanity({
  account,
  onSettings,
}: {
  account: string;
  onSettings?: () => void;
}) {
  const [human, setHuman] = useState<HumanRecord | null>(null);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [jurors, setJurors] = useState<JurorRecord[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [isMockAi, setIsMockAi] = useState<boolean | null>(null);

  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  // Form state
  const [vouchTo, setVouchTo] = useState("");
  const [challengeTarget, setChallengeTarget] = useState("");
  const [challengeRef, setChallengeRef] = useState("");

  // Async op state
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Vouch picker visibility
  const [showVouchPicker, setShowVouchPicker] = useState(false);

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

  const checkOracle = useCallback(async () => {
    try {
      const cfg = await oracle.getConfig();
      setIsMockAi(cfg.active === "mock");
    } catch {
      setIsMockAi(true);
    }
  }, []);

  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    checkOracle();
    const id = setInterval(() => pollRef.current(), 5000);
    return () => clearInterval(id);
  }, [refresh, checkOracle]);

  const signerAddr = connected ?? account;

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  const canApply = !human || human.status === "Unverified" || human.status === "Revoked";
  const canVouch = human?.status === "Verified";

  // Pending Registration cases that are still Open — these are valid vouch targets
  const vouchableCases = cases.filter(
    (c) => c.kind === "Registration" && c.status.type === "Open",
  );

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
    // Check if the target has an open Registration case
    const targetCase = vouchableCases.find(
      (c) => c.subject.toLowerCase() === vouchTo.toLowerCase(),
    );
    if (vouchableCases.length > 0 && !targetCase) {
      setNote({
        kind: "err",
        text:
          "The address you entered does not have an open registration request. " +
          "You can only vouch for accounts with a pending (Open) Registration case. " +
          "Use the picker below to choose from current candidates.",
      });
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
      // Surface the on-chain revert reason if present
      const msg = errMessage(e);
      setNote({ kind: "err", text: msg });
    } finally {
      setBusy(null);
    }
  }, [vouchTo, injected, signerAddr, refresh, vouchableCases]);

  const submitChallenge = useCallback(async () => {
    if (!/^0x[0-9a-fA-F]{40}$/.test(challengeTarget)) {
      setNote({ kind: "err", text: "Subject must be a valid 0x address." });
      return;
    }
    setBusy("challenge");
    setNote(null);
    try {
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
      // Surface the on-chain revert reason
      const msg = errMessage(e);
      setNote({ kind: "err", text: msg });
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

  return (
    <>
      {/* Mock AI banner */}
      {isMockAi && <MockAiBanner onSettings={onSettings} />}

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

        <div className="signer" style={{ marginTop: "0.75rem" }}>
          signing with <b>{signerLabel}</b>
          {injected && !connected && (
            <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
              Connect MetaMask
            </button>
          )}
        </div>

        {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
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

        {canVouch && (
          <>
            <div
              style={{
                background: "rgba(79,231,168,.05)",
                border: "1px solid rgba(79,231,168,.18)",
                borderRadius: "9px",
                padding: "0.65rem 0.85rem",
                marginBottom: "0.85rem",
                fontSize: "0.78rem",
                color: "var(--muted)",
                lineHeight: 1.55,
              }}
            >
              You can only vouch for accounts that have an <b style={{ color: "var(--ink)" }}>open Registration case</b>{" "}
              (i.e. they applied for verification but haven&apos;t been verified yet). Vouching for an
              address without a pending registration will fail with a &quot;vouchee has no open
              registration&quot; error from the node.
              {vouchableCases.length > 0 && (
                <>
                  {" "}There {vouchableCases.length === 1 ? "is" : "are"} currently{" "}
                  <b style={{ color: "var(--accent)" }}>{vouchableCases.length}</b> pending
                  candidate{vouchableCases.length !== 1 ? "s" : ""}.
                </>
              )}
            </div>

            {/* Vouch picker */}
            {vouchableCases.length > 0 && (
              <div style={{ marginBottom: "0.85rem" }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.5rem",
                    marginBottom: "0.5rem",
                  }}
                >
                  <div className="label" style={{ margin: 0 }}>
                    Pending candidates ({vouchableCases.length})
                  </div>
                  <button
                    className="ghost"
                    style={{ fontSize: "0.68rem", padding: "0.2rem 0.55rem" }}
                    onClick={() => setShowVouchPicker((v) => !v)}
                  >
                    {showVouchPicker ? "Hide" : "Show"}
                  </button>
                </div>
                {showVouchPicker && (
                  <div
                    style={{
                      border: "1px solid var(--line)",
                      borderRadius: "10px",
                      overflow: "hidden",
                    }}
                  >
                    {vouchableCases.map((c) => (
                      <PendingCasePickerRow
                        key={c.id}
                        c={c}
                        onPick={(addr) => {
                          setVouchTo(addr);
                          setShowVouchPicker(false);
                          setNote(null);
                        }}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}

            {vouchableCases.length === 0 && (
              <div
                className="muted small"
                style={{ marginBottom: "0.85rem", fontStyle: "italic" }}
              >
                No pending Registration cases right now. Vouching will fail unless the target
                has applied for verification first.
              </div>
            )}

            <div className="field">
              <label>Address to vouch for</label>
              <input
                id="vouch-addr"
                placeholder="0x… (must have an open Registration case)"
                value={vouchTo}
                onChange={(e) => { setVouchTo(e.target.value.trim()); setNote(null); }}
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

            <div className="signer" style={{ marginTop: "0.5rem" }}>
              signing with <b>{signerLabel}</b>
            </div>
          </>
        )}

        {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
      </section>

      {/* Challenge action */}
      <section className="card">
        <h2>Challenge address</h2>
        <div
          style={{
            background: "rgba(255,107,107,.05)",
            border: "1px solid rgba(255,107,107,.18)",
            borderRadius: "9px",
            padding: "0.65rem 0.85rem",
            marginBottom: "0.85rem",
            fontSize: "0.78rem",
            color: "var(--muted)",
            lineHeight: 1.55,
          }}
        >
          Challenges can only be submitted against accounts that are <b style={{ color: "var(--ink)" }}>Verified</b>{" "}
          or have an open Registration case. If the target does not meet these criteria, the
          transaction will fail and the node will return a reason inline.
        </div>
        <div className="field">
          <label>Subject address</label>
          <input
            id="challenge-addr"
            placeholder="0x…"
            value={challengeTarget}
            onChange={(e) => { setChallengeTarget(e.target.value.trim()); setNote(null); }}
            spellCheck={false}
          />
        </div>
        <div className="field">
          <label>Evidence ref (bytes32 hex, or a free-text label)</label>
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
                    <span
                      className="pill active"
                      style={{ marginLeft: "0.35rem", fontSize: "0.6rem" }}
                    >
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
