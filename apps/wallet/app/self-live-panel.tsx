"use client";

/**
 * M6 Stage C1 — the live Self client flow (spec 06b §5).
 *
 * Renders the Self QR code / mobile deeplink, waits for the phone app to complete verification
 * and POST the proof to `/api/self-verify` (our untrusted relay), polls for the encoded calldata,
 * and submits `submitZkPassportProof` via the injected EIP-1193 provider (MetaMask). Every step
 * is labeled with its real status — this panel does not pretend a genuine end-to-end run has
 * happened when it has not (spec §4.1 VK STATUS: the pinned VK is still a stale fixture; the
 * `staging` root/OFAC set is what a devnet node actually has pinned — see the Stage note below).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { sendZkPassportProof, ZkPassportReader, Ubi2Client, type HumanRecord } from "@ubi2/sdk";
import { RPC_URL, DEV_PRIVATE_KEY, SELF_ENDPOINT } from "./config";
import { buildSelfApp, getUniversalLink, SelfQRcodeWrapper, type SelfApp } from "./self-client";

const client = new Ubi2Client({ url: RPC_URL });
const zkReader = new ZkPassportReader(client);

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
  return String(e);
}

function short(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

type Phase = "not-configured" | "build-error" | "idle" | "waiting" | "received" | "submitting" | "submitted";

interface RelayRecord {
  status: "ready" | "error";
  calldata?: `0x${string}`;
  nullifier?: string;
  submitter?: string;
  error?: string;
}

interface SelfLivePanelProps {
  account: string;
  human: HumanRecord | null;
  onSuccess: () => void;
}

export function SelfLivePanel({ account, human, onSuccess }: SelfLivePanelProps) {
  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [selfApp, setSelfApp] = useState<SelfApp | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [record, setRecord] = useState<RelayRecord | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => setInjected(getInjected()), []);

  const effectiveAddress = connected ?? account;

  const connect = useCallback(async () => {
    if (!injected) {
      setNote({ kind: "err", text: "No injected wallet detected — install MetaMask." });
      return;
    }
    try {
      const accounts = (await injected.request({ method: "eth_requestAccounts" })) as string[];
      setConnected(accounts[0] ?? account);
      setNote(null);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected, account]);

  // Build the SelfApp descriptor whenever the effective address or endpoint changes.
  useEffect(() => {
    if (!SELF_ENDPOINT) {
      setPhase("not-configured");
      return;
    }
    try {
      const app = buildSelfApp(effectiveAddress, SELF_ENDPOINT);
      setSelfApp(app);
      setBuildError(null);
      setPhase("idle");
    } catch (e) {
      setSelfApp(null);
      setBuildError(errMessage(e));
      setPhase("build-error");
    }
  }, [effectiveAddress]);

  const stopPolling = useCallback(() => {
    if (pollTimer.current) {
      clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }, []);

  const startPolling = useCallback(() => {
    stopPolling();
    pollTimer.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/self-verify?address=${effectiveAddress}`);
        const data = (await res.json()) as { status: string } & RelayRecord;
        if (data.status === "ready") {
          setRecord(data);
          setPhase("received");
          stopPolling();
        } else if (data.status === "error") {
          setRecord(data);
          setNote({ kind: "err", text: data.error ?? "Relay reported an error." });
          stopPolling();
        }
        // status === "pending" — keep polling
      } catch {
        // transient network error while polling — keep trying
      }
    }, 2500);
  }, [effectiveAddress, stopPolling]);

  useEffect(() => () => stopPolling(), [stopPolling]);

  const handleQrSuccess = useCallback(() => {
    // The Self app's websocket relay signals "verification succeeded" here, but the actual
    // {proof, publicSignals} payload was POSTed server-side to /api/self-verify — not to this
    // browser tab. We poll our own relay for the encoded calldata (spec §5.2).
    setPhase("waiting");
    setNote({ kind: "ok", text: "Self app reported success — fetching the encoded proof from the relay…" });
    startPolling();
  }, [startPolling]);

  const handleQrError = useCallback((data: { error_code?: string; reason?: string }) => {
    setNote({ kind: "err", text: `Self app error: ${data.reason ?? data.error_code ?? "unknown"}` });
    stopPolling();
  }, [stopPolling]);

  const submit = useCallback(async () => {
    if (!record?.calldata) return;
    setPhase("submitting");
    setNote(null);
    try {
      const res = injected
        ? await sendZkPassportProof({
            data: record.calldata,
            from: effectiveAddress,
            provider: injected as Parameters<typeof sendZkPassportProof>[0]["provider"],
          })
        : await sendZkPassportProof({ data: record.calldata, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote({ kind: "ok", text: `Submitted · tx ${res.hash.slice(0, 14)}… · waiting for confirmation…` });
      setPhase("submitted");
      // Best-effort: clear the consumed relay record.
      fetch(`/api/self-verify?address=${effectiveAddress}`, { method: "DELETE" }).catch(() => {});
      setTimeout(onSuccess, 3000);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
      setPhase("received");
    }
  }, [record, injected, effectiveAddress, onSuccess]);

  const isAlreadyEnhanced = human?.assurance === "ENH" || human?.assurance === "DUAL";

  if (isAlreadyEnhanced) return null; // the paste-path panel already renders the "already enhanced" notice

  if (phase === "not-configured") {
    return (
      <div
        style={{
          padding: "0.75rem 0.9rem",
          background: "rgba(251,191,92,.06)",
          border: "1px solid rgba(251,191,92,.2)",
          borderRadius: "10px",
          fontSize: "0.77rem",
          color: "var(--muted)",
          lineHeight: 1.55,
        }}
      >
        <b style={{ color: "var(--warn)" }}>Live QR flow not configured.</b> Set{" "}
        <code style={{ fontFamily: "var(--mono)" }}>NEXT_PUBLIC_SELF_ENDPOINT</code> to a{" "}
        <b>publicly reachable</b> HTTPS URL for this app&apos;s <code>/api/self-verify</code> route
        (the Self mobile app cannot reach <code>localhost</code> — a tunnel like ngrok/cloudflared
        during dev, or your deployed relay&apos;s URL in production) to enable the live QR/deeplink
        flow. The paste/upload and dev-fixture paths below work without this.
      </div>
    );
  }

  if (phase === "build-error") {
    return (
      <div className="notice err" style={{ marginBottom: "0.75rem" }}>
        Could not build the Self app descriptor: {buildError}
      </div>
    );
  }

  return (
    <div>
      <div className="signer" style={{ marginBottom: "0.6rem" }}>
        binding to <b>{connected ? `MetaMask · ${short(connected)}` : injected ? "MetaMask (not connected)" : `dev account · ${short(account)}`}</b>
        {injected && !connected && (
          <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
            Connect MetaMask
          </button>
        )}
      </div>

      {(phase === "idle" || phase === "waiting") && selfApp && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "1.25rem", alignItems: "flex-start" }}>
          <div
            style={{
              background: "#fff",
              borderRadius: "12px",
              padding: "0.5rem",
              display: "inline-block",
            }}
          >
            <SelfQRcodeWrapper selfApp={selfApp} onSuccess={handleQrSuccess} onError={handleQrError} />
          </div>
          <div style={{ flex: 1, minWidth: "220px" }}>
            <div style={{ fontSize: "0.78rem", color: "var(--muted)", lineHeight: 1.6, marginBottom: "0.6rem" }}>
              Scan with the Self app, or open directly on this device:
            </div>
            <a
              href={getUniversalLink(selfApp)}
              target="_blank"
              rel="noreferrer"
              className="ghost"
              style={{ display: "inline-block", fontSize: "0.75rem", padding: "0.4rem 0.85rem", textDecoration: "none" }}
            >
              Open in Self app →
            </a>
            {phase === "waiting" && (
              <div style={{ marginTop: "0.75rem", fontSize: "0.75rem", color: "var(--accent-2)" }}>
                Waiting for the relay to receive the proof…
              </div>
            )}
          </div>
        </div>
      )}

      {phase === "received" && record && (
        <div
          style={{
            padding: "0.65rem 0.85rem",
            background: "rgba(79,231,168,.05)",
            border: "1px solid rgba(79,231,168,.2)",
            borderRadius: "9px",
            marginBottom: "0.75rem",
            fontSize: "0.76rem",
            lineHeight: 1.55,
          }}
        >
          <div style={{ color: "var(--accent)", fontWeight: 600, marginBottom: "0.3rem" }}>
            Proof received from the relay — ready to submit
          </div>
          <div style={{ fontFamily: "var(--mono)", color: "var(--muted)" }}>
            nullifier: <span style={{ color: "var(--ink)" }}>{record.nullifier?.slice(0, 18)}…</span>
          </div>
          <button
            className="primary"
            style={{
              marginTop: "0.6rem",
              background: "linear-gradient(135deg, rgba(139,123,255,.8), rgba(79,231,168,.8))",
              color: "#fff",
              fontWeight: 700,
            }}
            onClick={submit}
          >
            Submit ZK proof to chain
          </button>
        </div>
      )}

      {phase === "submitting" && (
        <div className="muted small" style={{ fontStyle: "italic" }}>
          Submitting…
        </div>
      )}

      {note && <div className={`notice ${note.kind}`} style={{ marginTop: "0.6rem" }}>{note.text}</div>}
    </div>
  );
}
