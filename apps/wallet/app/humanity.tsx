"use client";

/**
 * M3 Proof-of-Humanity UI — cycle 7 (PoH brand + NFT card).
 *
 * Changes:
 *  - PoH brand palette applied to all identity surfaces (card.poh, gradient accents,
 *    fingerprint mark, achievement banner).
 *  - PoH NFT card: fetches tokenURI from HumanityHub via PohNftReader and renders
 *    the on-chain SVG inline; shows token attributes.
 *  - "Add to MetaMask" (wallet_watchAsset ERC721) button in the NFT card.
 *  - Verified state feels like an achievement: green #009966 banner + fingerprint mark.
 *  - The rest (vouch, challenge, pending cases) is re-skinned with PoH-green hints.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  HumanityReader,
  PohNftReader,
  OracleAdminClient,
  sendHumanityTx,
  encodeRequestVerification,
  encodeVouch,
  encodeChallenge,
  deriveLivenessRef,
  humanStatusLabel,
  verdictLabel,
  confidenceLabel,
  pohTokenId,
  assuranceLevelLabel,
  assuranceLevelBadge,
  HUMANITY_HUB,
  type HumanRecord,
  type CaseRecord,
  type JurorRecord,
  type PohCard,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY } from "./config";
import { ZkPassportSection } from "./zk-passport";
import { svgImageSrc } from "./svg-image";

const client = new Ubi2Client({ url: RPC_URL });
const reader = new HumanityReader(client);
const pohReader = new PohNftReader(client);
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

// ---- Inline PoH mark (fingerprint-in-shield, gradient-filled) --------------------
// Extracted from poh-logo.svg: the mask path + gradient fill rectangle.

function PohMark({ size = 28, className = "" }: { size?: number; className?: string }) {
  const gradId = "poh-mark-grad";
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 370 414"
      className={className}
      aria-label="Proof of Humanity mark"
    >
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#FFFF00" />
          <stop offset="100%" stopColor="#FF6699" />
        </linearGradient>
        <mask id="poh-mark-mask">
          <path
            fill="#FFFFFF"
            d="
M 347.25 181.1
Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95 174.897265625 9.9517578125 173.65 9.95 172.40078125 9.9517578125 171.15 9.95 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1 0.0033203125 182.2296875 0 183.35 0.001953125 184.7263671875 0 186.1 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65
L 79.75 310.85 79.75 418.7
Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65
L 242.6 423.65
Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7
L 247.6 377.15 295.75 377.15
Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25
L 320.7 304.05 351.1 304.05
Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5 369.5890625 285.8658203125 369.2 283.3 369.8205078125 279.015625 368.4 274.95
L 347.25 212.2 347.25 181.1
M 332.3 218
Q 332.3 218.85 332.55 219.6
L 353.95 283.1
Q 353.980859375 283.1904296875 354 283.25 353.620703125 284.544140625 352.85 285.65 351.7 287.25 349.9 288.2 348.2853515625 289.007421875 346.5 289.05
L 310.7 289.05
Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05
L 305.7 347.55
Q 305.6390625 350.3458984375 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.8935546875 362.1400390625 291.05 362.2
L 237.6 362.2
Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2
L 232.6 408.7 94.75 408.7 94.75 303.05
Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8
L 74.95 288.15
Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.2994140625 198.1578125 14.95 183.05 15.5302734375 152.651171875 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.941796875 25.38046875 173.65 24.9 204.35625 25.38046875 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76171875 152.7470703125 332.3 183.3
L 332.3 218
M 234.25 188.1
Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35
L 229.25 183.35
Q 227.8 183.45 226.65 184.35
L 176.7 222.2 126.8 184.3
Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8
L 172.85 266.35
Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35
L 233.35 190.85
Q 234.25 189.65 234.25 188.1
M 174.4 77.35
Q 173.3 77.95 172.65 79.05
L 123.9 160.15
Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35
L 173.85 203.95
Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95
L 228.35 166.35
Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15
L 180.75 79.05
Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35
M 176.75 136.45
Q 177.6 136.45 178.4 136.8
L 219.8 155.55
Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95
L 178.2 145.65
Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65
L 137 162.95
Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55
L 175.05 136.8
Q 175.85 136.45 176.75 136.45 Z"
          />
        </mask>
      </defs>
      <rect
        x="0"
        y="0"
        width="370"
        height="424"
        fill={`url(#${gradId})`}
        mask="url(#poh-mark-mask)"
      />
    </svg>
  );
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
  if (status === "Verified") {
    return <span className="pill poh-verified">{humanStatusLabel(status as never)}</span>;
  }
  const cls =
    status === "Pending"
      ? "pill poh-pending"
      : status === "Challenged"
        ? "pill poh-challenged"
        : status === "Revoked"
          ? "pill stopped"
          : "pill completed";
  return <span className={cls}>{humanStatusLabel(status as never)}</span>;
}

// ---- PoH NFT card ----------------------------------------------------------------

function PohNftCard({ account, human }: { account: string; human: HumanRecord }) {
  const [card, setCard] = useState<PohCard | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [watchNote, setWatchNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(null);
    const tokenId = pohTokenId(account);
    pohReader
      .fetchPohCard(tokenId)
      .then((c) => { if (alive) { setCard(c); setLoading(false); } })
      .catch((e: unknown) => { if (alive) { setErr(errMessage(e)); setLoading(false); } });
    return () => { alive = false; };
  }, [account, human.status]);

  const addToMetaMask = useCallback(async () => {
    const eth = (window as unknown as { ethereum?: { request: (a: unknown) => Promise<unknown> } }).ethereum;
    if (!eth) {
      setWatchNote({ kind: "err", text: "MetaMask not detected." });
      return;
    }
    try {
      // tokenId as decimal string (wallet_watchAsset expects decimal for ERC721)
      const tokenId = pohTokenId(account).toString(10);
      await eth.request({
        method: "wallet_watchAsset",
        params: {
          type: "ERC721",
          options: {
            address: HUMANITY_HUB,
            tokenId,
          },
        },
      });
      setWatchNote({ kind: "ok", text: "PoH NFT added to MetaMask." });
    } catch (e) {
      setWatchNote({ kind: "err", text: errMessage(e) });
    }
  }, [account]);

  // Extract a few key attributes for the sidebar
  const getAttr = (traitType: string): string | number | undefined =>
    card?.attributes.find((a) => a.trait_type === traitType)?.value;

  return (
    <div className="poh-nft-card">
      <div className="poh-nft-card-head">
        <span className="poh-nft-label">Proof of Humanity NFT</span>
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button className="ghost poh" style={{ fontSize: "0.7rem", padding: "0.25rem 0.65rem" }} onClick={addToMetaMask}>
            Add to MetaMask
          </button>
          <span
            style={{
              fontSize: "0.68rem",
              fontFamily: "var(--mono)",
              color: "var(--faint)",
              alignSelf: "center",
            }}
          >
            {short(HUMANITY_HUB)}
          </span>
        </div>
      </div>

      {loading && (
        <div className="muted small" style={{ fontStyle: "italic" }}>Loading NFT card…</div>
      )}
      {err && !loading && (
        <div className="small" style={{ color: "var(--danger)" }}>{err}</div>
      )}

      {card && !loading && (
        <div className="poh-nft-body">
          {/* On-chain SVG — rendered as an inert <img> (issue #38): the tokenURI comes from an
              UNTRUSTED RPC, so it must never be injected as live DOM (script / onerror / onload). */}
          <img className="poh-nft-svg" src={svgImageSrc(card.svg)} alt="Proof of Humanity card" />

          {/* Attributes sidebar */}
          <div className="poh-nft-attrs">
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Status</span>
              <span className="poh-nft-attr-val green">{getAttr("Status") ?? "—"}</span>
            </div>
            {/* M6: Assurance level (STD/ENH/DUAL) — additive, no PII (spec §5.5/EC-6) */}
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Assurance</span>
              <span
                className="poh-nft-attr-val"
                style={{
                  fontWeight: 700,
                  color:
                    (getAttr("Assurance") ?? human.assurance ?? "STD") === "DUAL"
                      ? "#FF6699"
                      : (getAttr("Assurance") ?? human.assurance ?? "STD") === "ENH"
                        ? "#b9a6ff"
                        : "var(--poh-green)",
                }}
              >
                {assuranceLevelBadge(
                  ((getAttr("Assurance") ?? human.assurance ?? "STD") as "STD" | "ENH" | "DUAL")
                )}
              </span>
            </div>
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Token</span>
              <span className="poh-nft-attr-val" style={{ fontSize: "0.68rem" }}>
                #{pohTokenId(account).toString(10).slice(0, 8)}…
              </span>
            </div>
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Verified</span>
              <span className="poh-nft-attr-val">{getAttr("Verified date") ?? "—"}</span>
            </div>
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Vouches</span>
              <span className="poh-nft-attr-val">{getAttr("Vouches") ?? human.vouches_in.length}</span>
            </div>
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Reputation</span>
              <span className="poh-nft-attr-val">{getAttr("Reputation") ?? human.reputation}</span>
            </div>
            <div className="poh-nft-attr">
              <span className="poh-nft-attr-key">Collection</span>
              <span className="poh-nft-attr-val" style={{ fontSize: "0.72rem", color: "var(--muted)" }}>
                {card.name.split(" — ")[0]}
              </span>
            </div>
          </div>
        </div>
      )}

      {watchNote && (
        <div className={`notice ${watchNote.kind}`} style={{ marginTop: "0.6rem" }}>
          {watchNote.text}
        </div>
      )}
    </div>
  );
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
        background: isOpen && isRegistration ? "rgba(0,153,102,.03)" : "transparent",
      }}
    >
      <span
        style={{
          fontFamily: "var(--mono)",
          color: "var(--poh-green)",
          fontWeight: 600,
          fontSize: "0.8rem",
        }}
      >
        #{c.id}
      </span>
      <span className="addr" style={{ fontSize: "0.78rem" }}>{short(c.subject)}</span>
      <span
        className={c.kind === "Registration" ? "pill poh-verified" : "pill poh-challenged"}
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

  const kindCls = c.kind === "Registration" ? "pill poh-verified" : "pill poh-challenged";

  return (
    <div className="poh-case-row">
      <span className="poh-case-id" style={{ color: "var(--poh-green)" }}>#{c.id}</span>
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
  const isVerified = human?.status === "Verified";

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

      {/* Human status card — PoH branded */}
      <section className="card poh">
        {/* PoH section heading */}
        <div className="poh-section-head">
          <PohMark size={28} className="poh-mark" />
          <span className="poh-section-title">Proof of Humanity</span>
        </div>

        {loadErr && (
          <p className="small" style={{ color: "var(--danger)", marginBottom: "0.75rem" }}>
            {loadErr}
          </p>
        )}

        {/* Achievement banner when Verified */}
        {isVerified && human && (
          <div className="poh-achievement">
            <PohMark size={36} className="poh-achievement-icon" />
            <div className="poh-achievement-text">
              <div className="poh-achievement-title">Verified Human</div>
              <div className="poh-achievement-sub">
                This account holds a soulbound Proof of Humanity NFT (POH).
                {human.verified_at
                  ? ` Verified ${new Date(human.verified_at * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}.`
                  : ""}
                {human.vouches_in.length > 0
                  ? ` Vouched by ${human.vouches_in.length} ${human.vouches_in.length === 1 ? "peer" : "peers"}.`
                  : ""}
              </div>
            </div>
          </div>
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
          {human && (
            <div>
              <div className="label">Reputation</div>
              <div className="muted small">{human.reputation}</div>
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
              className="primary poh"
              onClick={applyVerification}
              disabled={busy === "apply"}
              style={{ marginTop: "0.5rem" }}
            >
              {busy === "apply" ? "Sending…" : "Apply for verification"}
            </button>
            <div className="muted small" style={{ marginTop: "0.4rem" }}>
              Submits a liveness commitment to HumanityHub ({short(HUMANITY_HUB)}) to open a
              Registration case. After the challenge window (5 blocks) clears, you become Verified
              and receive your PoH NFT.
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

        {/* PoH NFT card — shown only when Verified */}
        {isVerified && human && (
          <PohNftCard account={account} human={human} />
        )}
      </section>

      {/* M6 ZK-passport section — always shown in the Identity tab (spec §12.2 Stage C) */}
      <ZkPassportSection
        account={account}
        human={human}
        onRefreshHuman={refresh}
      />

      {/* Vouch action */}
      <section className="card poh">
        {/* Section heading */}
        <div className="poh-section-head">
          <PohMark size={20} className="poh-mark" />
          <span className="poh-section-title">Vouch for address</span>
        </div>

        {!canVouch && (
          <p className="muted small" style={{ marginBottom: "0.75rem" }}>
            Only Verified accounts can vouch. Current status:{" "}
            <b>{human?.status ?? "unknown"}</b>.
          </p>
        )}

        {canVouch && (
          <>
            <div className="poh-vouch-hint">
              You can only vouch for accounts that have an{" "}
              <b style={{ color: "var(--ink)" }}>open Registration case</b>{" "}
              (i.e. they applied for verification but haven&apos;t been verified yet). Vouching for
              an address without a pending registration will fail.
              {vouchableCases.length > 0 && (
                <>
                  {" "}There {vouchableCases.length === 1 ? "is" : "are"} currently{" "}
                  <b style={{ color: "var(--poh-green)" }}>{vouchableCases.length}</b> pending
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
                      border: "1px solid rgba(0,153,102,.22)",
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
              className="primary poh"
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
        <div className="poh-section-head">
          <span style={{ fontSize: "1rem", lineHeight: 1 }}>⚠</span>
          <span
            className="poh-section-title"
            style={{
              background: "none",
              WebkitBackgroundClip: "unset",
              color: "var(--danger)",
              WebkitTextFillColor: "unset",
            }}
          >
            Challenge address
          </span>
        </div>
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
          Challenges can only be submitted against accounts that are{" "}
          <b style={{ color: "var(--ink)" }}>Verified</b>{" "}
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
      <section className="card poh">
        <div className="poh-section-head">
          <PohMark size={20} className="poh-mark" />
          <span className="poh-section-title">Pending cases ({cases.length})</span>
        </div>
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
                      className="pill poh-verified"
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
