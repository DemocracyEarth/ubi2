"use client";

/**
 * M6 ZK-passport PoH UI — Stage 2.
 *
 * Adds a "Verify with passport (ZK)" path to the Identity section.  A user who has a
 * Self-app proof bundle (proof JSON + public signals from an OpenPassport-compatible prover)
 * can paste or upload it here, then submit the `submitZkPassportProof` transaction to
 * HumanityHub and see the resulting assurance level (STD / ENH / DUAL) on their PoH card.
 *
 * PRIVACY INVARIANT (spec I6):
 *   Only opaque proof bundles and 32-byte commitments are handled here.  No raw passport
 *   field — document number, date of birth, nationality string — ever appears in this
 *   component or leaves the device.  The proof bytes themselves are treated as opaque.
 *
 * STAGE NOTE:
 *   This is Stage 2 ("paste/upload a proof bundle").  The live in-app NFC scan (Stage C)
 *   depends on the Light-Node WASM prover and is the next milestone.  We are honest about
 *   this in the UI.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  HumanityReader,
  ZkPassportReader,
  sendZkPassportProof,
  encodeZkBundleAsCalldata,
  parseProofBundle,
  extractNullifier,
  extractSubmitterAddress,
  assuranceLevelLabel,
  assuranceLevelBadge,
  type HumanRecord,
  type AttributeCommitments,
  type AssuranceLevel,
  type SelfProofBundle,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY } from "./config";
import { SelfLivePanel } from "./self-live-panel";

const client = new Ubi2Client({ url: RPC_URL });
const reader = new HumanityReader(client);
const zkReader = new ZkPassportReader(client);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function short(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function shortHex(h: string): string {
  if (!h || h.length < 12) return h;
  return `${h.slice(0, 10)}…`;
}

// ---------------------------------------------------------------------------
// Assurance level badge component
// ---------------------------------------------------------------------------

function AssuranceBadge({ level }: { level: AssuranceLevel | undefined | null }) {
  if (!level) return null;
  const color =
    level === "DUAL"
      ? "linear-gradient(135deg, #FFFF00, #FF6699)"
      : level === "ENH"
        ? "linear-gradient(135deg, #b9a6ff, #8b7bff)"
        : "linear-gradient(135deg, #4fe7a8, #009966)";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.35rem",
        padding: "0.25rem 0.7rem",
        borderRadius: "999px",
        background: color,
        color: level === "ENH" ? "#fff" : "#0b0b0f",
        fontWeight: 700,
        fontSize: "0.75rem",
        letterSpacing: "0.06em",
      }}
    >
      {assuranceLevelBadge(level)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Privacy + Inclusion explainer banner
// ---------------------------------------------------------------------------

function ZkExplainerBanner() {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      style={{
        background: "rgba(139,123,255,.07)",
        border: "1px solid rgba(139,123,255,.22)",
        borderRadius: "12px",
        padding: "0.85rem 1rem",
        marginBottom: "1.1rem",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: "0.75rem" }}>
        <span style={{ fontSize: "1.1rem", lineHeight: 1, marginTop: "0.05rem", flexShrink: 0 }}>
          &#128272;
        </span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: "0.82rem", color: "var(--accent-2)", marginBottom: "0.3rem" }}>
            ZK-passport verification — Stage C (Self app, staging)
          </div>
          <div style={{ fontSize: "0.77rem", color: "var(--muted)", lineHeight: 1.55 }}>
            Submit a ZK-passport proof (from the Self app) to receive{" "}
            <b style={{ color: "var(--ink)" }}>Enhanced (ENH)</b> or{" "}
            <b style={{ color: "var(--ink)" }}>Dual (DUAL)</b> assurance level.
            The chain stores only a cryptographic nullifier and opaque attribute commitments —
            never your name, document number, or date of birth.
          </div>
          <button
            onClick={() => setExpanded((v) => !v)}
            style={{
              background: "none",
              border: "none",
              color: "var(--accent-2)",
              cursor: "pointer",
              fontSize: "0.74rem",
              fontWeight: 600,
              padding: "0.25rem 0",
              fontFamily: "inherit",
            }}
          >
            {expanded ? "Show less" : "Learn more"}
          </button>
        </div>
      </div>

      {expanded && (
        <div
          style={{
            marginTop: "0.75rem",
            paddingTop: "0.75rem",
            borderTop: "1px solid rgba(139,123,255,.15)",
            fontSize: "0.76rem",
            color: "var(--muted)",
            lineHeight: 1.6,
            display: "flex",
            flexDirection: "column",
            gap: "0.5rem",
          }}
        >
          <p style={{ margin: 0 }}>
            <b style={{ color: "var(--ink)" }}>Privacy.</b> Your passport never leaves your device.
            The Self app reads the NFC chip and generates a Groth16 zero-knowledge proof entirely
            on-device. The only data that reaches the chain is the proof bytes and public signals —
            mathematically opaque commitments from which no personal information can be recovered.
          </p>
          <p style={{ margin: 0 }}>
            <b style={{ color: "var(--ink)" }}>Inclusion.</b> ZK-passport is{" "}
            <b>never the only gate to UBI.</b> The M3 social-vouching path remains available to
            anyone — including the ~20% of the world&apos;s adults who do not hold a valid
            passport. STD and ENH/DUAL humans receive identical UBI streams; the assurance level
            is metadata for optional features, never a gate on accrual.
          </p>
          <p style={{ margin: 0 }}>
            <b style={{ color: "var(--ink)" }}>This stage (Stage C / C1 — honest status).</b> The
            live QR/deeplink flow below builds a real `SelfAppBuilder` (V2) request against Self&apos;s{" "}
            <b>staging</b> environment and submits through an untrusted relay that only encodes
            calldata — the runtime always re-verifies. A genuine end-to-end run (a real phone,
            Self&apos;s staging prover, and a pinned production verifying key) has not yet been
            captured on this devnet; that capture is the EC-C7 gate (spec 06b §4.1/§9). Until then,
            treat this as the wired plumbing, not a claim that a real passport has been verified
            here. The dev-fixture and paste-bundle paths remain the reliable way to exercise the
            on-chain submit + assurance flow today.
          </p>
          <p style={{ margin: 0 }}>
            <b style={{ color: "var(--ink)" }}>What goes on-chain:</b> a 32-byte nullifier
            (one-way hash of the passport secret + chain id), three opaque Pedersen attribute
            commitments (hiding: two different users with the same attribute get different
            commitments), and your assurance level. Nothing else.
          </p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attribute commitments display (opaque)
// ---------------------------------------------------------------------------

function AttributesPanel({ commitments }: { commitments: AttributeCommitments | null }) {
  if (!commitments) return null;
  const { ageCommitment, nationalityCommitment, expiryCommitment } = commitments;
  if (!ageCommitment && !nationalityCommitment && !expiryCommitment) return null;

  return (
    <div
      style={{
        marginTop: "0.75rem",
        padding: "0.75rem 1rem",
        background: "rgba(139,123,255,.05)",
        border: "1px solid rgba(139,123,255,.15)",
        borderRadius: "10px",
      }}
    >
      <div
        style={{
          fontSize: "0.74rem",
          fontWeight: 700,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--faint)",
          marginBottom: "0.6rem",
        }}
      >
        Attribute commitments (opaque)
      </div>
      {[
        ["Age threshold", ageCommitment],
        ["Nationality bucket", nationalityCommitment],
        ["Expiry epoch", expiryCommitment],
      ].map(([label, val]) =>
        val ? (
          <div
            key={label as string}
            style={{
              display: "flex",
              gap: "0.75rem",
              alignItems: "baseline",
              paddingBottom: "0.35rem",
              fontSize: "0.76rem",
            }}
          >
            <span style={{ color: "var(--faint)", width: "120px", flexShrink: 0 }}>{label}</span>
            <span
              style={{ fontFamily: "var(--mono)", color: "var(--accent-2)", fontSize: "0.7rem" }}
            >
              {shortHex(val as string)}
            </span>
            <span style={{ color: "var(--faint)", fontSize: "0.66rem" }}>
              Pedersen commitment — hides the value; proves statements without revealing it
            </span>
          </div>
        ) : null,
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Proof-bundle input panel (paste or file upload)
// ---------------------------------------------------------------------------

interface ProofInputPanelProps {
  onBundle: (json: string) => void;
  disabled?: boolean;
}

function ProofInputPanel({ onBundle, disabled }: ProofInputPanelProps) {
  const [text, setText] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [fixtureErr, setFixtureErr] = useState<string | null>(null);
  const [fixtureBusy, setFixtureBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleText = (v: string) => {
    setText(v);
    if (v.trim()) onBundle(v.trim());
  };

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result;
      if (typeof content === "string") {
        setText(content);
        onBundle(content);
      }
    };
    reader.readAsText(file);
  };

  // M6 Stage C1 (spec 06b §5.3): load the shared arity-21 synthetic fixture
  // (crates/zkpoh/fixtures/self_synthetic_{public,proof}.json) via the dev-fixture API route, so
  // the full parse → encode → submit flow is exercisable without a live Self app or phone.
  const loadDevFixture = useCallback(async () => {
    setFixtureBusy(true);
    setFixtureErr(null);
    try {
      const res = await fetch("/api/self-dev-fixture");
      const json = (await res.json()) as { ok: boolean; bundle?: SelfProofBundle; error?: string };
      if (!json.ok || !json.bundle) {
        setFixtureErr(json.error ?? "Could not load the dev fixture.");
        return;
      }
      const jsonStr = JSON.stringify(json.bundle, null, 2);
      setText(jsonStr);
      onBundle(jsonStr);
    } catch (e) {
      setFixtureErr(e instanceof Error ? e.message : String(e));
    } finally {
      setFixtureBusy(false);
    }
  }, [onBundle]);

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
      }}
      style={{
        border: `2px dashed ${dragOver ? "var(--accent-2)" : "rgba(139,123,255,.3)"}`,
        borderRadius: "12px",
        padding: "1rem",
        marginBottom: "1rem",
        background: dragOver ? "rgba(139,123,255,.07)" : "transparent",
        transition: "border-color .18s, background .18s",
      }}
    >
      <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginBottom: "0.6rem" }}>
        Paste your Self-app proof bundle JSON, drop / upload a file, or load the dev/CI fixture
        (dev-only — a synthetic non-production proof, spec 06b §5.3):
      </div>

      <textarea
        rows={5}
        disabled={disabled}
        placeholder={`{\n  "proof": { "pi_a": […], "pi_b": […], "pi_c": […] },\n  "publicSignals": ["…", "…", …]\n}`}
        value={text}
        onChange={(e) => handleText(e.target.value)}
        style={{
          width: "100%",
          background: "rgba(0,0,0,.3)",
          border: "1px solid rgba(139,123,255,.2)",
          borderRadius: "8px",
          color: "var(--ink)",
          fontFamily: "var(--mono)",
          fontSize: "0.7rem",
          padding: "0.5rem 0.65rem",
          resize: "vertical",
          outline: "none",
          marginBottom: "0.5rem",
        }}
        spellCheck={false}
      />

      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "center" }}>
        <button
          className="ghost"
          disabled={disabled}
          style={{ fontSize: "0.74rem", padding: "0.3rem 0.75rem" }}
          onClick={() => fileRef.current?.click()}
        >
          Upload .json file
        </button>
        <button
          className="ghost"
          disabled={disabled || fixtureBusy}
          style={{ fontSize: "0.74rem", padding: "0.3rem 0.75rem" }}
          onClick={loadDevFixture}
          title="Load crates/zkpoh/fixtures/self_synthetic_{public,proof}.json — a synthetic, non-production bundle for dev/CI"
        >
          {fixtureBusy ? "Loading…" : "Use dev fixture"}
        </button>
        {text && (
          <button
            className="ghost"
            disabled={disabled}
            style={{ fontSize: "0.74rem", padding: "0.3rem 0.75rem" }}
            onClick={() => {
              setText("");
              onBundle("");
            }}
          >
            Clear
          </button>
        )}
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = "";
          }}
        />
      </div>
      {fixtureErr && (
        <div className="notice err" style={{ marginTop: "0.5rem", fontSize: "0.72rem" }}>
          {fixtureErr}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ZK-passport submit flow component
// ---------------------------------------------------------------------------

interface ZkPassportSubmitProps {
  account: string;
  human: HumanRecord | null;
  onSuccess: () => void;
}

function ZkPassportSubmit({ account, human, onSuccess }: ZkPassportSubmitProps) {
  const [bundleJson, setBundleJson] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [bundleOk, setBundleOk] = useState(false);
  const [bundleInfo, setBundleInfo] = useState<{ nullifier: string; submitter: string } | null>(null);

  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  useEffect(() => setInjected(getInjected()), []);

  const handleBundle = useCallback((json: string) => {
    setBundleJson(json);
    setParseError(null);
    setBundleOk(false);
    setBundleInfo(null);
    setNote(null);

    if (!json.trim()) return;

    const { bundle, error } = parseProofBundle(json);
    if (error || !bundle) {
      setParseError(error ?? "Unknown parse error.");
      return;
    }

    try {
      const nullifier = extractNullifier(bundle);
      const submitter = extractSubmitterAddress(bundle);
      setBundleOk(true);
      setBundleInfo({ nullifier, submitter });
    } catch (e) {
      setParseError("Could not extract proof fields: " + errMessage(e));
    }
  }, []);

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

  const submit = useCallback(async () => {
    if (!bundleOk || !bundleJson) {
      setNote({ kind: "err", text: "Paste a valid proof bundle first." });
      return;
    }

    const { bundle, error } = parseProofBundle(bundleJson);
    if (error || !bundle) {
      setNote({ kind: "err", text: error ?? "Invalid proof bundle." });
      return;
    }

    setBusy(true);
    setNote(null);

    try {
      // Check if the nullifier is already spent before encoding + submitting
      const nullifier = extractNullifier(bundle);
      const used = await zkReader.isNullifierUsed(nullifier);
      if (used) {
        setNote({
          kind: "err",
          text: "This nullifier is already registered on-chain (NullifierAlreadyUsed). A passport can only be used once per chain.",
        });
        setBusy(false);
        return;
      }

      const data = encodeZkBundleAsCalldata(bundle);
      const signerAddr = connected ?? account;

      const res = injected
        ? await sendZkPassportProof({
            data,
            from: signerAddr,
            provider: injected as Parameters<typeof sendZkPassportProof>[0]["provider"],
          })
        : await sendZkPassportProof({
            data,
            privateKey: DEV_PRIVATE_KEY,
            rpcUrl: RPC_URL,
          });

      setNote({
        kind: "ok",
        text: `ZK proof submitted · tx ${res.hash.slice(0, 14)}… · Waiting for confirmation…`,
      });

      // Poll for the new assurance level
      setTimeout(onSuccess, 3000);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(false);
    }
  }, [bundleOk, bundleJson, connected, account, injected, onSuccess]);

  const isAlreadyEnhanced =
    human?.assurance === "ENH" || human?.assurance === "DUAL";

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  if (isAlreadyEnhanced) {
    return (
      <div
        style={{
          padding: "0.85rem 1rem",
          background: "rgba(139,123,255,.06)",
          border: "1px solid rgba(139,123,255,.2)",
          borderRadius: "10px",
          fontSize: "0.8rem",
          color: "var(--muted)",
        }}
      >
        This account already holds{" "}
        <b style={{ color: "var(--ink)" }}>{human?.assurance}</b> assurance level via
        ZK-passport. Submitting a second proof would be rejected on-chain (AlreadyEnhanced,
        idempotency guard). If you want to re-verify, you must revoke first.
      </div>
    );
  }

  return (
    <div>
      {/* Proof bundle input */}
      <ProofInputPanel onBundle={handleBundle} disabled={busy} />

      {/* Parse result */}
      {parseError && (
        <div className="notice err" style={{ marginBottom: "0.75rem" }}>
          {parseError}
        </div>
      )}

      {bundleOk && bundleInfo && (
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
            Proof bundle parsed successfully
          </div>
          <div style={{ fontFamily: "var(--mono)", color: "var(--muted)" }}>
            nullifier:{" "}
            <span style={{ color: "var(--ink)" }}>{shortHex(bundleInfo.nullifier)}</span>
          </div>
          <div style={{ fontFamily: "var(--mono)", color: "var(--muted)" }}>
            submitter:{" "}
            <span style={{ color: "var(--ink)" }}>{bundleInfo.submitter}</span>
          </div>
          {bundleInfo.submitter &&
            account &&
            bundleInfo.submitter.toLowerCase() !== account.toLowerCase() && (
              <div style={{ color: "var(--warn)", marginTop: "0.35rem", fontSize: "0.73rem" }}>
                Warning: the proof&apos;s embedded submitter address ({short(bundleInfo.submitter)})
                differs from the active account ({short(account)}). The transaction will fail
                unless you sign from the proof&apos;s submitter address (anti-replay, spec §4.3).
              </div>
            )}
        </div>
      )}

      {/* Submit button */}
      <button
        className="primary"
        style={{
          background:
            "linear-gradient(135deg, rgba(139,123,255,.8), rgba(79,231,168,.8))",
          color: "#fff",
          fontWeight: 700,
          marginBottom: "0.5rem",
        }}
        onClick={submit}
        disabled={busy || !bundleOk}
      >
        {busy ? "Submitting ZK proof…" : "Submit ZK passport proof"}
      </button>

      <div className="signer" style={{ marginTop: "0.35rem" }}>
        signing with <b>{signerLabel}</b>
        {injected && !connected && (
          <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
            Connect MetaMask
          </button>
        )}
      </div>

      {note && <div className={`notice ${note.kind}`} style={{ marginTop: "0.6rem" }}>{note.text}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ZK passport section (exported)
// ---------------------------------------------------------------------------

interface ZkPassportSectionProps {
  account: string;
  human: HumanRecord | null;
  onRefreshHuman: () => void;
}

/**
 * ZkPassportSection — the "Verify with passport (ZK)" panel embedded in the Identity tab.
 *
 * Shows:
 *  - A privacy + inclusion explainer (collapsible).
 *  - The current assurance level on the PoH card (STD / ENH / DUAL).
 *  - A proof-bundle input (paste JSON or file upload) + submit flow.
 *  - The attribute commitments (opaque) after ENH/DUAL verification.
 *  - The CSCA registry root (so a prover knows the live trust set).
 */
export function ZkPassportSection({ account, human, onRefreshHuman }: ZkPassportSectionProps) {
  const [attributes, setAttributes] = useState<AttributeCommitments | null>(null);
  const [cscaRoot, setCscaRoot] = useState<string | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const assurance = (human?.assurance ?? "STD") as AssuranceLevel;
  const isEnhanced = assurance === "ENH" || assurance === "DUAL";
  const isVerified = human?.status === "Verified";

  const refresh = useCallback(async () => {
    try {
      const [attrs, registry] = await Promise.all([
        zkReader.getAttributes(account),
        zkReader.getCscaRegistry(),
      ]);
      setAttributes(attrs);
      setCscaRoot(registry.root);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(errMessage(e));
    }
  }, [account]);

  const handleSuccess = useCallback(() => {
    onRefreshHuman();
    refresh();
  }, [onRefreshHuman, refresh]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <section className="card" style={{ borderColor: "rgba(139,123,255,.3)" }}>
      {/* Section heading */}
      <div className="poh-section-head" style={{ marginBottom: "0.85rem" }}>
        <span style={{ fontSize: "1.2rem", lineHeight: 1, flexShrink: 0 }}>&#128272;</span>
        <span
          className="poh-section-title"
          style={{
            background: "linear-gradient(135deg, #b9a6ff, #4fe7a8)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          ZK-Passport Verification
        </span>
      </div>

      {/* Privacy + inclusion explainer */}
      <ZkExplainerBanner />

      {loadErr && (
        <div className="notice err" style={{ marginBottom: "0.75rem" }}>
          {loadErr}
        </div>
      )}

      {/* Current assurance level */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "0.75rem",
          marginBottom: "1rem",
          flexWrap: "wrap",
        }}
      >
        <div>
          <div className="label" style={{ marginBottom: "0.25rem" }}>Assurance level</div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <AssuranceBadge level={assurance} />
            <span style={{ fontSize: "0.78rem", color: "var(--muted)" }}>
              {assuranceLevelLabel(assurance)}
            </span>
          </div>
        </div>

        {cscaRoot && (
          <div>
            <div className="label" style={{ marginBottom: "0.25rem" }}>CSCA registry root</div>
            <span
              style={{
                fontFamily: "var(--mono)",
                fontSize: "0.7rem",
                color: "var(--faint)",
              }}
            >
              {shortHex(cscaRoot)}
            </span>
          </div>
        )}
      </div>

      {/* Attribute commitments — shown for ENH/DUAL humans */}
      {isEnhanced && <AttributesPanel commitments={attributes} />}

      {/* Separator */}
      <div
        style={{
          height: "1px",
          background: "linear-gradient(90deg, transparent, rgba(139,123,255,.2), transparent)",
          margin: "1rem 0",
        }}
      />

      {/* Submit flow */}
      {!isVerified && (
        <div
          style={{
            padding: "0.65rem 0.85rem",
            background: "rgba(251,191,92,.06)",
            border: "1px solid rgba(251,191,92,.2)",
            borderRadius: "9px",
            marginBottom: "0.85rem",
            fontSize: "0.77rem",
            color: "var(--muted)",
          }}
        >
          <b style={{ color: "var(--warn)" }}>Not yet verified.</b> You can still submit a ZK
          passport proof — if valid, it will create your verified human record with ENH assurance
          level directly, without requiring social vouching first.
        </div>
      )}

      {!isEnhanced && (
        <div style={{ marginBottom: "1.1rem" }}>
          <div className="label" style={{ marginBottom: "0.5rem" }}>
            Verify with passport (ZK) — scan with the Self app
          </div>
          <SelfLivePanel account={account} human={human} onSuccess={handleSuccess} />
        </div>
      )}

      {/* Separator */}
      <div
        style={{
          height: "1px",
          background: "linear-gradient(90deg, transparent, rgba(139,123,255,.2), transparent)",
          margin: "1rem 0",
        }}
      />

      <div style={{ marginBottom: "0.5rem" }}>
        <div className="label" style={{ marginBottom: "0.5rem" }}>
          Dev fallback — paste / upload / load a proof bundle directly
        </div>
        <ZkPassportSubmit
          account={account}
          human={human}
          onSuccess={handleSuccess}
        />
      </div>

      {/* Stage note */}
      <div
        style={{
          marginTop: "0.85rem",
          padding: "0.6rem 0.85rem",
          background: "rgba(139,123,255,.04)",
          border: "1px solid rgba(139,123,255,.12)",
          borderRadius: "9px",
          fontSize: "0.73rem",
          color: "var(--faint)",
          lineHeight: 1.55,
        }}
      >
        <b style={{ color: "var(--muted)" }}>Stage C / C1 — the Self client flow.</b>{" "}
        The QR/deeplink panel above builds a real <code>SelfAppBuilder</code> V2 request (scope{" "}
        <code>ubi2-poh</code>) against Self&apos;s <b>staging</b> environment and relays through
        this app&apos;s own untrusted <code>/api/self-verify</code> encoder — MetaMask signs the
        final transaction, and the runtime is the sole authority on validity (spec 06b §4.4/§5.2).
        The dev fallback below (paste, upload, or &quot;Use dev fixture&quot;) submits the identical
        calldata path and is how CI and offline development exercise the flow without a phone.
        The Social vouching path (M3) remains available in parallel at all stages.
      </div>
    </section>
  );
}
