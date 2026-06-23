"use client";

/**
 * M4 Contracts section — cycle 6.
 *
 * - Template library (6 templates with icons + explainers).
 * - Polished authoring flow: choose template → set parties + escrow → deploy → invoke.
 * - Full contract detail view reachable from the list: text, parties, escrow_address,
 *   status, deploy_block (block link), deploy_tx (tx link), vars, and the exec-case
 *   timeline with committed effect ops or abort reason.
 * - Actions on detail: Fund escrow + Invoke (dual signer).
 * - AI-config clarity banner when oracle is in mock mode.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ContractReader,
  OracleAdminClient,
  sendContractTx,
  encodeDeployContract,
  encodeFundContract,
  encodeInvokeContract,
  deriveTriggerRef,
  contractStatusLabel,
  execStatusLabel,
  formatUbi,
  parseUbiToBaseUnits,
  CONTRACT_HUB,
  type ContractView,
  type ExecCaseSummary,
  type ContractOp,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const reader = new ContractReader(client);
const oracle = new OracleAdminClient(client);

// ---- Template library ---------------------------------------------------------------

interface ContractTemplate {
  id: string;
  icon: string;
  title: string;
  explainer: string;
  /** The plain-language text that goes on-chain. */
  text: string;
  /** How many parties (min). */
  minParties: number;
  /** Suggested escrow amount (UBI). */
  suggestedEscrow: string;
  /** Role labels for parties (for form hints). */
  partyRoles: string[];
}

const TEMPLATES: ContractTemplate[] = [
  {
    id: "escrow-release",
    icon: "▣",
    title: "Escrow Release",
    explainer:
      "Holds funds in escrow until both the buyer and seller confirm delivery. The AI interprets the confirmation trigger and releases a Transfer effect to the payee — or issues a Refund if the parties disagree.",
    text:
      "Pay the payee from escrow when both parties confirm that delivery has been completed. " +
      "If either party disputes delivery within the challenge window, refund the buyer instead.",
    minParties: 2,
    suggestedEscrow: "10",
    partyRoles: ["Buyer (0x…)", "Seller / Payee (0x…)"],
  },
  {
    id: "recurring-payroll",
    icon: "⧗",
    title: "Recurring Stream / Payroll",
    explainer:
      "Opens a continuous UBI stream from the escrow to a worker at a set rate for a set duration. The AI interprets an OpenStream effect when invoked with a 'start payroll' trigger, and a StopStream when invoked with a 'stop payroll' trigger.",
    text:
      "Stream UBI to the worker at 1 UBI per hour for up to 100 hours from the escrow deposit. " +
      "Open the stream when the employer confirms work has started. Stop the stream when either party " +
      "signals that the engagement has ended.",
    minParties: 2,
    suggestedEscrow: "100",
    partyRoles: ["Employer (0x…)", "Worker (0x…)"],
  },
  {
    id: "milestone-payout",
    icon: "◈",
    title: "Milestone Payout",
    explainer:
      "Releases escrow in proportional tranches as project milestones are individually confirmed. Each invocation with a milestone trigger commits a Transfer effect for that milestone's share. Unspent escrow is refunded at the end.",
    text:
      "Divide the escrow into three equal milestone payments. Release one third of the escrow to " +
      "the contractor when the client confirms each milestone (milestone-1, milestone-2, milestone-3). " +
      "Refund any remaining escrow to the client if the project is cancelled.",
    minParties: 2,
    suggestedEscrow: "30",
    partyRoles: ["Client (0x…)", "Contractor (0x…)"],
  },
  {
    id: "mutual-aid-pool",
    icon: "⬡",
    title: "Mutual-Aid Pool",
    explainer:
      "Members fund a shared escrow pool. Any member can invoke the contract with a 'request aid' trigger; the group votes by quorum and the AI commits a Transfer to the member in need or an Abort if consensus is not reached.",
    text:
      "This is a mutual-aid pool. Any member may request assistance by invoking with a trigger " +
      "describing their need and the requested amount. Approve and transfer the requested amount from " +
      "the pool escrow to the requesting member if a simple majority of declared members confirms the " +
      "request is valid. Abort and keep the funds in pool if less than majority approves.",
    minParties: 3,
    suggestedEscrow: "50",
    partyRoles: ["Member 1 (0x…)", "Member 2 (0x…)", "Member 3 (0x…)"],
  },
  {
    id: "bounty",
    icon: "◉",
    title: "Bounty",
    explainer:
      "Pays a claimant from escrow when the work is verified. The poster funds the escrow; any claimant can invoke with a 'claim bounty' trigger describing their work. The AI verifies the claim against the contract text and commits a Transfer or Abort.",
    text:
      "Pay the claimant the full escrow amount when they submit proof of completing the specified " +
      "task via a 'claim bounty' trigger. The AI will verify that the submitted work matches the " +
      "bounty requirements before committing the transfer. Abort and hold the escrow if the work " +
      "does not meet the requirements.",
    minParties: 1,
    suggestedEscrow: "25",
    partyRoles: ["Bounty Poster (0x…)"],
  },
  {
    id: "split-payment",
    icon: "⊞",
    title: "Split Payment",
    explainer:
      "Divides the escrow among several parties by pre-set shares when a 'release splits' trigger is received. The AI reads the share proportions from the contract text and commits multiple Transfer ops in one effect.",
    text:
      "Split the escrow among the listed parties in equal shares when the payer invokes with a " +
      "'release splits' trigger. Each party receives an equal portion of the escrow balance at the " +
      "time of invocation. If the payer invokes with a 'cancel' trigger, refund the full escrow to " +
      "the original depositor.",
    minParties: 3,
    suggestedEscrow: "15",
    partyRoles: ["Payer (0x…)", "Recipient A (0x…)", "Recipient B (0x…)"],
  },
];

// ---- Helpers -----------------------------------------------------------------------

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

function shortHash(h: string): string {
  if (!h || h.length < 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-6)}`;
}

function hexToUbi(hex: string, frac = 4): string {
  try { return formatUbi(BigInt(hex), frac); }
  catch { return "0.0000 UBI"; }
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
          Mock AI active — contract interpretation is stubbed
        </div>
        <div style={{ fontSize: "0.77rem", color: "var(--muted)", lineHeight: 1.55 }}>
          Your node is running a deterministic mock AI. Proof-of-humanity verdicts and
          contract interpretation are pre-scripted (the MockInterpreter always commits a
          deterministic effect). To use real AI, configure a local Ollama model or a cloud
          API key in{" "}
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

// ---- Exec Case Op Renderer --------------------------------------------------------

function OpLine({ op }: { op: ContractOp }) {
  return (
    <div
      style={{
        fontFamily: "var(--mono)",
        fontSize: "0.75rem",
        color: "var(--muted)",
        paddingLeft: "0.75rem",
        marginTop: "0.2rem",
        display: "flex",
        alignItems: "center",
        gap: "0.5rem",
      }}
    >
      <span style={{ color: "var(--faint)" }}>—</span>
      {op.type === "Transfer" && (
        <span>
          <span style={{ color: "var(--accent-2)", fontWeight: 600 }}>Transfer</span>{" "}
          {hexToUbi(op.amount)} → {short(op.to)}
        </span>
      )}
      {op.type === "Refund" && (
        <span>
          <span style={{ color: "var(--warn)", fontWeight: 600 }}>Refund</span>{" "}
          {hexToUbi(op.amount)} → {short(op.party)}
        </span>
      )}
      {op.type === "OpenStream" && (
        <span>
          <span style={{ color: "var(--accent)", fontWeight: 600 }}>OpenStream</span>{" "}
          → {short(op.to)}, deposit {hexToUbi(op.deposit)}
        </span>
      )}
      {op.type === "StopStream" && (
        <span>
          <span style={{ color: "var(--warn)", fontWeight: 600 }}>StopStream</span> #{op.id}
        </span>
      )}
      {op.type === "SetVar" && (
        <span>
          <span style={{ color: "var(--faint)", fontWeight: 600 }}>SetVar</span>{" "}
          {op.key} = {op.value}
        </span>
      )}
      {op.type === "Abort" && (
        <span style={{ color: "var(--danger)" }}>
          <span style={{ fontWeight: 600 }}>Abort</span> reason:{" "}
          {op.reason_hash.slice(0, 14)}…
        </span>
      )}
    </div>
  );
}

// ---- Exec Case Row ---------------------------------------------------------------

function ExecCaseRow({
  execCase,
  onOpenBlock,
}: {
  execCase: ExecCaseSummary;
  onOpenBlock?: (n: number) => void;
}) {
  const label = execStatusLabel(execCase.status);
  const pillCls =
    execCase.status.type === "Committed"
      ? "pill active"
      : execCase.status.type === "Aborted"
        ? "pill stopped"
        : "pill poh-pending";

  return (
    <div
      style={{
        background: "var(--glass-2)",
        border: "1px solid var(--line)",
        borderRadius: "10px",
        padding: "0.65rem 0.85rem",
        marginTop: "0.5rem",
        fontSize: "0.82rem",
      }}
    >
      <div className="row" style={{ marginBottom: "0.25rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span className="muted small" style={{ fontFamily: "var(--mono)" }}>
            Case #{execCase.id}
          </span>
          <span className={pillCls}>{label}</span>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
          {execCase.opened_at != null && (
            <span
              className="muted small"
              style={{ fontFamily: "var(--mono)", cursor: onOpenBlock ? "pointer" : "default", color: "var(--accent)" }}
              onClick={() => onOpenBlock?.(execCase.opened_at)}
              title={onOpenBlock ? "Open block in Explorer" : undefined}
            >
              opened #{execCase.opened_at}
            </span>
          )}
          {execCase.resolved_at != null && (
            <span
              className="muted small"
              style={{ fontFamily: "var(--mono)", cursor: onOpenBlock ? "pointer" : "default", color: "var(--accent)" }}
              onClick={() => onOpenBlock?.(execCase.resolved_at!)}
              title={onOpenBlock ? "Open block in Explorer" : undefined}
            >
              resolved #{execCase.resolved_at}
            </span>
          )}
        </div>
      </div>
      <div className="muted small" style={{ marginBottom: "0.15rem" }}>
        Invoker: <span style={{ fontFamily: "var(--mono)", color: "var(--ink)" }}>{short(execCase.invoker)}</span>
      </div>
      {execCase.status.type === "Committed" && execCase.status.effect.ops.length > 0 && (
        <div style={{ marginTop: "0.35rem" }}>
          <div className="muted small" style={{ marginBottom: "0.1rem" }}>Effect ops:</div>
          {execCase.status.effect.ops.map((op, i) => (
            <OpLine key={i} op={op} />
          ))}
        </div>
      )}
      {execCase.status.type === "Aborted" && (
        <div
          className="small"
          style={{ marginTop: "0.25rem", color: "var(--danger)", fontSize: "0.75rem" }}
        >
          Effect aborted — no state change (fail-closed, I4).
        </div>
      )}
    </div>
  );
}

// ---- Contract Detail View --------------------------------------------------------

interface ContractDetailProps {
  contractId: number;
  account: string;
  injected: Injected | null;
  onBack: () => void;
  onOpenBlock?: (n: number) => void;
  onOpenTx?: (hash: string) => void;
}

function ContractDetail({
  contractId,
  account,
  injected,
  onBack,
  onOpenBlock,
  onOpenTx,
}: ContractDetailProps) {
  const [contract, setContract] = useState<ContractView | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  const [fundAmount, setFundAmount] = useState("1");
  const [trigger, setTrigger] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const c = await reader.getContract(contractId);
      setContract(c);
      setErr(null);
    } catch (e) {
      setErr(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [contractId]);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const connect = useCallback(async () => {
    if (!injected) return;
    try {
      setConnected(await requestFrom(injected, account));
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected, account]);

  const fund = useCallback(async () => {
    if (!contract) return;
    setBusy("fund");
    setNote(null);
    try {
      const value = parseUbiToBaseUnits(fundAmount || "0");
      if (value <= 0n) throw new Error("Amount must be > 0");
      const data = encodeFundContract(contract.id);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendContractTx({ data, from, provider: injected as never, value })
        : await sendContractTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL, value });
      setNote({ kind: "ok", text: `fundContract sent · ${res.hash.slice(0, 14)}…` });
      setTimeout(load, 2500);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [contract, fundAmount, injected, account, load]);

  const invoke = useCallback(async () => {
    if (!contract) return;
    setBusy("invoke");
    setNote(null);
    try {
      const triggerRef = deriveTriggerRef(trigger || "default-trigger");
      const data = encodeInvokeContract(contract.id, triggerRef);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendContractTx({ data, from, provider: injected as never })
        : await sendContractTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setNote({ kind: "ok", text: `invokeContract sent · ${res.hash.slice(0, 14)}…` });
      setTrigger("");
      setTimeout(load, 3000);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [contract, trigger, injected, account, load]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  if (loading) {
    return (
      <section className="card">
        <div className="row" style={{ marginBottom: "1rem" }}>
          <button className="ghost" onClick={onBack}>Back</button>
        </div>
        <p className="muted small">Loading contract…</p>
      </section>
    );
  }

  if (!contract) {
    return (
      <section className="card">
        <div className="row" style={{ marginBottom: "1rem" }}>
          <button className="ghost" onClick={onBack}>Back</button>
        </div>
        <p className="muted small">{err ?? `Contract #${contractId} not found.`}</p>
      </section>
    );
  }

  const statusCls = contract.status === "Active" ? "pill active" : "pill stopped";
  const escrowBig = (() => { try { return BigInt(contract.escrow); } catch { return 0n; } })();

  return (
    <>
      {/* Header */}
      <section className="card">
        <div className="row" style={{ marginBottom: "1rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <button className="ghost" onClick={onBack}>Back</button>
            <span className="block-num" style={{ fontSize: "1rem" }}>
              Contract #{contract.id}
            </span>
            <span className={statusCls}>{contractStatusLabel(contract.status)}</span>
          </div>
        </div>

        {/* Plain-language text */}
        <div className="contract-text-box" style={{ marginBottom: "1rem" }}>
          {contract.text || <i>No text stored</i>}
        </div>

        {/* Core fields */}
        <dl className="kv" style={{ marginBottom: "1rem" }}>
          <dt>Deploy block</dt>
          <dd>
            <span
              style={{
                fontFamily: "var(--mono)",
                color: "var(--accent)",
                cursor: onOpenBlock ? "pointer" : "default",
                textDecoration: onOpenBlock ? "underline" : "none",
              }}
              onClick={() => onOpenBlock?.(contract.deploy_block)}
              title={onOpenBlock ? "Open in Explorer" : undefined}
            >
              #{contract.deploy_block}
            </span>
          </dd>
          <dt>Deploy tx</dt>
          <dd>
            <span
              style={{
                fontFamily: "var(--mono)",
                fontSize: "0.75rem",
                color: "var(--muted)",
                cursor: onOpenTx ? "pointer" : "default",
                textDecoration: onOpenTx ? "underline" : "none",
                wordBreak: "break-all",
              }}
              onClick={() => onOpenTx?.(contract.deploy_tx)}
              title={onOpenTx ? "Open in Explorer" : undefined}
            >
              {shortHash(contract.deploy_tx)}
            </span>
          </dd>
          <dt>Escrow balance</dt>
          <dd style={{ color: escrowBig > 0n ? "var(--accent)" : "var(--muted)" }}>
            {hexToUbi(contract.escrow)}
          </dd>
          <dt>Escrow address</dt>
          <dd style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
            {contract.escrow_address}
          </dd>
          <dt>Parties ({contract.parties.length})</dt>
          <dd style={{ fontSize: "0.78rem" }}>
            {contract.parties.length > 0
              ? contract.parties.map(short).join(", ")
              : "—"}
          </dd>
          <dt>Text ref</dt>
          <dd style={{ fontSize: "0.72rem", color: "var(--faint)", wordBreak: "break-all" }}>
            {contract.text_ref}
          </dd>
        </dl>

        {/* Contract-local vars */}
        {contract.vars && contract.vars.length > 0 && (
          <div style={{ marginBottom: "1rem" }}>
            <div className="label" style={{ marginBottom: "0.4rem" }}>Contract vars</div>
            {contract.vars.map((v, i) => (
              <div
                key={i}
                style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--muted)", marginBottom: "0.15rem" }}
              >
                <span style={{ color: "var(--faint)" }}>{v.key}</span> ={" "}
                <span style={{ color: "var(--ink)" }}>{v.value}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Exec cases timeline */}
      {contract.cases && contract.cases.length > 0 && (
        <section className="card">
          <div className="row" style={{ marginBottom: "0.75rem" }}>
            <h2 style={{ margin: 0 }}>Execution history ({contract.cases.length})</h2>
          </div>
          {contract.cases.map((c) => (
            <ExecCaseRow
              key={c.id}
              execCase={c}
              onOpenBlock={onOpenBlock}
            />
          ))}
        </section>
      )}

      {contract.cases && contract.cases.length === 0 && (
        <section className="card">
          <h2>Execution history</h2>
          <p className="muted small">No invocations yet — use the form below to invoke the contract.</p>
        </section>
      )}

      {/* Interact (Active only) */}
      {contract.status === "Active" && (
        <section className="card">
          <h2>Interact</h2>
          <div className="muted small" style={{ marginBottom: "0.85rem", lineHeight: 1.55 }}>
            Fund the escrow to give the contract buying power, then invoke it with a plain-language
            trigger describing what happened. The AI interprets the trigger against the contract text
            and commits a deterministic effect (Transfer / Refund / OpenStream / Abort).
          </div>

          {/* Fund */}
          <div className="field">
            <label>Fund escrow (UBI amount)</label>
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <input
                style={{ width: "8rem", fontFamily: "var(--mono)" }}
                placeholder="e.g. 10"
                value={fundAmount}
                onChange={(e) => setFundAmount(e.target.value)}
              />
              <button className="ghost" onClick={fund} disabled={busy === "fund"}>
                {busy === "fund" ? "Funding…" : "Fund escrow"}
              </button>
            </div>
          </div>

          {/* Invoke */}
          <div className="field">
            <label>Invoke trigger (plain language)</label>
            <textarea
              rows={2}
              style={{
                background: "rgba(10,12,18,.6)",
                border: "1px solid var(--line-2)",
                borderRadius: "10px",
                color: "var(--ink)",
                fontFamily: "ui-sans-serif, system-ui, sans-serif",
                fontSize: "0.88rem",
                padding: "0.6rem 0.75rem",
                outline: "none",
                resize: "vertical",
                lineHeight: "1.5",
                width: "100%",
                boxSizing: "border-box",
              }}
              placeholder='e.g. "Both parties confirm delivery is complete" or "milestone-1 completed"'
              value={trigger}
              onChange={(e) => setTrigger(e.target.value)}
            />
          </div>

          <button
            className="primary violet"
            onClick={invoke}
            disabled={busy === "invoke"}
            style={{ marginBottom: "0.5rem" }}
          >
            {busy === "invoke" ? "Invoking…" : "Invoke contract"}
          </button>

          <div className="signer">
            target <b>{short(CONTRACT_HUB)}</b> · signing with <b>{signerLabel}</b>
            {injected && !connected && (
              <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
                Connect MetaMask
              </button>
            )}
          </div>

          {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
        </section>
      )}
    </>
  );
}

// ---- Template Card ---------------------------------------------------------------

function TemplateCard({
  template,
  onSelect,
}: {
  template: ContractTemplate;
  onSelect: (t: ContractTemplate) => void;
}) {
  return (
    <div
      onClick={() => onSelect(template)}
      style={{
        background: "var(--glass)",
        border: "1px solid var(--line)",
        borderRadius: "12px",
        padding: "1rem 1.1rem",
        cursor: "pointer",
        transition: "border-color .15s, background .15s",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "rgba(139,123,255,.4)";
        e.currentTarget.style.background = "rgba(139,123,255,.05)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--line)";
        e.currentTarget.style.background = "var(--glass)";
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: "0.65rem", marginBottom: "0.5rem" }}>
        <span
          style={{
            fontSize: "1.25rem",
            color: "var(--accent-2)",
            lineHeight: 1,
            marginTop: "0.05rem",
            flexShrink: 0,
          }}
        >
          {template.icon}
        </span>
        <div>
          <div style={{ fontWeight: 700, fontSize: "0.88rem", color: "var(--ink)", marginBottom: "0.2rem" }}>
            {template.title}
          </div>
          <div style={{ fontSize: "0.76rem", color: "var(--muted)", lineHeight: 1.5 }}>
            {template.explainer}
          </div>
        </div>
      </div>
      <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.6rem", flexWrap: "wrap" }}>
        <span className="tag violet" style={{ fontSize: "0.62rem" }}>
          {template.minParties}+ parties
        </span>
        <span className="tag warn" style={{ fontSize: "0.62rem" }}>
          ~{template.suggestedEscrow} UBI escrow
        </span>
      </div>
    </div>
  );
}

// ---- Template Library -----------------------------------------------------------

function TemplateLibrary({ onSelect }: { onSelect: (t: ContractTemplate) => void }) {
  return (
    <section className="card">
      <h2>Template library</h2>
      <div
        style={{
          fontSize: "0.8rem",
          color: "var(--muted)",
          marginBottom: "1rem",
          lineHeight: 1.55,
        }}
      >
        Choose a starter template or write from scratch below. Each template includes plain-language
        text that the AI interprets into a deterministic effect (Transfer / Refund / OpenStream /
        Abort) when you invoke the contract with a trigger.
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
          gap: "0.75rem",
        }}
      >
        {TEMPLATES.map((t) => (
          <TemplateCard key={t.id} template={t} onSelect={onSelect} />
        ))}
      </div>
    </section>
  );
}

// ---- Deploy step indicator -------------------------------------------------------

function StepDot({ n, active, done }: { n: number; active: boolean; done: boolean }) {
  const bg = done
    ? "var(--accent)"
    : active
      ? "var(--accent-2)"
      : "var(--glass-2)";
  return (
    <div
      style={{
        width: "1.5rem",
        height: "1.5rem",
        borderRadius: "50%",
        background: bg,
        border: `1px solid ${done ? "var(--accent)" : active ? "rgba(139,123,255,.5)" : "var(--line)"}`,
        color: done || active ? "#07080c" : "var(--faint)",
        display: "grid",
        placeItems: "center",
        fontSize: "0.7rem",
        fontWeight: 700,
        flexShrink: 0,
        boxShadow: active ? "0 0 10px rgba(139,123,255,.35)" : "none",
      }}
    >
      {done ? "✓" : n}
    </div>
  );
}

// ---- (Legacy AuthoringForm removed — AuthoringFormWithTemplates is the current impl) ---

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _Noop({ account, injected, onDeployed }: {
  account: string;
  injected: Injected | null;
  onDeployed: (id: number) => void;
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [connected, setConnected] = useState<string | null>(null);

  // Step 1: template / text
  const [selectedTemplate, setSelectedTemplate] = useState<ContractTemplate | null>(null);
  const [contractText, setContractText] = useState("");

  // Step 2: parties + escrow
  const [partiesInput, setPartiesInput] = useState("");
  const [escrowAmount, setEscrowAmount] = useState("0");

  // Step 3: deploy
  const [deploying, setDeploying] = useState(false);
  const [deployNote, setDeployNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [deployedId, setDeployedId] = useState<number | null>(null);

  const loadTemplate = useCallback((t: ContractTemplate) => {
    setSelectedTemplate(t);
    setContractText(t.text);
    setPartiesInput(t.partyRoles.join(", "));
    setEscrowAmount(t.suggestedEscrow);
    setStep(1);
  }, []);

  const clearTemplate = useCallback(() => {
    setSelectedTemplate(null);
    setContractText("");
    setPartiesInput("");
    setEscrowAmount("0");
  }, []);

  const parseParties = (): string[] => {
    return partiesInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => /^0x[0-9a-fA-F]{40}$/.test(s));
  };

  const validateStep1 = (): string | null => {
    if (!contractText.trim()) return "Contract text is required.";
    if (contractText.trim().length < 20)
      return "Contract text should be at least 20 characters of plain language.";
    return null;
  };

  const validateStep2 = (): string | null => {
    if (partiesInput.trim()) {
      const parties = parseParties();
      const raw = partiesInput.split(",").map((s) => s.trim()).filter(Boolean);
      if (raw.length > 0 && parties.length === 0)
        return "Parties must be valid 0x addresses (42 chars). Clear the field to use your address as the sole party.";
    }
    return null;
  };

  const connect = useCallback(async () => {
    if (!injected) {
      setDeployNote({ kind: "err", text: "No injected wallet — install MetaMask." });
      return;
    }
    try {
      setConnected(await requestFrom(injected, account));
      setDeployNote(null);
    } catch (e) {
      setDeployNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected, account]);

  const deploy = useCallback(async () => {
    setDeploying(true);
    setDeployNote(null);
    try {
      const parties = parseParties();
      const effectiveParties = parties.length > 0 ? parties : [account];
      const data = encodeDeployContract(contractText, effectiveParties);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendContractTx({ data, from, provider: injected as never })
        : await sendContractTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });

      setDeployNote({
        kind: "ok",
        text: `deployContract sent · ${res.hash.slice(0, 14)}… — polling for contract id…`,
      });

      // Poll for the newly-deployed contract in the account's list
      let found = false;
      for (let attempt = 0; attempt < 12 && !found; attempt++) {
        await new Promise((r) => setTimeout(r, 1500));
        try {
          const cs = await reader.getContractsOf(account);
          if (cs.length > 0) {
            const latest = cs[cs.length - 1];
            setDeployedId(latest.id);
            setDeployNote({
              kind: "ok",
              text: `Contract #${latest.id} deployed · tx ${res.hash.slice(0, 14)}…`,
            });
            onDeployed(latest.id);
            found = true;
          }
        } catch { /* ignore */ }
      }
      if (!found) {
        setDeployNote({ kind: "ok", text: `Tx sent · ${res.hash.slice(0, 14)}… — check My Contracts below` });
      }
      setStep(3);
    } catch (e) {
      setDeployNote({ kind: "err", text: errMessage(e) });
    } finally {
      setDeploying(false);
    }
  }, [contractText, partiesInput, escrowAmount, account, injected, onDeployed]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  const TRANSFER_FEE = "0.0000 UBI (gas 200000 × 0 gwei on devnet)";

  return (
    <section className="card">
      {/* Step indicator */}
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1.25rem" }}>
        {([1, 2, 3] as const).map((n) => (
          <div key={n} style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <StepDot n={n} active={step === n} done={step > n || (step === 3 && !!deployedId)} />
            <span
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                color:
                  step === n ? "var(--ink)" : step > n ? "var(--muted)" : "var(--faint)",
              }}
            >
              {n === 1 ? "Contract text" : n === 2 ? "Parties & escrow" : "Deploy"}
            </span>
            {n < 3 && (
              <span style={{ color: "var(--line-2)", fontSize: "0.7rem", marginLeft: "0.25rem" }}>
                →
              </span>
            )}
          </div>
        ))}
      </div>

      {/* Step 1: text */}
      {step === 1 && (
        <>
          <h2>Author your contract</h2>

          {selectedTemplate && (
            <div
              style={{
                background: "rgba(139,123,255,.08)",
                border: "1px solid rgba(139,123,255,.25)",
                borderRadius: "10px",
                padding: "0.65rem 0.85rem",
                marginBottom: "0.85rem",
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
              }}
            >
              <span style={{ fontSize: "1rem", color: "var(--accent-2)" }}>{selectedTemplate.icon}</span>
              <span style={{ fontSize: "0.82rem", color: "var(--ink)", fontWeight: 600 }}>
                {selectedTemplate.title}
              </span>
              <button
                className="ghost"
                style={{ marginLeft: "auto", fontSize: "0.7rem" }}
                onClick={clearTemplate}
              >
                Clear template
              </button>
            </div>
          )}

          <div className="field">
            <label>Contract text (plain language)</label>
            <textarea
              rows={6}
              value={contractText}
              onChange={(e) => setContractText(e.target.value)}
              style={{
                background: "rgba(10,12,18,.6)",
                border: "1px solid var(--line-2)",
                borderRadius: "10px",
                color: "var(--ink)",
                fontFamily: "ui-sans-serif, system-ui, sans-serif",
                fontSize: "0.9rem",
                padding: "0.65rem 0.8rem",
                outline: "none",
                resize: "vertical",
                lineHeight: "1.6",
                width: "100%",
                boxSizing: "border-box",
              }}
              placeholder="Describe the agreement in plain English. The AI will interpret this text when the contract is invoked with a trigger and commit a deterministic effect (Transfer, Refund, OpenStream, or Abort)."
            />
          </div>

          <div className="muted small" style={{ marginBottom: "0.85rem", lineHeight: 1.55 }}>
            The full text is stored on-chain for transparency. When you invoke the contract with a
            trigger, the AI interprets the trigger against this text and commits an effect agreed by
            quorum. The mock AI on the devnet commits a deterministic stub effect.
          </div>

          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              className="primary"
              onClick={() => {
                const e = validateStep1();
                if (e) { setDeployNote({ kind: "err", text: e }); return; }
                setDeployNote(null);
                setStep(2);
              }}
            >
              Next: Set parties
            </button>
            {contractText && (
              <button className="ghost" onClick={clearTemplate}>
                Reset
              </button>
            )}
          </div>
          {deployNote && <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>}
        </>
      )}

      {/* Step 2: parties + escrow */}
      {step === 2 && (
        <>
          <h2>Parties and escrow</h2>

          <div className="field">
            <label>
              Parties (comma-separated 0x addresses)
              <span style={{ color: "var(--faint)", textTransform: "none", letterSpacing: 0, marginLeft: "0.4rem" }}>
                optional — defaults to your address
              </span>
            </label>
            <input
              placeholder={
                selectedTemplate
                  ? selectedTemplate.partyRoles.join(", ")
                  : `${account} (defaults to you)`
              }
              value={partiesInput}
              onChange={(e) => setPartiesInput(e.target.value)}
              spellCheck={false}
            />
          </div>

          {selectedTemplate && (
            <div className="muted small" style={{ marginBottom: "0.85rem" }}>
              Roles: {selectedTemplate.partyRoles.join(" · ")}
            </div>
          )}

          <div className="field">
            <label>
              Initial escrow (UBI to fund on deploy)
              <span style={{ color: "var(--faint)", textTransform: "none", letterSpacing: 0, marginLeft: "0.4rem" }}>
                optional — you can fund after deploy too
              </span>
            </label>
            <input
              placeholder="0 (fund later)"
              value={escrowAmount}
              onChange={(e) => setEscrowAmount(e.target.value)}
            />
          </div>

          <div className="muted small" style={{ marginBottom: "0.85rem", lineHeight: 1.55 }}>
            Deploy fee: <span style={{ fontFamily: "var(--mono)", color: "var(--warn)" }}>{TRANSFER_FEE}</span>
          </div>

          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="ghost" onClick={() => { setStep(1); setDeployNote(null); }}>
              Back
            </button>
            <button
              className="primary violet"
              onClick={() => {
                const e = validateStep2();
                if (e) { setDeployNote({ kind: "err", text: e }); return; }
                setDeployNote(null);
                setStep(3);
              }}
            >
              Next: Review
            </button>
          </div>
          {deployNote && <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>}
        </>
      )}

      {/* Step 3: review + deploy */}
      {step === 3 && (
        <>
          <h2>Review and deploy</h2>

          {!deployedId && (
            <>
              <div
                style={{
                  background: "var(--glass-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "10px",
                  padding: "0.85rem 1rem",
                  marginBottom: "1rem",
                }}
              >
                <div className="label" style={{ marginBottom: "0.6rem" }}>Contract text</div>
                <div style={{ fontSize: "0.84rem", color: "var(--muted)", lineHeight: 1.55 }}>
                  {contractText}
                </div>
              </div>

              <dl className="kv" style={{ marginBottom: "1rem" }}>
                <dt>Parties</dt>
                <dd style={{ fontSize: "0.78rem" }}>
                  {parseParties().length > 0
                    ? parseParties().map(short).join(", ")
                    : `${short(account)} (you)`}
                </dd>
                <dt>Initial escrow</dt>
                <dd>{escrowAmount || "0"} UBI</dd>
                <dt>Hub target</dt>
                <dd style={{ fontSize: "0.75rem" }}>{CONTRACT_HUB}</dd>
                <dt>Signer</dt>
                <dd>{signerLabel}</dd>
              </dl>

              <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                <button className="ghost" onClick={() => { setStep(2); setDeployNote(null); }}>
                  Back
                </button>
                <button
                  className="primary violet"
                  onClick={deploy}
                  disabled={deploying}
                >
                  {deploying ? "Deploying…" : "Deploy contract"}
                </button>
              </div>

              <div className="signer">
                signing with <b>{signerLabel}</b>
                {injected && !connected && (
                  <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
                    Connect MetaMask
                  </button>
                )}
              </div>
            </>
          )}

          {deployedId != null && (
            <div
              style={{
                background: "rgba(79,231,168,.06)",
                border: "1px solid rgba(79,231,168,.25)",
                borderRadius: "10px",
                padding: "1rem 1.1rem",
                marginBottom: "1rem",
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
              }}
            >
              <span style={{ fontSize: "1.3rem" }}>✓</span>
              <div>
                <div style={{ fontWeight: 700, color: "var(--accent)", marginBottom: "0.2rem" }}>
                  Contract #{deployedId} deployed
                </div>
                <div className="muted small">
                  View it in My Contracts below, or open its detail view to fund and invoke it.
                </div>
              </div>
            </div>
          )}

          {deployNote && <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>}

          <button
            className="ghost"
            style={{ marginTop: "0.5rem" }}
            onClick={() => {
              setStep(1);
              setSelectedTemplate(null);
              setContractText("");
              setPartiesInput("");
              setEscrowAmount("0");
              setDeployNote(null);
              setDeployedId(null);
            }}
          >
            Deploy another
          </button>
        </>
      )}
    </section>
  );
}

// ---- Contract List Card ---------------------------------------------------------

function ContractListCard({
  contract,
  onOpen,
}: {
  contract: ContractView;
  onOpen: (id: number) => void;
}) {
  const statusCls = contract.status === "Active" ? "pill active" : "pill stopped";
  const escrowBig = (() => { try { return BigInt(contract.escrow); } catch { return 0n; } })();

  return (
    <div
      style={{
        border: "1px solid var(--line)",
        borderRadius: "12px",
        padding: "0.85rem 1rem",
        marginBottom: "0.75rem",
        background: "var(--glass)",
        cursor: "pointer",
        transition: "border-color .15s, background .15s",
      }}
      onClick={() => onOpen(contract.id)}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "rgba(139,123,255,.35)";
        e.currentTarget.style.background = "rgba(139,123,255,.04)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--line)";
        e.currentTarget.style.background = "var(--glass)";
      }}
    >
      <div className="row" style={{ marginBottom: "0.45rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <span className="block-num">#{contract.id}</span>
          <span className={statusCls}>{contractStatusLabel(contract.status)}</span>
          {contract.cases && contract.cases.length > 0 && (
            <span className="pill violet" style={{ fontSize: "0.58rem" }}>
              {contract.cases.length} case{contract.cases.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        <span className="muted small" style={{ fontSize: "0.72rem", fontFamily: "var(--mono)" }}>
          block #{contract.deploy_block}
        </span>
      </div>
      <div
        style={{
          fontSize: "0.8rem",
          color: "var(--muted)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          marginBottom: "0.35rem",
        }}
      >
        {contract.text || "(no text)"}
      </div>
      <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
        <span className="muted small" style={{ fontSize: "0.72rem" }}>
          escrow{" "}
          <span style={{ color: escrowBig > 0n ? "var(--accent)" : "var(--faint)", fontFamily: "var(--mono)" }}>
            {hexToUbi(contract.escrow)}
          </span>
        </span>
        <span className="muted small" style={{ fontSize: "0.72rem" }}>
          {contract.parties.length} {contract.parties.length === 1 ? "party" : "parties"}
        </span>
      </div>
    </div>
  );
}

// ---- Main Contracts Component ---------------------------------------------------

export function Contracts({
  account,
  onOpenExplorerBlock,
  onOpenExplorerTx,
  onSettings,
}: {
  account: string;
  onOpenExplorerBlock?: (n: number) => void;
  onOpenExplorerTx?: (hash: string) => void;
  onSettings?: () => void;
}) {
  const [contracts, setContracts] = useState<ContractView[]>([]);
  const [injected, setInjected] = useState<Injected | null>(null);
  const [isMockAi, setIsMockAi] = useState<boolean | null>(null);
  const [detailId, setDetailId] = useState<number | null>(null);

  const pollRef = useRef<() => void>(() => {});

  useEffect(() => setInjected(getInjected()), []);

  const refresh = useCallback(async () => {
    try {
      const cs = await reader.getContractsOf(account);
      setContracts(cs);
    } catch { /* node may be down */ }
  }, [account]);

  const checkOracle = useCallback(async () => {
    try {
      const cfg = await oracle.getConfig();
      setIsMockAi(cfg.active === "mock");
    } catch {
      // If oracle check fails (non-loopback), assume mock
      setIsMockAi(true);
    }
  }, []);

  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    checkOracle();
    const id = setInterval(() => pollRef.current(), 4000);
    return () => clearInterval(id);
  }, [refresh, checkOracle]);

  // If we're in detail view, show it
  if (detailId !== null) {
    return (
      <ContractDetail
        contractId={detailId}
        account={account}
        injected={injected}
        onBack={() => { setDetailId(null); refresh(); }}
        onOpenBlock={onOpenExplorerBlock}
        onOpenTx={onOpenExplorerTx}
      />
    );
  }

  return (
    <>
      {/* Mock AI banner */}
      {isMockAi && <MockAiBanner onSettings={onSettings} />}

      {/* Section header */}
      <section className="card">
        <h2 style={{ margin: 0 }}>Prompt contracts</h2>
        <div className="muted small" style={{ marginTop: "0.3rem", lineHeight: 1.5 }}>
          Plain-language agreements interpreted by AI into deterministic on-chain effects.
          Browse the template library in the authoring form below.
        </div>
      </section>

      {/* Authoring form */}
      <AuthoringFormWithTemplates
        account={account}
        injected={injected}
        onDeployed={(id) => {
          setDetailId(id);
          refresh();
        }}
      />

      {/* My contracts */}
      <section className="card">
        <h2>My contracts ({contracts.length})</h2>
        {contracts.length === 0 ? (
          <p className="muted small">
            No contracts yet. Browse the template library above or write a contract from scratch.
          </p>
        ) : (
          contracts.map((c) => (
            <ContractListCard
              key={c.id}
              contract={c}
              onOpen={(id) => setDetailId(id)}
            />
          ))
        )}
      </section>
    </>
  );
}

// ---- Authoring form with template integration -----------------------------------

function AuthoringFormWithTemplates({
  account,
  injected,
  onDeployed,
}: {
  account: string;
  injected: Injected | null;
  onDeployed: (id: number) => void;
}) {
  const [selectedTemplate, setSelectedTemplate] = useState<ContractTemplate | null>(null);
  const [showLib, setShowLib] = useState(false);
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [connected, setConnected] = useState<string | null>(null);

  const [contractText, setContractText] = useState("");
  const [partiesInput, setPartiesInput] = useState("");
  const [escrowAmount, setEscrowAmount] = useState("0");

  const [deploying, setDeploying] = useState(false);
  const [deployNote, setDeployNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [deployedId, setDeployedId] = useState<number | null>(null);

  const loadTemplate = useCallback((t: ContractTemplate) => {
    setSelectedTemplate(t);
    setContractText(t.text);
    setPartiesInput(t.partyRoles.join(", "));
    setEscrowAmount(t.suggestedEscrow);
    setShowLib(false);
    setStep(1);
  }, []);

  const parseParties = (): string[] =>
    partiesInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => /^0x[0-9a-fA-F]{40}$/.test(s));

  const connect = useCallback(async () => {
    if (!injected) { setDeployNote({ kind: "err", text: "No injected wallet — install MetaMask." }); return; }
    try {
      setConnected(await requestFrom(injected, account));
      setDeployNote(null);
    } catch (e) {
      setDeployNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected, account]);

  const deploy = useCallback(async () => {
    setDeploying(true);
    setDeployNote(null);
    try {
      const parties = parseParties();
      const effectiveParties = parties.length > 0 ? parties : [account];
      const data = encodeDeployContract(contractText, effectiveParties);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendContractTx({ data, from, provider: injected as never })
        : await sendContractTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });

      setDeployNote({ kind: "ok", text: `Tx sent · ${res.hash.slice(0, 14)}… — polling for contract…` });

      let found = false;
      for (let attempt = 0; attempt < 12 && !found; attempt++) {
        await new Promise((r) => setTimeout(r, 1500));
        try {
          const cs = await reader.getContractsOf(account);
          if (cs.length > 0) {
            const latest = cs[cs.length - 1];
            setDeployedId(latest.id);
            setDeployNote({ kind: "ok", text: `Contract #${latest.id} deployed · tx ${res.hash.slice(0, 14)}…` });
            onDeployed(latest.id);
            found = true;
          }
        } catch { /* ignore */ }
      }
      if (!found) {
        setDeployNote({ kind: "ok", text: `Tx sent · ${res.hash.slice(0, 14)}… — see My Contracts below` });
        onDeployed(-1);
      }
      setStep(3);
    } catch (e) {
      setDeployNote({ kind: "err", text: errMessage(e) });
    } finally {
      setDeploying(false);
    }
  }, [contractText, partiesInput, account, injected, onDeployed]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  const reset = () => {
    setStep(1);
    setSelectedTemplate(null);
    setContractText("");
    setPartiesInput("");
    setEscrowAmount("0");
    setDeployNote(null);
    setDeployedId(null);
  };

  return (
    <>
      {/* Template library */}
      {showLib && (
        <section className="card" style={{ border: "1px solid rgba(139,123,255,.3)" }}>
          <div className="row" style={{ marginBottom: "0.85rem" }}>
            <h2 style={{ margin: 0 }}>Template library</h2>
            <button className="ghost" onClick={() => setShowLib(false)}>Close</button>
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
              gap: "0.65rem",
            }}
          >
            {TEMPLATES.map((t) => (
              <TemplateCard key={t.id} template={t} onSelect={loadTemplate} />
            ))}
          </div>
        </section>
      )}

      {/* Authoring form */}
      <section className="card">
        {/* Step indicator */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1.25rem", flexWrap: "wrap" }}>
          {([1, 2, 3] as const).map((n) => (
            <div key={n} style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <StepDot
                n={n}
                active={step === n}
                done={n < step || (step === 3 && !!deployedId)}
              />
              <span
                style={{
                  fontSize: "0.73rem",
                  fontWeight: 600,
                  color: step === n ? "var(--ink)" : step > n ? "var(--muted)" : "var(--faint)",
                }}
              >
                {n === 1 ? "Write" : n === 2 ? "Configure" : "Deploy"}
              </span>
              {n < 3 && <span style={{ color: "var(--line-2)", fontSize: "0.65rem" }}>—</span>}
            </div>
          ))}
        </div>

        {/* Step 1: Contract text */}
        {step === 1 && (
          <>
            <div className="row" style={{ marginBottom: "0.85rem" }}>
              <h2 style={{ margin: 0 }}>Write your contract</h2>
              <button
                className="ghost"
                style={{ fontSize: "0.75rem" }}
                onClick={() => setShowLib(!showLib)}
              >
                {showLib ? "Hide templates" : "Browse templates"}
              </button>
            </div>

            {selectedTemplate && (
              <div
                style={{
                  background: "rgba(139,123,255,.08)",
                  border: "1px solid rgba(139,123,255,.22)",
                  borderRadius: "9px",
                  padding: "0.6rem 0.85rem",
                  marginBottom: "0.85rem",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                }}
              >
                <span style={{ color: "var(--accent-2)", fontSize: "0.95rem" }}>
                  {selectedTemplate.icon}
                </span>
                <span style={{ fontSize: "0.8rem", color: "var(--ink)", fontWeight: 600 }}>
                  {selectedTemplate.title}
                </span>
                <button
                  className="ghost"
                  style={{ marginLeft: "auto", fontSize: "0.68rem" }}
                  onClick={() => { setSelectedTemplate(null); setContractText(""); setPartiesInput(""); setEscrowAmount("0"); }}
                >
                  Clear
                </button>
              </div>
            )}

            <div className="field">
              <label>Contract text (plain language)</label>
              <textarea
                rows={6}
                value={contractText}
                onChange={(e) => setContractText(e.target.value)}
                style={{
                  background: "rgba(10,12,18,.6)",
                  border: "1px solid var(--line-2)",
                  borderRadius: "10px",
                  color: "var(--ink)",
                  fontFamily: "ui-sans-serif, system-ui, sans-serif",
                  fontSize: "0.9rem",
                  padding: "0.65rem 0.8rem",
                  outline: "none",
                  resize: "vertical",
                  lineHeight: "1.6",
                  width: "100%",
                  boxSizing: "border-box",
                  transition: "border-color .15s",
                }}
                placeholder="Describe the agreement in plain English. The AI interprets this text when the contract is invoked with a trigger and commits an effect (Transfer / Refund / OpenStream / Abort) by quorum."
              />
            </div>

            <div className="muted small" style={{ marginBottom: "0.85rem", lineHeight: 1.55 }}>
              The full text is stored on-chain for transparency and reproducibility. Choose a
              template above to get started quickly, or write your own.
            </div>

            <button
              className="primary"
              onClick={() => {
                if (!contractText.trim() || contractText.trim().length < 10) {
                  setDeployNote({ kind: "err", text: "Contract text must be at least 10 characters." });
                  return;
                }
                setDeployNote(null);
                setStep(2);
              }}
            >
              Next: Configure parties
            </button>
            {deployNote && <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>}
          </>
        )}

        {/* Step 2: Parties + escrow */}
        {step === 2 && (
          <>
            <h2>Configure parties and escrow</h2>

            <div className="field">
              <label>
                Parties (comma-separated 0x addresses)
                <span style={{ color: "var(--faint)", textTransform: "none", letterSpacing: 0, marginLeft: "0.4em" }}>
                  optional
                </span>
              </label>
              <input
                placeholder={
                  selectedTemplate
                    ? selectedTemplate.partyRoles.join(", ")
                    : `defaults to ${short(account)}`
                }
                value={partiesInput}
                onChange={(e) => setPartiesInput(e.target.value)}
                spellCheck={false}
              />
            </div>

            {selectedTemplate && (
              <div className="muted small" style={{ marginBottom: "0.85rem" }}>
                Expected roles: {selectedTemplate.partyRoles.join(" · ")}
              </div>
            )}

            <div className="field">
              <label>
                Initial escrow (UBI)
                <span style={{ color: "var(--faint)", textTransform: "none", letterSpacing: 0, marginLeft: "0.4em" }}>
                  can fund after deploy too
                </span>
              </label>
              <input
                placeholder="0"
                value={escrowAmount}
                onChange={(e) => setEscrowAmount(e.target.value)}
              />
            </div>

            <div className="muted small" style={{ marginBottom: "0.85rem" }}>
              Deploy gas: <span style={{ fontFamily: "var(--mono)", color: "var(--warn)" }}>0 UBI (devnet)</span>
            </div>

            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button className="ghost" onClick={() => { setStep(1); setDeployNote(null); }}>
                Back
              </button>
              <button
                className="primary violet"
                onClick={() => {
                  const raw = partiesInput.split(",").map((s) => s.trim()).filter(Boolean);
                  const valid = parseParties();
                  if (raw.length > 0 && valid.length === 0) {
                    setDeployNote({ kind: "err", text: "Parties must be valid 0x addresses or leave field empty." });
                    return;
                  }
                  setDeployNote(null);
                  setStep(3);
                }}
              >
                Next: Review & deploy
              </button>
            </div>
            {deployNote && <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>}
          </>
        )}

        {/* Step 3: Review + deploy */}
        {step === 3 && (
          <>
            <h2>Review and deploy</h2>

            {!deployedId && (
              <>
                <div
                  style={{
                    background: "var(--glass-2)",
                    border: "1px solid var(--line)",
                    borderRadius: "10px",
                    padding: "0.85rem 1rem",
                    marginBottom: "1rem",
                  }}
                >
                  <div className="label" style={{ marginBottom: "0.5rem" }}>Contract text</div>
                  <div style={{ fontSize: "0.84rem", color: "var(--muted)", lineHeight: 1.55 }}>
                    {contractText}
                  </div>
                </div>

                <dl className="kv" style={{ marginBottom: "1rem" }}>
                  <dt>Parties</dt>
                  <dd style={{ fontSize: "0.78rem" }}>
                    {parseParties().length > 0
                      ? parseParties().map(short).join(", ")
                      : `${short(account)} (you)`}
                  </dd>
                  <dt>Initial escrow</dt>
                  <dd>{escrowAmount || "0"} UBI (fund after deploy if not specified)</dd>
                  <dt>Hub target</dt>
                  <dd style={{ fontSize: "0.73rem" }}>{CONTRACT_HUB}</dd>
                </dl>

                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                  <button className="ghost" onClick={() => { setStep(2); setDeployNote(null); }}>
                    Back
                  </button>
                  <button
                    className="primary violet"
                    onClick={deploy}
                    disabled={deploying}
                  >
                    {deploying ? "Deploying…" : "Deploy contract"}
                  </button>
                </div>

                <div className="signer">
                  signing with <b>{signerLabel}</b>
                  {injected && !connected && (
                    <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
                      Connect MetaMask
                    </button>
                  )}
                </div>
              </>
            )}

            {deployedId != null && deployedId >= 0 && (
              <div
                style={{
                  background: "rgba(79,231,168,.06)",
                  border: "1px solid rgba(79,231,168,.28)",
                  borderRadius: "10px",
                  padding: "0.9rem 1.1rem",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.75rem",
                  marginBottom: "0.75rem",
                }}
              >
                <span style={{ fontSize: "1.2rem" }}>✓</span>
                <div>
                  <div style={{ fontWeight: 700, color: "var(--accent)", marginBottom: "0.2rem" }}>
                    Contract #{deployedId} deployed — opening detail view…
                  </div>
                  <div className="muted small">Navigating to the contract detail view.</div>
                </div>
              </div>
            )}

            {deployNote && <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>}

            <button className="ghost" style={{ marginTop: "0.5rem" }} onClick={reset}>
              Deploy another
            </button>
          </>
        )}
      </section>
    </>
  );
}

// Export for Explorer integration — open contract detail from a ContractHub tx
export { ContractDetail };
export type { ContractDetailProps };
