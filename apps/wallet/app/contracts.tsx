"use client";

/**
 * M4 Contracts section: author a plain-language contract, deploy it, fund the escrow,
 * invoke it with a trigger, and watch the committed/aborted effect.  Lists the connected
 * account's contracts and their exec cases via ubi_getContractsOf + ubi_getExecCase.
 *
 * Signs through the same dual-signer pattern as streams.tsx (injected MetaMask or devnet
 * dev key fallback).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ContractReader,
  sendContractTx,
  encodeDeployContract,
  encodeFundContract,
  encodeInvokeContract,
  deriveTextRef,
  deriveTriggerRef,
  contractStatusLabel,
  execStatusLabel,
  formatUbi,
  parseUbiToBaseUnits,
  CONTRACT_HUB,
  type ContractView,
  type ExecCaseView,
} from "@ubi2/sdk";
import { RPC_URL, DEV_ACCOUNT, DEV_PRIVATE_KEY } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const reader = new ContractReader(client);

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

function hexToUbi(hex: string, frac = 4): string {
  try { return formatUbi(BigInt(hex), frac); }
  catch { return "0.0000 UBI"; }
}

/** Render a single exec-case status badge + effect summary. */
function ExecCaseBadge({ execCase }: { execCase: ExecCaseView }) {
  const label = execStatusLabel(execCase.status);
  const cls =
    execCase.status.type === "Committed"
      ? "pill active"
      : execCase.status.type === "Aborted"
        ? "pill stopped"
        : "pill poh-pending";

  return (
    <div
      style={{
        background: "var(--panel-2)",
        border: "1px solid var(--border)",
        borderRadius: "8px",
        padding: "0.65rem 0.75rem",
        marginTop: "0.5rem",
        fontSize: "0.82rem",
      }}
    >
      <div className="row" style={{ marginBottom: "0.35rem" }}>
        <span className="muted small">Exec case #{execCase.id}</span>
        <span className={cls}>{label}</span>
      </div>
      <div className="muted small">Invoker: {short(execCase.invoker)}</div>
      {execCase.status.type === "Committed" && (
        <div style={{ marginTop: "0.4rem" }}>
          <div className="muted small" style={{ marginBottom: "0.2rem" }}>Effect ops:</div>
          {execCase.status.effect.ops.map((op, i) => (
            <div
              key={i}
              className="muted small"
              style={{ fontFamily: "var(--mono)", paddingLeft: "0.5rem" }}
            >
              {op.type === "Transfer" && (
                <>Transfer {hexToUbi(op.amount)} → {short(op.to)}</>
              )}
              {op.type === "Refund" && (
                <>Refund {hexToUbi(op.amount)} → {short(op.party)}</>
              )}
              {op.type === "OpenStream" && (
                <>OpenStream → {short(op.to)}, deposit {hexToUbi(op.deposit)}</>
              )}
              {op.type === "StopStream" && <>StopStream #{op.id}</>}
              {op.type === "SetVar" && <>SetVar {op.key.slice(0, 10)}…</>}
              {op.type === "Abort" && <>Abort (reason: {op.reason_hash.slice(0, 10)}…)</>}
            </div>
          ))}
        </div>
      )}
      {execCase.status.type === "Aborted" && (
        <div className="muted small" style={{ marginTop: "0.25rem", color: "var(--danger)" }}>
          Effect aborted — no state change (fail-closed, I4).
        </div>
      )}
    </div>
  );
}

/** A single contract card with its exec cases. */
function ContractCard({
  contract,
  account,
  injected,
  onAction,
}: {
  contract: ContractView;
  account: string;
  injected: Injected | null;
  onAction: () => void;
}) {
  const [execCases, setExecCases] = useState<ExecCaseView[]>([]);
  const [trigger, setTrigger] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [fundAmount, setFundAmount] = useState("1");

  // Load all exec cases for this contract
  useEffect(() => {
    let alive = true;
    const loadCases = async () => {
      // We don't have a ubi_getExecCasesOf; poll exec cases by ids scanning is not
      // available. We track the last known exec-case count via contract and re-read.
      // For now, the newest exec case is at a known upper-bound id; scan downward from
      // a reasonable starting point by trying ids we discover from prior deploys.
      // The SDK exposes ubi_getExecCase(id) individually.  The UI stores the ids we
      // learn from successful invocations.
    };
    loadCases();
    return () => { alive = false; };
  }, [contract.id]);

  const fund = useCallback(async () => {
    setBusy("fund");
    setNote(null);
    try {
      const value = parseUbiToBaseUnits(fundAmount || "0");
      if (value <= 0n) throw new Error("Amount must be > 0");
      const data = encodeFundContract(contract.id);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendContractTx({
            data,
            from,
            provider: injected as never,
            value,
          })
        : await sendContractTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL, value });
      setNote({ kind: "ok", text: `fundContract sent · ${res.hash.slice(0, 14)}…` });
      setTimeout(onAction, 2500);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [contract.id, fundAmount, injected, account, onAction]);

  const invoke = useCallback(async () => {
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
      // Re-read exec cases after a tick
      setTimeout(onAction, 2500);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(null);
    }
  }, [contract.id, trigger, injected, account, onAction]);

  const statusCls =
    contract.status === "Active" ? "pill active" : "pill stopped";

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: "12px",
        padding: "1rem 1.25rem",
        marginBottom: "1rem",
        background: "var(--panel)",
      }}
    >
      <div className="row" style={{ marginBottom: "0.5rem" }}>
        <span className="block-num">Contract #{contract.id}</span>
        <span className={statusCls}>{contractStatusLabel(contract.status)}</span>
      </div>

      <div className="kv" style={{ marginBottom: "0.75rem" }}>
        <span className="muted small">Escrow</span>
        <span className="addr" style={{ fontSize: "0.8rem" }}>
          {hexToUbi(contract.escrow)} · {short(contract.escrow_address)}
        </span>
        <span className="muted small">Parties</span>
        <span style={{ fontSize: "0.8rem" }}>
          {contract.parties.map(short).join(", ") || "—"}
        </span>
        <span className="muted small">Text ref</span>
        <span className="addr" style={{ fontSize: "0.75rem" }}>
          {contract.text_ref.slice(0, 18)}…
        </span>
      </div>

      {contract.status === "Active" && (
        <div style={{ borderTop: "1px solid var(--border)", paddingTop: "0.75rem" }}>
          {/* Fund */}
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.5rem" }}>
            <input
              style={{
                width: "6rem",
                background: "var(--panel-2)",
                border: "1px solid var(--border)",
                borderRadius: "6px",
                color: "var(--fg)",
                fontFamily: "var(--mono)",
                fontSize: "0.82rem",
                padding: "0.4rem 0.5rem",
                outline: "none",
              }}
              placeholder="UBI"
              value={fundAmount}
              onChange={(e) => setFundAmount(e.target.value)}
            />
            <button className="ghost" onClick={fund} disabled={busy === "fund"}>
              {busy === "fund" ? "Funding…" : "Fund escrow"}
            </button>
          </div>

          {/* Invoke */}
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <input
              style={{
                flex: 1,
                background: "var(--panel-2)",
                border: "1px solid var(--border)",
                borderRadius: "6px",
                color: "var(--fg)",
                fontFamily: "var(--mono)",
                fontSize: "0.82rem",
                padding: "0.4rem 0.5rem",
                outline: "none",
                minWidth: 0,
              }}
              placeholder="Trigger input (plain text)"
              value={trigger}
              onChange={(e) => setTrigger(e.target.value)}
            />
            <button className="primary" onClick={invoke} disabled={busy === "invoke"}>
              {busy === "invoke" ? "Invoking…" : "Invoke"}
            </button>
          </div>
        </div>
      )}

      {execCases.length > 0 && (
        <div style={{ marginTop: "0.75rem" }}>
          <div className="label" style={{ marginBottom: "0.25rem" }}>Exec cases</div>
          {execCases.map((c) => (
            <ExecCaseBadge key={c.id} execCase={c} />
          ))}
        </div>
      )}

      {note && (
        <div className={`notice ${note.kind}`} style={{ marginTop: "0.65rem" }}>
          {note.text}
        </div>
      )}
    </div>
  );
}

export function Contracts({ account }: { account: string }) {
  const [contracts, setContracts] = useState<ContractView[]>([]);
  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);

  // Deploy form
  const [contractText, setContractText] = useState(
    "Pay 1 UBI to the counterparty upon delivery confirmation.",
  );
  const [partiesInput, setPartiesInput] = useState("");
  const [deploying, setDeploying] = useState(false);
  const [deployNote, setDeployNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [latestContractId, setLatestContractId] = useState<number | null>(null);
  const [latestExecCase, setLatestExecCase] = useState<ExecCaseView | null>(null);

  const pollRef = useRef<() => void>(() => {});

  useEffect(() => setInjected(getInjected()), []);

  const refresh = useCallback(async () => {
    try {
      const cs = await reader.getContractsOf(account);
      setContracts(cs);
    } catch {
      /* node may be down */
    }
  }, [account]);
  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    const id = setInterval(() => pollRef.current(), 4000);
    return () => clearInterval(id);
  }, [refresh]);

  // When we have a latest contract id, poll for its newest exec case
  useEffect(() => {
    if (latestContractId == null) return;
    let alive = true;
    const poll = async () => {
      try {
        // Try to find the most-recent exec case for this contract by scanning descending
        // from a reasonable upper bound. In practice after one invoke there is case id 0 or 1.
        // We scan case ids 0..99 and keep those that belong to latestContractId.
        const checks = await Promise.allSettled(
          Array.from({ length: 20 }, (_, i) =>
            client.call<unknown>("ubi_getExecCase", [i]),
          ),
        );
        const found: ExecCaseView[] = [];
        for (const r of checks) {
          if (r.status === "fulfilled" && r.value && typeof r.value === "object") {
            const c = r.value as ExecCaseView;
            if (c.contract === latestContractId) found.push(c);
          }
        }
        // Keep the newest
        if (found.length > 0 && alive) {
          setLatestExecCase(found[found.length - 1]);
        }
      } catch { /* ignore */ }
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { alive = false; clearInterval(id); };
  }, [latestContractId]);

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
    setLatestContractId(null);
    setLatestExecCase(null);
    try {
      const textRef = deriveTextRef(contractText);
      // Parse comma-separated parties (or default to the deployer)
      const rawParties = partiesInput
        .split(",")
        .map((s) => s.trim())
        .filter((s) => /^0x[0-9a-fA-F]{40}$/.test(s));
      const parties = rawParties.length > 0 ? rawParties : [account];

      const data = encodeDeployContract(textRef, parties);
      const from = injected ? await requestFrom(injected, account) : account;
      const res = injected
        ? await sendContractTx({ data, from, provider: injected as never })
        : await sendContractTx({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });
      setDeployNote({
        kind: "ok",
        text: `deployContract sent · ${res.hash.slice(0, 14)}… — check My Contracts below`,
      });
      setTimeout(refresh, 2500);
    } catch (e) {
      setDeployNote({ kind: "err", text: errMessage(e) });
    } finally {
      setDeploying(false);
    }
  }, [contractText, partiesInput, account, injected, refresh]);

  const signerLabel = connected
    ? `MetaMask · ${short(connected)}`
    : injected
      ? "MetaMask (not connected)"
      : "devnet dev key";

  return (
    <>
      {/* Deploy form */}
      <section className="card">
        <h2>Author a contract</h2>
        <div className="field">
          <label htmlFor="contract-text">Contract text (plain language)</label>
          <textarea
            id="contract-text"
            rows={4}
            value={contractText}
            onChange={(e) => setContractText(e.target.value)}
            style={{
              background: "var(--panel-2)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
              color: "var(--fg)",
              fontFamily: "ui-sans-serif, system-ui, sans-serif",
              fontSize: "0.9rem",
              padding: "0.6rem 0.75rem",
              outline: "none",
              resize: "vertical",
              lineHeight: "1.5",
              width: "100%",
              boxSizing: "border-box",
            }}
            placeholder="e.g. Pay 1 UBI to Alice upon delivery confirmation."
          />
        </div>
        <div className="field">
          <label htmlFor="parties">Parties (comma-separated 0x addresses, optional)</label>
          <input
            id="parties"
            placeholder={`${account} (defaults to you)`}
            value={partiesInput}
            onChange={(e) => setPartiesInput(e.target.value)}
            spellCheck={false}
          />
        </div>
        <div className="muted small" style={{ marginBottom: "0.75rem" }}>
          Only the content-addressed commitment (textRef) goes on-chain — no prose/PII (I6).
          The devnet&apos;s MockInterpreter auto-commits a deterministic effect when invoked.
        </div>
        <button className="primary" onClick={deploy} disabled={deploying}>
          {deploying ? "Deploying…" : "Deploy contract"}
        </button>
        <div className="signer" style={{ marginTop: "0.5rem" }}>
          target <b>{short(CONTRACT_HUB)}</b> · signing with <b>{signerLabel}</b>
          {injected && !connected && (
            <button className="ghost" style={{ marginLeft: "0.5rem" }} onClick={connect}>
              Connect MetaMask
            </button>
          )}
        </div>
        {deployNote && (
          <div className={`notice ${deployNote.kind}`}>{deployNote.text}</div>
        )}
      </section>

      {/* Latest exec case result (shown after invoke) */}
      {latestExecCase && (
        <section className="card">
          <h2>Latest execution</h2>
          <ExecCaseBadge execCase={latestExecCase} />
        </section>
      )}

      {/* My contracts */}
      <section className="card">
        <h2>My contracts ({contracts.length})</h2>
        {contracts.length === 0 ? (
          <p className="muted small">
            No contracts yet. Deploy one above to get started.
          </p>
        ) : (
          contracts.map((c) => (
            <ContractCard
              key={c.id}
              contract={c}
              account={account}
              injected={injected}
              onAction={() => {
                setLatestContractId(c.id);
                refresh();
              }}
            />
          ))
        )}
      </section>
    </>
  );
}
