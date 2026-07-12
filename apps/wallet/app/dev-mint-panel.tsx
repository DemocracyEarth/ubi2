"use client";

/**
 * M6 Stage C1 — "Dev mint (mock)" (spec 06b §5/§6.3, devnet-only).
 *
 * THE PROBLEM THIS FIXES: the raw C0 synthetic fixture served by `/api/self-dev-fixture`
 * (`crates/zkpoh/fixtures/self_synthetic_public.json`) carries ARBITRARY de-risk values for the
 * runtime's policy-bound public-signal slots (scope@19=999, user_identifier@20=12345,
 * current_date@10..16=501..506, merkle_root@9=111) — values that exercise the C0 crypto crate's
 * ARITY (21-signal shape), not the C1 runtime's on-chain BINDING checks
 * (`submit_zk_passport_proof`, `crates/runtime/src/lifecycle.rs`). Submitting that fixture as-is
 * to a devnet is rejected at the FIRST binding check (`WrongScope`) — no human is ever minted, so
 * the "Use dev fixture" path below exercises the parse→encode→submit plumbing but never the mint.
 *
 * THIS PANEL: builds a BINDING-CORRECT 21-signal vector via `@ubi2/sdk`'s
 * `buildDevMockSubmission` — it reads the LIVE accepted Self identity + OFAC roots from
 * `ubi_getSelfRoots` (never hardcodes the devnet seed), encodes TODAY as the six YYMMDD signals
 * the exact way the runtime decodes them, and binds `scope`/`user_identifier` to the exact values
 * `submit_zk_passport_proof` checks (spec 06b §4.4). The devnet's `MockZkVerifier` — the consensus
 * default (`crates/runtime::MockZkVerifier`) — never inspects proof bytes, so this mints a REAL
 * on-chain `Verified`/`ENH` (or `DUAL`, if the address was already Std-verified) human record.
 *
 * **THIS IS A MOCK MINT, NOT PROOF OF HUMANITY.** It demonstrates the mint mechanics only. It must
 * never be reachable against a real Groth16 verifier (a separate, opt-in, non-default code path).
 */

import { useCallback, useEffect, useState } from "react";
import {
  Ubi2Client,
  ZkPassportReader,
  sendZkPassportProof,
  encodeDevMockSubmission,
  type HumanRecord,
} from "@ubi2/sdk";
import { RPC_URL, DEV_PRIVATE_KEY } from "./config";

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

interface DevMintPanelProps {
  account: string;
  human: HumanRecord | null;
  onSuccess: () => void;
}

export function DevMintPanel({ account, human, onSuccess }: DevMintPanelProps) {
  const [injected, setInjected] = useState<Injected | null>(null);
  const [connected, setConnected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  useEffect(() => setInjected(getInjected()), []);

  const isAlreadyEnhanced = human?.assurance === "ENH" || human?.assurance === "DUAL";
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

  const mint = useCallback(async () => {
    setBusy(true);
    setNote(null);
    try {
      // Read the LIVE accepted Self roots (never hardcoded — a governance repin stays correct).
      const roots = await zkReader.getSelfRoots();
      const { data, nullifier } = encodeDevMockSubmission(effectiveAddress, roots);

      const res = injected
        ? await sendZkPassportProof({
            data,
            from: effectiveAddress,
            provider: injected as Parameters<typeof sendZkPassportProof>[0]["provider"],
          })
        : await sendZkPassportProof({ data, privateKey: DEV_PRIVATE_KEY, rpcUrl: RPC_URL });

      setNote({
        kind: "ok",
        text: `Dev mint submitted · tx ${res.hash.slice(0, 14)}… · nullifier ${nullifier.slice(0, 14)}… · waiting for confirmation…`,
      });
      setTimeout(onSuccess, 3000);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    } finally {
      setBusy(false);
    }
  }, [effectiveAddress, injected, onSuccess]);

  if (isAlreadyEnhanced) return null;

  return (
    <div
      style={{
        marginTop: "0.9rem",
        padding: "0.75rem 0.9rem",
        background: "rgba(251,191,92,.06)",
        border: "1px dashed rgba(251,191,92,.45)",
        borderRadius: "10px",
      }}
    >
      <div
        style={{
          fontSize: "0.74rem",
          fontWeight: 700,
          letterSpacing: "0.06em",
          color: "var(--warn)",
          marginBottom: "0.35rem",
        }}
      >
        DEV MINT (MOCK) — devnet only, bypasses real passport verification
      </div>
      <div style={{ fontSize: "0.74rem", color: "var(--muted)", lineHeight: 1.55, marginBottom: "0.65rem" }}>
        Builds a public-signal vector that satisfies every on-chain binding this devnet checks
        (scope, submitter address, freshness, Self identity + OFAC roots — read live from{" "}
        <code>ubi_getSelfRoots</code>) with an inert proof. Because this devnet&apos;s consensus
        verifier is <code>MockZkVerifier</code> (it never inspects proof bytes), this produces a
        real on-chain mint — but <b>proves nothing about you being a real, unique human</b>. It
        exists to demonstrate the mint mechanics without a live Self phone flow.
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
        <button
          className="ghost"
          style={{ fontSize: "0.74rem", padding: "0.3rem 0.85rem", borderColor: "var(--warn)", color: "var(--warn)" }}
          onClick={mint}
          disabled={busy}
        >
          {busy ? "Minting…" : "Dev mint (mock)"}
        </button>
        <span className="signer" style={{ fontSize: "0.72rem" }}>
          signing with{" "}
          <b>{connected ? `MetaMask · ${short(connected)}` : injected ? "MetaMask (not connected)" : `dev account · ${short(account)}`}</b>
        </span>
        {injected && !connected && (
          <button className="ghost" style={{ fontSize: "0.72rem", padding: "0.25rem 0.6rem" }} onClick={connect}>
            Connect MetaMask
          </button>
        )}
      </div>
      {note && <div className={`notice ${note.kind}`} style={{ marginTop: "0.6rem" }}>{note.text}</div>}
    </div>
  );
}
