"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  IndexedDbCredentialVaultStore,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED,
  addPasskeyKeySlot,
  createPasskeyProtectedCredentialVault,
  generateCredentialVaultBackupKey,
  inspectIndexedDbCredentialVaultStore,
  transformCredentialVaultPayload,
  unlockCredentialVault,
  zkHolderCredentialVaultSha256,
  type PortableCredentialVault,
} from "@ubi2/sdk";
import type { Address } from "viem";
import { SELF_ENV, V2_HOLDER_VAULT_TESTNET_ENABLED } from "./config";
import {
  HOLDER_VAULT_BINDING_SCHEMA,
  HOLDER_VAULT_PRODUCT_PRODUCTION_APPROVED,
  HolderVaultSessionBoundary,
  createHolderVaultPayload,
  createHolderVaultRecoveryPackage,
  decodeHolderVaultRecoveryKey,
  encodeHolderVaultRecoveryKey,
  holderVaultBinding,
  holderVaultDatabaseName,
  holderVaultFeatureGate,
  parseHolderVaultPayload,
  parseHolderVaultRecoveryPackage,
} from "./lib/holder-vault-product";
import {
  enrollWebAuthnPrfPasskey,
  inspectWebAuthnPrfCapabilities,
  unlockWithWebAuthnPrf,
  type WebAuthnPrfCapabilities,
} from "./lib/webauthn-prf";

export interface HolderVaultTarget {
  chainId: number;
  name: string;
  network: "local" | "testnet" | "mainnet";
  /** Canonical public voucher/contract binding. It is hashed before entering the encrypted payload. */
  proofBinding: string | null;
}

export function HolderVaultPanel(props: {
  account: Address;
  verificationSession: string;
  target: HolderVaultTarget;
}): React.ReactNode {
  const gate = holderVaultFeatureGate({
    publicFlag: V2_HOLDER_VAULT_TESTNET_ENABLED ? "true" : "false",
    selfEnvironment: SELF_ENV,
    chainNetwork: props.target.network,
  });
  if (!gate.visible) return null;
  return <EnabledHolderVaultPanel {...props} actionAllowed={gate.actionAllowed} gateReason={gate.reason} />;
}

type VaultPhase = "loading" | "empty" | "locked" | "unlocked";
type BusyAction = "enroll" | "unlock" | "add-passkey" | "bind-proof" | "backup" | "restore";

function EnabledHolderVaultPanel(props: {
  account: Address;
  verificationSession: string;
  target: HolderVaultTarget;
  actionAllowed: boolean;
  gateReason: string;
}) {
  const rpId = typeof location === "undefined" ? "invalid.local" : location.hostname;
  const [phase, setPhase] = useState<VaultPhase>("loading");
  const [vault, setVault] = useState<PortableCredentialVault | null>(null);
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "warn" | "err"; text: string } | null>(null);
  const [capabilities, setCapabilities] = useState<WebAuthnPrfCapabilities | null>(null);
  const [recoveryKey, setRecoveryKey] = useState("");
  const [restoreKey, setRestoreKey] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [summary, setSummary] = useState<{ chainId: number; proofBound: boolean } | null>(null);
  const storeRef = useRef<IndexedDbCredentialVaultStore | null>(null);
  const databaseNameRef = useRef<string | null>(null);
  const recoveryKeyRef = useRef("");
  const busyActionRef = useRef<BusyAction | null>(null);
  const operationGenerationRef = useRef(0);
  const sessionBinding = useMemo(
    () => `${props.account.toLowerCase()}:${props.verificationSession}:${props.target.chainId}:${props.target.proofBinding ?? "unbound"}`,
    [props.account, props.target.chainId, props.target.proofBinding, props.verificationSession],
  );
  const boundaryRef = useRef<HolderVaultSessionBoundary | null>(null);
  if (boundaryRef.current === null) boundaryRef.current = new HolderVaultSessionBoundary(sessionBinding);

  const clearUnlockedState = useCallback(() => {
    setSummary(null);
    setPhase((current) => current === "empty" || current === "loading" ? current : "locked");
    recoveryKeyRef.current = "";
    setRecoveryKey("");
  }, []);

  useEffect(() => {
    operationGenerationRef.current += 1;
    busyActionRef.current = null;
    setBusy(null);
    boundaryRef.current?.rotate(sessionBinding);
    clearUnlockedState();
  }, [clearUnlockedState, sessionBinding]);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    let opened: IndexedDbCredentialVaultStore | undefined;
    setPhase("loading");
    setNotice(null);
    void (async () => {
      const databaseName = await holderVaultDatabaseName(props.account, rpId);
      databaseNameRef.current = databaseName;
      const metadata = await inspectIndexedDbCredentialVaultStore({ databaseName });
      if (disposed) return;
      if (!metadata) {
        setVault(null);
        setPhase("empty");
        return;
      }
      if (metadata.binding.schema !== HOLDER_VAULT_BINDING_SCHEMA || metadata.binding.rpId !== rpId) {
        throw new Error("The local vault has an unexpected site binding.");
      }
      opened = new IndexedDbCredentialVaultStore({
        databaseName,
        vaultId: metadata.vaultId,
        binding: metadata.binding,
      });
      storeRef.current?.close();
      storeRef.current = opened;
      const refresh = async () => {
        const current = await opened?.read();
        if (!disposed && current) {
          setVault(current);
          clearUnlockedState();
          setNotice({ kind: "warn", text: "Another tab updated this vault. It was re-read and relocked." });
        }
      };
      unsubscribe = opened.subscribe(() => { void refresh(); });
      const current = await opened.read();
      if (!disposed && current) {
        setVault(current);
        setPhase("locked");
      }
    })().catch((error) => {
      if (!disposed) {
        setPhase("empty");
        setNotice({ kind: "err", text: safeError(error) });
      }
    });
    return () => {
      disposed = true;
      unsubscribe?.();
      opened?.close();
      if (storeRef.current === opened) storeRef.current = null;
    };
  }, [clearUnlockedState, props.account, reloadToken, rpId]);

  useEffect(() => {
    void inspectWebAuthnPrfCapabilities().then(setCapabilities);
    return () => {
      operationGenerationRef.current += 1;
      busyActionRef.current = null;
      boundaryRef.current?.cancel();
      recoveryKeyRef.current = "";
    };
  }, []);

  const run = useCallback(async (action: BusyAction, operation: (signal: AbortSignal) => Promise<void>) => {
    if (busyActionRef.current !== null) return;
    busyActionRef.current = action;
    const generation = operationGenerationRef.current + 1;
    operationGenerationRef.current = generation;
    const signal = boundaryRef.current!.signal;
    setBusy(action);
    setNotice(null);
    try {
      await operation(signal);
      throwIfAborted(signal);
    } catch (error) {
      if (operationGenerationRef.current === generation) {
        setNotice({ kind: isAbort(error) ? "warn" : "err", text: isAbort(error) ? "Passkey operation canceled; the vault remains locked." : safeError(error) });
      }
    } finally {
      if (operationGenerationRef.current === generation) {
        busyActionRef.current = null;
        setBusy(null);
      }
    }
  }, []);

  const enroll = useCallback(() => run("enroll", async (signal) => {
    if (!props.actionAllowed) throw new Error(props.gateReason);
    if (!databaseNameRef.current) throw new Error("Vault storage is still loading.");
    const enrollment = await enrollWebAuthnPrfPasskey({ signal });
    throwIfAborted(signal);
    boundaryRef.current!.track(enrollment.prfOutput);
    try {
      const payload = await createHolderVaultPayload({
        account: props.account,
        verificationSession: props.verificationSession,
        testnetChainId: props.target.chainId,
        proofBinding: props.target.proofBinding,
      });
      const created = await createPasskeyProtectedCredentialVault(payload, holderVaultBinding(rpId), enrollment);
      throwIfAborted(signal);
      const store = new IndexedDbCredentialVaultStore({
        databaseName: databaseNameRef.current,
        vaultId: created.vaultId,
        binding: created.binding,
      });
      const initialized = await store.initialize(created);
      store.close();
      throwIfAborted(signal);
      if (!initialized) throw new Error("A vault was created in another tab. Reload and unlock that vault instead.");
      setVault(created);
      setPhase("locked");
      setNotice({ kind: "ok", text: "Passkey enrolled. The encrypted rehearsal vault is durable and locked." });
      setReloadToken((value) => value + 1);
    } finally {
      boundaryRef.current!.release(enrollment.prfOutput);
    }
  }), [props.account, props.actionAllowed, props.gateReason, props.target.chainId, props.target.proofBinding, props.verificationSession, rpId, run]);

  const unlock = useCallback(() => run("unlock", async (signal) => {
    const current = await requireCurrentVault(storeRef.current, vault);
    const unlockInput = await unlockWithWebAuthnPrf({ slots: current.keySlots, signal });
    throwIfAborted(signal);
    boundaryRef.current!.track(unlockInput.prfOutput);
    try {
      const payload = parseHolderVaultPayload(await unlockCredentialVault(current, unlockInput), props.account);
      throwIfAborted(signal);
      setSummary({ chainId: payload.testnetChainId, proofBound: payload.proofBindingSha256 !== null });
      setPhase("unlocked");
      setNotice({ kind: "ok", text: "Unlocked for this tab only. No PRF output or plaintext was persisted." });
    } finally {
      boundaryRef.current!.release(unlockInput.prfOutput);
    }
  }), [props.account, run, vault]);

  const addPasskey = useCallback(() => run("add-passkey", async (signal) => {
    const store = requireStore(storeRef.current);
    const current = await requireCurrentVault(store, vault);
    const digest = await zkHolderCredentialVaultSha256(current);
    const existingUnlock = await unlockWithWebAuthnPrf({ slots: current.keySlots, signal });
    throwIfAborted(signal);
    boundaryRef.current!.track(existingUnlock.prfOutput);
    let enrollment: Awaited<ReturnType<typeof enrollWebAuthnPrfPasskey>> | undefined;
    try {
      enrollment = await enrollWebAuthnPrfPasskey({
        excludeCredentialIds: current.keySlots.map(({ credentialId }) => credentialId),
        signal,
      });
      throwIfAborted(signal);
      boundaryRef.current!.track(enrollment.prfOutput);
      const replacement = await addPasskeyKeySlot(current, existingUnlock, enrollment);
      throwIfAborted(signal);
      if (!await store.compareAndSwap(digest, replacement)) throw new Error("Another tab updated the vault; no passkey was added.");
      throwIfAborted(signal);
      setVault(replacement);
      setPhase("locked");
      setSummary(null);
      setNotice({ kind: "ok", text: "A second passkey was added atomically. Unlock again to continue." });
    } finally {
      boundaryRef.current!.release(existingUnlock.prfOutput);
      if (enrollment) boundaryRef.current!.release(enrollment.prfOutput);
    }
  }), [run, vault]);

  const bindProof = useCallback(() => run("bind-proof", async (signal) => {
    if (!props.actionAllowed || !props.target.proofBinding) throw new Error("Complete a proof-bound testnet voucher first.");
    const store = requireStore(storeRef.current);
    const current = await requireCurrentVault(store, vault);
    const digest = await zkHolderCredentialVaultSha256(current);
    const unlockInput = await unlockWithWebAuthnPrf({ slots: current.keySlots, signal });
    throwIfAborted(signal);
    boundaryRef.current!.track(unlockInput.prfOutput);
    try {
      const payload = await createHolderVaultPayload({
        account: props.account,
        verificationSession: props.verificationSession,
        testnetChainId: props.target.chainId,
        proofBinding: props.target.proofBinding,
      });
      const transformed = await transformCredentialVaultPayload(current, unlockInput, (decrypted) => {
        parseHolderVaultPayload(decrypted, props.account);
        return { status: "updated", payload };
      });
      if (transformed.status !== "updated") throw new Error("The vault proof binding was not updated.");
      throwIfAborted(signal);
      if (!await store.compareAndSwap(digest, transformed.vault)) throw new Error("Another tab updated the vault; bind the proof again.");
      throwIfAborted(signal);
      setVault(transformed.vault);
      setPhase("locked");
      setSummary(null);
      setNotice({ kind: "ok", text: "The encrypted rehearsal payload is now bound to this testnet voucher." });
    } finally {
      boundaryRef.current!.release(unlockInput.prfOutput);
    }
  }), [props.account, props.actionAllowed, props.target.chainId, props.target.proofBinding, props.verificationSession, run, vault]);

  const backup = useCallback(() => run("backup", async (signal) => {
    const store = requireStore(storeRef.current);
    const current = await requireCurrentVault(store, vault);
    const key = boundaryRef.current!.track(generateCredentialVaultBackupKey());
    try {
      const encrypted = await store.exportEncryptedBackup(key);
      throwIfAborted(signal);
      const recoveryPackage = createHolderVaultRecoveryPackage({ account: props.account, vault: current, backup: encrypted });
      const serialized = `${JSON.stringify(recoveryPackage, null, 2)}\n`;
      const url = URL.createObjectURL(new Blob([serialized], { type: "application/json" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `poh-testnet-vault-${props.account.slice(2, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      const encoded = encodeHolderVaultRecoveryKey(key);
      recoveryKeyRef.current = encoded;
      setRecoveryKey(encoded);
      setNotice({ kind: "warn", text: "Encrypted backup downloaded. Store the one-time recovery key separately; an enrolled passkey is still required." });
    } finally {
      boundaryRef.current!.release(key);
    }
  }), [props.account, run, vault]);

  const restore = useCallback(() => run("restore", async (signal) => {
    if (!props.actionAllowed) throw new Error(props.gateReason);
    if (!restoreFile) throw new Error("Choose an encrypted recovery package.");
    if (restoreFile.size > 768 * 1024) throw new Error("The recovery package is too large.");
    if (!databaseNameRef.current) throw new Error("Vault storage is still loading.");
    if (vault || await storeRef.current?.read()) throw new Error("Restore is empty-only and cannot replace this device's vault.");
    const parsed = parseHolderVaultRecoveryPackage(JSON.parse(await restoreFile.text()) as unknown, {
      account: props.account,
      rpId,
    });
    const key = boundaryRef.current!.track(decodeHolderVaultRecoveryKey(restoreKey));
    throwIfAborted(signal);
    const store = new IndexedDbCredentialVaultStore({
      databaseName: databaseNameRef.current,
      vaultId: parsed.vaultId,
      binding: parsed.binding,
    });
    try {
      throwIfAborted(signal);
      const result = await store.restoreEncryptedBackup({ backup: parsed.backup, recoveryKey: key, mode: "empty-only" });
      throwIfAborted(signal);
      if (result !== "restored") throw new Error("A vault already exists on this device; restore did not overwrite it.");
    } finally {
      store.close();
      boundaryRef.current!.release(key);
    }
    setRestoreKey("");
    setRestoreFile(null);
    setNotice({ kind: "ok", text: "Encrypted vault restored. Use one of its enrolled passkeys to unlock it." });
    setReloadToken((value) => value + 1);
  }), [props.account, props.actionAllowed, props.gateReason, restoreFile, restoreKey, rpId, run, vault]);

  const cancel = useCallback(() => {
    operationGenerationRef.current += 1;
    busyActionRef.current = null;
    boundaryRef.current?.cancel();
    clearUnlockedState();
    setBusy(null);
    setNotice({ kind: "warn", text: "Operation canceled. In-memory key material was cleared and the vault is locked." });
  }, [clearUnlockedState]);

  const capabilityCopy = capabilities === null
    ? "checking passkey support…"
    : !capabilities.available
      ? "WebAuthn unavailable"
      : capabilities.prfClientHint === "supported"
        ? "WebAuthn PRF reported"
        : capabilities.prfClientHint === "unsupported"
          ? "PRF not reported; ceremony will verify"
          : "PRF capability unknown; ceremony will verify";

  return (
    <div className="step-row holder-vault-step" data-testid="holder-vault-panel">
      <div className="step-badge">4</div>
      <div className="step-body">
        <div className="account-privacy-head">
          <h4>Protect your private holder vault</h4>
          <span className="pill warn">testnet lab</span>
        </div>
        <p className="muted small">
          A passkey protects an encrypted rehearsal vault in this PWA. It stores no production passport payload,
          makes no production proof, and is available only while the staging flag and an explicit testnet are active.
        </p>
        <div className="holder-vault-gates" aria-label="Production admission gates">
          <span className="pill">audit admission: {ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED ? "open" : "closed"}</span>
          <span className="pill">product admission: {HOLDER_VAULT_PRODUCT_PRODUCTION_APPROVED ? "open" : "closed"}</span>
          <span className="pill">{capabilityCopy}</span>
        </div>
        <div className="kv holder-vault-status">
          <span className="k">Vault</span>
          <span data-testid="holder-vault-status">{phase}</span>
        </div>
        <div className="kv">
          <span className="k">Target</span>
          <span>{props.target.name} · {props.target.network}</span>
        </div>
        {vault && (
          <div className="kv">
            <span className="k">Passkeys</span>
            <span data-testid="holder-vault-passkey-count">{vault.keySlots.length}</span>
          </div>
        )}
        {summary && (
          <div className="notice ok" data-testid="holder-vault-unlocked-summary">
            Unlocked rehearsal for chain {summary.chainId}. Proof binding: {summary.proofBound ? "present" : "not added yet"}.
          </div>
        )}
        <div className="row holder-vault-actions">
          {phase === "empty" && (
            <button className="btn primary sm" type="button" onClick={enroll} disabled={busy !== null || !props.actionAllowed} data-testid="holder-vault-enroll">
              {busy === "enroll" ? "Enrolling passkey…" : "Enroll passkey & create vault"}
            </button>
          )}
          {vault && (
            <>
              <button className="btn primary sm" type="button" onClick={unlock} disabled={busy !== null} data-testid="holder-vault-unlock">
                {busy === "unlock" ? "Unlocking…" : "Unlock with passkey"}
              </button>
              <button className="btn ghost sm" type="button" onClick={addPasskey} disabled={busy !== null} data-testid="holder-vault-add-passkey">
                {busy === "add-passkey" ? "Adding passkey…" : "Add another passkey"}
              </button>
              <button className="btn ghost sm" type="button" onClick={backup} disabled={busy !== null} data-testid="holder-vault-backup">
                {busy === "backup" ? "Encrypting backup…" : "Download encrypted backup"}
              </button>
              {props.target.proofBinding && (
                <button className="btn ghost sm" type="button" onClick={bindProof} disabled={busy !== null || !props.actionAllowed}>
                  {busy === "bind-proof" ? "Binding proof…" : "Bind verified testnet voucher"}
                </button>
              )}
            </>
          )}
          {busy !== null && (
            <button className="btn ghost sm" type="button" onClick={cancel} data-testid="holder-vault-cancel">Cancel</button>
          )}
        </div>
        {recoveryKey && (
          <div className="holder-vault-recovery-key" data-testid="holder-vault-recovery-key">
            <b>One-time recovery key</b>
            <code>{recoveryKey}</code>
            <p className="muted small">Copy it only on a trusted device and keep it separate from the encrypted backup. It is never persisted by this app.</p>
            <div className="row">
              <button className="btn ghost sm" type="button" onClick={() => navigator.clipboard.writeText(recoveryKeyRef.current)}>Copy key</button>
              <button className="btn ghost sm" type="button" onClick={() => { recoveryKeyRef.current = ""; setRecoveryKey(""); }}>Hide key</button>
            </div>
          </div>
        )}
        {phase === "empty" && (
          <div className="holder-vault-restore" data-testid="holder-vault-restore">
            <b>Restore on an empty device profile</b>
            <p className="muted small">The package must match this account and site. Recovery never overwrites an existing vault and still requires an enrolled passkey.</p>
            <input type="file" accept="application/json,.json" onChange={(event) => setRestoreFile(event.target.files?.[0] ?? null)} data-testid="holder-vault-restore-file" />
            <input type="password" autoComplete="off" spellCheck={false} placeholder="Recovery key" value={restoreKey} onChange={(event) => setRestoreKey(event.target.value)} data-testid="holder-vault-restore-key" />
            <button className="btn ghost sm" type="button" onClick={restore} disabled={busy !== null || !restoreFile || !restoreKey} data-testid="holder-vault-restore-submit">
              {busy === "restore" ? "Restoring…" : "Restore encrypted vault"}
            </button>
          </div>
        )}
        {notice && <div className={`notice ${notice.kind}`} role="status" data-testid="holder-vault-notice">{notice.text}</div>}
      </div>
    </div>
  );
}

function requireStore(store: IndexedDbCredentialVaultStore | null): IndexedDbCredentialVaultStore {
  if (!store) throw new Error("The encrypted vault store is not ready.");
  return store;
}

async function requireCurrentVault(
  store: IndexedDbCredentialVaultStore | null,
  fallback: PortableCredentialVault | null,
): Promise<PortableCredentialVault> {
  const current = store ? await store.read() : fallback;
  if (!current) throw new Error("The encrypted vault is not initialized.");
  return current;
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new DOMException("The operation was aborted.", "AbortError");
}

function safeError(error: unknown): string {
  if (error instanceof Error && error.message.length > 0 && error.message.length <= 300) return error.message;
  return "The holder vault operation failed closed.";
}
