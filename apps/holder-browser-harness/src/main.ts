import "./styles.css";
import {
  IndexedDbCredentialVaultStore,
  createPasskeyProtectedCredentialVault,
  createZkHolderPrivateStatusRefreshBrowserClient,
  createZkHolderPrivateStatusRefreshRequest,
  generateCredentialVaultBackupKey,
  generatePasskeyPrfSalt,
  zkHolderCredentialVaultSha256,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256,
  type EncryptedCredentialVaultBackup,
  type PortableCredentialVault,
  type ZkHolderPrivateStatusRefreshBrowserWorkerConstructor,
} from "@ubi2/sdk";
import { HARNESS_POLICY, HARNESS_POLICY_PRODUCTION_APPROVED, HARNESS_RESOLUTION } from "./policy";
import probeWorkerUrl from "./probe-worker?worker&url";

const WORKER_URL = new URL(
  `/assets/holder-private-status-refresh-worker.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256}.js`,
  location.origin,
);
const stores = new Map<string, IndexedDbCredentialVaultStore>();
const encoder = new TextEncoder();
const trustedScriptPolicy = createTrustedScriptPolicy();
const TrustedWorkerConstructor = class {
  constructor(url: URL, options: WorkerOptions) {
    return new Worker(trustedWorkerUrl(url), options);
  }
} as unknown as ZkHolderPrivateStatusRefreshBrowserWorkerConstructor;

interface ProbeResult {
  status: "ok" | "failed" | "rejected";
  wasmSha256?: string;
  bindingsSha256?: string;
  memoryBytes?: number;
  siblingCount?: number;
  elapsedMs?: number;
  networkLocked?: boolean;
  message?: string;
}

async function syntheticVault(): Promise<PortableCredentialVault> {
  return createPasskeyProtectedCredentialVault(
    { schema: "org.proofofhumanity.synthetic-browser-evidence/1", counter: 0 },
    { schema: "org.proofofhumanity.synthetic-browser-evidence/1", rpId: location.hostname },
    {
      credentialId: "c3ludGhldGljLWJyb3dzZXItaGFybmVzcw",
      prfSalt: generatePasskeyPrfSalt(),
      prfOutput: new Uint8Array(32).fill(0x41),
    },
  );
}

function replacement(vault: PortableCredentialVault, marker: number): PortableCredentialVault {
  const bytes = new Uint8Array(32).fill(marker & 0xff);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return {
    ...structuredClone(vault),
    payload: { ...vault.payload, iv: vault.payload.iv, ciphertext: btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "") },
  };
}

async function failClosedRefresh(): Promise<{ code: string; detached: boolean; auditApproved: false; policyApproved: false }> {
  const vault = await syntheticVault();
  const prf = new Uint8Array(32).fill(0x41).buffer;
  const request = await createZkHolderPrivateStatusRefreshRequest({
    vault,
    unlock: { credentialId: vault.keySlots[0]!.credentialId, prfOutput: prf },
    cohortBundles: [{
      resolution: HARNESS_RESOLUTION,
      snapshotBytes: encoder.encode('{"chunks":[]}').buffer as ArrayBuffer,
      attestationBytes: encoder.encode("{}").buffer as ArrayBuffer,
    }],
  });
  const result = await createZkHolderPrivateStatusRefreshBrowserClient({
    workerUrl: WORKER_URL,
    WorkerConstructor: TrustedWorkerConstructor,
  }).refresh(request);
  return {
    code: result.status === "failed" ? result.code : result.status,
    detached: prf.byteLength === 0,
    auditApproved: ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED,
    policyApproved: HARNESS_POLICY_PRODUCTION_APPROVED,
  };
}

async function cancellationSample(): Promise<number> {
  const vault = await syntheticVault();
  const request = await createZkHolderPrivateStatusRefreshRequest({
    vault,
    unlock: { credentialId: vault.keySlots[0]!.credentialId, prfOutput: new Uint8Array(32).fill(0x41).buffer },
    cohortBundles: [{
      resolution: HARNESS_RESOLUTION,
      snapshotBytes: encoder.encode('{"chunks":[]}').buffer as ArrayBuffer,
      attestationBytes: encoder.encode("{}").buffer as ArrayBuffer,
    }],
  });
  const controller = new AbortController();
  const started = performance.now();
  const pending = createZkHolderPrivateStatusRefreshBrowserClient({
    workerUrl: WORKER_URL,
    WorkerConstructor: TrustedWorkerConstructor,
  })
    .refresh(request, { signal: controller.signal });
  controller.abort();
  const result = await pending;
  if (result.status !== "failed" || result.code !== "CANCELLED") throw new Error("refresh did not cancel");
  return performance.now() - started;
}

function publicProbe(): Promise<ProbeResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(trustedWorkerUrl(new URL(probeWorkerUrl, location.origin)), { type: "module", name: "holder-public-probe" });
    const timeout = setTimeout(() => { worker.terminate(); reject(new Error("public probe timed out")); }, 15_000);
    worker.onmessage = ({ data }: MessageEvent<ProbeResult>) => {
      clearTimeout(timeout);
      worker.terminate();
      resolve(data);
    };
    worker.onerror = (event) => {
      clearTimeout(timeout);
      worker.terminate();
      reject(new Error(event.message));
    };
    worker.postMessage({ type: "run-public-probe" });
  });
}

function storeFor(databaseName: string, vault: PortableCredentialVault, crash = false): IndexedDbCredentialVaultStore {
  const prior = stores.get(databaseName);
  prior?.close();
  const store = new IndexedDbCredentialVaultStore({
    databaseName,
    vaultId: vault.vaultId,
    binding: vault.binding,
    testHooks: crash ? { beforeCommit() { throw new Error("simulated crash before commit"); } } : undefined,
  });
  stores.set(databaseName, store);
  return store;
}

async function deleteDatabase(databaseName: string): Promise<void> {
  stores.get(databaseName)?.close();
  stores.delete(databaseName);
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(databaseName);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("database deletion blocked"));
  });
}

async function prepareStore(databaseName: string): Promise<{ vault: PortableCredentialVault; digest: string }> {
  await deleteDatabase(databaseName);
  const vault = await syntheticVault();
  const store = storeFor(databaseName, vault);
  if (!await store.initialize(vault)) throw new Error("store was unexpectedly occupied");
  return { vault, digest: await zkHolderCredentialVaultSha256(vault) };
}

async function openStore(databaseName: string, vault: PortableCredentialVault): Promise<void> {
  const store = storeFor(databaseName, vault);
  store.subscribe(() => {
    (globalThis as unknown as { __vaultInvalidations?: number }).__vaultInvalidations =
      ((globalThis as unknown as { __vaultInvalidations?: number }).__vaultInvalidations ?? 0) + 1;
  });
}

async function cas(databaseName: string, vault: PortableCredentialVault, expected: string, marker: number): Promise<boolean> {
  const store = stores.get(databaseName) ?? storeFor(databaseName, vault);
  return store.compareAndSwap(expected, replacement(vault, marker));
}

async function readStore(databaseName: string, vault: PortableCredentialVault): Promise<PortableCredentialVault | undefined> {
  return (stores.get(databaseName) ?? storeFor(databaseName, vault)).read();
}

async function crashDrill(databaseName: string): Promise<{ rejected: boolean; oldVaultIntact: boolean; restartIntact: boolean }> {
  const { vault, digest } = await prepareStore(databaseName);
  const crashing = storeFor(databaseName, vault, true);
  let rejected = false;
  try { await crashing.compareAndSwap(digest, replacement(vault, 7)); } catch { rejected = true; }
  crashing.close();
  stores.delete(databaseName);
  const reopened = storeFor(databaseName, vault);
  const current = await reopened.read();
  const oldVaultIntact = current !== undefined && await zkHolderCredentialVaultSha256(current) === digest;
  reopened.close();
  stores.delete(databaseName);
  const restarted = storeFor(databaseName, vault);
  const afterRestart = await restarted.read();
  return { rejected, oldVaultIntact, restartIntact: afterRestart !== undefined && await zkHolderCredentialVaultSha256(afterRestart) === digest };
}

async function backupRestoreDrill(databaseName: string): Promise<{
  restored: string;
  sameVault: boolean;
  wrongKeyRejected: boolean;
  tamperRejected: boolean;
  bindingRejected: boolean;
  occupiedProtected: boolean;
  staleCasProtected: boolean;
  casRestoreSucceeded: boolean;
}> {
  const sourceName = `${databaseName}-source`;
  const restoreName = `${databaseName}-restore`;
  const wrongName = `${databaseName}-wrong`;
  const tamperName = `${databaseName}-tamper`;
  const bindingName = `${databaseName}-binding`;
  const occupiedName = `${databaseName}-occupied`;
  const { vault, digest } = await prepareStore(sourceName);
  const key = generateCredentialVaultBackupKey();
  const backup = await stores.get(sourceName)!.exportEncryptedBackup(key);
  await deleteDatabase(restoreName);
  const restoreStore = storeFor(restoreName, vault);
  const restored = await restoreStore.restoreEncryptedBackup({ backup, recoveryKey: key, mode: "empty-only" });
  const restoredVault = await restoreStore.read();

  let wrongKeyRejected = false;
  await deleteDatabase(wrongName);
  try {
    await storeFor(wrongName, vault).restoreEncryptedBackup({ backup, recoveryKey: new Uint8Array(32).fill(9), mode: "empty-only" });
  } catch { wrongKeyRejected = true; }

  let tamperRejected = false;
  const tampered: EncryptedCredentialVaultBackup = {
    ...backup,
    ciphertext: `${backup.ciphertext[0] === "A" ? "B" : "A"}${backup.ciphertext.slice(1)}`,
  };
  await deleteDatabase(tamperName);
  try {
    await storeFor(tamperName, vault).restoreEncryptedBackup({ backup: tampered, recoveryKey: key, mode: "empty-only" });
  } catch { tamperRejected = true; }

  let bindingRejected = false;
  await deleteDatabase(bindingName);
  const wrongBindingVault = { ...structuredClone(vault), binding: { ...vault.binding, rpId: "wrong.invalid" } };
  try {
    await storeFor(bindingName, wrongBindingVault).restoreEncryptedBackup({ backup, recoveryKey: key, mode: "empty-only" });
  } catch { bindingRejected = true; }

  await deleteDatabase(occupiedName);
  const occupiedStore = storeFor(occupiedName, vault);
  const occupiedVault = replacement(vault, 11);
  await occupiedStore.initialize(occupiedVault);
  const occupiedDigest = await zkHolderCredentialVaultSha256(occupiedVault);
  const occupiedProtected = await occupiedStore.restoreEncryptedBackup({
    backup,
    recoveryKey: key,
    mode: "empty-only",
  }) === "occupied" && await zkHolderCredentialVaultSha256((await occupiedStore.read())!) === occupiedDigest;
  const staleCasProtected = await occupiedStore.restoreEncryptedBackup({
    backup,
    recoveryKey: key,
    mode: "compare-and-swap",
    expectedCurrentVaultSha256: "00".repeat(32),
  }) === "stale" && await zkHolderCredentialVaultSha256((await occupiedStore.read())!) === occupiedDigest;
  const casRestoreSucceeded = await occupiedStore.restoreEncryptedBackup({
    backup,
    recoveryKey: key,
    mode: "compare-and-swap",
    expectedCurrentVaultSha256: occupiedDigest,
  }) === "restored" && await zkHolderCredentialVaultSha256((await occupiedStore.read())!) === digest;

  return {
    restored,
    sameVault: restoredVault !== undefined && await zkHolderCredentialVaultSha256(restoredVault) === digest,
    wrongKeyRejected,
    tamperRejected,
    bindingRejected,
    occupiedProtected,
    staleCasProtected,
    casRestoreSucceeded,
  };
}

async function registerServiceWorker(script: string): Promise<void> {
  const registrations = await navigator.serviceWorker.getRegistrations();
  await Promise.all(registrations.map((registration) => registration.unregister()));
  await navigator.serviceWorker.register(trustedServiceWorkerUrl(script), { scope: "/" });
  await navigator.serviceWorker.ready;
}

async function serviceWorkerObservations(): Promise<unknown[]> {
  const controller = navigator.serviceWorker.controller;
  if (!controller) return [];
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    channel.port1.onmessage = ({ data }) => resolve(Array.isArray(data) ? data : []);
    controller.postMessage("observations", [channel.port2]);
  });
}

export const holderHarness = {
  failClosedRefresh,
  cancellationSample,
  publicProbe,
  prepareStore,
  openStore,
  cas,
  readStore,
  crashDrill,
  backupRestoreDrill,
  registerServiceWorker,
  serviceWorkerObservations,
  deleteDatabase,
  workerUrl: WORKER_URL.href,
  admission: {
    independentAuditApproved: ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED,
    workerPolicyApproved: HARNESS_POLICY_PRODUCTION_APPROVED,
  },
};

declare global {
  interface Window { __holderHarness: typeof holderHarness; __vaultInvalidations?: number }
}
window.__holderHarness = holderHarness;

if (new URLSearchParams(location.search).get("serviceWorker") !== "manual" && "serviceWorker" in navigator) {
  void navigator.serviceWorker.register(trustedServiceWorkerUrl("/sw.js"), { scope: "/" });
}

function createTrustedScriptPolicy(): { createScriptURL(value: string): unknown } | undefined {
  const factory = (globalThis as unknown as {
    trustedTypes?: { createPolicy(name: string, rules: { createScriptURL(value: string): string }): { createScriptURL(value: string): unknown } };
  }).trustedTypes;
  if (!factory) return undefined;
  return factory.createPolicy("ubi2-holder-harness", {
    createScriptURL(value: string): string {
      const url = new URL(value, location.origin);
      const permitted =
        url.origin === location.origin &&
        (
          url.pathname === "/sw.js" ||
          url.pathname === "/adversarial-sw.js" ||
          url.href === WORKER_URL.href ||
          /^\/assets\/probe-worker-[A-Za-z0-9_-]+\.js$/u.test(url.pathname)
        );
      if (!permitted) throw new TypeError("unreviewed Worker URL");
      return url.href;
    },
  });
}

function trustedServiceWorkerUrl(value: string): string {
  return (trustedScriptPolicy?.createScriptURL(value) ?? value) as string;
}

function trustedWorkerUrl(value: string | URL): string {
  const url = value instanceof URL ? value.href : value;
  return (trustedScriptPolicy?.createScriptURL(url) ?? url) as string;
}
