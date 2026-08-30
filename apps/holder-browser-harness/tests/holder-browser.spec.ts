import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";

test.describe.configure({ mode: "serial" });

const evidence: Record<string, unknown> = {
  schema: "org.proofofhumanity.v2-holder-browser-hardening-evidence/1",
  productionEligible: false,
  environment: { kind: "emulated-mobile-chromium", viewport: "390x844", deviceScaleFactor: 3, cpuThrottle: 4 },
};

test.beforeEach(async ({ context }) => {
  await installExtensionAdversary(context);
});

test.afterAll(async () => {
  await mkdir("test-results", { recursive: true });
  await writeFile("test-results/holder-browser-hardening-evidence.json", `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
});

test("production CSP, Trusted Types, PWA, Worker integrity and adversarial boundaries", async ({ page, context }) => {
  const response = await page.goto("/?serviceWorker=manual");
  await waitForHarness(page);
  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("require-trusted-types-for 'script'");
  expect(csp).toContain("trusted-types ubi2-holder-harness");
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(true);
  expect(await page.evaluate(() => typeof (window as unknown as { trustedTypes?: unknown }).trustedTypes === "object")).toBe(true);
  const trustedTypesBlocked = await page.evaluate(() => {
    try { document.body.innerHTML = "<img src=x onerror=alert(1)>"; return false; } catch { return true; }
  });
  expect(trustedTypesBlocked).toBe(true);

  const manifest = await page.evaluate(async () => fetch("/manifest.webmanifest").then((response) => response.json()));
  expect(manifest.display).toBe("standalone");
  await page.evaluate(() => window.__holderHarness.registerServiceWorker("/sw.js"));
  await page.reload();
  await waitForHarness(page);
  await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);

  const requests: { url: string; method: string; postData: string | null }[] = [];
  page.on("request", (request) => requests.push({ url: request.url(), method: request.method(), postData: request.postData() }));
  const closed = await page.evaluate(() => window.__holderHarness.failClosedRefresh());
  expect(closed).toEqual({ code: "PROFILE_REJECTED", detached: true, auditApproved: false, policyApproved: false });
  const extensionBoundary = await page.evaluate(() => (window as unknown as { __extensionEvidence?: { clonedBeforeTransfer: boolean } }).__extensionEvidence);
  expect(extensionBoundary?.clonedBeforeTransfer).toBe(true);

  const probe = await page.evaluate(() => window.__holderHarness.publicProbe());
  expect(probe).toMatchObject({ status: "ok", siblingCount: 24, networkLocked: true });
  expect(probe.memoryBytes).toBeGreaterThan(0);
  expect(requests.every(({ url }) => new URL(url).origin === "http://127.0.0.1:4174")).toBe(true);
  expect(requests.every(({ url, postData }) => !`${url}${postData ?? ""}`.includes("synthetic-browser-evidence"))).toBe(true);

  const cacheUrls = await page.evaluate(async () => {
    const urls: string[] = [];
    for (const name of await caches.keys()) for (const request of await (await caches.open(name)).keys()) urls.push(request.url);
    return urls;
  });
  expect(cacheUrls.every((url) => !new URL(url).pathname.startsWith("/private/"))).toBe(true);
  expect(cacheUrls.some((url) => /holder-refresh-engine\.[0-9a-f]{64}\.wasm$/u.test(url))).toBe(true);

  await page.evaluate(() => window.__holderHarness.registerServiceWorker("/adversarial-sw.js"));
  await page.reload();
  await waitForHarness(page);
  await expect.poll(() => page.evaluate(() => navigator.serviceWorker.controller?.scriptURL.endsWith("/adversarial-sw.js"))).toBe(true);
  const corrupted = await page.evaluate(() => window.__holderHarness.publicProbe());
  expect(corrupted.status).toBe("failed");
  expect(corrupted.message).toMatch(/length|content address|magic|module/u);
  const serviceWorkerObservations = await page.evaluate(() => window.__holderHarness.serviceWorkerObservations());
  expect(serviceWorkerObservations.some((entry) => /holder-refresh-engine\.[0-9a-f]{64}\.wasm$/u.test(String((entry as { path?: unknown }).path)))).toBe(true);

  evidence.browserBoundary = {
    cspHeader: true,
    cspPolicy: csp,
    trustedTypesBlockedStringSink: trustedTypesBlocked,
    crossOriginIsolated: true,
    pwaControlled: true,
    cacheUrls,
    failClosed: closed,
    publicProbe: probe,
    adversarialServiceWorkerArtifactRejected: corrupted,
    extensionPreTransferClonePossible: extensionBoundary?.clonedBeforeTransfer === true,
    noPrivateNetworkSelector: true,
  };
  await context.clearCookies();
});

test("two tabs serialize whole-vault CAS and broadcast content-free invalidation", async ({ context, page }) => {
  await page.goto("/?serviceWorker=manual");
  await waitForHarness(page);
  const second = await context.newPage();
  await second.goto("/?serviceWorker=manual");
  await waitForHarness(second);
  const databaseName = `holder-cas-${Date.now()}`;
  const prepared = await page.evaluate((name) => window.__holderHarness.prepareStore(name), databaseName);
  await second.evaluate(({ name, vault }) => window.__holderHarness.openStore(name, vault), { name: databaseName, vault: prepared.vault });

  const [first, competing] = await Promise.all([
    page.evaluate(({ name, vault, digest }) => window.__holderHarness.cas(name, vault, digest, 1), { name: databaseName, ...prepared }),
    second.evaluate(({ name, vault, digest }) => window.__holderHarness.cas(name, vault, digest, 2), { name: databaseName, ...prepared }),
  ]);
  expect([first, competing].filter(Boolean)).toHaveLength(1);
  await expect.poll(() => second.evaluate(() => window.__vaultInvalidations ?? 0)).toBeGreaterThan(0);
  const stored = await page.evaluate(({ name, vault }) => window.__holderHarness.readStore(name, vault), { name: databaseName, vault: prepared.vault });
  expect(stored).toBeDefined();
  expect(stored?.keySlots).toEqual(prepared.vault.keySlots);
  const persistedRecord = await page.evaluate(async (name) => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(name);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const transaction = database.transaction("whole-vault", "readonly");
    const record = await new Promise<unknown>((resolve, reject) => {
      const request = transaction.objectStore("whole-vault").get("current");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    database.close();
    return { keys: Object.keys(record as object).sort(), serialized: JSON.stringify(record) };
  }, databaseName);
  expect(persistedRecord.keys).toEqual(["key", "revision", "schema", "vault"]);
  expect(persistedRecord.serialized).not.toContain(prepared.digest);
  expect(persistedRecord.serialized).not.toContain('"counter"');
  const broadcastMessages = await page.evaluate(() =>
    (window as unknown as { __extensionEvidence?: { broadcastMessages: unknown[] } }).__extensionEvidence?.broadcastMessages ?? []
  );
  expect(broadcastMessages.length).toBeGreaterThan(0);
  expect(broadcastMessages.every((message) => JSON.stringify(message) === '{"schema":"org.proofofhumanity.credential-vault-changed/1"}')).toBe(true);
  evidence.multiTabCas = {
    exactlyOneCommitted: true,
    wholeVaultReadable: true,
    contentFreeInvalidation: true,
    persistedRecordKeys: persistedRecord.keys,
    digestReceiptPersisted: false,
    decryptedPayloadPersisted: false,
  };
  await second.close();
});

test("crash, restart, authenticated backup and restore drills keep old-or-new whole vaults", async ({ page }) => {
  await page.goto("/?serviceWorker=manual");
  await waitForHarness(page);
  const crash = await page.evaluate((name) => window.__holderHarness.crashDrill(name), `holder-crash-${Date.now()}`);
  expect(crash).toEqual({ rejected: true, oldVaultIntact: true, restartIntact: true });
  const recovery = await page.evaluate((name) => window.__holderHarness.backupRestoreDrill(name), `holder-backup-${Date.now()}`);
  expect(recovery).toEqual({
    restored: "restored",
    sameVault: true,
    wrongKeyRejected: true,
    tamperRejected: true,
    bindingRejected: true,
    occupiedProtected: true,
    staleCasProtected: true,
    casRestoreSucceeded: true,
  });
  evidence.recovery = { crash, backupRestore: recovery };
});

test("emulated mobile Chromium measures disposable Worker memory and cancellation", async ({ page, context }) => {
  await page.goto("/?serviceWorker=manual");
  await waitForHarness(page);
  const cdp = await context.newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
  const probes = [];
  const cancellations = [];
  for (let index = 0; index < 10; index += 1) probes.push(await page.evaluate(() => window.__holderHarness.publicProbe()));
  for (let index = 0; index < 20; index += 1) cancellations.push(await page.evaluate(() => window.__holderHarness.cancellationSample()));
  expect(probes.every((probe) => probe.status === "ok" && probe.networkLocked && probe.siblingCount === 24)).toBe(true);
  const memoryBytes = probes.map((probe) => probe.memoryBytes ?? 0);
  expect(Math.max(...memoryBytes)).toBeLessThanOrEqual(256 * 1024 * 1024);
  const cancellationP95Ms = percentile(cancellations, 0.95);
  expect(cancellationP95Ms).toBeLessThan(1_000);
  const userAgent = await page.evaluate(() => navigator.userAgent);
  const jsHeapBytes = await page.evaluate(() => (performance as Performance & { memory?: { usedJSHeapSize: number } }).memory?.usedJSHeapSize ?? null);
  evidence.mobile = {
    label: "emulated Chromium mobile profile; not physical-device admission evidence",
    userAgent,
    wasmLinearMemoryBytes: memoryBytes,
    peakWasmLinearMemoryBytes: Math.max(...memoryBytes),
    cancellationMs: cancellations,
    cancellationP95Ms,
    usedJsHeapBytesAfterSamples: jsHeapBytes,
    samples: { probes: probes.length, cancellations: cancellations.length },
  };
});

async function waitForHarness(page: Page): Promise<void> {
  await page.waitForFunction(() => Boolean(window.__holderHarness));
}

async function installExtensionAdversary(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const original = Worker.prototype.postMessage;
    const evidence = { clonedBeforeTransfer: false, broadcastMessages: [] as unknown[] };
    Object.defineProperty(window, "__extensionEvidence", { value: evidence, configurable: false });
    Worker.prototype.postMessage = function(this: Worker, message: unknown, transferOrOptions?: Transferable[] | StructuredSerializeOptions) {
      if (message && typeof message === "object" && "vault" in message) {
        structuredClone(message);
        evidence.clonedBeforeTransfer = true;
      }
      return Reflect.apply(original as unknown as (...args: unknown[]) => void, this, [message, transferOrOptions ?? []]);
    } as Worker["postMessage"];
    const broadcast = BroadcastChannel.prototype.postMessage;
    BroadcastChannel.prototype.postMessage = function(this: BroadcastChannel, message: unknown) {
      evidence.broadcastMessages.push(structuredClone(message));
      return broadcast.call(this, message);
    };
  });
}

function percentile(values: number[], ratio: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * ratio) - 1)]!;
}
