import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const OTHER_ACCOUNT = "0x2222222222222222222222222222222222222222";

test("real PoH PWA enrolls, relocks, adds a passkey, backs up, restores and cancels fail closed", async ({ browser, context, page }) => {
  await installProductFakes(context);
  await connectHolder(page);

  await expect(page.getByTestId("holder-vault-panel")).toBeVisible();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("empty");
  await page.getByTestId("holder-vault-enroll").click();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("locked");
  await expect(page.getByTestId("holder-vault-passkey-count")).toHaveText("1");

  await page.getByTestId("holder-vault-unlock").click();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("unlocked");
  await expect(page.getByTestId("holder-vault-unlocked-summary")).toContainText("Proof binding: not added yet");

  await page.getByTestId("holder-vault-add-passkey").click();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("locked");
  await expect(page.getByTestId("holder-vault-passkey-count")).toHaveText("2");

  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId("holder-vault-backup").click();
  const download = await downloadPromise;
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const recoveryKey = await page.getByTestId("holder-vault-recovery-key").locator("code").textContent();
  expect(recoveryKey).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  const recoveryPackage = JSON.parse(await readFile(downloadPath!, "utf8")) as Record<string, unknown>;
  expect(recoveryPackage.productionEligible).toBe(false);
  expect(recoveryPackage.subjectAccount).toBe(ACCOUNT);
  expect(JSON.stringify(recoveryPackage)).not.toContain(recoveryKey!);

  const persistence = await page.evaluate(async () => {
    const databases = await indexedDB.databases();
    const databaseName = databases.find(({ name }) => name?.startsWith("poh-holder-vault-"))?.name;
    if (!databaseName) throw new Error("holder vault database missing");
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(databaseName);
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
    return {
      databaseName,
      serialized: JSON.stringify(record),
      local: JSON.stringify(localStorage),
      session: JSON.stringify(sessionStorage),
    };
  });
  expect(persistence.databaseName).not.toContain(ACCOUNT.slice(2));
  expect(persistence.serialized).not.toContain("v2-holder-pwa-testnet-rehearsal");
  expect(persistence.serialized).not.toContain(ACCOUNT);
  expect(`${persistence.local}${persistence.session}`).not.toContain(recoveryKey!);

  const manifest = await page.evaluate(() => fetch("/manifest.webmanifest").then((response) => response.json()));
  expect(manifest.display).toBe("standalone");
  await page.reload();
  await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
  expect(await page.evaluate(() => caches.keys())).toEqual([]);
  await connectHolder(page, false);
  await expect(page.getByTestId("holder-vault-status")).toHaveText("locked");

  const getCallsBeforeDoubleClick = await page.evaluate(() => window.__pohWebAuthnGetCalls);
  await page.getByTestId("holder-vault-unlock").evaluate((button: HTMLButtonElement) => {
    button.click();
    button.click();
  });
  await expect(page.getByTestId("holder-vault-status")).toHaveText("unlocked");
  expect(await page.evaluate(() => window.__pohWebAuthnGetCalls)).toBe(getCallsBeforeDoubleClick + 1);
  await page.reload();
  await connectHolder(page, false);
  await expect(page.getByTestId("holder-vault-status")).toHaveText("locked");

  await page.evaluate(() => {
    window.__pohSlowWebAuthn = true;
    window.__pohIgnoreWebAuthnAbort = true;
  });
  await page.getByTestId("holder-vault-unlock").click();
  await expect(page.getByTestId("holder-vault-cancel")).toBeVisible();
  await page.getByTestId("holder-vault-cancel").click();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("locked");
  await expect(page.getByTestId("holder-vault-notice")).toContainText("canceled");
  await page.waitForTimeout(350);
  await expect(page.getByTestId("holder-vault-status")).toHaveText("locked");
  await expect(page.getByTestId("holder-vault-notice")).toContainText("canceled");
  await page.evaluate(() => {
    window.__pohSlowWebAuthn = false;
    window.__pohIgnoreWebAuthnAbort = false;
  });

  await page.getByTestId("holder-vault-unlock").click();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("unlocked");
  await page.evaluate((account) => window.__setPohWalletAccount(account), OTHER_ACCOUNT);
  await expect(page.getByText("Wallet account changed. The previous Self session and voucher were discarded", { exact: false })).toBeVisible();
  await page.getByLabel("I understand that this address and credential are public and permanent", { exact: false }).check();
  await expect(page.getByTestId("holder-vault-status")).toHaveText("empty");
  await expect(page.getByTestId("holder-vault-recovery-key")).toHaveCount(0);

  const restoreContext = await browser.newContext({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 3,
    hasTouch: true,
    isMobile: true,
    serviceWorkers: "allow",
  });
  await installProductFakes(restoreContext);
  const restorePage = await restoreContext.newPage();
  await connectHolder(restorePage);
  await restorePage.getByTestId("holder-vault-restore-file").setInputFiles(downloadPath!);
  await restorePage.getByTestId("holder-vault-restore-key").fill(recoveryKey!);
  await restorePage.getByTestId("holder-vault-restore-submit").click();
  await expect(restorePage.getByTestId("holder-vault-status")).toHaveText("locked");
  await restorePage.getByTestId("holder-vault-unlock").click();
  await expect(restorePage.getByTestId("holder-vault-status")).toHaveText("unlocked");
  await restoreContext.close();

  await mkdir("test-results", { recursive: true });
  await writeFile(
    "test-results/holder-vault-pwa-evidence.json",
    `${JSON.stringify({
      schema: "org.proofofhumanity.v2-holder-pwa-browser-evidence/1",
      productionEligible: false,
      environment: "emulated-mobile-chromium",
      webauthn: "deterministic PRF API double; not physical-authenticator evidence",
      checks: {
        productionBuild: true,
        installablePwa: true,
        serviceWorkerCacheStorageEmpty: true,
        enrollmentAndUnlock: true,
        atomicSecondPasskey: true,
        encryptedBackupAndEmptyProfileRestore: true,
        crashRestartRelocked: true,
        cancellationRelocked: true,
        rapidDuplicateActionSuppressed: true,
        ignoredNativeAbortCompletionStayedInvalidated: true,
        accountSwitchInvalidatedSession: true,
        plaintextAndRecoveryKeyNotPersisted: true,
      },
    }, null, 2)}\n`,
    "utf8",
  );
});

async function connectHolder(page: Page, navigate = true): Promise<void> {
  if (navigate) await page.goto("/#mint");
  await page.getByRole("button", { name: "Connect credential account" }).click();
  await page.getByLabel("I understand that this address and credential are public and permanent", { exact: false }).check();
}

async function installProductFakes(context: BrowserContext): Promise<void> {
  await context.addInitScript(({ account }) => {
    let walletAccount = account;
    let credentialCounter = 0;
    window.__pohWebAuthnGetCalls = 0;
    const listeners = new Set<(accounts: string[]) => void>();
    const encoder = new TextEncoder();

    Object.defineProperty(window, "ethereum", {
      configurable: false,
      value: {
        async request({ method }: { method: string }) {
          if (method === "eth_requestAccounts" || method === "eth_accounts") return [walletAccount];
          if (method === "wallet_requestPermissions") return [];
          throw new Error(`unexpected wallet method: ${method}`);
        },
        on(event: string, listener: (accounts: string[]) => void) {
          if (event === "accountsChanged") listeners.add(listener);
        },
        removeListener(event: string, listener: (accounts: string[]) => void) {
          if (event === "accountsChanged") listeners.delete(listener);
        },
      },
    });
    window.__setPohWalletAccount = (next: string) => {
      walletAccount = next;
      for (const listener of listeners) listener([next]);
    };

    const base64Url = (bytes: Uint8Array) => {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
    };
    const bytes = (source: BufferSource) => {
      const view = ArrayBuffer.isView(source)
        ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
        : new Uint8Array(source);
      return new Uint8Array(view);
    };
    const prf = async (credentialId: Uint8Array, salt: BufferSource) => {
      const saltBytes = bytes(salt);
      const combined = new Uint8Array(credentialId.byteLength + saltBytes.byteLength);
      combined.set(credentialId);
      combined.set(saltBytes, credentialId.byteLength);
      return crypto.subtle.digest("SHA-256", combined);
    };
    const result = (credentialId: Uint8Array, output: ArrayBuffer, registration: boolean) => ({
      id: base64Url(credentialId),
      type: "public-key",
      rawId: credentialId.buffer.slice(credentialId.byteOffset, credentialId.byteOffset + credentialId.byteLength),
      response: {},
      getClientExtensionResults: () => ({ prf: { ...(registration ? { enabled: true } : {}), results: { first: output } } }),
    });
    const waitForCeremony = (signal?: AbortSignal) => {
      if (!window.__pohSlowWebAuthn) return Promise.resolve();
      if (window.__pohIgnoreWebAuthnAbort) {
        return new Promise<void>((resolve) => setTimeout(resolve, 250));
      }
      return new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, 10_000);
        signal?.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(new DOMException("The operation was aborted.", "AbortError"));
        }, { once: true });
      });
    };
    Object.defineProperty(navigator.credentials, "create", {
      configurable: true,
      value: async ({ publicKey, signal }: CredentialCreationOptions & { signal?: AbortSignal }) => {
        await waitForCeremony(signal);
        const credentialId = encoder.encode(`poh-passkey-${++credentialCounter}`);
        const extension = publicKey?.extensions as unknown as { prf?: { eval?: { first?: BufferSource } } };
        const salt = extension.prf?.eval?.first;
        if (!salt) throw new Error("PRF registration salt missing");
        return result(credentialId, await prf(credentialId, salt), true);
      },
    });
    Object.defineProperty(navigator.credentials, "get", {
      configurable: true,
      value: async ({ publicKey, signal }: CredentialRequestOptions & { signal?: AbortSignal }) => {
        window.__pohWebAuthnGetCalls += 1;
        await waitForCeremony(signal);
        const descriptor = publicKey?.allowCredentials?.[0];
        if (!descriptor) throw new Error("allowCredentials missing");
        const credentialId = bytes(descriptor.id);
        const encoded = base64Url(credentialId);
        const extension = publicKey.extensions as unknown as {
          prf?: { eval?: { first?: BufferSource }; evalByCredential?: Record<string, { first?: BufferSource }> };
        };
        const salt = extension.prf?.eval?.first ?? extension.prf?.evalByCredential?.[encoded]?.first;
        if (!salt) throw new Error("PRF assertion salt missing");
        return result(credentialId, await prf(credentialId, salt), false);
      },
    });
  }, { account: ACCOUNT });
}

declare global {
  interface Window {
    __pohSlowWebAuthn?: boolean;
    __pohIgnoreWebAuthnAbort?: boolean;
    __pohWebAuthnGetCalls: number;
    __setPohWalletAccount(account: string): void;
  }
}
