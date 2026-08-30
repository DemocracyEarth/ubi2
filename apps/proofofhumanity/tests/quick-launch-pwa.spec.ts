import { expect, test } from "@playwright/test";

test("Quick Launch PWA exposes only the Base Sepolia v1 journey", async ({ page, request }) => {
  await page.goto("/#mint");

  await expect(page.getByText("Quick Launch", { exact: false }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Base Sepolia" })).toHaveCount(1);
  await expect(page.getByTestId("holder-vault-panel")).toHaveCount(0);
  await expect(page.getByText("v2 policy designer", { exact: false })).toHaveCount(0);
  await expect(page.getByText("Ethereum", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Optimism", { exact: true })).toHaveCount(0);

  const demoCredential = await request.post("/api/predicate/demo-credential");
  expect(demoCredential.status()).toBe(404);

  const v2Refresh = await request.patch(
    "/api/self-verify?address=0x1111111111111111111111111111111111111111",
    { headers: { "x-poh-verification-session": "0123456789abcdef0123456789abcdef" } },
  );
  expect(v2Refresh.status()).toBe(405);

  await page.goto("/verify");
  await expect(page.getByText("Quick Launch · Base Sepolia")).toBeVisible();
  await expect(page.getByText("Custom v2 proofs", { exact: false })).toBeVisible();
  await expect(page.getByText("Canonical policy preview", { exact: false })).toHaveCount(0);

  const manifest = await page.evaluate(() => fetch("/manifest.webmanifest").then((response) => response.json()));
  expect(manifest.description).toContain("Base Sepolia");
  expect(manifest.description).not.toContain("passkey");

  await page.goto("/#mint");
  await expect.poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBe(true);
  expect(await page.evaluate(() => caches.keys())).toEqual([]);
});
