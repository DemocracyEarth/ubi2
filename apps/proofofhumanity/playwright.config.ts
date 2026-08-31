import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  reporter: [["line"]],
  use: {
    baseURL: "http://127.0.0.1:4175",
    browserName: "chromium",
    headless: true,
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 3,
    hasTouch: true,
    isMobile: true,
    serviceWorkers: "allow",
  },
  webServer: {
    command: "pnpm build && pnpm start -H 127.0.0.1 -p 4175",
    port: 4175,
    reuseExistingServer: false,
    timeout: 180_000,
    env: {
      NEXT_PUBLIC_SELF_ENV: "staging",
      NEXT_PUBLIC_SELF_ENDPOINT: "",
      // Test-only: exercise the dedicated-origin route contract without any secret or transaction.
      POH_API_RUNTIME: "dedicated-single-replica",
      POH_BLOCKCHAIN_TRANSACTIONS_ENABLED: "false",
    },
  },
});
