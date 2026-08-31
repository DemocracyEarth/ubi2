import path from "node:path";
import { fileURLToPath } from "node:url";
import { quickLaunchApiRewrites } from "./quick-launch-proxy.mjs";

const appDirectory = path.dirname(fileURLToPath(import.meta.url));
const standaloneApiBuild = process.env.POH_BUILD_STANDALONE_API === "true";

/** @type {import('next').NextConfig} */
const nextConfig = {
  ...(standaloneApiBuild
    ? {
        output: "standalone",
        outputFileTracingRoot: path.resolve(appDirectory, "../.."),
      }
    : {}),
  reactStrictMode: true,
  // Hide the floating Next.js dev-tools indicator (the bottom-left "N" badge). Dev-only anyway.
  devIndicators: false,
  // No ESLint config is shipped with this app; skip lint during `next build` so the
  // production build is deterministic (typecheck is enforced separately via `tsc --noEmit`).
  eslint: { ignoreDuringBuilds: true },
  async rewrites() {
    return {
      beforeFiles: quickLaunchApiRewrites(process.env.POH_QUICK_LAUNCH_API_ORIGIN),
      afterFiles: [],
      fallback: [],
    };
  },
};

export default nextConfig;
