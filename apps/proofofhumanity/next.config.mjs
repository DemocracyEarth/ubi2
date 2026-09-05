import path from "node:path";
import { fileURLToPath } from "node:url";
import { quickLaunchApiRewrites } from "./quick-launch-proxy.mjs";

const appDirectory = path.dirname(fileURLToPath(import.meta.url));
const standaloneApiBuild = process.env.POH_BUILD_STANDALONE_API === "true";

function quickLaunchBuildId() {
  const sourceRevision = process.env.POH_SOURCE_REVISION;
  if (!/^[0-9a-f]{40}$/.test(sourceRevision ?? "")) {
    throw new Error("POH_SOURCE_REVISION must be an exact lowercase Git commit for standalone builds");
  }
  return sourceRevision;
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  ...(standaloneApiBuild
    ? {
        output: "standalone",
        outputFileTracingRoot: path.resolve(appDirectory, "../.."),
        generateBuildId: async () => quickLaunchBuildId(),
      }
    : {}),
  reactStrictMode: true,
  // Hide the floating Next.js dev-tools indicator (the bottom-left "N" badge). Dev-only anyway.
  devIndicators: false,
  // No ESLint config is shipped with this app; skip lint during `next build` so the
  // production build is deterministic (typecheck is enforced separately via `tsc --noEmit`).
  eslint: { ignoreDuringBuilds: true },
  // The standalone signing origin contains application code only. Product tests and operational
  // evidence remain outside the Docker context and are validated before this build.
  typescript: {
    tsconfigPath: standaloneApiBuild ? "tsconfig.standalone.json" : "tsconfig.json",
  },
  async rewrites() {
    return {
      beforeFiles: quickLaunchApiRewrites(process.env.POH_QUICK_LAUNCH_API_ORIGIN),
      afterFiles: [],
      fallback: [],
    };
  },
};

export default nextConfig;
