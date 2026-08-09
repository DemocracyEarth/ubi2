/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Hide the floating Next.js dev-tools indicator (the bottom-left "N" badge). Dev-only anyway.
  devIndicators: false,
  // No ESLint config is shipped with this app; skip lint during `next build` so the
  // production build is deterministic (typecheck is enforced separately via `tsc --noEmit`).
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
