/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // No ESLint config is shipped with this app; skip lint during `next build` so the
  // production build is deterministic (typecheck is enforced separately via `tsc --noEmit`).
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
