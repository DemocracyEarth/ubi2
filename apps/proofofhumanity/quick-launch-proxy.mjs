export const QUICK_LAUNCH_API_PATHS = Object.freeze([
  "/api/self-verify",
  "/api/predicate",
  "/api/sponsored-mint",
  "/api/quick-launch-readiness",
]);

const CANONICAL_ORIGIN = "https://proofofhumanity.org";

/** Validate the only non-secret value Amplify needs in order to proxy the canonical API paths. */
export function parseQuickLaunchApiOrigin(value) {
  const candidate = value?.trim();
  if (!candidate) return null;

  let url;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error("POH_QUICK_LAUNCH_API_ORIGIN must be an absolute HTTPS origin.");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    ["localhost", "127.0.0.1", "::1"].includes(url.hostname.toLowerCase())
  ) {
    throw new Error(
      "POH_QUICK_LAUNCH_API_ORIGIN must be a credential-free public HTTPS origin with no path, query, or fragment.",
    );
  }
  if (url.origin === CANONICAL_ORIGIN) {
    throw new Error("POH_QUICK_LAUNCH_API_ORIGIN must not point back to the Amplify frontend.");
  }
  return url.origin;
}

export function quickLaunchApiRewrites(value) {
  const origin = parseQuickLaunchApiOrigin(value);
  if (!origin) return [];
  return QUICK_LAUNCH_API_PATHS.map((source) => ({ source, destination: `${origin}${source}` }));
}
