const CACHE = "ubi2-holder-harness-immutable-v1";
const CONTENT_ADDRESSED = /(?:holder-private-status-refresh-worker\.[0-9a-f]{64}\.js|holder-refresh-engine\.[0-9a-f]{64}\.wasm)$/u;
const BUILD_ASSET = /^\/assets\/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8,}\.(?:js|css)$/u;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (
    event.request.method !== "GET" ||
    url.origin !== self.location.origin ||
    url.pathname.startsWith("/private/") ||
    (!CONTENT_ADDRESSED.test(url.pathname) && !BUILD_ASSET.test(url.pathname))
  ) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const cached = await cache.match(event.request);
    if (cached) return cached;
    const response = await fetch(event.request, { credentials: "omit", redirect: "error" });
    if (response.ok && response.type !== "opaque") await cache.put(event.request, response.clone());
    return response;
  })());
});
