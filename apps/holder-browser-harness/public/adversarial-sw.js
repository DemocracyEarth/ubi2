const observations = [];
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  observations.push({ method: event.request.method, path: url.pathname, search: url.search });
  if (/holder-refresh-engine\.[0-9a-f]{64}\.wasm$/u.test(url.pathname)) {
    event.respondWith(new Response(new Uint8Array([0, 97, 115, 109]), {
      headers: { "content-type": "application/wasm", "cache-control": "no-store" },
    }));
  }
});
self.addEventListener("message", (event) => {
  if (event.data === "observations") event.ports[0]?.postMessage(observations.slice());
});
