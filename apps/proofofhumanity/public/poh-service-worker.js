"use strict";

const VERSION = "poh-shell-lifecycle-v1";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("message", (event) => {
  if (event.data === "poh-version" && event.ports[0]) {
    event.ports[0].postMessage({ version: VERSION, cacheStorageUsed: false });
  }
});

// Deliberately no fetch event: private routes, recovery files, WebAuthn data and
// API requests are never observed or cached by the application service worker.
