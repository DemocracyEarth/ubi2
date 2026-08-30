"use client";

import { useEffect } from "react";

/**
 * The service worker intentionally has no fetch handler or Cache Storage. It
 * supplies install/standalone lifecycle only; encrypted vault data remains in
 * the dedicated IndexedDB store and all network requests keep browser defaults.
 */
export function PwaRegistration() {
  useEffect(() => {
    if (!("serviceWorker" in navigator) || !globalThis.isSecureContext) return;
    void navigator.serviceWorker.register("/poh-service-worker.js", { scope: "/" }).catch(() => {
      // PWA installation is optional; a failed registration must not change the identity flow.
    });
  }, []);
  return null;
}
