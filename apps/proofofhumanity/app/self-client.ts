"use client";

/**
 * The Self client-SDK isolation seam (adapted from apps/wallet/app/self-client.ts).
 *
 * Every other client file imports `@selfxyz/qrcode` ONLY through this module, so the SDK dependency
 * is swappable/stubbable in one place. `@selfxyz/qrcode@1.0.24` is the installed, `version: 2`
 * (V2) SDK — the QR/deeplink builder that runs in the browser; the heavy backend verifier
 * (`@selfxyz/core`) is imported only server-side in api/self-verify/route.ts.
 */

import {
  SelfAppBuilder,
  getUniversalLink,
  SelfQRcodeWrapper,
  type SelfApp,
} from "@selfxyz/qrcode";

export { SelfQRcodeWrapper, getUniversalLink };
export type { SelfApp };

import { SELF_APP_NAME, SELF_SCOPE, SELF_ENDPOINT_TYPE } from "./config";

/**
 * Build the Proof-of-Humanity SelfApp descriptor.
 *
 *   - `scope`        = the ONE canonical scope (matches the backend verifier, or it rejects).
 *   - `endpoint`     = the public URL of THIS app's `/api/self-verify` relay.
 *   - `endpointType` = "staging_https" (staging) or "https" (production), in lockstep with the
 *                      backend `mockPassport` flag (see config.ts SELF_ENV).
 *   - `userId`/`userDefinedData` = the connected EVM address (`userIdType: "hex"`). This is what
 *                      binds the proof to the wallet: the disclosed `userIdentifier` the backend
 *                      reads out is exactly this address, and the voucher's `to` is set from it.
 *   - `disclosures`  = { nationality, gender, ofac } — the public anonymous traits the PoH token
 *                      carries. (Age flags come from an OPTIONAL second proof; see page.tsx.)
 *
 * Throws if `endpoint` is empty or a loopback URL — callers should catch and show the caveat.
 */
export function buildSelfApp(address: string, endpoint: string): SelfApp {
  return new SelfAppBuilder({
    version: 2,
    appName: SELF_APP_NAME,
    scope: SELF_SCOPE,
    endpoint,
    endpointType: SELF_ENDPOINT_TYPE,
    userId: address,
    userIdType: "hex",
    userDefinedData: address,
    disclosures: {
      nationality: true,
      gender: true,
      ofac: true,
    },
  }).build();
}
