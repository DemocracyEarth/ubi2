"use client";

/**
 * M6 Stage C1 — the Self SDK wrapper (spec 06b §5.1).
 *
 * Every OTHER file in this app imports the Self client SDK ONLY through this module. That is a
 * deliberate isolation seam (per the interface-engineer's hard constraint): if `@selfxyz/qrcode`
 * cannot be installed in some environment, this is the one file that needs a stub swapped in —
 * the dev/fixture and paste-bundle submit paths (`zk-passport.tsx`) do not import `@selfxyz/*`
 * at all and keep working unconditionally.
 *
 * INSTALL STATUS (this build): `@selfxyz/qrcode@1.0.24` installed cleanly from the public npm
 * registry (peer-dep warning only: `react-spinners` wants React 16-18, we run React 19 — cosmetic,
 * not a build blocker). `version: 2` is pinned per spec (the V1 API differs).
 */

import {
  SelfAppBuilder,
  getUniversalLink,
  SelfQRcodeWrapper,
  type SelfApp,
} from "@selfxyz/qrcode";

export { SelfQRcodeWrapper, getUniversalLink };
export type { SelfApp };

import { SELF_ENDPOINT, UBI2_SELF_SCOPE_SEED } from "./config";

export { SELF_ENDPOINT, UBI2_SELF_SCOPE_SEED };

/**
 * Build the ubi2 SelfApp descriptor (spec 06b §5.1).
 *
 *  - `scope` is pinned to the ONE canonical ubi2 scope (`UBI2_SELF_SCOPE_SEED`, spec §3) — never
 *    per-context, or one human could mint multiple nullifiers.
 *  - `userId` = the connected ubi2 address (`userIdType: "hex"`) — this is what makes the
 *    runtime's `user_identifier == tx sender` bind enforceable (spec §4.4 step 4): a proof
 *    generated for one address cannot be relayed and submitted from another.
 *  - `endpointType: "staging_https"` — Stage C1 targets the Self STAGING environment (accepts
 *    Self's mock/test passports for de-risking the plumbing before a real passport / production
 *    VK is pinned, spec §4.1 VK STATUS note). Mainnet would use `"https"` — never mix them
 *    (spec EC-F-C1).
 *  - `disclosures` requests the PUBLIC anonymous PoH traits (Phase B): `nationality` (ISO-3166
 *    alpha-3) + `gender` + `ofac`. These are low-entropy, non-identifying fields the runtime decodes
 *    from `revealedData_packed` and surfaces on the soulbound PoH NFT. Identity fields (`name`,
 *    `date_of_birth`, `passport_number`) are NEVER requested. Age flags (18+/21+/…) are added later via
 *    an OPTIONAL additional `minimumAge` proof — the deterministic nullifier accumulates them onto the
 *    same human without a DOB ever being disclosed.
 *
 * Throws if `endpoint` is empty or is a `localhost`/`127.0.0.1` URL — `@selfxyz/sdk-common`
 * enforces this because the Self app runs on a phone that cannot reach your laptop's loopback
 * address. Callers should catch this and show the reachability caveat rather than crash (see
 * `zk-passport.tsx`'s `SelfLivePanel`).
 */
export function buildSelfApp(address: string, endpoint: string): SelfApp {
  return new SelfAppBuilder({
    version: 2,
    appName: "ubi2",
    scope: UBI2_SELF_SCOPE_SEED,
    endpoint,
    endpointType: "staging_https",
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
