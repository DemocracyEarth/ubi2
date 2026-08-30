"use client";

/**
 * proofofhumanity.org — the landing site.
 *
 * A complete, brand-matched marketing + product page that explains the technology and its usage,
 * with the mint flow integrated at the bottom:
 *   Hero · Why · How it works · Privacy model · For builders/DAOs · Tech · Mint · Footer.
 *
 * The credential is MINIMAL: a Self zero-knowledge passport proof establishes a unique human and
 * yields a nullifier; the relay signs a slim { to, nullifier, epoch } voucher; the holder mints a
 * soulbound ERC-721 that stores only that nullifier + a coarse 90-day validity epoch. No
 * nationality / gender / age is ever disclosed to the chain. In v1, optional age/nationality facts
 * live in a private browser-held credential and the issuer signs consumer-bound Boolean results.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createPublicClient,
  createWalletClient,
  custom,
  http,
  defineChain,
  type Address,
  type Chain,
  type Hex,
} from "viem";
import { buildSelfApp, getUniversalLink, SelfQRcodeWrapper, type SelfApp } from "./self-client";
import { CHAINS, SELF_ENDPOINT, isDeployed, type ChainConfig } from "./config";
import { proofOfHumanityAbi } from "./abi/proofOfHumanity";
import type { SerializedHumanCredential } from "./lib/predicate";
import type { AgeThreshold, DisclosureProfile } from "./lib/disclosure-profile";
import { clearHeldCredential, saveHeldCredential } from "./lib/held-credential";
import {
  ACCOUNT_PRIVACY_REASON_LABELS,
  resolveWalletAccountChange,
  sameWalletAccount,
  scanAccountPrivacy,
  type AccountPrivacyAssessment,
} from "./lib/account-privacy";
import type { SponsoredMintEvidence, SponsoredMintPublicEvidence } from "./lib/sponsored-mint";
import { PredicateCenter } from "./predicates/predicate-center";
import { HolderVaultPanel, type HolderVaultTarget } from "./holder-vault-panel";

/*//////////////////////////////////////////////////////////////
                     BRAND ASSETS (from card-minimal-final.svg)
//////////////////////////////////////////////////////////////*/

/** The head emblem path — the single source of truth, reused by the card and the logo. */
const HEAD_PATH =
  "M 347.25 181.1 Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95 174.897265625 9.9517578125 173.65 9.95 172.40078125 9.9517578125 171.15 9.95 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1 0.0033203125 182.2296875 0 183.35 0.001953125 184.7263671875 0 186.1 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65 L 79.75 310.85 79.75 418.7 Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65 L 242.6 423.65 Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7 L 247.6 377.15 295.75 377.15 Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25 L 320.7 304.05 351.1 304.05 Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5 369.5890625 285.8658203125 369.2 283.3 369.8205078125 279.015625 368.4 274.95 L 347.25 212.2 347.25 181.1 M 332.3 218 Q 332.3 218.85 332.55 219.6 L 353.95 283.1 Q 353.980859375 283.1904296875 354 283.25 353.620703125 284.544140625 352.85 285.65 351.7 287.25 349.9 288.2 348.2853515625 289.007421875 346.5 289.05 L 310.7 289.05 Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05 L 305.7 347.55 Q 305.6390625 350.3458984375 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.8935546875 362.1400390625 291.05 362.2 L 237.6 362.2 Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2 L 232.6 408.7 94.75 408.7 94.75 303.05 Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8 L 74.95 288.15 Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.2994140625 198.1578125 14.95 183.05 15.5302734375 152.651171875 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.941796875 25.38046875 173.65 24.9 204.35625 25.38046875 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76171875 152.7470703125 332.3 183.3 L 332.3 218 M 234.25 188.1 Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35 L 229.25 183.35 Q 227.8 183.45 226.65 184.35 L 176.7 222.2 126.8 184.3 Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8 L 172.85 266.35 Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35 L 233.35 190.85 Q 234.25 189.65 234.25 188.1 M 174.4 77.35 Q 173.3 77.95 172.65 79.05 L 123.9 160.15 Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35 L 173.85 203.95 Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95 L 228.35 166.35 Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15 L 180.75 79.05 Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35 M 176.75 136.45 Q 177.6 136.45 178.4 136.8 L 219.8 155.55 Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95 L 178.2 145.65 Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65 L 137 162.95 Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55 L 175.05 136.8 Q 175.85 136.45 176.75 136.45 Z";

/** The LOCKED minimal card, as a self-contained SVG string. Only `HUMAN ID` is dynamic. */
function minimalCardSvg(humanId: string): string {
  return `<svg viewBox="0 0 1000 1000" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg" role="img"><title>Proof of Humanity — zero-knowledge</title>
<defs>
<linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FFE24B"/><stop offset="52%" stop-color="#FF9A55"/><stop offset="100%" stop-color="#FF6B8A"/></linearGradient>
<linearGradient id="ok" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#6EE7B7"/><stop offset="100%" stop-color="#22C55E"/></linearGradient>
<linearGradient id="card" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#101016"/><stop offset="100%" stop-color="#08080B"/></linearGradient>
<radialGradient id="glow" cx="50%" cy="27%" r="46%"><stop offset="0%" stop-color="#FF7A66" stop-opacity="0.16"/><stop offset="100%" stop-color="#000000" stop-opacity="0"/></radialGradient>
</defs>
<rect width="1000" height="1000" fill="#08080B"/>
<rect width="1000" height="1000" fill="url(#glow)"/>
<rect x="24" y="24" width="952" height="952" rx="44" fill="url(#card)" stroke="url(#g)" stroke-width="2"/>

<path d="M74 60 L79 78 L97 83 L79 88 L74 106 L69 88 L51 83 L69 78 Z" fill="url(#g)" opacity="0.9"/>
<text x="936" y="74" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="13" letter-spacing="3" fill="#C9A24E">HUMAN ID</text>
<text x="936" y="100" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="18" fill="#E8E8EC">${humanId}</text>

<path d="M656 250 L578 385 L422 385 L344 250 L422 115 L578 115 Z" fill="none" stroke="url(#g)" stroke-opacity="0.18" stroke-width="1.2" stroke-dasharray="2 9"/>
<circle cx="500" cy="250" r="146" fill="none" stroke="url(#g)" stroke-opacity="0.26" stroke-width="1" stroke-dasharray="1.5 7"/>
<circle cx="382" cy="250" r="3.5" fill="url(#g)"/>
<circle cx="618" cy="250" r="3.5" fill="url(#g)"/>
<circle cx="500" cy="250" r="118" fill="#0B0B10" stroke="url(#g)" stroke-opacity="0.5" stroke-width="1.5"/>
<g transform="translate(427,157) scale(0.42)"><path fill="url(#g)" d="${HEAD_PATH}"/></g>

<text x="500" y="452" text-anchor="middle" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="50" font-weight="800" letter-spacing="-1.5" fill="#F5F5F7">Proof of Humanity</text>
<text x="500" y="489" text-anchor="middle" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="21" font-weight="600" fill="url(#g)">Verified with Self</text>

<line x1="152" y1="537" x2="352" y2="537" stroke="url(#g)" stroke-opacity="0.4"/>
<line x1="648" y1="537" x2="848" y2="537" stroke="url(#g)" stroke-opacity="0.4"/>
<text x="500" y="542" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="13" letter-spacing="4.5" fill="#C9A24E">ZERO-KNOWLEDGE PROOF OF HUMANITY</text>

<rect x="60" y="562" width="880" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/>
<rect x="76" y="578" width="28" height="22" rx="3" fill="none" stroke="url(#g)" stroke-width="1.5"/>
<circle cx="85" cy="586" r="3.6" fill="none" stroke="url(#g)" stroke-width="1.4"/>
<line x1="93" y1="584" x2="100" y2="584" stroke="url(#g)" stroke-width="1.4"/><line x1="93" y1="590" x2="100" y2="590" stroke="url(#g)" stroke-width="1.4"/><line x1="80" y1="595" x2="100" y2="595" stroke="url(#g)" stroke-width="1.4" stroke-opacity="0.7"/>
<text x="130" y="596" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#EAEAEE">Valid passport</text>
<text x="856" y="596" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#F2F2F4">Verified</text>
<circle cx="900" cy="589" r="13" fill="none" stroke="url(#ok)" stroke-width="1.7"/>
<path d="M893 589 l5 5 l9 -9.5" fill="none" stroke="url(#ok)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>

<rect x="60" y="624" width="880" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/>
<circle cx="90" cy="645" r="6" fill="none" stroke="url(#g)" stroke-width="1.6"/>
<path d="M78 664 q12 -14 24 0" fill="none" stroke="url(#g)" stroke-width="1.6" stroke-linecap="round"/>
<text x="130" y="658" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#EAEAEE">Unique human</text>
<text x="856" y="658" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#F2F2F4">Verified</text>
<circle cx="900" cy="651" r="13" fill="none" stroke="url(#ok)" stroke-width="1.7"/>
<path d="M893 651 l5 5 l9 -9.5" fill="none" stroke="url(#ok)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>

<rect x="60" y="686" width="880" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/>
<rect x="82" y="712" width="18" height="13" rx="2" fill="none" stroke="url(#g)" stroke-width="1.6"/>
<path d="M85 712 v-4 a6 6 0 0 1 12 0 v4" fill="none" stroke="url(#g)" stroke-width="1.6"/>
<text x="130" y="720" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#EAEAEE">Personal data on-chain</text>
<text x="856" y="720" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="url(#ok)">None</text>
<circle cx="900" cy="713" r="13" fill="none" stroke="url(#ok)" stroke-width="1.7"/>
<path d="M893 713 l5 5 l9 -9.5" fill="none" stroke="url(#ok)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>

<text x="500" y="782" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="12" letter-spacing="3.5" fill="#C9A24E">PROVABLE ON DEMAND · NEVER STORED</text>
<g font-family="Helvetica,Arial,sans-serif" font-size="16" font-weight="500">
<rect x="60" y="800" width="280" height="50" rx="25" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/>
<g stroke="url(#g)" stroke-width="1.5" fill="none" stroke-linecap="round"><rect x="81" y="826" width="14" height="6" rx="1.5"/><line x1="88" y1="826" x2="88" y2="821"/></g><circle cx="88" cy="818.5" r="1.5" fill="url(#g)"/>
<text x="110" y="831" fill="#EDEDF1">Age 18+</text>
<rect x="360" y="800" width="280" height="50" rx="25" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/>
<g stroke="url(#g)" fill="none"><circle cx="388" cy="825" r="8" stroke-width="1.5"/><line x1="380" y1="825" x2="396" y2="825" stroke-width="1.3"/><path d="M388 817 C383 820 383 830 388 833" stroke-width="1.3"/><path d="M388 817 C393 820 393 830 388 833" stroke-width="1.3"/></g>
<text x="410" y="831" fill="#EDEDF1">Nationality</text>
<rect x="660" y="800" width="280" height="50" rx="25" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/>
<g fill="none" stroke="url(#g)" stroke-linecap="round" stroke-linejoin="round"><path d="M688 817 l7 3 v5 c0 4 -3 6.3 -7 7.6 c-4 -1.3 -7 -3.6 -7 -7.6 v-5 z" stroke-width="1.5"/><path d="M685 825 l2.2 2.2 l4 -4.4" stroke-width="1.6"/></g>
<text x="710" y="831" fill="#EDEDF1">Sanctions</text>
</g>

<path d="M244 903 l7 6 l-7 5 z" fill="url(#g)"/><path d="M244 903 l-7 6 l7 5 z" fill="url(#g)" opacity="0.55"/>
<text x="500" y="913" text-anchor="middle" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="13" font-weight="600" letter-spacing="2" fill="url(#g)">ONE HUMAN · ONE CREDENTIAL · SOULBOUND</text>
<path d="M756 903 l7 6 l-7 5 z" fill="url(#g)" opacity="0.55"/><path d="M756 903 l-7 6 l7 5 z" fill="url(#g)"/>
</svg>`;
}

function MinimalCard({ humanId, className }: { humanId: string; className?: string }) {
  return <div className={className} dangerouslySetInnerHTML={{ __html: minimalCardSvg(humanId) }} />;
}

function Emblem() {
  return (
    <svg viewBox="0 0 348 424" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id="eg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#FFE24B" />
          <stop offset="52%" stopColor="#FF9A55" />
          <stop offset="100%" stopColor="#FF6B8A" />
        </linearGradient>
      </defs>
      <path fill="url(#eg)" d={HEAD_PATH} />
    </svg>
  );
}

/** Shared gradient for the small stroke icons. */
function GradDefs() {
  return (
    <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden="true">
      <defs>
        <linearGradient id="ig" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#FFE24B" />
          <stop offset="52%" stopColor="#FF9A55" />
          <stop offset="100%" stopColor="#FF6B8A" />
        </linearGradient>
      </defs>
    </svg>
  );
}

type IconName = "shield" | "lock" | "globe" | "spark" | "check";
function Icon({ name }: { name: IconName }) {
  const s = { fill: "none", stroke: "url(#ig)", strokeWidth: 1.7, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  return (
    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      {name === "shield" && (
        <>
          <path {...s} d="M12 3l7 3v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6z" />
          <path {...s} d="M9 12l2.2 2.2L15.5 10" />
        </>
      )}
      {name === "lock" && (
        <>
          <rect {...s} x="5" y="11" width="14" height="9" rx="2.2" />
          <path {...s} d="M8 11V8a4 4 0 0 1 8 0v3" />
        </>
      )}
      {name === "globe" && (
        <>
          <circle {...s} cx="12" cy="12" r="9" />
          <path {...s} d="M3 12h18M12 3c3.2 3 3.2 15 0 18M12 3c-3.2 3-3.2 15 0 18" />
        </>
      )}
      {name === "spark" && (
        <path {...s} d="M12 3l2.1 5.6L20 10l-5.9 1.4L12 17l-2.1-5.6L4 10l5.9-1.4z" />
      )}
      {name === "check" && (
        <>
          <circle {...s} cx="12" cy="12" r="9" />
          <path {...s} d="M8.5 12.2l2.4 2.4 4.6-5" />
        </>
      )}
    </svg>
  );
}

/*//////////////////////////////////////////////////////////////
                         CLIENT-SIDE TYPES
//////////////////////////////////////////////////////////////*/

interface Injected {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: "accountsChanged", listener: (accounts: unknown[]) => void): void;
  removeListener?(event: "accountsChanged", listener: (accounts: unknown[]) => void): void;
}

interface SerializedVoucher {
  to: Address;
  nullifier: string;
  epoch: number;
}

interface SignedForChain {
  chainId: number;
  name: string;
  pohAddress: Address;
  voucher: SerializedVoucher;
  signature: Hex;
}

interface RelayReady {
  status: "ready";
  proof: { nullifier: string; epoch: number };
  vouchers: SignedForChain[];
  credential?: SerializedHumanCredential;
  credentialSig?: Hex;
  issuer?: Address;
  sponsoredChainIds: number[];
}

type Phase = "connect" | "scan" | "waiting" | "ready" | "minting" | "minted";
type AccountPrivacyUiState = { status: "idle" | "scanning" } | AccountPrivacyAssessment;

interface Minted {
  tokenId: bigint;
  tokenURI: string;
  valid: boolean;
  locked: boolean;
  nullifier: bigint;
  sponsoredEvidence?: SponsoredMintEvidence;
}

function getInjected(): Injected | null {
  if (typeof window === "undefined") return null;
  return (window as unknown as { ethereum?: Injected }).ethereum ?? null;
}

function errMessage(e: unknown): string {
  if (e && typeof e === "object" && "shortMessage" in e) return String((e as { shortMessage: unknown }).shortMessage);
  if (e instanceof Error) return e.message;
  return String(e);
}

function short(addr: string): string {
  return addr && addr.length >= 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;
}

/** The anonymous HUMAN ID shown on the card: 0x + first 4 + … + last 4 hex of the nullifier. */
function humanIdFromNullifier(n: bigint): string {
  const hex = n.toString(16).padStart(64, "0");
  return `0x${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

function newVerificationSession(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function viemChain(c: ChainConfig): Chain {
  return defineChain({
    id: c.chainId,
    name: c.name,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [c.rpcUrl] } },
    ...(c.explorer ? { blockExplorers: { default: { name: "Explorer", url: c.explorer } } } : {}),
  });
}

/*//////////////////////////////////////////////////////////////
                            MINT FLOW
//////////////////////////////////////////////////////////////*/

function MintFlow() {
  const [injected, setInjected] = useState<Injected | null>(null);
  const [account, setAccount] = useState<Address | null>(null);
  const [phase, setPhase] = useState<Phase>("connect");
  const [selfApp, setSelfApp] = useState<SelfApp | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [ready, setReady] = useState<RelayReady | null>(null);
  const [selectedChainId, setSelectedChainId] = useState<number | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err" | "warn"; text: string } | null>(null);
  const [minted, setMinted] = useState<Minted | null>(null);
  const [mintMethod, setMintMethod] = useState<"sponsored" | "wallet" | null>(null);
  const [verificationSession, setVerificationSession] = useState<string | null>(null);
  const [privacyAcknowledged, setPrivacyAcknowledged] = useState(false);
  const [privacyScan, setPrivacyScan] = useState<AccountPrivacyUiState>({ status: "idle" });
  const [ageThreshold, setAgeThreshold] = useState<AgeThreshold>(null);
  const [includeNationality, setIncludeNationality] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const accountRef = useRef<Address | null>(null);
  const verificationSessionRef = useRef<string | null>(null);
  const verificationBindingRef = useRef<string | null>(null);
  const privacyScanRequestRef = useRef(0);

  const disclosureProfile = useMemo<DisclosureProfile>(
    () => ({ age: ageThreshold, nationality: includeNationality }),
    [ageThreshold, includeNationality],
  );

  useEffect(() => setInjected(getInjected()), []);

  const stopPolling = useCallback(() => {
    if (pollTimer.current) {
      clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  const resetAccountSession = useCallback(
    (
      nextAccount: Address | null,
      nextNote: { kind: "ok" | "err" | "warn"; text: string } | null,
    ) => {
      const previousAccount = accountRef.current;
      const previousSession = verificationSessionRef.current;
      stopPolling();
      privacyScanRequestRef.current += 1;
      verificationBindingRef.current = null;
      verificationSessionRef.current = null;
      if (previousAccount && previousSession) {
        fetch(`/api/self-verify?address=${previousAccount}`, {
          method: "DELETE",
          headers: { "x-poh-verification-session": previousSession },
        }).catch(() => {});
      }
      if (previousAccount !== null || previousSession !== null) clearHeldCredential();
      accountRef.current = nextAccount;
      setAccount(nextAccount);
      setVerificationSession(null);
      setPrivacyAcknowledged(false);
      setPrivacyScan({ status: "idle" });
      setSelfApp(null);
      setBuildError(null);
      setReady(null);
      setSelectedChainId(null);
      setMinted(null);
      setMintMethod(null);
      setPhase("connect");
      setNote(nextNote);
    },
    [stopPolling],
  );

  const applyWalletAccounts = useCallback(
    (accounts: readonly unknown[], source: "connect" | "change"): Address | null => {
      const previousAccount = accountRef.current;
      const change = resolveWalletAccountChange(previousAccount, accounts);
      if (change.account === previousAccount) return change.account;
      resetAccountSession(
        change.account,
        source === "change" && change.invalidatesSession
          ? {
              kind: "warn",
              text: change.account
                ? "Wallet account changed. The previous Self session and voucher were discarded; review and acknowledge the new credential account."
                : "Wallet disconnected. The previous Self session and voucher were discarded.",
            }
          : null,
      );
      return change.account;
    },
    [resetAccountSession],
  );

  useEffect(() => {
    if (!injected?.on) return;
    const onAccountsChanged = (accounts: unknown[]) => {
      applyWalletAccounts(accounts, "change");
    };
    injected.on("accountsChanged", onAccountsChanged);
    return () => injected.removeListener?.("accountsChanged", onAccountsChanged);
  }, [applyWalletAccounts, injected]);

  useEffect(() => {
    if (!account || !privacyAcknowledged || !verificationSession) {
      setSelfApp(null);
      return;
    }
    if (!SELF_ENDPOINT) {
      setSelfApp(null);
      return;
    }
    try {
      setSelfApp(buildSelfApp(account, SELF_ENDPOINT, disclosureProfile, verificationSession));
      setBuildError(null);
    } catch (e) {
      setSelfApp(null);
      setBuildError(errMessage(e));
    }
  }, [account, disclosureProfile, privacyAcknowledged, verificationSession]);

  const connect = useCallback(async () => {
    if (!injected) {
      setNote({ kind: "err", text: "No injected wallet detected — install MetaMask or another EIP-1193 wallet." });
      return;
    }
    try {
      const accounts = (await injected.request({ method: "eth_requestAccounts" })) as unknown[];
      if (applyWalletAccounts(accounts, "connect") === null) throw new Error("No valid account returned.");
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    }
  }, [applyWalletAccounts, injected]);

  const chooseAnotherAccount = useCallback(async () => {
    if (!injected) return;
    const previousAccount = accountRef.current;
    try {
      await injected.request({ method: "wallet_requestPermissions", params: [{ eth_accounts: {} }] });
      const accounts = (await injected.request({ method: "eth_accounts" })) as unknown[];
      const nextAccount = applyWalletAccounts(accounts, "change");
      if (nextAccount === previousAccount) {
        setNote({
          kind: "warn",
          text: "The wallet kept the same account. Open its account selector if you want to use a dedicated credential account.",
        });
      }
    } catch (e) {
      const code = e && typeof e === "object" ? (e as { code?: number }).code : undefined;
      setNote({
        kind: "warn",
        text:
          code === 4001
            ? "Account selection was canceled."
            : "This wallet cannot open its account selector here. Switch accounts in the wallet; the app will detect the change and reset safely.",
      });
    }
  }, [applyWalletAccounts, injected]);

  const setPrivacyAcknowledgement = useCallback(
    (acknowledged: boolean) => {
      const activeAccount = accountRef.current;
      if (!activeAccount) return;
      if (!acknowledged) {
        resetAccountSession(activeAccount, {
          kind: "warn",
          text: "Privacy acknowledgment removed. Complete it again before starting a Self verification.",
        });
        return;
      }
      const session = newVerificationSession();
      verificationSessionRef.current = session;
      verificationBindingRef.current = `${activeAccount.toLowerCase()}:${session}`;
      setVerificationSession(session);
      setPrivacyAcknowledged(true);
      setPhase("scan");
      setNote(null);
    },
    [resetAccountSession],
  );

  const runPrivacyScan = useCallback(async () => {
    const activeAccount = accountRef.current;
    if (!activeAccount) return;
    const requestId = privacyScanRequestRef.current + 1;
    privacyScanRequestRef.current = requestId;
    setPrivacyScan({ status: "scanning" });
    const scanChains = CHAINS.filter(isDeployed);
    const assessment = await scanAccountPrivacy({
      account: activeAccount,
      chains: scanChains,
      probe: async (chain, probedAccount) => {
        const client = createPublicClient({
          chain: viemChain(chain),
          transport: http(chain.rpcUrl, { retryCount: 0, timeout: 5_000 }),
        });
        const blockNumber = await client.getBlockNumber();
        const [transactionCount, nativeBalance, bytecode, pohBalance] = await Promise.all([
          client.getTransactionCount({ address: probedAccount, blockNumber }),
          client.getBalance({ address: probedAccount, blockNumber }),
          client.getBytecode({ address: probedAccount, blockNumber }),
          client.readContract({
            address: chain.pohAddress,
            abi: proofOfHumanityAbi,
            functionName: "balanceOf",
            args: [probedAccount],
            blockNumber,
          }),
        ]);
        return { transactionCount, nativeBalance, bytecode, pohBalance };
      },
    });
    if (privacyScanRequestRef.current === requestId && sameWalletAccount(accountRef.current, activeAccount)) {
      setPrivacyScan(assessment);
    }
  }, []);

  const startPolling = useCallback(() => {
    if (!account || !verificationSession) return;
    const binding = `${account.toLowerCase()}:${verificationSession}`;
    if (verificationBindingRef.current !== binding) return;
    stopPolling();
    pollTimer.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/self-verify?address=${account}`, {
          headers: { "x-poh-verification-session": verificationSession },
        });
        const data = (await res.json()) as {
          status: string;
          proof?: RelayReady["proof"];
          vouchers?: SignedForChain[];
          credential?: SerializedHumanCredential;
          credentialSig?: Hex;
          issuer?: Address;
          sponsoredChainIds?: number[];
          error?: string;
        };
        if (verificationBindingRef.current !== binding) return;
        if (data.status === "ready" && data.vouchers && data.proof) {
          if (data.vouchers.some(({ voucher }) => !sameWalletAccount(voucher.to, account))) {
            setNote({ kind: "err", text: "Relay returned a voucher for a different wallet account." });
            setPhase("scan");
            stopPolling();
            return;
          }
          const nextReady: RelayReady = {
            status: "ready",
            proof: data.proof,
            vouchers: data.vouchers,
            credential: data.credential,
            credentialSig: data.credentialSig,
            issuer: data.issuer,
            sponsoredChainIds: data.sponsoredChainIds ?? [],
          };
          setReady(nextReady);
          if (data.credential && data.credentialSig) {
            saveHeldCredential({ credential: data.credential, credentialSig: data.credentialSig, issuer: data.issuer });
          }
          setSelectedChainId(data.vouchers[0]?.chainId ?? null);
          setPhase("ready");
          stopPolling();
          if (!data.vouchers.length) {
            setNote({
              kind: "warn",
              text: "Proof verified, but no chain has a deployed ProofOfHumanity address configured.",
            });
          }
        } else if (data.status === "error") {
          setNote({ kind: "err", text: data.error ?? "Relay reported an error." });
          setPhase("scan");
          stopPolling();
        }
      } catch {
        /* transient — keep polling */
      }
    }, 2500);
  }, [account, stopPolling, verificationSession]);

  const onQrSuccess = useCallback(() => {
    if (!privacyAcknowledged || !verificationSession) {
      setNote({ kind: "err", text: "Acknowledge the credential-account privacy notice before verifying." });
      return;
    }
    setPhase("waiting");
    setNote({ kind: "ok", text: "Self reported success — verifying your proof and signing the voucher…" });
    startPolling();
  }, [privacyAcknowledged, startPolling, verificationSession]);

  const onQrError = useCallback((data: { error_code?: string; reason?: string }) => {
    setNote({ kind: "err", text: `Self app error: ${data.reason ?? data.error_code ?? "unknown"}` });
  }, []);

  const selected = useMemo<SignedForChain | null>(
    () => ready?.vouchers.find((v) => v.chainId === selectedChainId) ?? null,
    [ready, selectedChainId],
  );
  const selectedChain = useMemo(
    () => (selected ? CHAINS.find((chain) => chain.chainId === selected.chainId) ?? null : null),
    [selected],
  );
  const holderVaultTarget = useMemo<HolderVaultTarget | null>(() => {
    const chain = selectedChain ?? CHAINS.find((candidate) => candidate.network === "testnet" && isDeployed(candidate));
    if (!chain) return null;
    const proofBinding = selected
      ? JSON.stringify([
          "org.proofofhumanity.testnet-voucher-binding",
          1,
          selected.chainId,
          selected.pohAddress.toLowerCase(),
          selected.voucher.to.toLowerCase(),
          selected.voucher.nullifier,
          selected.voucher.epoch,
          selected.signature.toLowerCase(),
        ])
      : null;
    return { chainId: chain.chainId, name: chain.name, network: chain.network, proofBinding };
  }, [selected, selectedChain]);

  // The chain menu shown inside step 3: every marketed chain, each paired with its
  // deployed voucher if one exists, plus any deployed chain not in the marketed set.
  const displayChains = useMemo(() => {
    const marketed = MINT_CHAINS.map((c) => ({
      ...c,
      voucher: ready?.vouchers.find((v) => chainStyle(v.name).dot === c.id) ?? null,
    }));
    const extra = (ready?.vouchers ?? [])
      .filter((v) => !MINT_CHAINS.some((c) => c.id === chainStyle(v.name).dot))
      .map((v) => ({ id: `v${v.chainId}`, dot: chainStyle(v.name).dot, label: chainStyle(v.name).label, voucher: v }));
    return [...marketed, ...extra];
  }, [ready]);

  const ensureChain = useCallback(
    async (chain: Chain) => {
      if (!injected) return;
      const hexId = `0x${chain.id.toString(16)}`;
      try {
        await injected.request({ method: "wallet_switchEthereumChain", params: [{ chainId: hexId }] });
      } catch (e) {
        if (e && typeof e === "object" && (e as { code?: number }).code === 4902) {
          await injected.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: hexId,
                chainName: chain.name,
                nativeCurrency: chain.nativeCurrency,
                rpcUrls: chain.rpcUrls.default.http,
                blockExplorerUrls: chain.blockExplorers ? [chain.blockExplorers.default.url] : undefined,
              },
            ],
          });
        } else {
          throw e;
        }
      }
    },
    [injected],
  );

  const mint = useCallback(async () => {
    if (!injected || !account || !selected || !privacyAcknowledged) return;
    const binding = verificationBindingRef.current;
    if (binding === null) return;
    const chainCfg = CHAINS.find((c) => c.chainId === selected.chainId);
    if (!chainCfg) return;
    const chain = viemChain(chainCfg);

    try {
      const activeAccounts = (await injected.request({ method: "eth_accounts" })) as unknown[];
      const activeAccount = resolveWalletAccountChange(account, activeAccounts).account;
      if (!sameWalletAccount(activeAccount, account)) {
        resetAccountSession(activeAccount, {
          kind: "warn",
          text: "The wallet account changed before minting. The previous voucher was discarded; verify again with the intended credential account.",
        });
        return;
      }
      if (!sameWalletAccount(selected.voucher.to, account)) {
        setNote({ kind: "err", text: "The selected voucher belongs to a different wallet account." });
        return;
      }
      setPhase("minting");
      setMintMethod("wallet");
      setNote(null);
      await ensureChain(chain);
      if (verificationBindingRef.current !== binding) return;

      const wallet = createWalletClient({ account, chain, transport: custom(injected) });
      const pub = createPublicClient({ chain, transport: http(chainCfg.rpcUrl) });

      const sv = selected.voucher;
      const voucherArg = {
        to: sv.to,
        nullifier: BigInt(sv.nullifier),
        epoch: sv.epoch,
      } as const;

      const hash = await wallet.writeContract({
        address: chainCfg.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "mintWithVoucher",
        args: [voucherArg, selected.signature],
      });
      setNote({ kind: "ok", text: `Submitted · tx ${short(hash)} · waiting for confirmation…` });
      await pub.waitForTransactionReceipt({ hash });
      if (verificationBindingRef.current !== binding) return;

      const nullifier = BigInt(sv.nullifier);
      const tokenId = await pub.readContract({
        address: chainCfg.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "tokenOfNullifier",
        args: [nullifier],
      });
      const [tokenURI, valid, locked] = await Promise.all([
        pub.readContract({ address: chainCfg.pohAddress, abi: proofOfHumanityAbi, functionName: "tokenURI", args: [tokenId] }),
        pub.readContract({ address: chainCfg.pohAddress, abi: proofOfHumanityAbi, functionName: "isValid", args: [tokenId] }),
        pub.readContract({ address: chainCfg.pohAddress, abi: proofOfHumanityAbi, functionName: "locked", args: [tokenId] }),
      ]);

      setMinted({ tokenId, tokenURI: tokenURI as string, valid: valid as boolean, locked: locked as boolean, nullifier });
      setPhase("minted");
      setNote({ kind: "ok", text: `Minted Proof of Humanity #${tokenId} on ${chainCfg.name}.` });
      if (verificationSession) {
        fetch(`/api/self-verify?address=${account}`, {
          method: "DELETE",
          headers: { "x-poh-verification-session": verificationSession },
        }).catch(() => {});
      }
    } catch (e) {
      if (verificationBindingRef.current !== binding) return;
      setNote({ kind: "err", text: errMessage(e) });
      setPhase("ready");
      setMintMethod(null);
    }
  }, [
    injected,
    account,
    selected,
    privacyAcknowledged,
    ensureChain,
    resetAccountSession,
    verificationSession,
  ]);

  const sponsoredMint = useCallback(async () => {
    if (!injected || !account || !selected || !privacyAcknowledged || !verificationSession) return;
    const binding = verificationBindingRef.current;
    if (binding === null) return;
    const chainCfg = CHAINS.find((chain) => chain.chainId === selected.chainId);
    if (!chainCfg || chainCfg.network !== "testnet") {
      setNote({ kind: "err", text: "Sponsored minting is available only on configured testnets." });
      return;
    }

    try {
      const activeAccounts = (await injected.request({ method: "eth_accounts" })) as unknown[];
      const activeAccount = resolveWalletAccountChange(account, activeAccounts).account;
      if (!sameWalletAccount(activeAccount, account)) {
        resetAccountSession(activeAccount, {
          kind: "warn",
          text: "The wallet account changed before sponsorship. The previous voucher was discarded; verify again with the intended credential account.",
        });
        return;
      }
      if (!sameWalletAccount(selected.voucher.to, account)) {
        setNote({ kind: "err", text: "The selected voucher belongs to a different wallet account." });
        return;
      }

      setPhase("minting");
      setMintMethod("sponsored");
      setNote({ kind: "ok", text: "Requesting testnet sponsorship for the proof-bound credential account…" });

      const url = `/api/sponsored-mint?address=${account}&chainId=${selected.chainId}`;
      const request = async (method: "POST" | "GET") => {
        const response = await fetch(url, {
          method,
          headers: { "x-poh-verification-session": verificationSession },
        });
        const data = (await response.json()) as {
          ok?: boolean;
          status?: string;
          evidence?: SponsoredMintPublicEvidence | null;
          error?: string;
        };
        if (!response.ok && response.status !== 202) {
          throw new Error(data.error ?? "Testnet sponsorship is unavailable.");
        }
        return { response, data };
      };

      let result = await request("POST");
      for (let poll = 0; result.response.status === 202 && poll < 40; poll += 1) {
        if (verificationBindingRef.current !== binding) return;
        const submission = result.data.evidence;
        setNote({
          kind: "ok",
          text:
            submission?.status === "submitted"
              ? `Sponsor submitted · tx ${short(submission.transactionHash)} · waiting for confirmation…`
              : "Sponsor is preparing the bound testnet transaction…",
        });
        await new Promise((resolve) => window.setTimeout(resolve, 3_000));
        result = await request("GET");
      }
      if (verificationBindingRef.current !== binding) return;
      const evidence = result.data.evidence;
      if (!evidence || evidence.status !== "confirmed") {
        throw new Error("The sponsor transaction is still pending. Retry to recover its receipt.");
      }
      if (
        evidence.chainId !== chainCfg.chainId ||
        !sameWalletAccount(evidence.contract, chainCfg.pohAddress) ||
        !sameWalletAccount(evidence.recipient, account)
      ) {
        throw new Error("Sponsored receipt evidence does not match the selected account and chain.");
      }

      const tokenId = BigInt(evidence.tokenId);
      const nullifier = BigInt(selected.voucher.nullifier);
      const pub = createPublicClient({ chain: viemChain(chainCfg), transport: http(chainCfg.rpcUrl) });
      const [owner, onchainTokenId, tokenURI, valid, locked] = await Promise.all([
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "ownerOf",
          args: [tokenId],
        }),
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "tokenOfNullifier",
          args: [nullifier],
        }),
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "tokenURI",
          args: [tokenId],
        }),
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "isValid",
          args: [tokenId],
        }),
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "locked",
          args: [tokenId],
        }),
      ]);
      if (!sameWalletAccount(owner, account) || onchainTokenId !== tokenId || !valid || !locked) {
        throw new Error("The confirmed sponsor receipt does not match the credential contract state.");
      }

      setMinted({
        tokenId,
        tokenURI: tokenURI as string,
        valid: valid as boolean,
        locked: locked as boolean,
        nullifier,
        sponsoredEvidence: evidence,
      });
      setPhase("minted");
      setNote({
        kind: "ok",
        text: `Sponsored Proof of Humanity #${tokenId} on ${chainCfg.name}; no credential-account gas was required.`,
      });
    } catch (error) {
      if (verificationBindingRef.current !== binding) return;
      setNote({ kind: "err", text: errMessage(error) });
      setPhase("ready");
      setMintMethod(null);
    }
  }, [
    injected,
    account,
    selected,
    privacyAcknowledged,
    verificationSession,
    resetAccountSession,
  ]);

  const decodedMetadata = useMemo(() => {
    if (!minted) return null;
    const uri = minted.tokenURI;
    const prefix = "data:application/json;base64,";
    if (!uri.startsWith(prefix)) return uri;
    try {
      return atob(uri.slice(prefix.length));
    } catch {
      return uri;
    }
  }, [minted]);

  const stepConnectDone = !!account && privacyAcknowledged;
  const stepProofDone = !!ready;

  return (
    <div className="mint-wrap">
      {/* Left: the flow */}
      <div className="panel">
        {/* STEP 1 — connect */}
        <div className={`step-row${stepConnectDone ? " done" : ""}`}>
          <div className="step-badge">{stepConnectDone ? "✓" : "1"}</div>
          <div className="step-body">
            <h4>Choose your credential account</h4>
            <div className="account-privacy-card">
              <div className="account-privacy-head">
                <b>Use a dedicated account for better privacy</b>
                <span className="pill">recommended</span>
              </div>
              <p>
                Your Proof of Humanity address and soulbound credential are public and permanent. An account used
                only for this credential reduces links to your payments, ENS, DeFi, voting, and social activity.
              </p>
              <p className="muted small">
                This does not make you anonymous: funding, later usage, and the current credential identifier can
                still create links.
              </p>
            </div>
            {account ? (
              <>
                <div className="row account-privacy-actions">
                  <span className="mono">{short(account)}</span>
                  <span className="pill ok">connected</span>
                  <button
                    className="btn ghost sm"
                    type="button"
                    onClick={chooseAnotherAccount}
                    disabled={phase === "waiting" || phase === "minting"}
                  >
                    Choose another account
                  </button>
                  <button
                    className="btn ghost sm"
                    type="button"
                    onClick={runPrivacyScan}
                    disabled={privacyScan.status === "scanning" || phase === "waiting" || phase === "minting"}
                  >
                    {privacyScan.status === "scanning" ? "Checking activity…" : "Optional activity check"}
                  </button>
                </div>
                <p className="muted small account-privacy-disclosure">
                  The optional check sends this public address to every configured chain RPC. It looks only for
                  obvious activity and can never prove that an account is fresh, private, or unlinkable.
                </p>

                {privacyScan.status === "scanning" && (
                  <div className="notice warn" role="status">
                    Checking configured networks. This never blocks verification or minting.
                  </div>
                )}
                {privacyScan.status === "activity-detected" && (
                  <div className="notice warn" role="status">
                    <b>Prior activity detected — warning only.</b> You can continue, or switch to a more dedicated
                    account.
                    <ul className="account-privacy-findings">
                      {privacyScan.findings.map((finding) => (
                        <li key={finding.chainId}>
                          {finding.chainName}:{" "}
                          {finding.reasons.map((reason) => ACCOUNT_PRIVACY_REASON_LABELS[reason]).join(", ")}
                        </li>
                      ))}
                    </ul>
                    {privacyScan.unavailableChains.length > 0 && (
                      <span>
                        Check unavailable on: {privacyScan.unavailableChains.join(", ")}.
                      </span>
                    )}
                  </div>
                )}
                {privacyScan.status === "incomplete" && (
                  <div className="notice warn" role="status">
                    <b>Activity check incomplete.</b> No obvious activity was found on {privacyScan.checkedChains}{" "}
                    reachable network(s). Unavailable:{" "}
                    {privacyScan.unavailableChains.join(", ") || "all configured networks"}. This is not proof of
                    freshness.
                  </div>
                )}
                {privacyScan.status === "no-obvious-activity" && (
                  <div className="notice ok" role="status">
                    <b>No obvious prior activity detected</b> on {privacyScan.checkedChains} configured network(s).
                    This is a limited warning check, not proof that the account is fresh or anonymous.
                  </div>
                )}

                <label className="account-privacy-ack">
                  <input
                    type="checkbox"
                    checked={privacyAcknowledged}
                    onChange={(event) => setPrivacyAcknowledgement(event.target.checked)}
                    disabled={phase === "waiting" || phase === "minting" || phase === "minted" || ready !== null}
                  />
                  <span>
                    I understand that this address and credential are public and permanent, and that using a
                    dedicated account is recommended.
                  </span>
                </label>
              </>
            ) : (
              <div className="account-connect-action">
                <p className="muted small">Create or select the account in your wallet before connecting.</p>
                <button className="btn primary sm" onClick={connect}>
                  {injected ? "Connect credential account" : "No wallet detected"}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* STEP 2 — Self proof */}
        <div className={`step-row${!stepConnectDone ? " disabled" : stepProofDone ? " done" : ""}`}>
          <div className="step-badge">{stepProofDone ? "✓" : "2"}</div>
          <div className="step-body">
            <h4>Prove you are human with Self</h4>

            {!account && <p className="muted small">Connect a credential account first.</p>}
            {account && !privacyAcknowledged && (
              <p className="muted small">Review and acknowledge the public credential-account notice first.</p>
            )}

            {stepConnectDone && !SELF_ENDPOINT && (
              <div className="notice warn">
                <b>Live QR not configured.</b> Set <code>NEXT_PUBLIC_SELF_ENDPOINT</code> to this app&apos;s publicly
                reachable <code>/api/self-verify</code> URL (a tunnel like ngrok/cloudflared in dev, or the deployed
                origin in prod). The Self mobile app cannot reach <code>localhost</code>.
              </div>
            )}

            {stepConnectDone && buildError && (
              <div className="notice err">Could not build the Self request: {buildError}</div>
            )}

            {account && (phase === "scan" || phase === "waiting") && (
              <div className="disclosure-picker">
                <div>
                  <b>Prepare private predicate claims</b>
                  <p className="muted small">
                    Optional. Your exact birth date is never requested or stored. Choosing nationality reveals its
                    three-letter country code to the issuer so it can sign a private browser-held credential.
                  </p>
                </div>
                <label>
                  <span>Age proof</span>
                  <select
                    value={ageThreshold ?? ""}
                    onChange={(event) => {
                      const value = Number(event.target.value);
                      setAgeThreshold(value === 18 ? 18 : value === 21 ? 21 : null);
                    }}
                    disabled={phase === "waiting"}
                  >
                    <option value="">Not requested</option>
                    <option value="18">18+ (also sanctions)</option>
                    <option value="21">21+ (also proves 18+)</option>
                  </select>
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={includeNationality}
                    onChange={(event) => setIncludeNationality(event.target.checked)}
                    disabled={phase === "waiting"}
                  />
                  <span>Include nationality for private comparisons</span>
                </label>
                <span className="pill ok">Sanctions-clear is always required</span>
              </div>
            )}

            {account && SELF_ENDPOINT && selfApp && (phase === "scan" || phase === "waiting") && (
              <div className="row" style={{ alignItems: "flex-start", gap: "1.1rem" }}>
                <div className="qr">
                  <SelfQRcodeWrapper selfApp={selfApp} onSuccess={onQrSuccess} onError={onQrError} />
                </div>
                <div style={{ flex: 1, minWidth: 170 }}>
                  <p className="muted small">Scan with the Self app, or open it on this device:</p>
                  <a className="btn ghost sm" href={getUniversalLink(selfApp)} target="_blank" rel="noreferrer">
                    Open in Self →
                  </a>
                  {phase === "waiting" && (
                    <p className="small" style={{ color: "var(--ok-2)", marginTop: "0.7rem" }}>
                      Verifying and signing…
                    </p>
                  )}
                  <p className="muted small" style={{ marginTop: "0.8rem" }}>
                    Your passport is scanned on-device. No name, document number, face, or birth date is sent to us.
                    The issuer receives only the claims you selected above plus the mandatory sanctions result.
                  </p>
                </div>
              </div>
            )}

            {stepConnectDone && SELF_ENDPOINT && ready && phase !== "scan" && phase !== "waiting" && (
              <div className="notice ok">
                Unique human verified. Voucher signed for {ready.vouchers.length} chain(s); private predicate
                credential saved for this browser session.
              </div>
            )}
          </div>
        </div>

        {/* STEP 3 — mint */}
        <div className={`step-row${!ready ? " disabled" : minted ? " done" : ""}`}>
          <div className="step-badge">{minted ? "✓" : "3"}</div>
          <div className="step-body">
            <h4>Mint your soulbound credential</h4>

            {ready && (
              <div className="row" style={{ marginBottom: "0.85rem" }}>
                <span className="pill">
                  <b style={{ color: "var(--gold)" }}>HUMAN ID</b> {humanIdFromNullifier(BigInt(ready.proof.nullifier))}
                </span>
                <span className="pill">epoch {ready.proof.epoch}</span>
              </div>
            )}

            <span className="cs-label">
              {ready ? "Choose a chain to mint on" : "One credential — mint it on any of these"}
            </span>
            <div className="mint-chains" role="listbox" aria-label="Chain to mint on">
              {displayChains.map((c) => {
                const isSel = !!c.voucher && c.voucher.chainId === selectedChainId;
                const mintable = !!c.voucher;
                return (
                  <button
                    key={c.id}
                    type="button"
                    role="option"
                    aria-selected={isSel}
                    className={`chainpick${isSel ? " sel" : ""}${ready && !mintable ? " soon" : ""}`}
                    onClick={() => c.voucher && setSelectedChainId(c.voucher.chainId)}
                    disabled={phase === "minting" || !mintable}
                  >
                    <span className={`cdot ${c.dot}`} />
                    {c.label}
                    {ready && !mintable && <span className="soon-tag">soon</span>}
                  </button>
                );
              })}
            </div>

            {selectedChain?.network === "testnet" && ready?.sponsoredChainIds.includes(selectedChain.chainId) ? (
              <div className="sponsored-mint-choice">
                <button
                  className="btn primary sm"
                  onClick={sponsoredMint}
                  disabled={!ready || phase === "minting" || !selected}
                >
                  {phase === "minting" && mintMethod === "sponsored"
                    ? "Sponsor minting…"
                    : `Sponsored mint on ${chainStyle(selected?.name ?? selectedChain.name).label}`}
                </button>
                <p className="muted small">
                  Recommended for a dedicated credential account: the testnet sponsor pays gas, so you do not need
                  to fund this account from another wallet. Availability is rate- and budget-limited.
                </p>
                <button
                  className="btn ghost sm"
                  onClick={mint}
                  disabled={!ready || phase === "minting" || !selected}
                >
                  {phase === "minting" && mintMethod === "wallet" ? "Wallet minting…" : "Mint with wallet instead"}
                </button>
              </div>
            ) : (
              <button
                className="btn primary sm"
                onClick={mint}
                disabled={!ready || phase === "minting" || !selected}
                style={{ marginTop: "1rem" }}
              >
                {!ready
                  ? "Complete the Self proof first"
                  : phase === "minting"
                    ? "Minting…"
                    : selected
                      ? `Mint on ${chainStyle(selected.name).label}`
                      : "Select a deployed chain"}
              </button>
            )}
          </div>
        </div>

        {account && privacyAcknowledged && verificationSession && holderVaultTarget && (
          <HolderVaultPanel
            key={`${account.toLowerCase()}:${verificationSession}`}
            account={account}
            verificationSession={verificationSession}
            target={holderVaultTarget}
          />
        )}

        {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
      </div>

      {/* Right: the credential preview / result */}
      <div className="panel">
        {minted ? (
          <>
            <MinimalCard className="minted-card" humanId={humanIdFromNullifier(minted.nullifier)} />
            <div style={{ marginTop: "0.6rem" }}>
              <div className="kv">
                <span className="k">Token</span>
                <span className="mono">Proof of Humanity #{minted.tokenId.toString()}</span>
              </div>
              <div className="kv">
                <span className="k">Status</span>
                <span>{minted.valid ? "Valid ✓" : "Expired — re-verify"}</span>
              </div>
              <div className="kv">
                <span className="k">Transfer</span>
                <span>{minted.locked ? "Soulbound (ERC-5192)" : "transferable"}</span>
              </div>
              {minted.sponsoredEvidence && (
                <div className="sponsored-receipt" aria-label="Sponsored mint receipt evidence">
                  <div className="account-privacy-head">
                    <b>Sponsored mint receipt</b>
                    <span className="pill ok">confirmed</span>
                  </div>
                  <div className="kv">
                    <span className="k">Transaction</span>
                    {CHAINS.find((chain) => chain.chainId === minted.sponsoredEvidence?.chainId)?.explorer ? (
                      <a
                        className="mono tech-link"
                        href={`${CHAINS.find((chain) => chain.chainId === minted.sponsoredEvidence?.chainId)?.explorer}/tx/${minted.sponsoredEvidence.transactionHash}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {short(minted.sponsoredEvidence.transactionHash)} ↗
                      </a>
                    ) : (
                      <span className="mono">{short(minted.sponsoredEvidence.transactionHash)}</span>
                    )}
                  </div>
                  <div className="kv">
                    <span className="k">Block</span>
                    <span className="mono">{minted.sponsoredEvidence.blockNumber}</span>
                  </div>
                  <div className="kv">
                    <span className="k">Recipient</span>
                    <span className="mono">{short(minted.sponsoredEvidence.recipient)}</span>
                  </div>
                  <p className="muted small">
                    Bound to this account, contract, chain, voucher event, and confirmed block. The sponsor key was
                    used only on the server and was never exposed to this browser.
                  </p>
                </div>
              )}
              {decodedMetadata && <pre className="json">{decodedMetadata}</pre>}
            </div>
          </>
        ) : (
          <>
            <MinimalCard className="minted-card" humanId="0x7A3F…C9E2" />
            <p className="muted small" style={{ textAlign: "center", marginTop: "0.4rem" }}>
              A preview of the credential you will mint. The <b style={{ color: "var(--ink-2)" }}>HUMAN ID</b> is
              derived from your anonymous nullifier — it identifies the token, never you.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

/*//////////////////////////////////////////////////////////////
                       BUILDER CODE SNIPPET
//////////////////////////////////////////////////////////////*/

const GATE_CODE = `<span class="c">// One human, one vote — gate on the soulbound</span>
<span class="c">// credential, no personal data touched.</span>
<span class="t">IProofOfHumanity</span> poh = <span class="t">IProofOfHumanity</span>(<span class="s">0xPoH…</span>);

<span class="k">function</span> castVote(<span class="t">uint256</span> id, <span class="t">uint256</span> tokenId, <span class="t">bool</span> yes) <span class="k">external</span> {
    <span class="k">require</span>(poh.ownerOf(tokenId) == msg.sender, <span class="s">"not your credential"</span>);
    <span class="k">require</span>(poh.isValid(tokenId), <span class="s">"credential expired"</span>);
    _castVote(id, msg.sender, yes);
}`;

const TS_GATE_CODE = `<span class="c">// Read-only gate — validate the exact EIP-712 artifact</span>
<span class="c">// against the deployed verifier. The API receives no passport data.</span>
<span class="k">const</span> allowed = <span class="k">await</span> publicClient.readContract({
    address: PREDICATE_VERIFIER,
    abi: predicateVerifierAbi,
    functionName: <span class="s">"check"</span>,
    args: [attestation, signature, wallet, APP_ADDRESS],
});

<span class="k">if</span> (!allowed) <span class="k">throw new</span> Error(<span class="s">"predicate not satisfied"</span>);`;

/** The builders code panel: switch between the on-chain gate and the off-chain SDK gate. */
function BuilderCode() {
  const [tab, setTab] = useState<"sol" | "ts">("sol");
  return (
    <div className="codeblock">
      <div className="bar">
        <i />
        <i />
        <i />
        <div className="code-tabs" role="tablist" aria-label="Gating examples">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "sol"}
            className={tab === "sol" ? "on" : ""}
            onClick={() => setTab("sol")}
          >
            SybilResistantVote.sol
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "ts"}
            className={tab === "ts" ? "on" : ""}
            onClick={() => setTab("ts")}
          >
            gate.ts
          </button>
        </div>
      </div>
      <pre dangerouslySetInnerHTML={{ __html: tab === "sol" ? GATE_CODE : TS_GATE_CODE }} />
    </div>
  );
}

/*//////////////////////////////////////////////////////////////
                    UBI MARK · TECH · CHAINS · FLOW
//////////////////////////////////////////////////////////////*/

/** The primitives behind the credential — clickable, each with a plain-language note + a canonical link. */
const TECH_FEATURES: { k: string; d: string; href: string }[] = [
  {
    k: "Self (self.xyz) ZK passport",
    d: "Self turns your passport's NFC chip into a zero-knowledge proof built on your phone. The passport data never leaves the device — only the proof travels.",
    href: "https://docs.self.xyz/",
  },
  {
    k: "Groth16 proofs",
    d: "A zk-SNARK proving system with tiny, constant-size proofs that verify in milliseconds. It lets a contract check the passport proof without ever seeing your data.",
    href: "https://www.rareskills.io/post/groth16",
  },
  {
    k: "ERC-721",
    d: "Ethereum's non-fungible token standard. Your Proof-of-Humanity credential is one ERC-721 token — exactly one per human.",
    href: "https://eips.ethereum.org/EIPS/eip-721",
  },
  {
    k: "ERC-5192 soulbound",
    d: "A minimal standard that marks a token permanently non-transferable. The credential stays bound to the human who earned it — it can't be sold or moved.",
    href: "https://eips.ethereum.org/EIPS/eip-5192",
  },
  {
    k: "EIP-712 vouchers",
    d: "Typed, human-readable signed data. The issuer signs a slim voucher the contract verifies before minting — with a distinct domain per chain, so a voucher can't be replayed elsewhere.",
    href: "https://eips.ethereum.org/EIPS/eip-712",
  },
  {
    k: "Nullifier uniqueness",
    d: "A deterministic pseudonym derived from your passport: the same human always yields the same nullifier, so nobody can mint twice — while revealing nothing about who they are.",
    href: "https://docs.semaphore.pse.dev/glossary",
  },
  {
    k: "Coarse validity epoch",
    d: "The token stores only a ~90-day epoch instead of any passport date — enough to prove the credential is fresh, never enough to fingerprint or age you.",
    href: "https://eips.ethereum.org/EIPS/eip-5192",
  },
  {
    k: "Multi-chain EVM + UBI Chain",
    d: "The same credential mints on any EVM chain and on UBI Chain (ubi2 native), each with its own EIP-712 domain — one human, one credential, everywhere.",
    href: "https://ethereum.org/en/developers/docs/evm/",
  },
];

function TechChips() {
  const [open, setOpen] = useState<number | null>(null);
  const active = open === null ? null : TECH_FEATURES[open];
  let host = "";
  if (active) {
    try {
      host = new URL(active.href).hostname.replace(/^www\./, "");
    } catch {
      host = "reference";
    }
  }
  return (
    <>
      <div className="chips">
        {TECH_FEATURES.map((f, i) => (
          <button
            key={f.k}
            type="button"
            className={`tchip${open === i ? " on" : ""}`}
            onClick={() => setOpen(open === i ? null : i)}
            aria-expanded={open === i}
          >
            <span className="d" /> {f.k}
          </button>
        ))}
      </div>
      {active && (
        <div className="tech-detail" role="region" aria-live="polite">
          <p>{active.d}</p>
          <a className="tech-link" href={active.href} target="_blank" rel="noreferrer">
            Learn more · {host} ↗
          </a>
        </div>
      )}
    </>
  );
}

/** Map a configured chain name to its brand dot + display label (ubi2 → the light-green "UBI Chain"). */
function chainStyle(name: string): { dot: string; label: string } {
  const n = name.toLowerCase();
  if (n.includes("ubi")) return { dot: "ubi", label: "UBI Chain" };
  if (n.includes("base")) return { dot: "base", label: name };
  if (n.includes("celo")) return { dot: "celo", label: name };
  if (n.includes("optim") || n === "op") return { dot: "op", label: name };
  if (n.includes("eth") || n.includes("main")) return { dot: "eth", label: name };
  return { dot: "local", label: name };
}

/** The chains the app markets minting on — shown as the picker inside the mint step. */
const MINT_CHAINS: { id: string; dot: string; label: string }[] = [
  { id: "eth", dot: "eth", label: "Ethereum" },
  { id: "base", dot: "base", label: "Base" },
  { id: "op", dot: "op", label: "Optimism" },
  { id: "celo", dot: "celo", label: "Celo" },
  { id: "ubi", dot: "ubi", label: "UBI Chain" },
];

/** The four-step journey as a living rail: a comet runs the line, lighting each node in turn. */
function HowFlow() {
  const labels = ["Scan", "Verify", "Mint", "Prove"];
  const xs = [95, 285, 475, 665];
  return (
    <svg className="how-flow" viewBox="0 0 760 150" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id="howRail" x1="0" y1="0" x2="760" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#ffe24b" />
          <stop offset="0.52" stopColor="#ff9a55" />
          <stop offset="1" stopColor="#ff6b8a" />
        </linearGradient>
        <filter id="howGlow" x="-70%" y="-70%" width="240%" height="240%">
          <feGaussianBlur stdDeviation="3.4" />
        </filter>
      </defs>

      {/* the rail: faint base + a gradient that draws itself left→right */}
      <line className="hf-rail" x1="95" y1="58" x2="665" y2="58" />
      <line className="hf-progress" x1="95" y1="58" x2="665" y2="58" />

      {/* nodes: a ring + a halo that pulses as the comet arrives */}
      {xs.map((x, i) => (
        <g key={i}>
          <circle
            className="hf-halo"
            cx={x}
            cy="58"
            r="33"
            style={{ animationDelay: `${(i * 1.15).toFixed(2)}s` }}
          />
          <circle className="hf-ring" cx={x} cy="58" r="33" />
          <text x={x} y="134" textAnchor="middle" className="how-flow-label">
            {`0${i + 1} · ${labels[i]}`}
          </text>
        </g>
      ))}

      {/* the comet: a glowing core running the rail */}
      <g className="hf-comet">
        <circle className="hf-comet-glow" cx="95" cy="58" r="8" filter="url(#howGlow)" />
        <circle className="hf-comet-core" cx="95" cy="58" r="3.6" />
      </g>

      {/* 01 · Scan — passport */}
      <g stroke="#e8e8ec" strokeWidth="1.7" strokeLinecap="round" opacity="0.9">
        <rect x="82" y="43" width="26" height="30" rx="3.5" fill="none" />
        <circle cx="92" cy="54" r="3.4" fill="none" />
        <line x1="99" y1="52" x2="103" y2="52" />
        <line x1="99" y1="57" x2="103" y2="57" />
        <line x1="87" y1="65" x2="103" y2="65" />
      </g>
      {/* 02 · Verify — shield + check */}
      <g stroke="#e8e8ec" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" fill="none" opacity="0.9">
        <path d="M285 42 L301 48 V60 C301 69 285 75 285 75 C285 75 269 69 269 60 V48 Z" />
        <path d="M278 58 l5 5 l9 -11" stroke="var(--ok)" strokeWidth="2.1" />
      </g>
      {/* 03 · Mint — soulbound token card */}
      <g stroke="#e8e8ec" strokeWidth="1.7" strokeLinecap="round" fill="none" opacity="0.9">
        <rect x="459" y="45" width="32" height="26" rx="4" />
        <circle cx="469" cy="55" r="4" />
        <line x1="478" y1="53" x2="486" y2="53" />
        <line x1="478" y1="58" x2="484" y2="58" />
        <line x1="464" y1="65" x2="486" y2="65" />
      </g>
      {/* 04 · Prove — predicate badge */}
      <g opacity="0.95">
        <circle cx="665" cy="58" r="16" fill="none" stroke="var(--ok)" strokeWidth="1.7" />
        <text x="665" y="62" textAnchor="middle" className="how-flow-badge">18+</text>
      </g>
    </svg>
  );
}

/*//////////////////////////////////////////////////////////////
                              PAGE
//////////////////////////////////////////////////////////////*/

export default function Page() {
  // Reveal sections as they scroll into view. Guarded by html.js-reveal so
  // content is never hidden without JS (and honours prefers-reduced-motion via CSS).
  useEffect(() => {
    const root = document.documentElement;
    root.classList.add("js-reveal");
    const els = Array.from(document.querySelectorAll<HTMLElement>("main section.band, footer"));
    els.forEach((el) => el.classList.add("reveal"));
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            e.target.classList.add("in");
            io.unobserve(e.target);
          }
        }
      },
      { threshold: 0.06, rootMargin: "0px 0px -6% 0px" },
    );
    els.forEach((el) => io.observe(el));
    return () => {
      io.disconnect();
      root.classList.remove("js-reveal");
    };
  }, []);

  return (
    <>
      <GradDefs />

      {/* NAV */}
      <header className="nav">
        <div className="container nav-inner">
          <a className="logo" href="#top">
            <Emblem />
            <span>
              Proof of <span className="grad-text">Humanity</span>
            </span>
          </a>
          <nav className="nav-links">
            <a href="#how">How it works</a>
            <a href="#mint">App</a>
            <a href="/verify">Verify facts</a>
            <a href="/developers">Developers</a>
            <a href="#privacy">Privacy</a>
            <a href="#ubi">UBI</a>
          </nav>
          <a className="btn primary sm nav-cta" href="#mint">
            Verify with Self
          </a>
        </div>
      </header>

      <main id="top">
        {/* HERO */}
        <section className="hero">
          <div className="container hero-grid">
            <div>
              <span className="eyebrow">Zero-knowledge proof of humanity</span>
              <h1>
                One human.
                <br />
                <span className="grad-text grad-anim">One credential.</span>
              </h1>
              <p className="sub">
                Prove you are a unique, real person with a Self zero-knowledge passport proof — then carry a
                soulbound credential that stores nothing about who you are. Sybil resistance without the privacy
                cost of KYC.
              </p>
              <div className="hero-cta">
                <a className="btn primary" href="#mint">
                  Verify &amp; mint
                </a>
                <a className="btn ghost" href="#how">
                  See how it works
                </a>
              </div>
              <div className="hero-trust">
                <span>
                  <b>Self</b> zero-knowledge passport
                </span>
                <span>
                  <b>ERC-721 + ERC-5192</b> soulbound
                </span>
                <span>
                  <b>Multi-chain</b> EVM
                </span>
              </div>
            </div>
            <div className="hero-card">
              <MinimalCard className="card-frame float" humanId="0x7A3F…C9E2" />
            </div>
          </div>
        </section>

        {/* WHY */}
        <section className="band" id="why">
          <div className="container">
            <div className="why-lead">
              <div className="section-head bare">
                <span className="eyebrow">Why it matters</span>
                <h2>The internet needs a way to tell humans apart from bots — without a database of faces.</h2>
                <p>
                  Every open network — a DAO vote, an airdrop, a social feed, a UBI — breaks the moment one person
                  can be ten thousand. The usual fix is KYC: hand your identity to a company and trust it. Proof of
                  Humanity takes the opposite path. You prove you are a unique human, and reveal nothing else.
                </p>
              </div>
              <figure className="why-art">
                <img
                  src="/illustrations/verified-human.webp"
                  alt="A single verified human, uniquely counted, orbited by proof checkmarks"
                  loading="lazy"
                />
              </figure>
            </div>
            <div className="grid cols-3">
              <div className="tile">
                <div className="ico">
                  <Icon name="shield" />
                </div>
                <h3>Sybil resistance</h3>
                <p>
                  One passport yields one credential. A deterministic nullifier makes a second account for the same
                  human impossible — the foundation for fair votes, airdrops and UBI.
                </p>
              </div>
              <div className="tile">
                <div className="ico">
                  <Icon name="lock" />
                </div>
                <h3>No KYC, no data trove</h3>
                <p>
                  Your passport is read on your phone and never leaves it. No name, number, face or date is uploaded,
                  and nothing personal is written on-chain to leak later.
                </p>
              </div>
              <div className="tile">
                <div className="ico">
                  <Icon name="globe" />
                </div>
                <h3>Portable &amp; composable</h3>
                <p>
                  A soulbound token any contract can read. Gate an app, a vote, or a sub-group on unique humanity by
                  verifying a proof — not by trusting a central registry.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* HOW IT WORKS */}
        <section className="band" id="how">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">How it works</span>
              <h2>From passport to credential in four steps.</h2>
              <p>The proof is generated on your device; the chain only ever sees a signed assertion of humanity.</p>
            </div>
            <div className="steps">
              <div className="step">
                <span className="num">STEP 01</span>
                <h3>Scan with Self</h3>
                <p>
                  Open the Self app and scan your passport&apos;s NFC chip. A zero-knowledge proof is built on-device —
                  the passport data never leaves your phone.
                </p>
              </div>
              <div className="step">
                <span className="num">STEP 02</span>
                <h3>Verify a unique human</h3>
                <p>
                  The proof is checked against Self&apos;s identity registry: a valid, unrevoked passport, sanctions-clear,
                  reduced to a single anonymous nullifier.
                </p>
              </div>
              <div className="step">
                <span className="num">STEP 03</span>
                <h3>Mint a soulbound token</h3>
                <p>
                  The issuer signs a slim voucher and you mint an ERC-721 that cannot be transferred. It stores only the
                  nullifier and a coarse 90-day validity epoch.
                </p>
              </div>
              <div className="step">
                <span className="num">STEP 04</span>
                <h3>Prove predicates on demand</h3>
                <p>
                  Later, request a consumer-bound yes/no attestation — over 18, a nationality, sanctions-clear. In v1
                  the issuer evaluates your private credential; the consumer receives only the signed Boolean.
                </p>
              </div>
            </div>
            <HowFlow />
          </div>
        </section>

        {/* THE APP — mint (placed 3rd, right after How it works) */}
        <section className="band app" id="mint">
          <div className="container">
            <div className="section-head center">
              <span className="eyebrow grad-text">◆ The app · live</span>
              <h2>Get your credential.</h2>
              <p>
                Connect a wallet, prove humanity with Self, and mint your soulbound Proof-of-Humanity token — on any
                EVM chain or on <span className="ubi-ink">UBI Chain</span>. One human, one credential; nothing
                personal on-chain. Pick where to mint in step&nbsp;3.
              </p>
            </div>
            <MintFlow />
          </div>
        </section>

        {/* PRIVACY MODEL */}
        <section className="band" id="privacy">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">Privacy model</span>
              <h2>Nothing personal on-chain. The predicates travel, not the data.</h2>
              <p>
                Most identity systems store your attributes publicly and hope no one misuses them. Proof of Humanity
                stores the minimum that makes you countable. Optional facts stay in your browser session and are
                disclosed only to the issuer when you prepare or request a consumer-bound v1 attestation.
              </p>
            </div>
            <div className="privacy-grid">
              <div className="pcard good">
                <div className="pcard-art">
                  <img
                    src="/illustrations/privacy-vault.webp"
                    alt="Your personal data stays sealed in the credential; only a single yes/no answer leaves"
                    loading="lazy"
                  />
                </div>
                <div className="pcard-body">
                  <span className="ptag ok">Private by default</span>
                  <h3>On the Proof-of-Humanity token</h3>
                  <p className="pcard-sub">The minimum that makes you countable — and nothing else.</p>
                  <ul className="plist">
                    <li>
                      <span className="mk y">✓</span> A nullifier — proves one unique human, reveals nothing about them
                    </li>
                    <li>
                      <span className="mk y">✓</span> A coarse ~90-day validity epoch — never a passport date
                    </li>
                    <li>
                      <span className="mk y">✓</span> Soulbound: bound to you, non-transferable, one per human
                    </li>
                    <li>
                      <span className="mk y">✓</span> Boolean attestations bound to one consumer, context and subject
                    </li>
                  </ul>
                </div>
              </div>
              <div className="pcard bad">
                <div className="pcard-art">
                  <img
                    src="/illustrations/privacy-kyc.webp"
                    alt="A KYC database cracks open and spills your passport, ID, birth date and photo"
                    loading="lazy"
                  />
                </div>
                <div className="pcard-body">
                  <span className="ptag no">The old way</span>
                  <h3>The KYC anti-pattern</h3>
                  <p className="pcard-sub">Hand your identity to a company and hope it never leaks.</p>
                  <ul className="plist muted">
                  <li>
                    <span className="mk n">✕</span> Name, document number and photo stored in a database
                  </li>
                  <li>
                    <span className="mk n">✕</span> Nationality, gender and exact birth date written down
                  </li>
                  <li>
                    <span className="mk n">✕</span> One breach exposes everyone at once
                  </li>
                  <li>
                    <span className="mk n">✕</span> Every use is linkable back to a single real identity
                  </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* FOR BUILDERS */}
        <section className="band" id="builders">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">For builders &amp; DAOs</span>
              <h2>Gate on a proof, not a database.</h2>
              <p>
                Read the credential from any EVM contract. Require unique humanity for a vote or an airdrop, or ask for
                a predicate to form an age- or jurisdiction-gated sub-group — all without ever handling personal data.
              </p>
            </div>
            <div className="split">
              <div>
                <ul className="feat-list">
                  <li>
                    <span className="dot" />
                    <span>
                      <b>One human, one vote.</b> Check <code className="mono">isValid(tokenId)</code> on a soulbound
                      token instead of a token balance a whale can accumulate.
                    </span>
                  </li>
                  <li>
                    <span className="dot" />
                    <span>
                      <b>Fair airdrops &amp; UBI.</b> A deterministic nullifier means one claim per person — no Sybil
                      farms draining the allocation.
                    </span>
                  </li>
                  <li>
                    <span className="dot" />
                    <span>
                      <b>Gated sub-groups.</b> Ask a holder for a signed age, nationality or sanctions Boolean. Consumers
                      receive the answer and its bindings, never the private credential.
                    </span>
                  </li>
                  <li>
                    <span className="dot" />
                    <span>
                      <b>Multi-chain by design.</b> The same credential mints on any EVM chain and on ubi2 native, each
                      with its own EIP-712 domain.
                    </span>
                  </li>
                </ul>
              </div>
              <BuilderCode />
            </div>
            <div className="section-head predicate-section-head">
              <span className="eyebrow">Predicate center</span>
              <h2>Verify age, nationality or sanctions status.</h2>
              <p>
                Prepare optional claims during the Self scan, then issue a narrowly scoped artifact for one app or
                contract. The API checks the live soulbound token and configured verifier before signing.
              </p>
            </div>
            <PredicateCenter />
            <div className="builder-links">
              <a className="btn primary" href="/verify">Open full verification app</a>
              <a className="btn ghost" href="/developers">Read developer documentation</a>
            </div>
          </div>
        </section>

        {/* TECH */}
        <section className="band" id="tech">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">Under the hood</span>
              <h2>Open standards, all the way down.</h2>
              <p>Audited primitives, explicit trust boundaries, and byte-for-byte EIP-712 parity with Solidity.</p>
            </div>
            <p className="chips-hint muted small">Tap any primitive to see what it does and where to read more.</p>
            <TechChips />
          </div>
        </section>

        {/* UBI */}
        <section className="band ubi" id="ubi">
          <div className="container">
            <div className="section-head center">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img className="ubi-logo-img" src="/ubi-logo.png" alt="UBI" width={96} height={96} />
              <span className="eyebrow">Universal Basic Income</span>
              <h2>One human, one income.</h2>
              <p>
                Proof of Humanity is the Sybil-resistance layer behind <b>UBI</b> — a universal basic income
                streamed to every verified human. Because one passport yields exactly one credential, a basic
                income can pay a single stream per person: no bots, no duplicate claims, no whales draining the
                pool. Your soulbound token is minted under the <span className="mono">ubi.eth</span> domain and
                unlocks the stream.
              </p>
              <div className="hero-cta">
                <a className="btn primary" href="https://ubi.eth.limo/" target="_blank" rel="noreferrer">
                  How UBI works →
                </a>
                <a className="btn ghost" href="#mint">
                  Get your credential
                </a>
              </div>
            </div>
          </div>
        </section>

      </main>

      {/* FOOTER */}
      <footer className="site">
        <div className="container foot">
          <div>
            <a className="logo" href="#top" style={{ marginBottom: "0.7rem" }}>
              <Emblem />
              <span>
                Proof of <span className="grad-text">Humanity</span>
              </span>
            </a>
            <p className="fine">One human. One credential. Soulbound. Prove you are human without revealing who you are.</p>
          </div>
          <div className="links">
            <a href="/verify">Verify facts</a>
            <a href="/developers">Developers</a>
            <a href="https://ubi.eth.limo/" target="_blank" rel="noreferrer">
              UBI
            </a>
            <a href="https://github.com/DemocracyEarth" target="_blank" rel="noreferrer">
              GitHub
            </a>
            <a href="https://self.xyz" target="_blank" rel="noreferrer">
              Self
            </a>
            <a href="https://democracy.earth" target="_blank" rel="noreferrer">
              Democracy Earth
            </a>
          </div>
        </div>
      </footer>
    </>
  );
}
