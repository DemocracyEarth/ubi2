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
 * nationality / gender / age is ever disclosed to the chain — those stay zero-knowledge predicates,
 * provable on demand.
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
import { CHAINS, SELF_ENDPOINT, type ChainConfig } from "./config";
import { proofOfHumanityAbi } from "./abi/proofOfHumanity";
import {
  bytes3ToNationality,
  deserializePredicateAttestation,
  hashPredicateAttestation,
  recoverPredicateSigner,
  type SerializedHumanCredential,
  type SerializedPredicateAttestation,
} from "./lib/predicate";

/*//////////////////////////////////////////////////////////////
                     BRAND ASSETS (from card-minimal-final.svg)
//////////////////////////////////////////////////////////////*/

/** The head emblem path — the single source of truth, reused by the card and the logo. */
const HEAD_PATH =
  "M 347.25 181.1 Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95 174.897265625 9.9517578125 173.65 9.95 172.40078125 9.9517578125 171.15 9.95 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1 0.0033203125 182.2296875 0 183.35 0.001953125 184.7263671875 0 186.1 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65 L 79.75 310.85 79.75 418.7 Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65 L 242.6 423.65 Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7 L 247.6 377.15 295.75 377.15 Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25 L 320.7 304.05 351.1 304.05 Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5 369.5890625 285.8658203125 369.2 283.3 369.8205078125 279.015625 368.4 274.95 L 347.25 212.2 347.25 181.1 M 332.3 218 Q 332.3 218.85 332.55 219.6 L 353.95 283.1 Q 353.980859375 283.1904296875 354 283.25 353.620703125 284.544140625 352.85 285.65 351.7 287.25 349.9 288.2 348.2853515625 289.007421875 346.5 289.05 L 310.7 289.05 Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05 L 305.7 347.55 Q 305.6390625 350.3458984375 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.8935546875 362.1400390625 291.05 362.2 L 237.6 362.2 Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2 L 232.6 408.7 94.75 408.7 94.75 303.05 Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8 L 74.95 288.15 Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.2994140625 198.1578125 14.95 183.05 15.5302734375 152.651171875 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.941796875 25.38046875 173.65 24.9 204.35625 25.38046875 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76171875 152.7470703125 332.3 183.3 L 332.3 218 M 234.25 188.1 Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35 L 229.25 183.35 Q 227.8 183.45 226.65 184.35 L 176.7 222.2 126.8 184.3 Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8 L 172.85 266.35 Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35 L 233.35 190.85 Q 234.25 189.65 234.25 188.1 M 174.4 77.35 Q 173.3 77.95 172.65 79.05 L 123.9 160.15 Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35 L 173.85 203.95 Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95 L 228.35 166.35 Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15 L 180.75 79.05 Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35 M 176.75 136.45 Q 177.6 136.45 178.4 136.8 L 219.8 155.55 Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95 L 178.2 145.65 Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65 L 137 162.95 Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55 L 175.05 136.8 Q 175.85 136.45 176.75 136.45 Z";

/** The LOCKED minimal card, as a self-contained SVG string. Only `HUMAN ID` is dynamic. */
function minimalCardSvg(humanId: string): string {
  return `<svg viewBox="0 0 640 900" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg" role="img"><title>Proof of Humanity — minimal credential</title>
<defs>
<linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FFE24B"/><stop offset="52%" stop-color="#FF9A55"/><stop offset="100%" stop-color="#FF6B8A"/></linearGradient>
<linearGradient id="ok" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#6EE7B7"/><stop offset="100%" stop-color="#22C55E"/></linearGradient>
<linearGradient id="card" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#101016"/><stop offset="100%" stop-color="#08080B"/></linearGradient>
<radialGradient id="glow" cx="50%" cy="38%" r="42%"><stop offset="0%" stop-color="#FF7A66" stop-opacity="0.15"/><stop offset="100%" stop-color="#000000" stop-opacity="0"/></radialGradient>
</defs>
<rect width="640" height="900" fill="#000000"/>
<rect width="640" height="900" fill="url(#glow)"/>
<path d="M54 24 H562 L616 78 V846 A30 30 0 0 1 586 876 H54 A30 30 0 0 1 24 846 V54 A30 30 0 0 1 54 24 Z" fill="url(#card)" stroke="url(#g)" stroke-width="2"/>
<path d="M70 58 L74 74 L90 78 L74 82 L70 98 L66 82 L50 78 L66 74 Z" fill="url(#g)" opacity="0.9"/>
<text x="584" y="62" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="11" letter-spacing="3" fill="#C9A24E">HUMAN ID</text>
<text x="584" y="86" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="16" fill="#E8E8EC">${humanId}</text>
<text x="54" y="152" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="54" font-weight="800" letter-spacing="-1.5" fill="#F5F5F7">Proof of</text>
<text x="54" y="206" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="54" font-weight="800" letter-spacing="-1.5" fill="#F5F5F7">Humanity</text>
<text x="56" y="242" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="22" font-weight="600" fill="url(#g)">Verified with Self</text>
<circle cx="320" cy="368" r="112" fill="none" stroke="url(#g)" stroke-opacity="0.30" stroke-width="1" stroke-dasharray="1.5 7"/>
<circle cx="212" cy="368" r="3.5" fill="url(#g)"/>
<circle cx="428" cy="368" r="3.5" fill="url(#g)"/>
<circle cx="320" cy="368" r="86" fill="#0B0B10" stroke="url(#g)" stroke-opacity="0.55" stroke-width="1.5"/>
<g transform="translate(273,308) scale(0.253)"><path fill="url(#g)" d="${HEAD_PATH}"/></g>
<line x1="64" y1="516" x2="158" y2="516" stroke="url(#g)" stroke-opacity="0.4"/>
<line x1="482" y1="516" x2="576" y2="516" stroke="url(#g)" stroke-opacity="0.4"/>
<text x="320" y="521" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="12" letter-spacing="5" fill="#C9A24E">ZERO-KNOWLEDGE HUMANITY</text>
<rect x="52" y="540" width="536" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/>
<circle cx="84" cy="562" r="5.5" fill="none" stroke="url(#g)" stroke-width="1.5"/>
<path d="M73 579 q11 -13 22 0" fill="none" stroke="url(#g)" stroke-width="1.5" stroke-linecap="round"/>
<text x="116" y="573" font-family="Helvetica,Arial,sans-serif" font-size="18" fill="#EAEAEE">Unique human</text>
<text x="524" y="573" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="18" fill="#F2F2F4">Verified</text>
<circle cx="560" cy="567" r="13" fill="none" stroke="url(#ok)" stroke-width="1.6"/>
<path d="M554 567 l4 4 l8 -8.5" fill="none" stroke="url(#ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
<rect x="52" y="608" width="536" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/>
<rect x="76" y="636" width="16" height="12" rx="2" fill="none" stroke="url(#g)" stroke-width="1.5"/>
<path d="M79 636 v-4 a5 5 0 0 1 10 0 v4" fill="none" stroke="url(#g)" stroke-width="1.5"/>
<text x="116" y="641" font-family="Helvetica,Arial,sans-serif" font-size="18" fill="#EAEAEE">Personal data on-chain</text>
<text x="524" y="641" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="18" fill="url(#ok)">None</text>
<circle cx="560" cy="635" r="13" fill="none" stroke="url(#ok)" stroke-width="1.6"/>
<path d="M554 635 l4 4 l8 -8.5" fill="none" stroke="url(#ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
<text x="320" y="706" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="11" letter-spacing="4" fill="#C9A24E">PROVABLE ON DEMAND</text>
<g font-family="Helvetica,Arial,sans-serif" font-size="15" font-weight="500">
<rect x="52" y="722" width="168" height="46" rx="23" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/>
<line x1="74" y1="723.5" x2="198" y2="723.5" stroke="#FFFFFF" stroke-opacity="0.06"/>
<circle cx="96" cy="745" r="2.5" fill="url(#g)"/><text x="110" y="750" fill="#EDEDF1">Age 18+</text>
<rect x="236" y="722" width="168" height="46" rx="23" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/>
<line x1="258" y1="723.5" x2="382" y2="723.5" stroke="#FFFFFF" stroke-opacity="0.06"/>
<circle cx="270" cy="745" r="2.5" fill="url(#g)"/><text x="284" y="750" fill="#EDEDF1">Nationality</text>
<rect x="420" y="722" width="168" height="46" rx="23" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/>
<line x1="442" y1="723.5" x2="566" y2="723.5" stroke="#FFFFFF" stroke-opacity="0.06"/>
<circle cx="454" cy="745" r="2.5" fill="url(#g)"/><text x="468" y="750" fill="#EDEDF1">Sanctions</text>
</g>
<text x="320" y="800" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="12.5" fill="#7C7C86">Zero-knowledge predicates — nothing stored on-chain</text>
<path d="M96 844 l6 5 l-6 4 z" fill="url(#g)"/><path d="M96 844 l-6 5 l6 4 z" fill="url(#g)" opacity="0.55"/>
<text x="320" y="852" text-anchor="middle" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="13" font-weight="600" letter-spacing="3" fill="url(#g)">ONE HUMAN · ONE CREDENTIAL · SOULBOUND</text>
<path d="M544 844 l6 5 l-6 4 z" fill="url(#g)" opacity="0.55"/><path d="M544 844 l-6 5 l6 4 z" fill="url(#g)"/>
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
}

type Phase = "connect" | "scan" | "waiting" | "ready" | "minting" | "minted";

interface Minted {
  tokenId: bigint;
  tokenURI: string;
  valid: boolean;
  locked: boolean;
  nullifier: bigint;
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
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => setInjected(getInjected()), []);

  useEffect(() => {
    if (!account) return;
    if (!SELF_ENDPOINT) {
      setSelfApp(null);
      return;
    }
    try {
      setSelfApp(buildSelfApp(account, SELF_ENDPOINT));
      setBuildError(null);
    } catch (e) {
      setSelfApp(null);
      setBuildError(errMessage(e));
    }
  }, [account]);

  const stopPolling = useCallback(() => {
    if (pollTimer.current) {
      clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  const connect = useCallback(async () => {
    if (!injected) {
      setNote({ kind: "err", text: "No injected wallet detected — install MetaMask or another EIP-1193 wallet." });
      return;
    }
    try {
      const accounts = (await injected.request({ method: "eth_requestAccounts" })) as string[];
      const addr = accounts[0] as Address | undefined;
      if (!addr) throw new Error("No account returned.");
      setAccount(addr);
      setPhase("scan");
      setNote(null);
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
    }
  }, [injected]);

  const startPolling = useCallback(() => {
    if (!account) return;
    stopPolling();
    pollTimer.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/self-verify?address=${account}`);
        const data = (await res.json()) as {
          status: string;
          proof?: RelayReady["proof"];
          vouchers?: SignedForChain[];
          error?: string;
        };
        if (data.status === "ready" && data.vouchers && data.proof) {
          setReady({ status: "ready", proof: data.proof, vouchers: data.vouchers });
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
  }, [account, stopPolling]);

  const onQrSuccess = useCallback(() => {
    setPhase("waiting");
    setNote({ kind: "ok", text: "Self reported success — verifying your proof and signing the voucher…" });
    startPolling();
  }, [startPolling]);

  const onQrError = useCallback((data: { error_code?: string; reason?: string }) => {
    setNote({ kind: "err", text: `Self app error: ${data.reason ?? data.error_code ?? "unknown"}` });
  }, []);

  const selected = useMemo<SignedForChain | null>(
    () => ready?.vouchers.find((v) => v.chainId === selectedChainId) ?? null,
    [ready, selectedChainId],
  );

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
    if (!injected || !account || !selected) return;
    const chainCfg = CHAINS.find((c) => c.chainId === selected.chainId);
    if (!chainCfg) return;
    const chain = viemChain(chainCfg);

    setPhase("minting");
    setNote(null);
    try {
      await ensureChain(chain);

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
      fetch(`/api/self-verify?address=${account}`, { method: "DELETE" }).catch(() => {});
    } catch (e) {
      setNote({ kind: "err", text: errMessage(e) });
      setPhase("ready");
    }
  }, [injected, account, selected, ensureChain]);

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

  const stepConnectDone = !!account;
  const stepProofDone = !!ready;

  return (
    <div className="mint-wrap">
      {/* Left: the flow */}
      <div className="panel">
        {/* STEP 1 — connect */}
        <div className={`step-row${stepConnectDone ? " done" : ""}`}>
          <div className="step-badge">{stepConnectDone ? "✓" : "1"}</div>
          <div className="step-body">
            <h4>Connect a wallet</h4>
            {account ? (
              <div className="row">
                <span className="mono">{short(account)}</span>
                <span className="pill ok">connected</span>
              </div>
            ) : (
              <button className="btn primary sm" onClick={connect}>
                {injected ? "Connect wallet" : "No wallet detected"}
              </button>
            )}
          </div>
        </div>

        {/* STEP 2 — Self proof */}
        <div className={`step-row${!account ? " disabled" : stepProofDone ? " done" : ""}`}>
          <div className="step-badge">{stepProofDone ? "✓" : "2"}</div>
          <div className="step-body">
            <h4>Prove you are human with Self</h4>

            {!account && <p className="muted small">Connect a wallet first.</p>}

            {account && !SELF_ENDPOINT && (
              <div className="notice warn">
                <b>Live QR not configured.</b> Set <code>NEXT_PUBLIC_SELF_ENDPOINT</code> to this app&apos;s publicly
                reachable <code>/api/self-verify</code> URL (a tunnel like ngrok/cloudflared in dev, or the deployed
                origin in prod). The Self mobile app cannot reach <code>localhost</code>.
              </div>
            )}

            {account && buildError && <div className="notice err">Could not build the Self request: {buildError}</div>}

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
                    Your passport is scanned on-device. The proof discloses no name, number, nationality or age —
                    only that you are a unique, sanctions-clear human.
                  </p>
                </div>
              </div>
            )}

            {account && SELF_ENDPOINT && ready && phase !== "scan" && phase !== "waiting" && (
              <div className="notice ok">
                Unique human verified. Voucher signed for {ready.vouchers.length} chain(s).
              </div>
            )}
          </div>
        </div>

        {/* STEP 3 — mint */}
        <div className={`step-row${!ready ? " disabled" : minted ? " done" : ""}`}>
          <div className="step-badge">{minted ? "✓" : "3"}</div>
          <div className="step-body">
            <h4>Mint your soulbound credential</h4>
            {!ready && <p className="muted small">Complete the Self proof first.</p>}

            {ready && (
              <>
                <div className="row" style={{ marginBottom: "0.7rem" }}>
                  <span className="pill">
                    <b style={{ color: "var(--gold)" }}>HUMAN ID</b> {humanIdFromNullifier(BigInt(ready.proof.nullifier))}
                  </span>
                  <span className="pill">epoch {ready.proof.epoch}</span>
                </div>

                {ready.vouchers.length > 0 ? (
                  <div className="row">
                    <select
                      value={selectedChainId ?? ""}
                      onChange={(e) => setSelectedChainId(Number(e.target.value))}
                      disabled={phase === "minting"}
                    >
                      {ready.vouchers.map((v) => (
                        <option key={v.chainId} value={v.chainId}>
                          {v.name} (chain {v.chainId})
                        </option>
                      ))}
                    </select>
                    <button className="btn primary sm" onClick={mint} disabled={phase === "minting" || !selected}>
                      {phase === "minting" ? "Minting…" : "Mint credential"}
                    </button>
                  </div>
                ) : (
                  <p className="muted small">No deployed chain configured to mint on.</p>
                )}
              </>
            )}
          </div>
        </div>

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

<span class="k">function</span> castVote(<span class="t">uint256</span> id, <span class="t">bool</span> yes) <span class="k">external</span> {
    <span class="t">uint256</span> tokenId = poh.tokenOf(msg.sender);
    <span class="k">require</span>(tokenId != 0, <span class="s">"verify at proofofhumanity.org"</span>);
    <span class="k">require</span>(poh.isValid(tokenId), <span class="s">"credential expired"</span>);
    _castVote(id, msg.sender, yes);
}`;

/*//////////////////////////////////////////////////////////////
                     PREDICATE DEMO — "Prove you're 18+"
//////////////////////////////////////////////////////////////*/

/**
 * A self-contained, phone-free, chain-free demo of the PREDICATE LAYER (v1).
 *
 * It walks the whole thesis in the browser:
 *   1. mint a PRIVATE demo HumanCredential (kept in localStorage — the raw age /
 *      nationality live here, never leave the client store);
 *   2. ask `/api/predicate` to attest "age>=18" for one consumer + context + subject;
 *   3. verify, client-side, that the returned digest matches a locally-recomputed
 *      `hashPredicateAttestation` and that the signature recovers to the issuer.
 *
 * The punchline the UI drives home: the credential (with the actual nationality /
 * age facts) stays private; ONLY the boolean `result` crosses to the consumer,
 * and the attestation is bound to THIS consumer, so it is unlinkable across consumers.
 *
 * Demo domain constants: these are deterministic first-deploy anvil addresses, used
 * only so the EIP-712 domain (verifyingContract + chainId) is well-defined off-chain.
 * With a local anvil + a deployed `SybilResistantVote`, the same attestation would
 * cast a real gated vote (see `test/predicate.crossstack.ts`).
 */
const DEMO_CHAIN_ID = 31337;
const DEMO_VERIFIER = "0x5FbDB2315678afecb367f032d93F642f64180aa3" as Address; // anvil deploy #0
const DEMO_CONSUMER = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512" as Address; // anvil deploy #1
const DEMO_SUBJECT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" as Address; // anvil acct #2 — "the human"
// bytes32("proposal:demo") right-padded.
const DEMO_CONTEXT = "0x70726f706f73616c3a64656d6f00000000000000000000000000000000000000" as Hex;
const CREDENTIAL_STORE_KEY = "poh:humanCredential";

interface DemoProof {
  attestation: SerializedPredicateAttestation;
  credential: SerializedHumanCredential;
  parity: boolean;
  issuerOk: boolean;
  issuer: string;
}

function PredicateDemo() {
  const [phase, setPhase] = useState<"idle" | "working" | "proven">("idle");
  const [proof, setProof] = useState<DemoProof | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const prove = useCallback(async () => {
    setPhase("working");
    setErr(null);
    setProof(null);
    try {
      // 1) Obtain a PRIVATE held credential (demo issuance) and store it locally.
      const credRes = (await (
        await fetch("/api/predicate/demo-credential", { method: "POST" })
      ).json()) as { ok: boolean; credential?: SerializedHumanCredential; credentialSig?: Hex; error?: string };
      if (!credRes.ok || !credRes.credential || !credRes.credentialSig) {
        throw new Error(credRes.error ?? "Could not issue a demo credential.");
      }
      try {
        localStorage.setItem(
          CREDENTIAL_STORE_KEY,
          JSON.stringify({ credential: credRes.credential, credentialSig: credRes.credentialSig }),
        );
      } catch {
        /* storage may be unavailable — the demo still works from memory */
      }

      // 2) Request an "age>=18" attestation bound to one consumer + context + subject.
      const nonce = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
      const attRes = (await (
        await fetch("/api/predicate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            credential: credRes.credential,
            credentialSig: credRes.credentialSig,
            predicate: "age>=18",
            consumer: DEMO_CONSUMER,
            context: DEMO_CONTEXT,
            subject: DEMO_SUBJECT,
            nonce: nonce.toString(),
            verifier: DEMO_VERIFIER,
            chainId: DEMO_CHAIN_ID,
          }),
        })
      ).json()) as {
        ok: boolean;
        attestation?: SerializedPredicateAttestation;
        signature?: Hex;
        digest?: Hex;
        issuer?: string;
        error?: string;
      };
      if (!attRes.ok || !attRes.attestation || !attRes.signature || !attRes.digest || !attRes.issuer) {
        throw new Error(attRes.error ?? "Attestation request failed.");
      }

      // 3) Client-side parity: recompute the digest + recover the signer.
      const att = deserializePredicateAttestation(attRes.attestation);
      const localDigest = hashPredicateAttestation(att, DEMO_CHAIN_ID, DEMO_VERIFIER);
      const signer = await recoverPredicateSigner(att, attRes.signature, DEMO_CHAIN_ID, DEMO_VERIFIER);
      setProof({
        attestation: attRes.attestation,
        credential: credRes.credential,
        parity: localDigest.toLowerCase() === attRes.digest.toLowerCase(),
        issuerOk: signer.toLowerCase() === attRes.issuer.toLowerCase(),
        issuer: attRes.issuer,
      });
      setPhase("proven");
    } catch (e) {
      setErr(errMessage(e));
      setPhase("idle");
    }
  }, []);

  return (
    <div className="predicate-demo">
      <div className="pd-head">
        <div>
          <span className="eyebrow">Live demo · issuer-attested (v1)</span>
          <h3>Prove you are 18+ — reveal only the answer.</h3>
          <p className="muted small">
            A private credential is issued and kept in your browser. The issuer attests one predicate to one consumer.
            Only the boolean crosses the wire — no birthdate, no age, no nationality.
          </p>
        </div>
        <button className="btn primary" onClick={prove} disabled={phase === "working"}>
          {phase === "working" ? "Proving…" : proof ? "Prove again" : "Prove you're 18+"}
        </button>
      </div>

      {err && <p className="pd-note err">{err}</p>}

      {proof && (
        <div className="pd-grid">
          <div className="pd-col">
            <div className="pd-verdict">
              <span className="pd-badge">{proof.attestation.result ? "PROVEN ✓" : "NOT PROVEN"}</span>
              <span>
                <b>age ≥ 18</b> → <span className="mono">{String(proof.attestation.result)}</span>
              </span>
            </div>
            <div className="kv">
              <span className="k">Digest parity</span>
              <span>{proof.parity ? "matches on-chain hash ✓" : "MISMATCH ✗"}</span>
            </div>
            <div className="kv">
              <span className="k">Signed by</span>
              <span>{proof.issuerOk ? `issuer ${short(proof.issuer)} ✓` : "unknown signer ✗"}</span>
            </div>
            <div className="kv">
              <span className="k">Bound to</span>
              <span className="mono">{short(proof.attestation.consumer)}</span>
            </div>
            <p className="muted small" style={{ marginTop: "0.5rem" }}>
              Bound to one consumer — a different consumer gets a different, unlinkable attestation.
            </p>
          </div>

          <div className="pd-col">
            <div className="pd-panel">
              <div className="pd-panel-title ok">What crossed the wire (public)</div>
              <pre className="json">{JSON.stringify(proof.attestation, null, 2)}</pre>
            </div>
            <div className="pd-panel">
              <div className="pd-panel-title priv">What stayed private (your browser)</div>
              <pre className="json">
                {JSON.stringify(
                  {
                    ageFlags: proof.credential.ageFlags,
                    nationality: bytes3ToNationality(proof.credential.nationality) || "(undisclosed)",
                    ofacClear: proof.credential.ofacClear,
                  },
                  null,
                  2,
                )}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/*//////////////////////////////////////////////////////////////
                              PAGE
//////////////////////////////////////////////////////////////*/

export default function Page() {
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
            <a href="#privacy">Privacy</a>
            <a href="#builders">Builders</a>
            <a href="#tech">Tech</a>
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
                <span className="grad-text">One credential.</span>
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
              <MinimalCard className="card-frame" humanId="0x7A3F…C9E2" />
            </div>
          </div>
        </section>

        {/* WHY */}
        <section className="band" id="why">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">Why it matters</span>
              <h2>The internet needs a way to tell humans apart from bots — without a database of faces.</h2>
              <p>
                Every open network — a DAO vote, an airdrop, a social feed, a UBI — breaks the moment one person can
                be ten thousand. The usual fix is KYC: hand your identity to a company and trust it. Proof of Humanity
                takes the opposite path. You prove you are a unique human, and reveal nothing else.
              </p>
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
                  Later, prove a fact — over 18, a nationality, sanctions-clear — as a fresh zero-knowledge proof that
                  reveals only the answer, never the underlying data.
                </p>
              </div>
            </div>
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
                stores the minimum that makes you countable — and keeps every attribute as a proof you disclose only
                when, and to whom, you choose.
              </p>
            </div>
            <div className="privacy-grid">
              <div className="pcard good">
                <h3>
                  <Icon name="check" /> On the Proof-of-Humanity token
                </h3>
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
                    <span className="mk y">✓</span> Attributes proven on demand, unlinkable per context
                  </li>
                </ul>
              </div>
              <div className="pcard bad">
                <h3>The KYC anti-pattern</h3>
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
                      <b>Gated sub-groups.</b> Ask a holder to prove a predicate — over 18, a nationality, sanctions-clear
                      — to join, revealing only the answer.
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
              <div className="codeblock">
                <div className="bar">
                  <i />
                  <i />
                  <i />
                  <span className="fn">SybilResistantVote.sol</span>
                </div>
                <pre dangerouslySetInnerHTML={{ __html: GATE_CODE }} />
              </div>
            </div>
            <PredicateDemo />
          </div>
        </section>

        {/* TECH */}
        <section className="band" id="tech">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">Under the hood</span>
              <h2>Open standards, all the way down.</h2>
              <p>No custom trust assumptions — audited primitives composed into a minimal credential.</p>
            </div>
            <div className="chips">
              <span className="tchip">
                <span className="d" /> Self (self.xyz) ZK passport
              </span>
              <span className="tchip">
                <span className="d" /> Groth16 proofs
              </span>
              <span className="tchip">
                <span className="d" /> ERC-721
              </span>
              <span className="tchip">
                <span className="d" /> ERC-5192 soulbound
              </span>
              <span className="tchip">
                <span className="d" /> EIP-712 vouchers
              </span>
              <span className="tchip">
                <span className="d" /> Nullifier uniqueness
              </span>
              <span className="tchip">
                <span className="d" /> Coarse validity epoch
              </span>
              <span className="tchip">
                <span className="d" /> Multi-chain EVM + ubi2 native
              </span>
            </div>
          </div>
        </section>

        {/* MINT */}
        <section className="band" id="mint">
          <div className="container">
            <div className="section-head">
              <span className="eyebrow">Get your credential</span>
              <h2>Verify with Self &amp; mint.</h2>
              <p>
                Connect a wallet, prove humanity with Self, and mint your soulbound Proof-of-Humanity token. One human,
                one credential — nothing personal on-chain.
              </p>
            </div>
            <MintFlow />
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
