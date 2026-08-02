"use client";

/**
 * proofofhumanity.org — the mint UI.
 *
 * Flow (task §"The flow it implements"):
 *   1. connect an injected EVM wallet;
 *   2. scan the Self QR / open the deeplink → the Self app POSTs the proof to /api/self-verify,
 *      which verifies it and signs one voucher per chain; this page polls for those vouchers;
 *   3. pick a chain, `mintWithVoucher(voucher, signature)` on that chain's ProofOfHumanity, then
 *      read `tokenURI`/`attributesOf` back and render the soulbound token's public traits.
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
import { proofOfHumanityAbi, type OnChainAttributes } from "./abi/proofOfHumanity";

/*//////////////////////////////////////////////////////////////
                          TYPES / HELPERS
//////////////////////////////////////////////////////////////*/

interface Injected {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

interface SerializedVoucher {
  to: Address;
  nullifier: string;
  ageFlags: number;
  nationality: Hex;
  gender: number;
  ofacClear: boolean;
  expiry: string;
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
  attributes: {
    nationality: string;
    gender: string;
    olderThan: number;
    ofacClear: boolean;
    nullifier: string;
  };
  vouchers: SignedForChain[];
}

type Phase = "connect" | "scan" | "waiting" | "ready" | "minting" | "minted";

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

function viemChain(c: ChainConfig): Chain {
  return defineChain({
    id: c.chainId,
    name: c.name,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [c.rpcUrl] } },
    ...(c.explorer ? { blockExplorers: { default: { name: "Explorer", url: c.explorer } } } : {}),
  });
}

function genderLabel(g: string): string {
  if (g === "M") return "male";
  if (g === "F") return "female";
  return g ? "other" : "—";
}

/*//////////////////////////////////////////////////////////////
                              PAGE
//////////////////////////////////////////////////////////////*/

export default function Page() {
  const [injected, setInjected] = useState<Injected | null>(null);
  const [account, setAccount] = useState<Address | null>(null);
  const [phase, setPhase] = useState<Phase>("connect");
  const [selfApp, setSelfApp] = useState<SelfApp | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [ready, setReady] = useState<RelayReady | null>(null);
  const [selectedChainId, setSelectedChainId] = useState<number | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "err" | "warn"; text: string } | null>(null);
  const [minted, setMinted] = useState<{ tokenId: bigint; tokenURI: string; attrs: OnChainAttributes } | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => setInjected(getInjected()), []);

  // Build the SelfApp descriptor once we have an address + a public endpoint.
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
          attributes?: RelayReady["attributes"];
          vouchers?: SignedForChain[];
          error?: string;
        };
        if (data.status === "ready" && data.vouchers && data.attributes) {
          setReady(data as RelayReady);
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
    setNote({ kind: "ok", text: "Self app reported success — waiting for the relay to verify and sign your voucher…" });
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
        // 4902 = chain not added to the wallet yet.
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
        ageFlags: sv.ageFlags,
        nationality: sv.nationality,
        gender: sv.gender,
        ofacClear: sv.ofacClear,
        expiry: BigInt(sv.expiry),
      } as const;

      const hash = await wallet.writeContract({
        address: chainCfg.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "mintWithVoucher",
        args: [voucherArg, selected.signature],
      });
      setNote({ kind: "ok", text: `Submitted · tx ${short(hash)} · waiting for confirmation…` });
      await pub.waitForTransactionReceipt({ hash });

      // Read the token back: nullifier → tokenId → tokenURI + attributes.
      const tokenId = await pub.readContract({
        address: chainCfg.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "tokenOfNullifier",
        args: [BigInt(sv.nullifier)],
      });
      const [tokenURI, attrs] = await Promise.all([
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "tokenURI",
          args: [tokenId],
        }),
        pub.readContract({
          address: chainCfg.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "attributesOf",
          args: [tokenId],
        }),
      ]);

      setMinted({ tokenId, tokenURI: tokenURI as string, attrs: attrs as OnChainAttributes });
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

  const ageBadges = (flags: number) =>
    [
      [0x01, "13+"],
      [0x02, "18+"],
      [0x04, "21+"],
      [0x08, "65+"],
    ]
      .filter(([m]) => (flags & (m as number)) !== 0)
      .map(([, l]) => l as string);

  return (
    <main className="wrap">
      <div className="brand">
        <span className="dot" /> proofofhumanity.org
      </div>
      <h1>One human, one soulbound credential.</h1>
      <p className="lede">
        Prove you are a unique human with a Self zero-knowledge passport proof — no name, no passport
        number, nothing that identifies you. The relay verifies the proof off-chain and signs an
        EIP-712 humanity voucher; you redeem it for a soulbound Proof-of-Humanity NFT carrying only
        public anonymous traits, on any EVM chain.
      </p>

      {/* STEP 1 — connect */}
      <section className="card">
        <h2>
          <span className="step-num">1</span> Connect your wallet
        </h2>
        {account ? (
          <div className="row">
            <span className="mono">{short(account)}</span>
            <span className="chip">connected</span>
          </div>
        ) : (
          <button className="primary" onClick={connect}>
            {injected ? "Connect wallet" : "No wallet detected"}
          </button>
        )}
      </section>

      {/* STEP 2 — Self proof */}
      <section className={`card${account ? "" : " disabled"}`}>
        <h2>
          <span className="step-num">2</span> Scan the Self QR
        </h2>
        {!account && <p className="muted small">Connect a wallet first.</p>}

        {account && !SELF_ENDPOINT && (
          <div className="notice warn">
            <b>Live QR flow not configured.</b> Set <code>NEXT_PUBLIC_SELF_ENDPOINT</code> to this app&apos;s{" "}
            publicly reachable <code>/api/self-verify</code> URL (a tunnel like ngrok/cloudflared in
            dev, or the deployed origin in prod). The Self mobile app cannot reach{" "}
            <code>localhost</code>, so this is required for a real end-to-end proof.
          </div>
        )}

        {account && buildError && <div className="notice err">Could not build the Self app: {buildError}</div>}

        {account && SELF_ENDPOINT && selfApp && (phase === "scan" || phase === "waiting") && (
          <div className="row" style={{ alignItems: "flex-start", gap: "1.25rem" }}>
            <div className="qr">
              <SelfQRcodeWrapper selfApp={selfApp} onSuccess={onQrSuccess} onError={onQrError} />
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <p className="muted small">Scan with the Self app, or open directly on this device:</p>
              <a href={getUniversalLink(selfApp)} target="_blank" rel="noreferrer">
                Open in Self app →
              </a>
              {phase === "waiting" && (
                <p className="small" style={{ color: "var(--accent-2)", marginTop: "0.6rem" }}>
                  Waiting for the relay to verify and sign…
                </p>
              )}
              <p className="muted small" style={{ marginTop: "0.9rem" }}>
                Discloses: nationality, gender, OFAC-clear. TODO (nice-to-have): an optional
                &ldquo;prove 18+/21+&rdquo; second proof to add age flags.
              </p>
            </div>
          </div>
        )}

        {account && SELF_ENDPOINT && ready && phase !== "scan" && phase !== "waiting" && (
          <div className="notice ok">Voucher received and signed for {ready.vouchers.length} chain(s).</div>
        )}
      </section>

      {/* STEP 3 — mint */}
      <section className={`card${ready ? "" : " disabled"}`}>
        <h2>
          <span className="step-num">3</span> Pick a chain &amp; mint
        </h2>
        {!ready && <p className="muted small">Complete the Self proof first.</p>}

        {ready && (
          <>
            <div className="traits" style={{ marginBottom: "0.9rem" }}>
              {ready.attributes.nationality && (
                <span className="chip">
                  <b>Nationality</b> {ready.attributes.nationality}
                </span>
              )}
              <span className="chip">
                <b>Gender</b> {genderLabel(ready.attributes.gender)}
              </span>
              {ready.attributes.olderThan > 0 && (
                <span className="chip">
                  <b>Age</b> {ready.attributes.olderThan}+
                </span>
              )}
              <span className="chip">
                <b>OFAC</b> {ready.attributes.ofacClear ? "clear" : "—"}
              </span>
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
                <button className="primary" onClick={mint} disabled={phase === "minting" || !selected}>
                  {phase === "minting" ? "Minting…" : "Mint Proof of Humanity"}
                </button>
              </div>
            ) : (
              <p className="muted small">No deployed chain configured to mint on.</p>
            )}
          </>
        )}

        {minted && (
          <div style={{ marginTop: "1.1rem" }}>
            <div className="kv">
              <span className="k">Token</span>
              <span className="mono">Proof of Humanity #{minted.tokenId.toString()}</span>
            </div>
            <div className="kv">
              <span className="k">Soulbound</span>
              <span>locked (ERC-5192)</span>
            </div>
            <div className="traits" style={{ marginTop: "0.7rem" }}>
              {minted.attrs.nationality !== "0x000000" && (
                <span className="chip">
                  <b>Nationality</b>{" "}
                  {(() => {
                    try {
                      const h = minted.attrs.nationality.slice(2);
                      return String.fromCharCode(
                        parseInt(h.slice(0, 2), 16),
                        parseInt(h.slice(2, 4), 16),
                        parseInt(h.slice(4, 6), 16),
                      );
                    } catch {
                      return minted.attrs.nationality;
                    }
                  })()}
                </span>
              )}
              {minted.attrs.gender !== 0 && (
                <span className="chip">
                  <b>Gender</b> {minted.attrs.gender === 0x4d ? "male" : minted.attrs.gender === 0x46 ? "female" : "other"}
                </span>
              )}
              {ageBadges(minted.attrs.ageFlags).map((b) => (
                <span className="chip" key={b}>
                  <b>Age</b> {b}
                </span>
              ))}
              {minted.attrs.ofacClear && (
                <span className="chip">
                  <b>OFAC</b> clear
                </span>
              )}
            </div>
            {decodedMetadata && <pre className="json">{decodedMetadata}</pre>}
          </div>
        )}
      </section>

      {note && <div className={`notice ${note.kind}`}>{note.text}</div>}
    </main>
  );
}
