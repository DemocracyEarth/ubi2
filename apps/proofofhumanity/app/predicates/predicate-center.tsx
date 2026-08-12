"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  keccak256,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";
import { predicateVerifierAbi } from "../abi/predicateVerifier";
import { proofOfHumanityAbi } from "../abi/proofOfHumanity";
import { CHAINS, isPredicateDeployed } from "../config";
import { HELD_CREDENTIAL_EVENT, loadHeldCredential, type HeldCredential } from "../lib/held-credential";
import {
  AGE_FLAG_18,
  AGE_FLAG_21,
  bytes3ToNationality,
  descriptorHash,
  deserializePredicateAttestation,
  hashPredicateAttestation,
  recoverPredicateSigner,
  type SerializedPredicateAttestation,
} from "../lib/predicate";
import { CountryCombobox } from "./country-combobox";
import { FieldLabel } from "./field-help";
import {
  verificationGuidance,
  type ChainCredentialState,
} from "./verify-state";

interface InjectedProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: "accountsChanged", listener: (accounts: string[]) => void): void;
  removeListener?(event: "accountsChanged", listener: (accounts: string[]) => void): void;
}

type PredicateKind = "age18" | "age21" | "nationality" | "sanctions";

interface PredicateResponse {
  ok: boolean;
  attestation?: SerializedPredicateAttestation;
  signature?: Hex;
  digest?: Hex;
  result?: boolean;
  issuer?: Address;
  error?: string;
}

interface VerifiedResult extends PredicateResponse {
  ok: true;
  attestation: SerializedPredicateAttestation;
  signature: Hex;
  digest: Hex;
  issuer: Address;
  chainId: number;
  chainName: string;
  contextLabel: string;
  descriptor: string;
  explorer?: string;
  verifier: Address;
  bindingsMatch: boolean;
  localDigestMatches: boolean;
  signerMatches: boolean;
  contractCheck: boolean;
}

interface ChainCredentialCheck {
  state: ChainCredentialState;
  tokenId?: bigint;
  owner?: Address;
  detail?: string;
}

function walletProvider(): InjectedProvider | null {
  if (typeof window === "undefined") return null;
  return (window as unknown as { ethereum?: InjectedProvider }).ethereum ?? null;
}

function short(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function errorMessage(error: unknown): string {
  if (error && typeof error === "object") {
    const candidate = error as { code?: number; message?: unknown; shortMessage?: unknown };
    if (candidate.code === 4001) return "Wallet connection was cancelled. Connect the credential owner to continue.";
    if (candidate.shortMessage) return String(candidate.shortMessage);
    if (candidate.message && /user rejected|user denied/i.test(String(candidate.message))) {
      return "Wallet connection was cancelled. Connect the credential owner to continue.";
    }
  }
  const message = error instanceof Error ? error.message : String(error);
  if (/failed to fetch|networkerror|load failed/i.test(message)) {
    return "The issuer service could not be reached. Check your connection and try again.";
  }
  return message;
}

function availableClaims(held: HeldCredential | null) {
  const credential = held?.credential;
  return {
    age18: !!credential && (credential.ageFlags & AGE_FLAG_18) !== 0,
    age21: !!credential && (credential.ageFlags & AGE_FLAG_21) !== 0,
    nationality: !!credential && credential.nationality !== "0x000000",
    sanctions: !!credential?.ofacClear,
  };
}

function chainStatusCopy(check: ChainCredentialCheck, chainName: string): { title: string; body: string } {
  switch (check.state) {
    case "checking":
      return { title: "Checking your on-chain credential…", body: `Reading the deployed contract on ${chainName}.` };
    case "ready":
      return {
        title: `Credential #${check.tokenId?.toString() ?? "—"} is ready`,
        body: `Valid, soulbound, and owned by your connected wallet on ${chainName}.`,
      };
    case "missing":
      return { title: `No credential found on ${chainName}`, body: "Mint on this network before requesting a fact proof." };
    case "wrong-owner":
      return {
        title: "Connected wallet does not own this credential",
        body: check.owner ? `Token owner: ${short(check.owner)}` : "Switch accounts in your wallet and reconnect.",
      };
    case "expired":
      return { title: "This credential has expired", body: "Refresh it with Self before creating a new proof." };
    case "unavailable":
      return { title: `Could not read ${chainName}`, body: check.detail ?? "The public RPC may be temporarily unavailable." };
    default:
      return { title: "Waiting for prerequisites", body: "Prepare claims and connect the credential owner." };
  }
}

export function PredicateCenter({ standalone = false }: { standalone?: boolean }) {
  const deployedChains = useMemo(() => CHAINS.filter(isPredicateDeployed), []);
  const [held, setHeld] = useState<HeldCredential | null>(null);
  const [account, setAccount] = useState<Address | null>(null);
  const [kind, setKind] = useState<PredicateKind>("age18");
  const [nationality, setNationality] = useState("");
  const [chainId, setChainId] = useState<number | null>(deployedChains[0]?.chainId ?? null);
  const [consumer, setConsumer] = useState("");
  const [context, setContext] = useState("membership:season-1");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verified, setVerified] = useState<VerifiedResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [chainCheck, setChainCheck] = useState<ChainCredentialCheck>({ state: "idle" });
  const [checkAttempt, setCheckAttempt] = useState(0);

  const refreshCredential = useCallback(() => setHeld(loadHeldCredential()), []);
  useEffect(() => {
    refreshCredential();
    window.addEventListener(HELD_CREDENTIAL_EVENT, refreshCredential);
    return () => window.removeEventListener(HELD_CREDENTIAL_EVENT, refreshCredential);
  }, [refreshCredential]);

  useEffect(() => {
    const provider = walletProvider();
    if (!provider?.on) return;
    const onAccountsChanged = (accounts: string[]) => {
      const next = accounts[0];
      setAccount(next && isAddress(next) ? getAddress(next) : null);
      setVerified(null);
      setError(next ? null : "Wallet disconnected. Connect the credential owner to continue.");
    };
    provider.on("accountsChanged", onAccountsChanged);
    return () => provider.removeListener?.("accountsChanged", onAccountsChanged);
  }, []);

  const claims = useMemo(() => availableClaims(held), [held]);
  const selectedChain = deployedChains.find((chain) => chain.chainId === chainId) ?? null;
  const descriptor =
    kind === "age18"
      ? "age>=18"
      : kind === "age21"
        ? "age>=21"
        : kind === "nationality"
          ? nationality
            ? `nationality=${nationality}`
            : "nationality"
          : "sanctions-clear";
  const selectedClaimAvailable = claims[kind];
  const contextValue = context.trim();
  const contextValid = contextValue.length > 0 && contextValue.length <= 80;
  const consumerValue = consumer.trim();
  const consumerValid = isAddress(consumerValue);

  useEffect(() => {
    setVerified(null);
    setCopied(false);
  }, [account, chainId, consumer, context, held, kind, nationality]);

  useEffect(() => {
    if (!held || !account || !selectedChain) {
      setChainCheck({ state: "idle" });
      return;
    }

    let cancelled = false;
    setChainCheck({ state: "checking" });
    const check = async () => {
      try {
        const client = createPublicClient({ transport: http(selectedChain.rpcUrl) });
        const tokenId = await client.readContract({
          address: selectedChain.pohAddress,
          abi: proofOfHumanityAbi,
          functionName: "tokenOfNullifier",
          args: [BigInt(held.credential.nullifier)],
        });
        if (cancelled) return;
        if (tokenId === 0n) {
          setChainCheck({ state: "missing" });
          return;
        }
        const [owner, valid] = await Promise.all([
          client.readContract({
            address: selectedChain.pohAddress,
            abi: proofOfHumanityAbi,
            functionName: "ownerOf",
            args: [tokenId],
          }),
          client.readContract({
            address: selectedChain.pohAddress,
            abi: proofOfHumanityAbi,
            functionName: "isValid",
            args: [tokenId],
          }),
        ]);
        if (cancelled) return;
        if (getAddress(owner) !== getAddress(account)) {
          setChainCheck({ state: "wrong-owner", tokenId, owner: getAddress(owner) });
        } else if (!valid) {
          setChainCheck({ state: "expired", tokenId, owner: getAddress(owner) });
        } else {
          setChainCheck({ state: "ready", tokenId, owner: getAddress(owner) });
        }
      } catch (nextError) {
        if (!cancelled) setChainCheck({ state: "unavailable", detail: errorMessage(nextError) });
      }
    };
    void check();
    return () => {
      cancelled = true;
    };
  }, [account, checkAttempt, held, selectedChain]);

  const guidance = verificationGuidance({
    accountConnected: !!account,
    chainName: selectedChain?.name ?? "the selected network",
    chainState: chainCheck.state,
    claimAvailable: selectedClaimAvailable,
    consumerValid,
    contextValid,
    countrySelected: nationality.length === 3,
    hasCredential: !!held,
    nationalitySelected: kind === "nationality",
  });

  const connect = useCallback(async () => {
    const provider = walletProvider();
    if (!provider) {
      setError("No browser wallet detected. Install MetaMask or another EVM wallet, then reload this page.");
      return;
    }
    try {
      const accounts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
      const next = accounts[0];
      if (!next || !isAddress(next)) throw new Error("The wallet did not return a valid EVM address.");
      const address = getAddress(next);
      setAccount(address);
      setConsumer((current) => current || address);
      setError(null);
    } catch (nextError) {
      setError(errorMessage(nextError));
    }
  }, []);

  const issue = useCallback(async () => {
    if (!held || !account || !selectedChain || !guidance.canIssue || !isAddress(consumerValue)) return;
    setWorking(true);
    setError(null);
    setVerified(null);
    try {
      const contextHash = keccak256(stringToBytes(contextValue));
      const nonce = BigInt(Date.now()) * 1_000_000n + BigInt(Math.floor(Math.random() * 1_000_000));
      const response = await fetch("/api/predicate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          credential: held.credential,
          credentialSig: held.credentialSig,
          predicate: descriptor,
          consumer: consumerValue,
          context: contextHash,
          subject: account,
          nonce: nonce.toString(),
          verifier: selectedChain.predicateAddress,
          chainId: selectedChain.chainId,
        }),
      });
      const body = (await response.json().catch(() => ({ ok: false, error: "Issuer returned an unreadable response." }))) as PredicateResponse;
      if (!response.ok || !body.ok || !body.attestation || !body.signature || !body.digest || !body.issuer) {
        throw new Error(body.error ?? "The issuer refused the predicate request.");
      }

      const attestation = deserializePredicateAttestation(body.attestation);
      const bindingsMatch =
        getAddress(attestation.consumer) === getAddress(consumerValue) &&
        getAddress(attestation.subject) === getAddress(account) &&
        attestation.context.toLowerCase() === contextHash.toLowerCase() &&
        attestation.predicate.toLowerCase() === descriptorHash(descriptor).toLowerCase() &&
        attestation.epoch === held.credential.epoch &&
        attestation.nonce === nonce;
      if (!bindingsMatch) {
        throw new Error("The issuer returned an artifact that does not match this request. Nothing was accepted.");
      }
      const localDigest = hashPredicateAttestation(attestation, selectedChain.chainId, selectedChain.predicateAddress);
      const signer = await recoverPredicateSigner(
        attestation,
        body.signature,
        selectedChain.chainId,
        selectedChain.predicateAddress,
      );
      const localDigestMatches = localDigest.toLowerCase() === body.digest.toLowerCase();
      const signerMatches = signer.toLowerCase() === body.issuer.toLowerCase();
      if (!localDigestMatches || !signerMatches) {
        throw new Error("The artifact failed its local signature or integrity check. Nothing was accepted.");
      }
      const client = createPublicClient({ transport: http(selectedChain.rpcUrl) });
      const contractCheck = await client.readContract({
        address: selectedChain.predicateAddress,
        abi: predicateVerifierAbi,
        functionName: "check",
        args: [
          { ...attestation, nonce: BigInt(body.attestation.nonce) },
          body.signature,
          account,
          consumerValue,
        ],
      });
      setVerified({
        ...body,
        ok: true,
        attestation: body.attestation,
        signature: body.signature,
        digest: body.digest,
        issuer: body.issuer,
        chainId: selectedChain.chainId,
        chainName: selectedChain.name,
        contextLabel: contextValue,
        descriptor,
        explorer: selectedChain.explorer,
        verifier: selectedChain.predicateAddress,
        bindingsMatch,
        localDigestMatches,
        signerMatches,
        contractCheck,
      });
    } catch (nextError) {
      setError(errorMessage(nextError));
    } finally {
      setWorking(false);
    }
  }, [account, consumerValue, contextValue, descriptor, guidance.canIssue, held, selectedChain]);

  const copyArtifact = useCallback(async () => {
    if (!verified) return;
    try {
      await navigator.clipboard.writeText(
        JSON.stringify(
          {
            chainId: verified.chainId,
            verifier: verified.verifier,
            attestation: verified.attestation,
            signature: verified.signature,
          },
          null,
          2,
        ),
      );
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("The browser blocked clipboard access. Copy the artifact from a secure HTTPS page or update site permissions.");
    }
  }, [verified]);

  const chainCopy = chainStatusCopy(chainCheck, selectedChain?.name ?? "this network");
  const availableCount = Object.values(claims).filter(Boolean).length;

  return (
    <div className={`predicate-center${standalone ? " standalone" : ""}`} data-testid="predicate-center">
      <div className="predicate-trust">
        <div className="predicate-trust-title">
          <span className="pill ok">Live on {deployedChains.length} testnets</span>
          <strong>One private fact in. One signed answer out.</strong>
        </div>
        <p>
          Choose a fact and the app creates a consumer-bound true/false proof. Your wallet does not sign or spend gas;
          the deployed verifier checks the issuer&apos;s signature and every binding.
        </p>
        <p className="muted small">
          Privacy note: v1 is issuer-attested. The issuer evaluates your browser-held credential, while the receiving
          app gets only the Boolean artifact—not your passport data or full private credential.
        </p>
      </div>

      <div className="verify-progress" aria-label="Verification progress">
        <div className={held ? "complete" : "active"}>
          <span>{held ? "✓" : "1"}</span>
          <div><b>Private claims</b><small>{held ? `${availableCount} ready this session` : "Prepare with Self"}</small></div>
        </div>
        <i aria-hidden="true" />
        <div className={account ? "complete" : held ? "active" : ""}>
          <span>{account ? "✓" : "2"}</span>
          <div><b>Credential owner</b><small>{account ? short(account) : "Connect wallet"}</small></div>
        </div>
        <i aria-hidden="true" />
        <div className={chainCheck.state === "ready" ? "complete" : account ? "active" : ""}>
          <span>{chainCheck.state === "ready" ? "✓" : "3"}</span>
          <div><b>On-chain status</b><small>{chainCheck.state === "ready" ? "Valid credential found" : "Select a network"}</small></div>
        </div>
      </div>

      <div className="predicate-grid">
        <div className="predicate-controls">
          <div className="field-head">
            <span>1 · Your private credential</span>
            {held ? <span className="pill ok">available this session</span> : <span className="pill warn">action required</span>}
          </div>
          {held ? (
            <>
              <div className="claim-row" aria-label="Available private claims">
                <span className={claims.age18 ? "claim on" : "claim"}>Age 18+ {claims.age18 ? "✓" : "—"}</span>
                <span className={claims.age21 ? "claim on" : "claim"}>Age 21+ {claims.age21 ? "✓" : "—"}</span>
                <span className={claims.nationality ? "claim on" : "claim"}>Nationality {claims.nationality ? "✓" : "—"}</span>
                <span className={claims.sanctions ? "claim on" : "claim"}>Sanctions clear {claims.sanctions ? "✓" : "—"}</span>
              </div>
              <p className="session-note"><span aria-hidden="true">◉</span> Stored only in this tab. Closing it clears the private credential.</p>
            </>
          ) : (
            <div className="credential-callout">
              <div>
                <b>No private credential is loaded</b>
                <p>Complete Self verification, choose the facts you need, and mint on a testnet. Return here in the same tab.</p>
              </div>
              <a className="btn ghost sm" href={standalone ? "/#mint" : "#mint"}>Prepare with Self →</a>
            </div>
          )}

          <div className="field-head"><span>2 · Choose one fact to prove</span></div>
          <div className="predicate-options" role="radiogroup" aria-label="Fact to verify">
            {([
              ["age18", "18+", "Age threshold", claims.age18],
              ["age21", "21+", "Age threshold", claims.age21],
              ["nationality", "Nationality", "Country match", claims.nationality],
              ["sanctions", "Sanctions", "Screening clear", claims.sanctions],
            ] as const).map(([value, label, detail, available]) => (
              <button
                type="button"
                role="radio"
                aria-checked={kind === value}
                aria-label={`${label}. ${available ? "Ready" : "Not prepared"}`}
                className={`predicate-option${kind === value ? " selected" : ""}${available ? " available" : " unavailable"}`}
                key={value}
                onClick={() => {
                  setKind(value);
                  setError(null);
                }}
              >
                <span className="predicate-option-icon" aria-hidden="true">
                  {value === "age18" || value === "age21" ? "Aa" : value === "nationality" ? "◎" : "✓"}
                </span>
                <span>{label}</span>
                <small>{available ? `${detail} · ready` : held ? "Not included—re-verify to add" : "Prepare with Self first"}</small>
              </button>
            ))}
          </div>

          {kind === "nationality" && (
            <div className="predicate-field country-field">
              <FieldLabel htmlFor="predicate-country" label="Country to compare">
                Select the country you want to test against your private nationality. The signed artifact contains only
                true or false; the selected code is represented by its predicate hash.
              </FieldLabel>
              <CountryCombobox
                id="predicate-country"
                value={nationality}
                onChange={setNationality}
                disabled={!claims.nationality}
              />
              <span className="field-support">
                Search by name, two-letter code, or three-letter ISO code. Selecting a different country produces a valid false result.
              </span>
            </div>
          )}

          <div className="field-head bind-head"><span>3 · Bind the proof to its intended use</span></div>
          <div className="predicate-fields">
            <div className="predicate-field">
              <FieldLabel htmlFor="predicate-network" label="Credential network">
                Choose the network where this wallet minted its Proof-of-Humanity token. The app reads that deployed
                contract directly; your wallet does not need to switch networks for this check.
              </FieldLabel>
              <select id="predicate-network" value={chainId ?? ""} onChange={(event) => setChainId(Number(event.target.value))}>
                {deployedChains.length ? (
                  deployedChains.map((chain) => <option key={chain.chainId} value={chain.chainId}>{chain.name}</option>)
                ) : (
                  <option value="">No verifier deployment configured</option>
                )}
              </select>
              <span className="field-support"><span className="live-dot" /> {deployedChains.length} verified testnet deployments</span>
            </div>
            <div className="predicate-field">
              <FieldLabel htmlFor="predicate-context" label="Context label">
                A short purpose chosen by the receiving app, such as membership:season-1 or vote:proposal-42. It is
                hashed into the proof so an artifact created for one action cannot be reused for another.
              </FieldLabel>
              <input
                id="predicate-context"
                value={context}
                maxLength={80}
                onChange={(event) => setContext(event.target.value)}
                placeholder="membership:season-1"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={!contextValid}
              />
              <span className={`field-support${contextValid ? "" : " invalid"}`}>
                {contextValid ? "Purpose only—never put personal information here." : "Enter a short, non-personal purpose."}
              </span>
            </div>
          </div>

          <div className="predicate-field">
            <FieldLabel htmlFor="predicate-consumer" label="Receiving app or contract">
              The exact EVM address allowed to accept this proof. For a personal read-only test, use your connected wallet.
              For an integration, use the consumer contract address. No other address can replay the artifact.
            </FieldLabel>
            <div className="address-input-row">
              <input
                id="predicate-consumer"
                value={consumer}
                onChange={(event) => setConsumer(event.target.value)}
                placeholder="0x…"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={consumer.length > 0 && !consumerValid}
              />
              {account && (
                <button className="btn ghost sm" type="button" onClick={() => setConsumer(account)}>Use my wallet</button>
              )}
            </div>
            <span className={`field-support${consumer.length > 0 && !consumerValid ? " invalid" : ""}`}>
              {consumerValid ? "Valid EVM address ✓" : "For testing, connect your wallet and use its address."}
            </span>
          </div>

          {selectedChain && account && held && (
            <div className={`chain-readiness ${chainCheck.state}`} data-testid="contract-readiness" aria-live="polite">
              <span className="chain-readiness-icon" aria-hidden="true">
                {chainCheck.state === "ready" ? "✓" : chainCheck.state === "checking" ? "◌" : "!"}
              </span>
              <div><b>{chainCopy.title}</b><p>{chainCopy.body}</p></div>
              {chainCheck.state === "unavailable" ? (
                <button className="text-button" type="button" onClick={() => setCheckAttempt((attempt) => attempt + 1)}>Retry</button>
              ) : chainCheck.state !== "ready" ? (
                <a className="text-button" href={standalone ? "/#mint" : "#mint"}>Open mint flow</a>
              ) : selectedChain.explorer ? (
                <a className="text-button" href={`${selectedChain.explorer}/address/${selectedChain.pohAddress}`} target="_blank" rel="noreferrer">View contract ↗</a>
              ) : null}
            </div>
          )}

          <div className="predicate-actions">
            {!account ? (
              <button className="btn primary" type="button" onClick={connect}>Connect credential wallet</button>
            ) : (
              <button
                className="btn primary"
                type="button"
                onClick={issue}
                disabled={!guidance.canIssue || working}
              >
                {working ? "Creating and checking proof…" : guidance.canIssue ? `Create ${descriptor} proof` : "Complete the required steps"}
              </button>
            )}
            <span className="no-gas-note"><span aria-hidden="true">◇</span> No wallet signature · No gas</span>
          </div>

          {deployedChains.length === 0 && (
            <div className="notice warn">
              No paired ProofOfHumanity + PredicateVerifier deployment is configured. Issuance remains disabled.
            </div>
          )}
          {error && (
            <div className="notice err predicate-error" role="alert">
              <div><b>Could not create the proof</b><p>{error}</p></div>
              <button type="button" onClick={() => setError(null)} aria-label="Dismiss error">×</button>
            </div>
          )}
        </div>

        <div className="predicate-result" aria-live="polite">
          {verified ? (
            <div className="artifact-card" data-testid="predicate-artifact">
              <div className="artifact-topline">
                <span className={`predicate-verdict${verified.attestation.result ? " pass" : " fail"}`}>
                  {verified.attestation.result ? "TRUE · ACCEPTED" : "FALSE · SIGNED"}
                </span>
                <span className="pill">{verified.chainName}</span>
              </div>
              <span className="result-kicker">Portable fact proof</span>
              <h3>{verified.descriptor}</h3>
              <p className="result-summary">
                {verified.attestation.result
                  ? "The selected fact is true, and the deployed contract accepted every binding."
                  : "This is an authentic signed false result. A correctly configured consumer should reject access."}
              </p>

              <div className="artifact-checks">
                <div className={verified.bindingsMatch ? "ok" : "bad"}>
                  <span>{verified.bindingsMatch ? "✓" : "×"}</span>
                  <p><b>Requested bindings</b><small>Consumer, subject, context, fact, epoch, and nonce match</small></p>
                </div>
                <div className={verified.contractCheck === verified.attestation.result ? "ok" : "bad"}>
                  <span>{verified.contractCheck === verified.attestation.result ? "✓" : "×"}</span>
                  <p><b>On-chain result</b><small>{String(verified.contractCheck)} · matches signed result</small></p>
                </div>
                <div className={verified.localDigestMatches ? "ok" : "bad"}>
                  <span>{verified.localDigestMatches ? "✓" : "×"}</span>
                  <p><b>Artifact unchanged</b><small>Local digest matches issuer digest</small></p>
                </div>
                <div className={verified.signerMatches ? "ok" : "bad"}>
                  <span>{verified.signerMatches ? "✓" : "×"}</span>
                  <p><b>Trusted issuer</b><small>Recovered signer matches deployment</small></p>
                </div>
              </div>

              <div className="artifact-bindings">
                <div><span>Consumer</span><b className="mono">{short(verified.attestation.consumer)}</b></div>
                <div><span>Subject</span><b className="mono">{short(verified.attestation.subject)}</b></div>
                <div><span>Context</span><b>{verified.contextLabel}</b></div>
                <div><span>Valid epoch</span><b>{verified.attestation.epoch}</b></div>
              </div>

              <div className="artifact-actions">
                <button className="btn primary sm" type="button" onClick={copyArtifact}>{copied ? "Artifact copied ✓" : "Copy integration artifact"}</button>
                {verified.explorer && (
                  <a className="btn ghost sm" href={`${verified.explorer}/address/${verified.verifier}#readContract`} target="_blank" rel="noreferrer">
                    Inspect verifier ↗
                  </a>
                )}
              </div>
              <p className="artifact-footnote">Bound to this subject, consumer, context, network, verifier, epoch, and nonce. Raw passport attributes are not included.</p>
            </div>
          ) : (
            <div className={`predicate-empty state-${chainCheck.state}`} data-testid="verification-guidance">
              <span className="empty-kicker">{working ? "Creating proof" : guidance.eyebrow}</span>
              <span className={`predicate-orbit${working ? " working" : ""}`} aria-hidden="true">
                {working ? "◌" : guidance.canIssue ? "✓" : "→"}
              </span>
              <h3>{working ? "Signing and checking your artifact…" : guidance.title}</h3>
              <p className="muted small">
                {working ? "The issuer is evaluating one fact, then the app will independently check the signature and deployed contract." : guidance.body}
              </p>
              {!working && !held && <a className="btn primary sm" href={standalone ? "/#mint" : "#mint"}>Prepare with Self</a>}
              {!working && held && !account && <button className="btn primary sm" type="button" onClick={connect}>Connect wallet to continue</button>}
              {!working && guidance.canIssue && <span className="ready-descriptor mono">{descriptor}</span>}
              <div className="empty-privacy"><span aria-hidden="true">◈</span> Nothing is running until you press “Create proof.”</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
