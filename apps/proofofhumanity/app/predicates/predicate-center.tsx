"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createPublicClient,
  http,
  isAddress,
  keccak256,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";
import { predicateVerifierAbi } from "../abi/predicateVerifier";
import { CHAINS, isPredicateDeployed } from "../config";
import { HELD_CREDENTIAL_EVENT, loadHeldCredential, type HeldCredential } from "../lib/held-credential";
import {
  AGE_FLAG_18,
  AGE_FLAG_21,
  bytes3ToNationality,
  deserializePredicateAttestation,
  hashPredicateAttestation,
  recoverPredicateSigner,
  type SerializedPredicateAttestation,
} from "../lib/predicate";

interface InjectedProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
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
  localDigestMatches: boolean;
  signerMatches: boolean;
  contractCheck: boolean;
}

function injected(): InjectedProvider | null {
  if (typeof window === "undefined") return null;
  return (window as unknown as { ethereum?: InjectedProvider }).ethereum ?? null;
}

function short(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function errorMessage(error: unknown): string {
  if (error && typeof error === "object" && "shortMessage" in error) {
    return String((error as { shortMessage: unknown }).shortMessage);
  }
  return error instanceof Error ? error.message : String(error);
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

export function PredicateCenter({ standalone = false }: { standalone?: boolean }) {
  const deployedChains = useMemo(() => CHAINS.filter(isPredicateDeployed), []);
  const [held, setHeld] = useState<HeldCredential | null>(null);
  const [account, setAccount] = useState<Address | null>(null);
  const [kind, setKind] = useState<PredicateKind>("age18");
  const [nationality, setNationality] = useState("ARG");
  const [chainId, setChainId] = useState<number | null>(deployedChains[0]?.chainId ?? null);
  const [consumer, setConsumer] = useState("");
  const [context, setContext] = useState("membership:v1");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verified, setVerified] = useState<VerifiedResult | null>(null);
  const [copied, setCopied] = useState(false);

  const refreshCredential = useCallback(() => setHeld(loadHeldCredential()), []);
  useEffect(() => {
    refreshCredential();
    window.addEventListener(HELD_CREDENTIAL_EVENT, refreshCredential);
    return () => window.removeEventListener(HELD_CREDENTIAL_EVENT, refreshCredential);
  }, [refreshCredential]);

  const claims = useMemo(() => availableClaims(held), [held]);
  const selectedChain = deployedChains.find((chain) => chain.chainId === chainId) ?? null;
  const descriptor =
    kind === "age18"
      ? "age>=18"
      : kind === "age21"
        ? "age>=21"
        : kind === "nationality"
          ? `nationality=${nationality.trim().toUpperCase()}`
          : "sanctions-clear";

  const connect = useCallback(async () => {
    const provider = injected();
    if (!provider) {
      setError("No injected wallet detected. Install a wallet such as MetaMask, then reload.");
      return;
    }
    try {
      const accounts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
      const next = accounts[0];
      if (!next || !isAddress(next)) throw new Error("The wallet did not return an EVM address.");
      setAccount(next);
      setConsumer((current) => current || next);
      setError(null);
    } catch (nextError) {
      setError(errorMessage(nextError));
    }
  }, []);

  const issue = useCallback(async () => {
    if (!held || !account || !selectedChain) return;
    const consumerAddress = consumer.trim();
    const a3 = nationality.trim().toUpperCase();
    if (!isAddress(consumerAddress)) {
      setError("Consumer must be a valid EVM address.");
      return;
    }
    if (kind === "nationality" && !/^[A-Z]{3}$/.test(a3)) {
      setError("Nationality must be an ISO 3166-1 alpha-3 code such as ARG, USA, or ESP.");
      return;
    }
    setWorking(true);
    setError(null);
    setVerified(null);
    try {
      const contextHash = keccak256(stringToBytes(context.trim() || "membership:v1"));
      const nonce = BigInt(Date.now()) * 1_000_000n + BigInt(Math.floor(Math.random() * 1_000_000));
      const response = await fetch("/api/predicate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          credential: held.credential,
          credentialSig: held.credentialSig,
          predicate: descriptor,
          consumer: consumerAddress,
          context: contextHash,
          subject: account,
          nonce: nonce.toString(),
          verifier: selectedChain.predicateAddress,
          chainId: selectedChain.chainId,
        }),
      });
      const body = (await response.json()) as PredicateResponse;
      if (!response.ok || !body.ok || !body.attestation || !body.signature || !body.digest || !body.issuer) {
        throw new Error(body.error ?? "The issuer refused the predicate request.");
      }

      const attestation = deserializePredicateAttestation(body.attestation);
      const localDigest = hashPredicateAttestation(attestation, selectedChain.chainId, selectedChain.predicateAddress);
      const signer = await recoverPredicateSigner(
        attestation,
        body.signature,
        selectedChain.chainId,
        selectedChain.predicateAddress,
      );
      const client = createPublicClient({ transport: http(selectedChain.rpcUrl) });
      const contractCheck = await client.readContract({
        address: selectedChain.predicateAddress,
        abi: predicateVerifierAbi,
        functionName: "check",
        args: [
          {
            ...attestation,
            nonce: BigInt(body.attestation.nonce),
          },
          body.signature,
          account,
          consumerAddress,
        ],
      });
      setVerified({
        ...body,
        ok: true,
        attestation: body.attestation,
        signature: body.signature,
        digest: body.digest,
        issuer: body.issuer,
        localDigestMatches: localDigest.toLowerCase() === body.digest.toLowerCase(),
        signerMatches: signer.toLowerCase() === body.issuer.toLowerCase(),
        contractCheck,
      });
    } catch (nextError) {
      setError(errorMessage(nextError));
    } finally {
      setWorking(false);
    }
  }, [account, consumer, context, descriptor, held, kind, nationality, selectedChain]);

  const copyArtifact = useCallback(async () => {
    if (!verified || !selectedChain) return;
    await navigator.clipboard.writeText(
      JSON.stringify(
        {
          chainId: selectedChain.chainId,
          verifier: selectedChain.predicateAddress,
          attestation: verified.attestation,
          signature: verified.signature,
        },
        null,
        2,
      ),
    );
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }, [selectedChain, verified]);

  return (
    <div className={`predicate-center${standalone ? " standalone" : ""}`}>
      <div className="predicate-trust">
        <span className="pill ok">Live path · issuer-attested v1</span>
        <p>
          Self proves the selected facts to the issuer. The issuer checks your private browser-held credential and
          returns a signed Boolean for one consumer and context. The consumer never receives your passport data.
        </p>
        <p className="muted small">
          This is not the unshipped holder-side ZK prover. The deployed contract has a fixed upgrade seam for that
          future path; until a prover is configured, issuer signatures are the active trust model.
        </p>
      </div>

      <div className="predicate-grid">
        <div className="predicate-controls">
          <div className="field-head">
            <span>1 · Private credential</span>
            {held ? <span className="pill ok">available this session</span> : <span className="pill">not prepared</span>}
          </div>
          {held ? (
            <div className="claim-row" aria-label="Available private claims">
              <span className={claims.age18 ? "claim on" : "claim"}>Age 18+</span>
              <span className={claims.age21 ? "claim on" : "claim"}>Age 21+</span>
              <span className={claims.nationality ? "claim on" : "claim"}>Nationality</span>
              <span className={claims.sanctions ? "claim on" : "claim"}>Sanctions clear</span>
            </div>
          ) : (
            <p className="muted small">
              <a href={standalone ? "/#mint" : "#mint"}>Verify with Self</a> and opt into the facts you want to prove.
              The held credential is kept in session storage and cleared when the tab closes.
            </p>
          )}

          <div className="field-head"><span>2 · Select one predicate</span></div>
          <div className="predicate-options" role="radiogroup" aria-label="Predicate to verify">
            {([
              ["age18", "Age 18+", claims.age18],
              ["age21", "Age 21+", claims.age21],
              ["nationality", "Nationality", claims.nationality],
              ["sanctions", "Sanctions clear", claims.sanctions],
            ] as const).map(([value, label, available]) => (
              <button
                type="button"
                role="radio"
                aria-checked={kind === value}
                className={`predicate-option${kind === value ? " selected" : ""}`}
                key={value}
                onClick={() => setKind(value)}
              >
                <span>{label}</span>
                <small>{available ? "ready" : "re-verify to add"}</small>
              </button>
            ))}
          </div>

          {kind === "nationality" && (
            <label className="predicate-field">
              <span>Country code to test</span>
              <input
                value={nationality}
                maxLength={3}
                onChange={(event) => setNationality(event.target.value.toUpperCase())}
                placeholder="ARG"
                autoCapitalize="characters"
              />
            </label>
          )}

          <div className="predicate-fields">
            <label className="predicate-field">
              <span>Network</span>
              <select value={chainId ?? ""} onChange={(event) => setChainId(Number(event.target.value))}>
                {deployedChains.length ? (
                  deployedChains.map((chain) => <option key={chain.chainId} value={chain.chainId}>{chain.name}</option>)
                ) : (
                  <option value="">No predicate deployment configured</option>
                )}
              </select>
            </label>
            <label className="predicate-field">
              <span>Context label</span>
              <input value={context} onChange={(event) => setContext(event.target.value)} placeholder="membership:v1" />
            </label>
          </div>
          <label className="predicate-field">
            <span>Consumer app or contract</span>
            <input value={consumer} onChange={(event) => setConsumer(event.target.value)} placeholder="0x…" />
          </label>

          <div className="predicate-actions">
            {!account ? (
              <button className="btn primary" type="button" onClick={connect}>Connect wallet</button>
            ) : (
              <button
                className="btn primary"
                type="button"
                onClick={issue}
                disabled={!held || !selectedChain || working}
              >
                {working ? "Checking contract + signing…" : `Verify ${descriptor}`}
              </button>
            )}
            {account && <span className="mono muted small">subject {short(account)}</span>}
          </div>
          {deployedChains.length === 0 && (
            <div className="notice warn">
              The UI is ready, but no paired PoH + PredicateVerifier deployment is configured. Add the two public
              addresses for a testnet or mainnet in the environment before enabling issuance.
            </div>
          )}
          {error && <div className="notice err">{error}</div>}
        </div>

        <div className="predicate-result" aria-live="polite">
          {verified ? (
            <>
              <span className={`predicate-verdict${verified.attestation.result ? " pass" : " fail"}`}>
                {verified.attestation.result ? "VERIFIED TRUE" : "VERIFIED FALSE"}
              </span>
              <h3>{descriptor}</h3>
              <div className="kv"><span className="k">Contract check</span><span>{String(verified.contractCheck)} ✓</span></div>
              <div className="kv"><span className="k">Digest parity</span><span>{verified.localDigestMatches ? "match ✓" : "mismatch ✕"}</span></div>
              <div className="kv"><span className="k">Issuer recovery</span><span>{verified.signerMatches ? "match ✓" : "mismatch ✕"}</span></div>
              <div className="kv"><span className="k">Consumer</span><span className="mono">{short(verified.attestation.consumer)}</span></div>
              <div className="kv"><span className="k">Subject</span><span className="mono">{short(verified.attestation.subject)}</span></div>
              <button className="btn ghost sm" type="button" onClick={copyArtifact}>{copied ? "Copied ✓" : "Copy integration artifact"}</button>
              {selectedChain?.explorer && (
                <a className="text-link" href={`${selectedChain.explorer}/address/${selectedChain.predicateAddress}#readContract`} target="_blank" rel="noreferrer">
                  Inspect PredicateVerifier ↗
                </a>
              )}
            </>
          ) : (
            <div className="predicate-empty">
              <span className="predicate-orbit">✓</span>
              <h3>A portable yes/no artifact appears here.</h3>
              <p className="muted small">
                It is EIP-712 signed and checked against the configured PredicateVerifier. Raw age and nationality
                are never written on-chain or included in the artifact.
              </p>
              {held && held.credential.nationality !== "0x000000" && (
                <p className="muted tiny">Private nationality claim is present ({bytes3ToNationality(held.credential.nationality)}); it is shown only in your own browser.</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
