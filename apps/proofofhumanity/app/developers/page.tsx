import type { Metadata } from "next";
import { CHAINS, isPredicateDeployed } from "../config";
import { descriptorHash } from "../lib/predicate";

export const metadata: Metadata = {
  title: "Developer documentation · Proof of Humanity",
  description: "Integrate soulbound humanity and consumer-bound private predicates into an EVM app.",
};

const SOLIDITY_EXAMPLE = `interface IPredicateVerifier {
    struct PredicateAttestation {
        address consumer;
        bytes32 context;
        bytes32 predicate;
        bool result;
        address subject;
        uint32 epoch;
        uint256 nonce;
    }

    function consume(
        PredicateAttestation calldata att,
        bytes calldata signature,
        address presenter
    ) external returns (bool result);
}

bytes32 constant AGE_18 = keccak256("age>=18");

function join(
    IPredicateVerifier.PredicateAttestation calldata att,
    bytes calldata signature
) external {
    require(att.consumer == address(this), "wrong consumer");
    require(att.context == keccak256("community:season-1"), "wrong context");
    require(att.predicate == AGE_18 && att.result, "18+ required");
    require(verifier.consume(att, signature, msg.sender), "not eligible");
    _addMember(msg.sender);
}`;

const REQUEST_EXAMPLE = `import { predicateContext } from "@ubi2/sdk";

const response = await fetch("https://proofofhumanity.org/api/predicate", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    credential,       // private, holder-controlled v1 credential
    credentialSig,
    predicate: "age>=18",
    consumer: APP_OR_CONTRACT_ADDRESS,
    context: predicateContext("community:season-1"),
    subject: connectedWallet,
    nonce: cryptoNonce.toString(),
    verifier: PREDICATE_VERIFIER_ADDRESS,
    chainId: 8453,
  }),
});

const { attestation, signature } = await response.json();`;

const READ_EXAMPLE = `import { checkPredicateArtifact } from "@ubi2/sdk";

const result = await checkPredicateArtifact({
  artifact: { chainId, verifier, attestation, signature },
  rpcUrl,
  presenter: connectedWallet,
  consumer: APP_OR_CONTRACT_ADDRESS,
});

if (!result) throw new Error("predicate not satisfied");`;

const V2_POLICY_EXAMPLE = `import {
  countrySetCommitment,
  normalizeZkIdentityPolicy,
  zkIdentityPolicyHash,
} from "@ubi2/sdk";

const setId = "eu-eea:2026-08";
const setRoot = countrySetCommitment({
  setId,
  members: ["AUT", "BEL", "DEU", "ESP", "FRA" /* complete registry set */],
});

const policy = normalizeZkIdentityPolicy({
  kind: "country-set",
  attribute: "nationality",
  operator: "in",
  setId,
  setRoot,
});

const policyHash = zkIdentityPolicyHash(policy);
// Bind policyHash to chain, verifier, consumer, subject, context,
// challenge and epoch with zkPresentationBindingHash(...).`;

const V2_ISSUANCE_EXAMPLE = `import { encodeZkSelfIssuance } from "@ubi2/sdk";

// Returned only after the exact Self proof has bound the wallet and the
// holder prover's canonical BN254 credential commitment.
const { zkIssuance } = await pollVerificationResult();

const data = encodeZkSelfIssuance({
  authorization: zkIssuance.authorization,
  signature: zkIssuance.signature,
});

await walletClient.sendTransaction({
  account: connectedWallet, // must equal authorization.subject
  chain: canonicalIssuanceChain,
  to: zkIssuance.bridge,
  data,
});`;

const descriptors = ["age>=18", "age>=21", "nationality=ARG", "sanctions-clear"] as const;

export default function DevelopersPage() {
  return (
    <>
      <header className="subnav">
        <a className="wordmark" href="/">Proof of <span>Humanity</span></a>
        <nav>
          <a href="/verify">Verify facts</a>
          <a className="active" href="/developers">Developers</a>
          <a href="https://github.com/DemocracyEarth/ubi2" target="_blank" rel="noreferrer">GitHub ↗</a>
        </nav>
      </header>
      <main className="docs-page">
        <aside className="docs-nav">
          <span>Integration guide</span>
          <a href="#model">Trust model</a>
          <a href="#v2-policies">v2 policy SDK</a>
          <a href="#v2-issuance">v2 issuance bridge</a>
          <a href="#descriptors">Descriptors</a>
          <a href="#request">Request an attestation</a>
          <a href="#contract">Consume on-chain</a>
          <a href="#networks">Networks</a>
          <a href="#security">Security checklist</a>
          <a href="#release">Mainnet release gate</a>
        </aside>

        <article className="docs-content">
          <div className="docs-hero">
            <span className="eyebrow">Proof of Humanity · v1 live + v2 foundation</span>
            <h1>Build gates for humans,<br /><span className="grad-text">not identity databases.</span></h1>
            <p>
              Integrate a minimal soulbound humanity credential, or require a narrowly scoped age, nationality, or
              sanctions Boolean. All public artifacts use pinned EIP-712 domains and contract-enforced bindings.
            </p>
            <div className="builder-links">
              <a className="btn primary" href="/verify">Try the verification app</a>
              <a className="btn ghost" href="https://github.com/DemocracyEarth/ubi2/tree/main/contracts" target="_blank" rel="noreferrer">Read the contracts ↗</a>
            </div>
          </div>

          <section id="model" className="docs-section">
            <span className="doc-number">01</span><h2>Trust model</h2>
            <div className="trust-table">
              <div><b>Live v1 · issuer-attested</b><p>Self verifies passport facts. The issuer evaluates the private held credential and signs one Boolean attestation.</p></div>
              <div><b>v2 · reusable holder-side ZK</b><p>Foundation in development. A transitional Self issuance bridge and SDK are implemented but not deployed; production commitment generation, local proving, status roots and prover contracts remain gated.</p></div>
            </div>
            <div className="notice warn">
              Do not describe v1 predicate attestations as trustless ZK. Consumers trust the configured issuer to
              evaluate the fact correctly. They can independently verify the issuer, domain, bindings, and freshness.
            </div>
          </section>

          <section id="v2-policies" className="docs-section">
            <span className="doc-number">02</span><h2>Build canonical v2 policies</h2>
            <p>
              v2 policies are versioned objects with deterministic EVM hashes. The same object shown in the
              <a href="/verify"> policy designer</a> is intended to become a circuit public input and consumer
              allowlist value. Current helpers build and hash policies; they do not generate a proof.
            </p>
            <pre className="docs-code"><code>{V2_POLICY_EXAMPLE}</code></pre>
            <div className="notice warn">
              Treat country-set and status roots as governed registries. A friendly label is not security: consumers
              must allowlist the exact set id, root, version, circuit/prover, chain and verifier they reviewed.
            </div>
          </section>

          <section id="v2-issuance" className="docs-section">
            <span className="doc-number">03</span><h2>Submit a v2 issuance authorization</h2>
            <p>
              The developer-preview path verifies the exact configured Self e-passport proof off-chain, derives a
              registry-scoped duplicate key, and signs a ten-minute authorization for one immutable bridge. The
              wallet submits the transaction itself; another caller, chain, bridge, signer, verifier configuration,
              issuer key, slot, epoch, or changed commitment fails closed.
            </p>
            <pre className="docs-code"><code>{V2_ISSUANCE_EXAMPLE}</code></pre>
            <div className="notice warn">
              This is not live user functionality yet. The holder-side production commitment circuit and vault
              integration are still required, and the current bridge trusts a pinned off-chain Self verification
              authority. Never generate a placeholder commitment or treat this authorization as a presentation proof.
            </div>
          </section>

          <section id="descriptors" className="docs-section">
            <span className="doc-number">04</span><h2>Canonical v1 descriptors</h2>
            <p>Consumers require the hash of an exact canonical string. No spaces or aliases are accepted.</p>
            <div className="descriptor-table">
              {descriptors.map((descriptor) => (
                <div key={descriptor}><code>{descriptor}</code><code>{descriptorHash(descriptor)}</code></div>
              ))}
            </div>
            <p className="muted small">Nationality uses ISO 3166-1 alpha-3 uppercase codes: <code>nationality=ARG</code>, <code>nationality=USA</code>.</p>
          </section>

          <section id="request" className="docs-section">
            <span className="doc-number">05</span><h2>Request a v1 attestation</h2>
            <p>
              The holder calls the API from the verification app. Before signing, the server verifies the private
              credential signature and freshness, the subject&apos;s live SBT ownership, both contract issuer addresses,
              and the exact configured chain/verifier pair.
            </p>
            <pre className="docs-code"><code>{REQUEST_EXAMPLE}</code></pre>
            <h3>Read-only verification</h3>
            <pre className="docs-code"><code>{READ_EXAMPLE}</code></pre>
          </section>

          <section id="contract" className="docs-section">
            <span className="doc-number">06</span><h2>Consume v1 atomically on-chain</h2>
            <p>
              A state-changing consumer must call <code>consume</code> itself. The verifier requires
              <code>att.consumer == msg.sender</code>, checks subject and freshness, and marks the
              <code>(subject, consumer, context, nonce)</code> replay key as spent.
            </p>
            <pre className="docs-code"><code>{SOLIDITY_EXAMPLE}</code></pre>
          </section>

          <section id="networks" className="docs-section">
            <span className="doc-number">07</span><h2>Configured networks</h2>
            <p>The app exposes issuance only when both contract addresses are configured. Zero addresses fail closed.</p>
            <div className="network-table">
              <div className="network-row head"><span>Network</span><span>Chain</span><span>PoH</span><span>Predicate</span><span>Status</span></div>
              {CHAINS.filter((chain) => chain.chainId !== 31337).map((chain) => {
                const deployed = isPredicateDeployed(chain);
                const explorer = chain.explorer;
                return (
                  <div className="network-row" key={chain.chainId}>
                    <span>{chain.name}</span><code>{chain.chainId}</code>
                    <code>
                      {deployed && explorer ? (
                        <a href={`${explorer}/address/${chain.pohAddress}#code`} target="_blank" rel="noreferrer" title={chain.pohAddress}>
                          {chain.pohAddress.slice(0, 8)}…
                        </a>
                      ) : "—"}
                    </code>
                    <code>
                      {deployed && explorer ? (
                        <a href={`${explorer}/address/${chain.predicateAddress}#code`} target="_blank" rel="noreferrer" title={chain.predicateAddress}>
                          {chain.predicateAddress.slice(0, 8)}…
                        </a>
                      ) : "—"}
                    </code>
                    <span className={deployed ? "net-live" : "net-pending"}>{deployed ? "configured" : "pending deploy"}</span>
                  </div>
                );
              })}
            </div>
          </section>

          <section id="security" className="docs-section">
            <span className="doc-number">08</span><h2>Security checklist</h2>
            <ul className="docs-checks">
              <li>Require the exact descriptor hash, <code>result == true</code>, consumer, context, and subject your action expects.</li>
              <li>Use <code>consume</code> inside state-changing flows; use <code>check</code> only when replay is harmless.</li>
              <li>Never accept a chain ID or verifier address that is not in your own allowlist.</li>
              <li>Keep the issuer key server-side in an HSM or managed signer; never expose it as <code>NEXT_PUBLIC_*</code>.</li>
              <li>Keep owner and issuer roles distinct: owner is the governance multisig; issuer is the narrow operational signer.</li>
              <li>Do not log held credentials, Self proof payloads, passport attributes, or issuer secrets.</li>
              <li>Never accept a v2 policy preview as evidence. Require an audited configured prover and verify the exact policy and presentation-binding hashes.</li>
            </ul>
          </section>

          <section id="release" className="docs-section release-gate">
            <span className="doc-number">09</span><h2>Mainnet release gate</h2>
            <p>
              Mainnet is intentionally not activated by code merge alone. Every target chain must pass deterministic
              CI, testnet deployment and verification, live contract probes, issuer/owner checks, app configuration,
              rollback documentation, and an explicit per-chain human broadcast approval.
            </p>
            <div className="notice ok">The website can ship before addresses are added: unsupported networks remain visibly pending and issuance stays disabled.</div>
          </section>
        </article>
      </main>
    </>
  );
}
