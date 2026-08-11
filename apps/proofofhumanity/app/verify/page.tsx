import type { Metadata } from "next";
import { PredicateCenter } from "../predicates/predicate-center";

export const metadata: Metadata = {
  title: "Verify private facts · Proof of Humanity",
  description: "Create consumer-bound age, nationality, and sanctions attestations without putting personal data on-chain.",
};

export default function VerifyPage() {
  return (
    <>
      <header className="subnav">
        <a className="wordmark" href="/">Proof of <span>Humanity</span></a>
        <nav>
          <a href="/#mint">Prepare claims</a>
          <a className="active" href="/verify">Verify facts</a>
          <a href="/developers">Developers</a>
        </nav>
      </header>
      <main className="subpage">
        <section className="subhero">
          <span className="eyebrow">Private predicate verification</span>
          <h1>Prove one fact.<br /><span className="grad-text">Reveal one bit.</span></h1>
          <p>
            Generate a signed age, nationality, or sanctions result for one app or contract. Your private credential
            stays off-chain; the public artifact is bound to its consumer, context, subject, network, and verifier.
          </p>
        </section>
        <PredicateCenter standalone />
        <section className="verify-explainer">
          <article>
            <span>01</span><h2>Prepare</h2>
            <p>During Self verification, opt into only the private claims you expect to use. The token remains minimal.</p>
          </article>
          <article>
            <span>02</span><h2>Bind</h2>
            <p>Name the consumer and context. A proof for one integration cannot be replayed as another integration.</p>
          </article>
          <article>
            <span>03</span><h2>Check or consume</h2>
            <p>Use <code>check</code> for a read-only gate or <code>consume</code> for an atomic, single-use on-chain action.</p>
          </article>
        </section>
      </main>
    </>
  );
}
