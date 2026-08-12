import type { Metadata } from "next";
import { PredicateCenter } from "../predicates/predicate-center";
import { V2PolicyLab } from "../predicates/v2-policy-lab";

export const metadata: Metadata = {
  title: "Verify private facts · Proof of Humanity",
  description: "Use live v1 private predicates and explore canonical v2 passport policies for reusable local ZK proofs.",
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
          <span className="eyebrow">Private, contract-checked verification</span>
          <h1>Answer one question.<br /><span className="grad-text">Keep the rest private.</span></h1>
          <p>
            Today you can create issuer-attested age, nationality, or sanctions results on supported testnets. Below,
            explore the expanded v2 policies being built for one reusable, passkey-protected private credential.
          </p>
        </section>
        <PredicateCenter standalone />
        <section className="verify-explainer">
          <article>
            <span>01</span><h2>Prepare</h2>
            <p>Verify with Self, choose the facts you may need, and mint your soulbound credential on a supported network.</p>
          </article>
          <article>
            <span>02</span><h2>Choose and bind</h2>
            <p>Select one question, then bind its answer to the receiving address and purpose so it cannot be replayed elsewhere.</p>
          </article>
          <article>
            <span>03</span><h2>Use the answer</h2>
            <p>Copy the signed artifact into an app, or let a contract call <code>check</code> or single-use <code>consume</code>.</p>
          </article>
        </section>
        <V2PolicyLab />
      </main>
    </>
  );
}
