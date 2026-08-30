import type { Metadata } from "next";
import { PredicateCenter } from "../predicates/predicate-center";

export const metadata: Metadata = {
  title: "Verify private facts · Proof of Humanity",
  description: "Create Base Sepolia age, nationality, and sanctions attestations from a verified Self session.",
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
            Create an issuer-attested age, nationality, or sanctions result on the release-pinned Base Sepolia
            deployment. Custom v2 proofs and rehearsal credentials are outside this launch.
          </p>
        </section>
        <PredicateCenter standalone />
        <section className="verify-explainer">
          <article>
            <span>01</span><h2>Prepare</h2>
            <p>Verify with Self, choose the facts you may need, and mint your soulbound credential on Base Sepolia.</p>
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
      </main>
    </>
  );
}
