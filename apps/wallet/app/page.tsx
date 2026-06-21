export default function Home() {
  return (
    <main>
      <h1>
        ubi<span style={{ color: "var(--accent)" }}>2</span>
      </h1>
      <p style={{ color: "var(--muted)", fontSize: "1.1rem", lineHeight: 1.6 }}>
        A Universal Basic Income blockchain where humans are verified by AI, contracts are written in
        plain language, and money flows as a continuous stream of <strong>1 UBI / hour</strong>.
      </p>

      <h2 style={{ marginTop: "2.5rem" }}>Milestone 1 — EVM RPC + Wallet</h2>
      <p style={{ color: "var(--muted)" }}>
        This skeleton is built out by the agent loop. Next up (task <code>M1-T6</code>): connect to the
        devnet RPC, add it to MetaMask, and watch a verified account&rsquo;s balance tick upward in real
        time.
      </p>

      <ul style={{ color: "var(--muted)", lineHeight: 1.8 }}>
        <li>Add network / connect wallet</li>
        <li>Live-streaming balance view</li>
        <li>Block &amp; transaction explorer</li>
      </ul>

      <p style={{ marginTop: "2.5rem", color: "var(--muted)", fontSize: "0.9rem" }}>
        See <code>docs/roadmap.md</code> and <code>docs/board.md</code> for the plan.
      </p>
    </main>
  );
}
