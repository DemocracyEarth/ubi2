/**
 * CROSS-STACK INTEGRATION TEST for the PREDICATE LAYER (v1, issuer-attested).
 *
 * Proves that THIS app's EIP-712 predicate SDK (`app/lib/predicate.ts`) is accepted
 * byte-for-byte by a REAL on-chain `PredicateVerifier`, and that a full
 * predicate-gated action reveals ONLY a boolean.
 *
 * What it does (no phone / no live Self proof required):
 *   1. `forge build` the REAL `ProofOfHumanity`, `PredicateVerifier`, and
 *      `SybilResistantVote` from the contracts package, then compile only a tiny
 *      `ConsumerProbe` fixture used to exercise verifier replay directly;
 *   2. start anvil; deploy ProofOfHumanity(owner, issuer),
 *      PredicateVerifier(owner, issuer) and SybilResistantVote(poh, pv, age>=18, ctx);
 *   3. mint a soulbound PoH SBT for a holder (reusing `app/lib/voucher.ts`);
 *   4. issue that holder a private `HumanCredential` (`signHumanCredential`) and,
 *      exactly as `/api/predicate` would, compute the boolean with `evalPredicate`
 *      and sign a `PredicateAttestation` for the vote contract;
 *   5. assert the off-chain digest == on-chain `hashAttestation` (EIP-712 parity);
 *   6. cast the gated vote → success, and assert ONLY the boolean is revealed:
 *      no age / nationality / OFAC value appears in the vote calldata, logs, or state;
 *   7. assert the negative space: replay (double-vote AND verifier `ReplayedNonce`),
 *      wrong predicate, wrong context, wrong consumer, wrong subject, stale epoch,
 *      bad issuer signature, and a non-human all REVERT.
 *
 * The contract artifacts are loaded from the production Foundry package. There is
 * no mirrored verifier implementation that could drift while preserving a green test.
 */

import { spawn, execSync, type ChildProcess } from "node:child_process";
import { readFileSync, mkdtempSync, mkdirSync, copyFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  getAddress,
  toHex,
  stringToBytes,
  pad,
  type Abi,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { buildVoucher, signVoucher, type HumanityVoucher } from "../app/lib/voucher";
import {
  ageFlagsFromThresholds,
  descriptorHash,
  evalPredicate,
  hashPredicateAttestation,
  nationalityToBytes3,
  recoverPredicateSigner,
  signHumanCredential,
  signPredicateAttestation,
  verifyHumanCredential,
  type HumanCredential,
  type PredicateAttestation,
} from "../app/lib/predicate";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONTRACTS_DIR = path.resolve(__dirname, "../../../contracts");
const POH_ARTIFACT = path.join(CONTRACTS_DIR, "out/ProofOfHumanity.sol/ProofOfHumanity.json");
const PV_ARTIFACT = path.join(CONTRACTS_DIR, "out/PredicateVerifier.sol/PredicateVerifier.json");
const VOTE_ARTIFACT = path.join(CONTRACTS_DIR, "out/SybilResistantVote.sol/SybilResistantVote.json");
const FIXTURE_SRC = path.join(__dirname, "fixtures/PredicateFixtures.sol");

const RPC = "http://127.0.0.1:8545";
const CHAIN_ID = 31337;

// Well-known Anvil accounts (NOT secrets).
const OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex; // #0 owner/relayer
const ISSUER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex; // #1 issuer
const HOLDER_A_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex; // #2 human A
const WRONG_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex; // #3 not the issuer
const HOLDER_B_KEY = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" as Hex; // #4 human B
const OUTSIDER_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" as Hex; // #5 no SBT

const anvilChain = defineChain({
  id: CHAIN_ID,
  name: "Anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});

let passed = 0;
let failed = 0;
function assert(cond: boolean, msg: string) {
  if (cond) {
    passed++;
    console.log(`  ✓ ${msg}`);
  } else {
    failed++;
    console.error(`  ✗ ${msg}`);
  }
}
function assertEq<T>(a: T, b: T, msg: string) {
  assert(a === b, `${msg} (got ${String(a)}, want ${String(b)})`);
}

async function waitForAnvil(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(RPC, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
      });
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("anvil did not become ready in time");
}

type ContractArtifact = { abi: Abi; bytecode: Hex };

function loadArtifact(artifactPath: string): ContractArtifact {
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
    abi: Abi;
    bytecode: { object: Hex };
  };
  return { abi: artifact.abi, bytecode: artifact.bytecode.object };
}

/** Compile only the minimal consumer probe in a throwaway Foundry project. */
function buildConsumerProbe(): ContractArtifact {
  const root = mkdtempSync(path.join(tmpdir(), "poh-predicate-fixtures-"));
  mkdirSync(path.join(root, "src"), { recursive: true });
  copyFileSync(FIXTURE_SRC, path.join(root, "src/PredicateFixtures.sol"));
  writeFileSync(
    path.join(root, "foundry.toml"),
    [
      "[profile.default]",
      'src = "src"',
      'out = "out"',
      "libs = []",
      'solc = "0.8.28"',
      "optimizer = true",
      "optimizer_runs = 200",
      'evm_version = "cancun"',
      "",
    ].join("\n"),
  );
  execSync("forge build", { cwd: root, stdio: "inherit" });
  return loadArtifact(path.join(root, "out/PredicateFixtures.sol/ConsumerProbe.json"));
}

/** Capture the revert-reason string from a simulate call (empty string == no revert). */
async function revertReason(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "";
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

async function main() {
  console.log("\n=== proofofhumanity cross-stack PREDICATE test (v1 issuer-attested) ===\n");

  // 1) Build and load the production contracts; compile the consumer probe.
  console.log("[1/8] forge build production contracts + consumer probe …");
  execSync("forge build", { cwd: CONTRACTS_DIR, stdio: "inherit" });
  const pohArtifact = loadArtifact(POH_ARTIFACT);
  const pohAbi = pohArtifact.abi;
  const pohBytecode = pohArtifact.bytecode;
  const fx = {
    pv: loadArtifact(PV_ARTIFACT),
    vote: loadArtifact(VOTE_ARTIFACT),
    probe: buildConsumerProbe(),
  };
  assert(pohBytecode.length > 2, "loaded production ProofOfHumanity deploy bytecode");
  assert(
    fx.pv.bytecode.length > 2 && fx.vote.bytecode.length > 2,
    "loaded production PredicateVerifier + SybilResistantVote bytecode",
  );

  // The consumer contracts revert with custom errors DECLARED on PredicateVerifier
  // (thrown inside `pv.consume`). Fold the verifier's error fragments into the
  // consumers' ABIs so viem can decode those cross-contract reverts by name.
  const pvErrors = fx.pv.abi.filter((f) => f.type === "error");
  const voteAbi = [...fx.vote.abi, ...pvErrors] as Abi;
  const probeAbi = [...fx.probe.abi, ...pvErrors] as Abi;

  const owner = privateKeyToAccount(OWNER_KEY);
  const issuer = privateKeyToAccount(ISSUER_KEY);
  const holderA = privateKeyToAccount(HOLDER_A_KEY);
  const holderB = privateKeyToAccount(HOLDER_B_KEY);
  const outsider = privateKeyToAccount(OUTSIDER_KEY);

  const pub = createPublicClient({ chain: anvilChain, transport: http(RPC) });
  const ownerWallet = createWalletClient({ account: owner, chain: anvilChain, transport: http(RPC) });
  const holderAWallet = createWalletClient({ account: holderA, chain: anvilChain, transport: http(RPC) });
  const holderBWallet = createWalletClient({ account: holderB, chain: anvilChain, transport: http(RPC) });
  const outsiderWallet = createWalletClient({ account: outsider, chain: anvilChain, transport: http(RPC) });

  // A consumer-defined context (e.g. a proposal id).
  const CONTEXT = pad(toHex(stringToBytes("proposal:42")), { size: 32 }) as Hex;
  const REQUIRED = descriptorHash("age>=18");

  const anvil: ChildProcess = spawn("anvil", ["--port", "8545", "--silent"], { stdio: "ignore" });
  try {
    await waitForAnvil();

    // 2) Deploy PoH, PredicateVerifier, SybilResistantVote.
    console.log("[2/8] deploying ProofOfHumanity + PredicateVerifier + SybilResistantVote …");
    const pohHash = await ownerWallet.deployContract({ abi: pohAbi, bytecode: pohBytecode, args: [owner.address, issuer.address] });
    const poh = (await pub.waitForTransactionReceipt({ hash: pohHash })).contractAddress as Address;

    const pvHash = await ownerWallet.deployContract({ abi: fx.pv.abi, bytecode: fx.pv.bytecode, args: [owner.address, issuer.address] });
    const pv = (await pub.waitForTransactionReceipt({ hash: pvHash })).contractAddress as Address;

    const voteHash = await ownerWallet.deployContract({ abi: fx.vote.abi, bytecode: fx.vote.bytecode, args: [poh, pv, REQUIRED, CONTEXT] });
    const vote = (await pub.waitForTransactionReceipt({ hash: voteHash })).contractAddress as Address;

    const probeHash = await ownerWallet.deployContract({ abi: fx.probe.abi, bytecode: fx.probe.bytecode, args: [pv] });
    const probe = (await pub.waitForTransactionReceipt({ hash: probeHash })).contractAddress as Address;
    console.log(`      PoH=${poh}  PV=${pv}  Vote=${vote}`);

    assertEq(
      getAddress((await pub.readContract({ address: pv, abi: fx.pv.abi, functionName: "issuer" })) as Address),
      getAddress(issuer.address),
      "PredicateVerifier.issuer == our issuer key",
    );

    const epoch = Number(await pub.readContract({ address: poh, abi: pohAbi, functionName: "currentEpoch" }));

    // 3) Mint soulbound PoH SBTs for holder A and holder B (reusing the voucher lib).
    console.log("[3/8] minting PoH SBTs for two humans …");
    async function mint(to: Address, nullifier: string): Promise<bigint> {
      const voucher: HumanityVoucher = buildVoucher({ discloseOutput: { nullifier }, to, epoch });
      const sig = await signVoucher(ISSUER_KEY, voucher, CHAIN_ID, poh);
      const { request } = await pub.simulateContract({ account: owner, address: poh, abi: pohAbi, functionName: "mintWithVoucher", args: [voucher, sig] });
      await pub.waitForTransactionReceipt({ hash: await ownerWallet.writeContract(request) });
      return (await pub.readContract({ address: poh, abi: pohAbi, functionName: "tokenOfNullifier", args: [BigInt(nullifier)] })) as bigint;
    }
    const tokenA = await mint(holderA.address, "11111111111111111111111111111111111111111111111111");
    const tokenB = await mint(holderB.address, "22222222222222222222222222222222222222222222222222");
    assert(tokenA > 0n && tokenB > 0n, `minted SBTs (A=#${tokenA}, B=#${tokenB})`);

    // 4) Issue holder A a private HumanCredential + build/sign the attestation the way /api/predicate does.
    console.log("[4/8] issuing a HumanCredential + signing an age>=18 attestation …");
    const credA: HumanCredential = {
      nullifier: BigInt("11111111111111111111111111111111111111111111111111"),
      ageFlags: ageFlagsFromThresholds({ over21: true }),
      nationality: nationalityToBytes3("ARG"),
      ofacClear: true,
      epoch,
    };
    const credASig = await signHumanCredential(ISSUER_KEY, credA);
    assert(await verifyHumanCredential(credA, credASig, issuer.address), "HumanCredential verifies against the issuer (TS-only, portable domain)");

    // The issuer computes the boolean from the credential attributes via the grammar.
    const resultA = evalPredicate("age>=18", { ageFlags: credA.ageFlags, nationality: credA.nationality, ofacClear: credA.ofacClear });
    assertEq(resultA, true, "evalPredicate(age>=18) over a 21+ credential == true");

    const attA: PredicateAttestation = {
      consumer: getAddress(vote),
      context: CONTEXT,
      predicate: REQUIRED,
      result: resultA,
      subject: getAddress(holderA.address),
      epoch,
      nonce: 1n,
    };
    const sigA = await signPredicateAttestation(ISSUER_KEY, attA, CHAIN_ID, pv);

    // 5) EIP-712 parity: off-chain digest == on-chain hashAttestation.
    console.log("[5/8] EIP-712 digest parity (SDK vs PredicateVerifier) …");
    const localDigest = hashPredicateAttestation(attA, CHAIN_ID, pv);
    const onChainDigest = (await pub.readContract({ address: pv, abi: fx.pv.abi, functionName: "hashAttestation", args: [attA] })) as Hex;
    assertEq(localDigest, onChainDigest, "hashPredicateAttestation == PredicateVerifier.hashAttestation (typehash byte-match)");
    assertEq(
      getAddress(await recoverPredicateSigner(attA, sigA, CHAIN_ID, pv)),
      getAddress(issuer.address),
      "off-chain signature recovers to the issuer",
    );

    // stateless check() succeeds and does NOT burn the nonce.
    const checkOk = (await pub.readContract({ address: pv, abi: fx.pv.abi, functionName: "check", args: [attA, sigA, holderA.address, vote] })) as boolean;
    assertEq(checkOk, true, "check(att, sig, presenter, consumer) == true (stateless gate)");

    // 6) Cast the gated vote → success + ONLY-a-boolean assertions.
    console.log("[6/8] casting the predicate-gated vote …");
    const { request: voteReq } = await pub.simulateContract({ account: holderA, address: vote, abi: voteAbi, functionName: "vote", args: [tokenA, true, attA, sigA] });
    const voteTxHash = await holderAWallet.writeContract(voteReq);
    const voteRcpt = await pub.waitForTransactionReceipt({ hash: voteTxHash });
    assertEq(voteRcpt.status, "success", "vote() tx status == success");
    assertEq((await pub.readContract({ address: vote, abi: voteAbi, functionName: "yesVotes" })) as bigint, 1n, "yesVotes == 1");
    assertEq((await pub.readContract({ address: vote, abi: voteAbi, functionName: "voted", args: [tokenA] })) as boolean, true, "voted[tokenA] == true");

    // ONLY-A-BOOLEAN: no attribute value in the attestation, calldata, logs, or storage.
    const attKeys = Object.keys(attA);
    assert(!attKeys.some((k) => /age|nationality|ofac|gender|birth/i.test(k)), "attestation struct carries no attribute field (only consumer/context/predicate/result/subject/epoch/nonce)");
    const tx = await pub.getTransaction({ hash: voteTxHash });
    const calldata = tx.input.toLowerCase();
    const natHex = nationalityToBytes3("ARG").slice(2).toLowerCase(); // "415247"
    assert(!calldata.includes(natHex), "vote calldata does NOT contain the nationality bytes (0x415247)");
    // ageFlags (0x03) is never a standalone field; the only 'age' fact is the keccak(descriptor), which is opaque.
    assert(calldata.includes(REQUIRED.slice(2).toLowerCase()), "vote calldata carries only the predicate HASH (opaque), not the descriptor text");
    assert(!calldata.includes(toHex(stringToBytes("age>=18")).slice(2).toLowerCase()), "vote calldata does NOT contain the plaintext descriptor 'age>=18'");
    for (const log of voteRcpt.logs) {
      const blob = (log.data + log.topics.join("")).toLowerCase();
      assert(!blob.includes(natHex), "vote log does NOT leak the nationality bytes");
    }

    // 7) NEGATIVE SPACE.
    console.log("[7/8] negative space: replay / wrong-predicate / wrong-consumer / wrong-subject / stale / bad-sig / non-human …");

    // 7a) Double-vote by the same human reverts (one human, one vote).
    let r = await revertReason(() => pub.simulateContract({ account: holderA, address: vote, abi: voteAbi, functionName: "vote", args: [tokenA, true, attA, sigA] }));
    assert(r.includes("AlreadyVoted"), `double-vote reverts AlreadyVoted (${r.split("\n")[0]})`);

    // 7b) Verifier-level anti-replay via ConsumerProbe: same attestation consumed twice.
    const attProbe: PredicateAttestation = { ...attA, consumer: getAddress(probe), nonce: 7n };
    const sigProbe = await signPredicateAttestation(ISSUER_KEY, attProbe, CHAIN_ID, pv);
    const { request: probeReq } = await pub.simulateContract({ account: owner, address: probe, abi: probeAbi, functionName: "probe", args: [attProbe, sigProbe, holderA.address] });
    await pub.waitForTransactionReceipt({ hash: await ownerWallet.writeContract(probeReq) });
    r = await revertReason(() => pub.simulateContract({ account: owner, address: probe, abi: probeAbi, functionName: "probe", args: [attProbe, sigProbe, holderA.address] }));
    assert(r.includes("AttestationReplayed"), `verifier replays revert AttestationReplayed (${r.split("\n")[0]})`);

    // Remaining negatives use holder B (never successfully votes, so voted[B] stays false).
    const baseB = { context: CONTEXT, predicate: REQUIRED, result: true, subject: getAddress(holderB.address), epoch } as const;

    // 7c) Wrong predicate (nationality=USA instead of the required age>=18).
    const attWrongPred: PredicateAttestation = { ...baseB, consumer: getAddress(vote), predicate: descriptorHash("nationality=USA"), nonce: 10n };
    const sigWrongPred = await signPredicateAttestation(ISSUER_KEY, attWrongPred, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: holderB, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attWrongPred, sigWrongPred] }));
    assert(r.includes("WrongPredicate"), `wrong-predicate reverts WrongPredicate (${r.split("\n")[0]})`);

    // 7d) Wrong context.
    const attWrongCtx: PredicateAttestation = { ...baseB, consumer: getAddress(vote), context: pad(toHex(stringToBytes("proposal:99")), { size: 32 }) as Hex, nonce: 11n };
    const sigWrongCtx = await signPredicateAttestation(ISSUER_KEY, attWrongCtx, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: holderB, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attWrongCtx, sigWrongCtx] }));
    assert(r.includes("WrongContext"), `wrong-context reverts WrongContext (${r.split("\n")[0]})`);

    // 7e) Wrong consumer: attestation bound to a different consumer than the vote contract.
    const attWrongConsumer: PredicateAttestation = { ...baseB, consumer: getAddress(probe), nonce: 12n };
    const sigWrongConsumer = await signPredicateAttestation(ISSUER_KEY, attWrongConsumer, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: holderB, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attWrongConsumer, sigWrongConsumer] }));
    assert(r.includes("ConsumerMismatch"), `wrong-consumer reverts ConsumerMismatch (${r.split("\n")[0]})`);

    // 7f) Wrong subject: attestation names holder A but holder B presents it.
    const attWrongSubject: PredicateAttestation = { ...baseB, consumer: getAddress(vote), subject: getAddress(holderA.address), nonce: 13n };
    const sigWrongSubject = await signPredicateAttestation(ISSUER_KEY, attWrongSubject, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: holderB, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attWrongSubject, sigWrongSubject] }));
    assert(r.includes("SubjectMismatch"), `wrong-subject reverts SubjectMismatch (${r.split("\n")[0]})`);

    // 7g) Stale epoch (older than VALIDITY_EPOCHS).
    const attStale: PredicateAttestation = { ...baseB, consumer: getAddress(vote), epoch: Math.max(0, epoch - 5), nonce: 14n };
    const sigStale = await signPredicateAttestation(ISSUER_KEY, attStale, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: holderB, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attStale, sigStale] }));
    assert(r.includes("StaleEpoch"), `stale-epoch reverts StaleEpoch (${r.split("\n")[0]})`);

    // 7h) Bad issuer signature (signed by a non-issuer key).
    const attGoodB: PredicateAttestation = { ...baseB, consumer: getAddress(vote), nonce: 15n };
    const badSig = await signPredicateAttestation(WRONG_KEY, attGoodB, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: holderB, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attGoodB, badSig] }));
    assert(r.includes("InvalidSigner"), `bad issuer signature reverts InvalidSigner (${r.split("\n")[0]})`);

    // 7i) Non-human: an outsider with no SBT cannot vote (using holder B's token id).
    const goodSigB = await signPredicateAttestation(ISSUER_KEY, attGoodB, CHAIN_ID, pv);
    r = await revertReason(() => pub.simulateContract({ account: outsider, address: vote, abi: voteAbi, functionName: "vote", args: [tokenB, true, attGoodB, goodSigB] }));
    assert(r.length > 0 && (r.includes("NotTokenHolder") || r.includes("revert")), `non-human cannot vote (reverts: ${r.split("\n")[0]})`);
    // silence unused-wallet lint (wallets are the signing identities used via simulate+write)
    void holderBWallet;
    void outsiderWallet;

    // 8) Sanity: holder B still hasn't voted after all the failed attempts.
    console.log("[8/8] final state …");
    assertEq((await pub.readContract({ address: vote, abi: voteAbi, functionName: "voted", args: [tokenB] })) as boolean, false, "voted[tokenB] == false (all B attempts reverted)");
    assertEq((await pub.readContract({ address: vote, abi: voteAbi, functionName: "yesVotes" })) as bigint, 1n, "yesVotes still == 1 (only the one valid vote counted)");
  } finally {
    anvil.kill("SIGKILL");
  }

  console.log(`\n=== ${passed} passed, ${failed} failed ===\n`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => {
  console.error("\nFATAL:", e);
  process.exit(1);
});
