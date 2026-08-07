/**
 * CROSS-STACK INTEGRATION TEST — proves the relay's EIP-712 voucher signing is accepted by the
 * REAL `ProofOfHumanity` contract, byte-for-byte, for the MINIMAL voucher.
 *
 * What it does (no phone / no live Self proof required):
 *   1. `forge build` the contracts package and load ProofOfHumanity's bytecode+ABI;
 *   2. start a local `anvil`, deploy `ProofOfHumanity(owner, issuer)` with a KNOWN issuer key;
 *   3. using THIS app's `app/lib/voucher.ts`, build a MINIMAL voucher { to, nullifier, epoch } from
 *      a nullifier + the contract's current epoch, and sign it;
 *   4. assert the locally-computed EIP-712 digest == the contract's on-chain `hashVoucher(...)`;
 *   5. `mintWithVoucher(voucher, sig)` from a RELAYER account → assert it SUCCEEDS, `balanceOf(to)==1`,
 *      the token `isValid`, and its `tokenURI` carries NO nationality / gender / age;
 *   6. assert a voucher signed by the WRONG key reverts `InvalidSigner`;
 *   7. assert a fresh voucher (same nullifier, newer epoch) REFRESHES the token monotonically.
 *
 * WHAT THIS TEST DOES vs DEFERS (honest scope):
 *   - TESTED for real: the EIP-712 domain/type/field encoding + issuer-signature recovery, i.e. the
 *     exact seam where the backend meets the contract, plus the epoch refresh path. The nullifier is
 *     CONSTRUCTED, not produced by a real Self proof (a genuine proof needs a passport scan).
 *   - DEFERRED (needs a phone): `@selfxyz/core`'s `SelfBackendVerifier.verify(...)` (Groth16 +
 *     Self-registry membership). That path is wired in app/api/self-verify/route.ts but exercised
 *     only with a real passport.
 */

import { spawn, execSync, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  getAddress,
  type Abi,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { buildVoucher, voucherDigest, signVoucher, type HumanityVoucher } from "../app/lib/voucher";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONTRACTS_DIR = path.resolve(__dirname, "../../../contracts");
const ARTIFACT = path.join(CONTRACTS_DIR, "out/ProofOfHumanity.sol/ProofOfHumanity.json");

const RPC = "http://127.0.0.1:8545";
const CHAIN_ID = 31337;

// Well-known Anvil accounts (NOT secrets).
const OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex; // acct #0
const ISSUER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex; // acct #1
const RELAYER_KEY = OWNER_KEY; // acct #0 relays the mint tx
const TO_ADDRESS = getAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"); // acct #2 — the "human"
const WRONG_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex; // acct #3

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

async function main() {
  console.log("\n=== proofofhumanity cross-stack voucher test (minimal) ===\n");

  // 1) Build + load the real contract artifact.
  console.log("[1/7] forge build …");
  execSync("forge build", { cwd: CONTRACTS_DIR, stdio: "inherit" });
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as {
    abi: Abi;
    bytecode: { object: Hex };
  };
  const abi = artifact.abi;
  const bytecode = artifact.bytecode.object;
  assert(bytecode.length > 2, "loaded ProofOfHumanity deploy bytecode");

  // 2) Start anvil + deploy ProofOfHumanity(owner, issuer).
  console.log("[2/7] starting anvil + deploying ProofOfHumanity …");
  const owner = privateKeyToAccount(OWNER_KEY);
  const issuer = privateKeyToAccount(ISSUER_KEY);
  const relayer = privateKeyToAccount(RELAYER_KEY);

  const pub = createPublicClient({ chain: anvilChain, transport: http(RPC) });
  const ownerWallet = createWalletClient({ account: owner, chain: anvilChain, transport: http(RPC) });
  const relayerWallet = createWalletClient({ account: relayer, chain: anvilChain, transport: http(RPC) });

  let poh: Address;
  const anvil: ChildProcess = spawn("anvil", ["--port", "8545", "--silent"], { stdio: "ignore" });

  try {
    await waitForAnvil();

    const deployHash = await ownerWallet.deployContract({
      abi,
      bytecode,
      args: [owner.address, issuer.address],
    });
    const deployRcpt = await pub.waitForTransactionReceipt({ hash: deployHash });
    if (!deployRcpt.contractAddress) throw new Error("deploy produced no contract address");
    poh = deployRcpt.contractAddress;
    console.log(`      ProofOfHumanity @ ${poh}`);
    console.log(`      issuer          = ${issuer.address}`);

    const onChainIssuer = (await pub.readContract({ address: poh, abi, functionName: "issuer" })) as Address;
    assertEq(getAddress(onChainIssuer), getAddress(issuer.address), "on-chain issuer == our issuer key");

    // 3) Build + sign a MINIMAL voucher from a constructed nullifier at the contract's current epoch.
    console.log("[3/7] building + signing a minimal voucher …");
    const nullifier = "12345678901234567890123456789012345678901234567890"; // a BN254-ish field element
    const epoch = Number(await pub.readContract({ address: poh, abi, functionName: "currentEpoch" }));
    assert(epoch > 0, `contract currentEpoch() == ${epoch}`);
    const voucher: HumanityVoucher = buildVoucher({ discloseOutput: { nullifier }, to: TO_ADDRESS, epoch });

    assertEq(voucher.to, TO_ADDRESS, "voucher.to == recipient");
    assertEq(voucher.nullifier, BigInt(nullifier), "voucher.nullifier == constructed nullifier");
    assertEq(voucher.epoch, epoch, "voucher.epoch == currentEpoch()");

    const signature = await signVoucher(ISSUER_KEY, voucher, CHAIN_ID, poh);

    // 4) Local EIP-712 digest MUST equal the contract's on-chain hashVoucher(...).
    console.log("[4/7] cross-checking EIP-712 digest against on-chain hashVoucher …");
    const localDigest = voucherDigest(voucher, CHAIN_ID, poh);
    const onChainDigest = (await pub.readContract({
      address: poh,
      abi,
      functionName: "hashVoucher",
      args: [voucher],
    })) as Hex;
    assertEq(localDigest, onChainDigest, "lib/voucher digest == contract hashVoucher (domain+type+fields match)");

    // 5) Mint from the relayer → success + read back the minimal token.
    console.log("[5/7] mintWithVoucher from relayer …");
    const { request } = await pub.simulateContract({
      account: relayer,
      address: poh,
      abi,
      functionName: "mintWithVoucher",
      args: [voucher, signature],
    });
    const mintHash = await relayerWallet.writeContract(request);
    const mintRcpt = await pub.waitForTransactionReceipt({ hash: mintHash });
    assertEq(mintRcpt.status, "success", "mintWithVoucher tx status == success");

    const bal = (await pub.readContract({ address: poh, abi, functionName: "balanceOf", args: [TO_ADDRESS] })) as bigint;
    assertEq(bal, 1n, "balanceOf(to) == 1");

    const tokenId = (await pub.readContract({
      address: poh,
      abi,
      functionName: "tokenOfNullifier",
      args: [voucher.nullifier],
    })) as bigint;
    assert(tokenId > 0n, `tokenOfNullifier(nullifier) == ${tokenId}`);

    const valid = (await pub.readContract({ address: poh, abi, functionName: "isValid", args: [tokenId] })) as boolean;
    assertEq(valid, true, "isValid(tokenId) == true right after mint");

    const locked = (await pub.readContract({ address: poh, abi, functionName: "locked", args: [tokenId] })) as boolean;
    assertEq(locked, true, "locked(tokenId) == true (ERC-5192 soulbound)");

    // tokenURI must carry NO personal data — the minimal credential.
    const tokenURI = (await pub.readContract({ address: poh, abi, functionName: "tokenURI", args: [tokenId] })) as string;
    const jsonStr = tokenURI.startsWith("data:application/json;base64,")
      ? Buffer.from(tokenURI.split(",")[1], "base64").toString("utf8")
      : tokenURI;
    const lower = jsonStr.toLowerCase();
    assert(!lower.includes("nationality"), "tokenURI has NO nationality field");
    assert(!lower.includes("gender"), "tokenURI has NO gender field");
    assert(!/\bage\b/.test(lower), "tokenURI has NO age field");

    // 6) Wrong-key signature MUST revert InvalidSigner (use a different nullifier so it's a fresh mint).
    console.log("[6/7] wrong-key voucher must revert InvalidSigner …");
    const voucher2: HumanityVoucher = { ...voucher, nullifier: voucher.nullifier + 1n };
    const badSig = await signVoucher(WRONG_KEY, voucher2, CHAIN_ID, poh);
    let reverted = false;
    let reason = "";
    try {
      await pub.simulateContract({
        account: relayer,
        address: poh,
        abi,
        functionName: "mintWithVoucher",
        args: [voucher2, badSig],
      });
    } catch (e) {
      reverted = true;
      reason = e instanceof Error ? e.message : String(e);
    }
    assert(reverted, "wrong-key mintWithVoucher reverts");
    assert(reason.includes("InvalidSigner"), `revert reason is InvalidSigner (got: ${reason.split("\n")[0]})`);

    // 7) Re-verification refresh: same nullifier, a NEWER epoch, correctly signed → succeeds (monotonic).
    console.log("[7/7] refresh with a newer epoch (same nullifier) …");
    const refreshed: HumanityVoucher = { ...voucher, epoch: voucher.epoch + 1 };
    const refreshSig = await signVoucher(ISSUER_KEY, refreshed, CHAIN_ID, poh);
    const { request: refreshReq } = await pub.simulateContract({
      account: relayer,
      address: poh,
      abi,
      functionName: "mintWithVoucher",
      args: [refreshed, refreshSig],
    });
    const refreshHash = await relayerWallet.writeContract(refreshReq);
    const refreshRcpt = await pub.waitForTransactionReceipt({ hash: refreshHash });
    assertEq(refreshRcpt.status, "success", "refresh (newer epoch) tx status == success");
    const balAfter = (await pub.readContract({
      address: poh,
      abi,
      functionName: "balanceOf",
      args: [TO_ADDRESS],
    })) as bigint;
    assertEq(balAfter, 1n, "balanceOf(to) still == 1 after refresh (no second token)");
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
