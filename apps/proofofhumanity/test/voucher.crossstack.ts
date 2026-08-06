/**
 * CROSS-STACK INTEGRATION TEST — proves the relay's EIP-712 voucher signing is accepted by the
 * REAL Phase C `ProofOfHumanity` contract, byte-for-byte.
 *
 * What it does (no phone / no live Self proof required):
 *   1. `forge build` the contracts package and load ProofOfHumanity's bytecode+ABI;
 *   2. start a local `anvil`, deploy `ProofOfHumanity(owner, issuer)` with a KNOWN issuer key;
 *   3. using THIS app's `app/lib/voucher.ts`, map a CONSTRUCTED Self discloseOutput
 *      (nationality "ARG", gender "M", olderThan 18, ofac true) to a voucher and sign it;
 *   4. assert the locally-computed EIP-712 digest == the contract's on-chain `hashVoucher(...)`;
 *   5. `mintWithVoucher(voucher, sig)` from a RELAYER account → assert it SUCCEEDS, `balanceOf(to)==1`,
 *      and `attributesOf`/`tokenURI` carry ARG / male / 18+ / OFAC-clear;
 *   6. assert a voucher signed by the WRONG key reverts `InvalidSigner`.
 *
 * WHAT THIS TEST DOES vs DEFERS (honest scope):
 *   - TESTED for real: the EIP-712 domain/type/field encoding + issuer-signature recovery, i.e. the
 *     exact seam where the backend meets Phase C. The discloseOutput is CONSTRUCTED, not produced by
 *     a real Self proof, because a genuine proof needs a passport scan on a phone.
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
import {
  buildVoucherFromDisclose,
  voucherDigest,
  signVoucher,
  type HumanityVoucher,
} from "../app/lib/voucher";

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
  console.log("\n=== proofofhumanity cross-stack voucher test ===\n");

  // 1) Build + load the real Phase C artifact.
  console.log("[1/6] forge build …");
  execSync("forge build", { cwd: CONTRACTS_DIR, stdio: "inherit" });
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as {
    abi: Abi;
    bytecode: { object: Hex };
  };
  const abi = artifact.abi;
  const bytecode = artifact.bytecode.object;
  assert(bytecode.length > 2, "loaded ProofOfHumanity deploy bytecode");

  // 2) Start anvil + deploy ProofOfHumanity(owner, issuer).
  console.log("[2/6] starting anvil + deploying ProofOfHumanity …");
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

    // 3) Build + sign a voucher from a CONSTRUCTED discloseOutput (real proof needs a phone).
    console.log("[3/6] building + signing voucher from a constructed discloseOutput …");
    const discloseOutput = {
      nullifier: "12345678901234567890123456789012345678901234567890", // a BN254-ish field element
      nationality: "ARG",
      gender: "M",
      minimumAge: "18",
      ofac: [true, true, true] as boolean[],
    };
    const expiry = BigInt(Math.floor(Date.now() / 1000)) + 365n * 24n * 60n * 60n;
    const voucher: HumanityVoucher = buildVoucherFromDisclose({ discloseOutput, to: TO_ADDRESS, expiry });

    assertEq(voucher.nationality, "0x415247", "nationality 'ARG' → bytes3 0x415247");
    assertEq(voucher.gender, 0x4d, "gender 'M' → uint8 0x4d");
    assertEq(voucher.ageFlags, 0x03, "olderThan 18 → ageFlags 0x03 (13+ | 18+)");
    assertEq(voucher.ofacClear, true, "ofac [true,true,true] → ofacClear true");

    const signature = await signVoucher(ISSUER_KEY, voucher, CHAIN_ID, poh);

    // 4) Local EIP-712 digest MUST equal the contract's on-chain hashVoucher(...).
    console.log("[4/6] cross-checking EIP-712 digest against on-chain hashVoucher …");
    const localDigest = voucherDigest(voucher, CHAIN_ID, poh);
    const onChainDigest = (await pub.readContract({
      address: poh,
      abi,
      functionName: "hashVoucher",
      args: [voucher],
    })) as Hex;
    assertEq(localDigest, onChainDigest, "lib/voucher digest == contract hashVoucher (domain+type+fields match)");

    // 5) Mint from the relayer → success + read back traits.
    console.log("[5/6] mintWithVoucher from relayer …");
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

    const attrs = (await pub.readContract({
      address: poh,
      abi,
      functionName: "attributesOf",
      args: [tokenId],
    })) as { ageFlags: number; nationality: Hex; gender: number; ofacClear: boolean; expiry: bigint };
    assertEq(attrs.nationality, "0x415247", "attributesOf.nationality == 0x415247 (ARG)");
    assertEq(attrs.gender, 0x4d, "attributesOf.gender == 0x4d (male)");
    assertEq(attrs.ageFlags, 0x03, "attributesOf.ageFlags == 0x03 (13+ | 18+)");
    assertEq(attrs.ofacClear, true, "attributesOf.ofacClear == true");

    const tokenURI = (await pub.readContract({ address: poh, abi, functionName: "tokenURI", args: [tokenId] })) as string;
    const jsonStr = tokenURI.startsWith("data:application/json;base64,")
      ? Buffer.from(tokenURI.split(",")[1], "base64").toString("utf8")
      : tokenURI;
    assert(jsonStr.includes('"value":"ARG"'), "tokenURI metadata contains Nationality ARG");
    assert(jsonStr.includes('"value":"male"'), "tokenURI metadata contains Gender male");
    assert(jsonStr.includes('"value":"18+"'), "tokenURI metadata contains Age 18+");
    assert(jsonStr.includes('"value":"clear"'), "tokenURI metadata contains OFAC clear");

    // 6) Wrong-key signature MUST revert InvalidSigner.
    console.log("[6/6] wrong-key voucher must revert InvalidSigner …");
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
