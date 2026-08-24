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
 *   6. assert an identical voucher replay reverts `VoucherReplayed`;
 *   7. assert a voucher signed by the WRONG key or for the WRONG chain reverts `InvalidSigner`;
 *   8. assert a fresh voucher (same nullifier, newer epoch) REFRESHES the token monotonically.
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
import { NextRequest } from "next/server";
import {
  buildVoucher,
  serializeVoucher,
  voucherDigest,
  signVoucher,
  type HumanityVoucher,
} from "../app/lib/voucher";
import {
  readSponsoredMintEvidence,
  SponsoredMintExecutionError,
  submitSponsoredMint,
  waitForSponsoredMintEvidence,
} from "../app/lib/server/sponsored-mint-executor";
import type { ChainConfig } from "../app/config";
import type { SponsoredMintServerConfig } from "../app/server-config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONTRACTS_DIR = path.resolve(__dirname, "../../../contracts");
const ARTIFACT = path.join(CONTRACTS_DIR, "out/ProofOfHumanity.sol/ProofOfHumanity.json");

const RPC = "http://127.0.0.1:8545";
const CHAIN_ID = 11_155_111;

// Well-known Anvil accounts (NOT secrets).
const OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex; // acct #0
const ISSUER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex; // acct #1
const RELAYER_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex; // acct #3
const RECIPIENT_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex; // acct #2
const TO_ADDRESS = getAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"); // acct #2 — the "human"
const WRONG_KEY = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" as Hex; // acct #4

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

async function sponsorFailureCode(task: () => Promise<unknown>): Promise<string> {
  try {
    await task();
    return "none";
  } catch (error) {
    return error instanceof SponsoredMintExecutionError ? error.code : "unexpected";
  }
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
  console.log("[1/9] forge build …");
  execSync("forge build", { cwd: CONTRACTS_DIR, stdio: "inherit" });
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as {
    abi: Abi;
    bytecode: { object: Hex };
  };
  const abi = artifact.abi;
  const bytecode = artifact.bytecode.object;
  assert(bytecode.length > 2, "loaded ProofOfHumanity deploy bytecode");

  // 2) Start anvil + deploy ProofOfHumanity(owner, issuer).
  console.log("[2/9] starting anvil + deploying ProofOfHumanity …");
  const owner = privateKeyToAccount(OWNER_KEY);
  const issuer = privateKeyToAccount(ISSUER_KEY);
  const relayer = privateKeyToAccount(RELAYER_KEY);

  const pub = createPublicClient({ chain: anvilChain, transport: http(RPC) });
  const ownerWallet = createWalletClient({ account: owner, chain: anvilChain, transport: http(RPC) });
  const relayerWallet = createWalletClient({ account: relayer, chain: anvilChain, transport: http(RPC) });

  let poh: Address;
  const anvil: ChildProcess = spawn("anvil", ["--port", "8545", "--chain-id", String(CHAIN_ID), "--silent"], {
    stdio: "ignore",
  });

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
    console.log("[3/9] building + signing a minimal voucher …");
    const nullifier = "12345678901234567890123456789012345678901234567890"; // a BN254-ish field element
    const epoch = Number(await pub.readContract({ address: poh, abi, functionName: "currentEpoch" }));
    assert(epoch > 0, `contract currentEpoch() == ${epoch}`);
    const voucher: HumanityVoucher = buildVoucher({ discloseOutput: { nullifier }, to: TO_ADDRESS, epoch });

    assertEq(voucher.to, TO_ADDRESS, "voucher.to == recipient");
    assertEq(voucher.nullifier, BigInt(nullifier), "voucher.nullifier == constructed nullifier");
    assertEq(voucher.epoch, epoch, "voucher.epoch == currentEpoch()");

    const signature = await signVoucher(ISSUER_KEY, voucher, CHAIN_ID, poh);

    // 4) Local EIP-712 digest MUST equal the contract's on-chain hashVoucher(...).
    console.log("[4/9] cross-checking EIP-712 digest against on-chain hashVoucher …");
    const localDigest = voucherDigest(voucher, CHAIN_ID, poh);
    const onChainDigest = (await pub.readContract({
      address: poh,
      abi,
      functionName: "hashVoucher",
      args: [voucher],
    })) as Hex;
    assertEq(localDigest, onChainDigest, "lib/voucher digest == contract hashVoucher (domain+type+fields match)");

    // 5) Run the production sponsor executor → success + verified receipt evidence + token state.
    console.log("[5/9] production sponsored-mint executor from an isolated relayer …");
    const sponsoredChain: ChainConfig = {
      chainId: CHAIN_ID,
      name: "Anvil testnet fixture",
      network: "testnet",
      rpcUrl: RPC,
      pohAddress: poh,
      predicateAddress: "0x0000000000000000000000000000000000000000",
    };
    const sponsorConfig: SponsoredMintServerConfig = {
      privateKey: RELAYER_KEY,
      enabledChainIds: [CHAIN_ID],
      maxGas: 350_000n,
      maxFeeWei: 1_000_000_000_000_000_000n,
      minimumReserveWei: 1_000_000_000_000n,
      confirmations: 1,
      receiptTimeoutMs: 15_000,
      dailyTransactionLimit: 100,
    };
    const execution = { chain: sponsoredChain, voucher, signature, config: sponsorConfig };
    assertEq(
      await sponsorFailureCode(() =>
        submitSponsoredMint({ ...execution, config: { ...sponsorConfig, privateKey: ISSUER_KEY } }),
      ),
      "signer-role-overlap",
      "issuer key cannot be reused as the sponsor",
    );
    assertEq(
      await sponsorFailureCode(() =>
        submitSponsoredMint({ ...execution, config: { ...sponsorConfig, privateKey: OWNER_KEY } }),
      ),
      "signer-role-overlap",
      "contract owner key cannot be reused as the sponsor",
    );
    assertEq(
      await sponsorFailureCode(() =>
        submitSponsoredMint({ ...execution, config: { ...sponsorConfig, privateKey: RECIPIENT_KEY } }),
      ),
      "signer-role-overlap",
      "proof-bound recipient key cannot be reused as the sponsor",
    );
    assertEq(
      await sponsorFailureCode(() =>
        submitSponsoredMint({ ...execution, chain: { ...sponsoredChain, network: "mainnet" } }),
      ),
      "policy-disabled",
      "mainnet classification is rejected before RPC or spending",
    );
    assertEq(
      await sponsorFailureCode(() =>
        submitSponsoredMint({ ...execution, config: { ...sponsorConfig, maxGas: 1n } }),
      ),
      "gas-limit",
      "gas estimate above the hard envelope is rejected",
    );
    assertEq(
      await sponsorFailureCode(() =>
        submitSponsoredMint({ ...execution, config: { ...sponsorConfig, maxFeeWei: 1n } }),
      ),
      "fee-limit",
      "maximum transaction fee above the sponsor budget is rejected",
    );
    const submitted = await submitSponsoredMint(execution);
    const evidence = await waitForSponsoredMintEvidence(execution, submitted.transactionHash);
    assertEq(evidence.status, "confirmed", "sponsor returned confirmed receipt evidence");
    assertEq(evidence.event, "minted", "receipt contains the bound HumanityMinted event");
    assertEq(evidence.transactionHash, submitted.transactionHash, "receipt is bound to the submitted tx hash");
    assertEq(getAddress(evidence.recipient), TO_ADDRESS, "receipt recipient == proof-bound account");
    assertEq(getAddress(evidence.contract), getAddress(poh), "receipt contract == selected PoH deployment");
    assertEq(evidence.chainId, CHAIN_ID, "receipt chain id == selected chain");
    assert(!JSON.stringify(evidence).includes(RELAYER_KEY), "receipt evidence does not expose the sponsor private key");
    assertEq(
      (await readSponsoredMintEvidence(execution, submitted.transactionHash))?.transactionHash,
      submitted.transactionHash,
      "a later status poll recovers the same receipt without another transaction",
    );

    const bal = (await pub.readContract({ address: poh, abi, functionName: "balanceOf", args: [TO_ADDRESS] })) as bigint;
    assertEq(bal, 1n, "balanceOf(to) == 1");

    const tokenId = (await pub.readContract({
      address: poh,
      abi,
      functionName: "tokenOfNullifier",
      args: [voucher.nullifier],
    })) as bigint;
    assert(tokenId > 0n, `tokenOfNullifier(nullifier) == ${tokenId}`);
    assertEq(evidence.tokenId, tokenId.toString(), "receipt token id == contract tokenOfNullifier");

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

    // 6) The exact voucher is single-use; only a strictly newer epoch may refresh.
    console.log("[6/9] identical voucher replay must revert VoucherReplayed …");
    let reason = "";
    try {
      await pub.simulateContract({
        account: relayer,
        address: poh,
        abi,
        functionName: "mintWithVoucher",
        args: [voucher, signature],
      });
    } catch (e) {
      reason = e instanceof Error ? e.message : String(e);
    }
    assert(reason.includes("VoucherReplayed"), `identical replay reverts VoucherReplayed (got: ${reason.split("\n")[0]})`);

    // 7) Wrong-key and wrong-chain signatures MUST revert InvalidSigner.
    console.log("[7/9] wrong-key / wrong-chain vouchers must revert InvalidSigner …");
    const voucher2: HumanityVoucher = { ...voucher, nullifier: voucher.nullifier + 1n };
    const badSig = await signVoucher(WRONG_KEY, voucher2, CHAIN_ID, poh);
    let reverted = false;
    reason = "";
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

    const wrongChainSig = await signVoucher(ISSUER_KEY, voucher2, CHAIN_ID + 1, poh);
    reason = "";
    try {
      await pub.simulateContract({
        account: relayer,
        address: poh,
        abi,
        functionName: "mintWithVoucher",
        args: [voucher2, wrongChainSig],
      });
    } catch (e) {
      reason = e instanceof Error ? e.message : String(e);
    }
    assert(reason.includes("InvalidSigner"), `wrong-chain voucher reverts InvalidSigner (got: ${reason.split("\n")[0]})`);

    // 8) Exercise the real Next route: capability binding, no-body contract, idempotency and quotas.
    console.log("[8/9] sponsored-mint HTTP route binding + idempotency + abuse controls …");
    process.env.NEXT_PUBLIC_ETHEREUM_SEPOLIA_RPC_URL = RPC;
    process.env.NEXT_PUBLIC_ETHEREUM_SEPOLIA_POH = poh;
    process.env.POH_SPONSOR_PRIVATE_KEY = RELAYER_KEY;
    process.env.POH_SPONSOR_TESTNET_CHAIN_IDS = String(CHAIN_ID);
    process.env.POH_SPONSOR_MAX_GAS = "350000";
    process.env.POH_SPONSOR_MAX_FEE_WEI = "1000000000000000000";
    process.env.POH_SPONSOR_MIN_RESERVE_WEI = "1000000000000";
    process.env.POH_SPONSOR_CONFIRMATIONS = "1";
    process.env.POH_SPONSOR_RECEIPT_TIMEOUT_MS = "15000";
    process.env.POH_SPONSOR_DAILY_TX_LIMIT = "100";

    const [{ GET: sponsoredStatus, POST: sponsoredPost }, { setVerificationRecord }] = await Promise.all([
      import("../app/api/sponsored-mint/route"),
      import("../app/lib/server/verification-store"),
    ]);
    const routeVoucher: HumanityVoucher = { ...voucher, nullifier: voucher.nullifier + 10n };
    const routeSignature = await signVoucher(ISSUER_KEY, routeVoucher, CHAIN_ID, poh);
    const routeSession = "0123456789abcdef0123456789abcdef";
    setVerificationRecord(TO_ADDRESS, routeSession, {
      status: "ready",
      proof: { nullifier: routeVoucher.nullifier.toString(), epoch: routeVoucher.epoch },
      vouchers: [
        {
          chainId: CHAIN_ID,
          name: "Ethereum Sepolia",
          pohAddress: poh,
          voucher: serializeVoucher(routeVoucher),
          signature: routeSignature,
        },
      ],
      receivedAt: Date.now(),
    });
    const routeUrl = `http://localhost/api/sponsored-mint?address=${TO_ADDRESS}&chainId=${CHAIN_ID}`;
    const routeHeaders = {
      "x-poh-verification-session": routeSession,
      "x-forwarded-for": "198.51.100.20",
    };
    const nonceBeforeRoute = await pub.getTransactionCount({ address: relayer.address });
    const routeResponse = await sponsoredPost(new NextRequest(routeUrl, { method: "POST", headers: routeHeaders }));
    const routeJson = (await routeResponse.json()) as {
      ok: boolean;
      status: string;
      evidence: { transactionHash: Hex; recipient: Address; tokenId: string };
    };
    assertEq(routeResponse.status, 200, "route confirms the sponsored mint");
    assertEq(routeJson.ok, true, "route response is successful");
    assertEq(routeJson.status, "confirmed", "route returns confirmed evidence");
    assertEq(getAddress(routeJson.evidence.recipient), TO_ADDRESS, "route evidence stays bound to the capability account");
    assert(!JSON.stringify(routeJson).includes(RELAYER_KEY), "route response never contains the sponsor private key");
    const nonceAfterRoute = await pub.getTransactionCount({ address: relayer.address });
    assertEq(nonceAfterRoute, nonceBeforeRoute + 1, "first route POST spends exactly one sponsor nonce");

    const repeated = await sponsoredPost(new NextRequest(routeUrl, { method: "POST", headers: routeHeaders }));
    const repeatedJson = (await repeated.json()) as typeof routeJson;
    assertEq(repeated.status, 200, "repeated POST recovers confirmed evidence");
    assertEq(
      repeatedJson.evidence.transactionHash,
      routeJson.evidence.transactionHash,
      "repeated POST returns the same transaction hash",
    );
    assertEq(
      await pub.getTransactionCount({ address: relayer.address }),
      nonceAfterRoute,
      "repeated POST does not issue another transaction",
    );
    const statusResponse = await sponsoredStatus(new NextRequest(routeUrl, { headers: routeHeaders }));
    const statusJson = (await statusResponse.json()) as typeof routeJson;
    assertEq(statusJson.evidence.transactionHash, routeJson.evidence.transactionHash, "GET recovers the same receipt");

    const bodyResponse = await sponsoredPost(
      new NextRequest(routeUrl, { method: "POST", headers: routeHeaders, body: "{}" }),
    );
    assertEq(bodyResponse.status, 400, "request bodies are rejected before sponsor work");

    const tamperedSession = "1123456789abcdef0123456789abcdef";
    const tamperedVoucher = { ...routeVoucher, to: getAddress("0x2222222222222222222222222222222222222222") };
    setVerificationRecord(TO_ADDRESS, tamperedSession, {
      status: "ready",
      proof: { nullifier: tamperedVoucher.nullifier.toString(), epoch: tamperedVoucher.epoch },
      vouchers: [
        {
          chainId: CHAIN_ID,
          name: "Ethereum Sepolia",
          pohAddress: poh,
          voucher: serializeVoucher(tamperedVoucher),
          signature: await signVoucher(ISSUER_KEY, tamperedVoucher, CHAIN_ID, poh),
        },
      ],
      receivedAt: Date.now(),
    });
    const tamperedResponse = await sponsoredPost(
      new NextRequest(routeUrl, {
        method: "POST",
        headers: {
          "x-poh-verification-session": tamperedSession,
          "x-forwarded-for": "198.51.100.21",
        },
      }),
    );
    assertEq(tamperedResponse.status, 403, "voucher recipient mismatch is rejected before spending");
    assertEq(
      await pub.getTransactionCount({ address: relayer.address }),
      nonceAfterRoute,
      "binding rejection spends no sponsor nonce",
    );

    const zero = "0x0000000000000000000000000000000000000000" as Address;
    const mainnetSession = "2123456789abcdef0123456789abcdef";
    setVerificationRecord(TO_ADDRESS, mainnetSession, {
      status: "ready",
      proof: { nullifier: routeVoucher.nullifier.toString(), epoch: routeVoucher.epoch },
      vouchers: [
        {
          chainId: 1,
          name: "Ethereum",
          pohAddress: zero,
          voucher: serializeVoucher(routeVoucher),
          signature: await signVoucher(ISSUER_KEY, routeVoucher, 1, zero),
        },
      ],
      receivedAt: Date.now(),
    });
    const mainnetResponse = await sponsoredPost(
      new NextRequest(`http://localhost/api/sponsored-mint?address=${TO_ADDRESS}&chainId=1`, {
        method: "POST",
        headers: {
          "x-poh-verification-session": mainnetSession,
          "x-forwarded-for": "198.51.100.22",
        },
      }),
    );
    assertEq(mainnetResponse.status, 403, "mainnet sponsorship fails closed before spending");

    let withinSourceLimit = true;
    for (let requestNumber = 0; requestNumber < 28; requestNumber += 1) {
      const allowed = await sponsoredPost(new NextRequest(routeUrl, { method: "POST", headers: routeHeaders }));
      withinSourceLimit &&= allowed.status === 200;
    }
    assert(withinSourceLimit, "the first 30 source requests remain within the fixed-window limit");
    const limitedResponse = await sponsoredPost(new NextRequest(routeUrl, { method: "POST", headers: routeHeaders }));
    assertEq(limitedResponse.status, 429, "the 31st source request in one minute is rate-limited");
    assertEq(
      await pub.getTransactionCount({ address: relayer.address }),
      nonceAfterRoute,
      "rate-limit and idempotent recovery spend no extra sponsor nonce",
    );

    const concurrentVoucher: HumanityVoucher = { ...voucher, nullifier: voucher.nullifier + 20n };
    const concurrentSession = "3123456789abcdef0123456789abcdef";
    setVerificationRecord(TO_ADDRESS, concurrentSession, {
      status: "ready",
      proof: { nullifier: concurrentVoucher.nullifier.toString(), epoch: concurrentVoucher.epoch },
      vouchers: [
        {
          chainId: CHAIN_ID,
          name: "Ethereum Sepolia",
          pohAddress: poh,
          voucher: serializeVoucher(concurrentVoucher),
          signature: await signVoucher(ISSUER_KEY, concurrentVoucher, CHAIN_ID, poh),
        },
      ],
      receivedAt: Date.now(),
    });
    const concurrentHeaders = {
      "x-poh-verification-session": concurrentSession,
      "x-forwarded-for": "198.51.100.23",
    };
    const nonceBeforeConcurrent = await pub.getTransactionCount({ address: relayer.address });
    const concurrentResponses = await Promise.all([
      sponsoredPost(new NextRequest(routeUrl, { method: "POST", headers: concurrentHeaders })),
      sponsoredPost(new NextRequest(routeUrl, { method: "POST", headers: concurrentHeaders })),
    ]);
    assert(
      concurrentResponses.every((response) => response.status === 200 || response.status === 202),
      "concurrent duplicate requests return confirmed or recoverable pending evidence",
    );
    const concurrentStatus = await sponsoredStatus(
      new NextRequest(routeUrl, { headers: concurrentHeaders }),
    );
    assertEq(concurrentStatus.status, 200, "concurrent request status recovers confirmed evidence");
    assertEq(
      await pub.getTransactionCount({ address: relayer.address }),
      nonceBeforeConcurrent + 1,
      "two concurrent POSTs spend exactly one sponsor nonce",
    );

    // 9) Re-verification refresh: same nullifier, a NEWER epoch, correctly signed → succeeds (monotonic).
    console.log("[9/9] refresh with a newer epoch (same nullifier) …");
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
    assertEq(balAfter, 3n, "refresh adds no token beyond the three distinct nullifiers minted in this test");
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
