/**
 * @ubi2/sdk/contracts — M4 prompt-contract helpers.
 *
 * Implements the ContractHub interface from `docs/specs/04-prompt-contracts.md`:
 *  - calldata encoders for the four write ops (deployContract, fundContract,
 *    invokeContract, submitEffect) targeting CONTRACT_HUB (0x…5043),
 *  - typed reads via the custom `ubi_*` RPC methods (ubi_getContract,
 *    ubi_getExecCase, ubi_getContractsOf),
 *  - a `sendContractTx` helper that signs either through an injected EIP-1193
 *    provider (MetaMask) or a local private key (viem wallet client, for devnet).
 *
 * Mirrors the humanity.ts / streaming.ts pattern — same dual-signer, same
 * encodeFunctionData path so viem encodes bytes that match the on-chain selectors.
 */

import {
  createWalletClient,
  http,
  defineChain,
  encodeFunctionData,
  type Chain,
  type EIP1193Provider,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

/** Reserved system "ContractHub" address — 0x5043 = ASCII "PC" (Prompt-Contract). */
export const CONTRACT_HUB = "0x0000000000000000000000000000000000005043" as const;

// ---------------------------------------------------------------------------
// ABI fragments (minimal, human-readable) matching the IContractHub interface
// in crates/rpc/src/contracts.rs.  Selectors match the Solidity keccak sigs.
// ---------------------------------------------------------------------------

const DEPLOY_CONTRACT_ABI = [
  {
    type: "function",
    name: "deployContract",
    stateMutability: "nonpayable",
    inputs: [
      { name: "text", type: "string" },
      { name: "parties", type: "address[]" },
    ],
    outputs: [],
  },
] as const;

const FUND_CONTRACT_ABI = [
  {
    type: "function",
    name: "fundContract",
    stateMutability: "payable",
    inputs: [{ name: "id", type: "uint256" }],
    outputs: [],
  },
] as const;

const INVOKE_CONTRACT_ABI = [
  {
    type: "function",
    name: "invokeContract",
    stateMutability: "nonpayable",
    inputs: [
      { name: "id", type: "uint256" },
      { name: "triggerRef", type: "bytes32" },
    ],
    outputs: [],
  },
] as const;

const SUBMIT_EFFECT_ABI = [
  {
    type: "function",
    name: "submitEffect",
    stateMutability: "nonpayable",
    inputs: [
      { name: "caseId", type: "uint256" },
      { name: "ops", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

// ---------------------------------------------------------------------------
// Calldata encoders
// ---------------------------------------------------------------------------

/**
 * ABI-encode a `deployContract(text, parties)` call.
 * `text` is the FULL plain-language contract text — it travels in calldata and is stored on-chain
 * (transparency). The node derives `text_ref = keccak256(utf8(text))`; the client no longer derives it.
 * `parties` are the declared counterparties (authority/escrow scope).
 */
export function encodeDeployContract(text: string, parties: string[]): Hex {
  return encodeFunctionData({
    abi: DEPLOY_CONTRACT_ABI,
    functionName: "deployContract",
    args: [text, parties as Hex[]],
  });
}

/**
 * ABI-encode a `fundContract(id)` call.
 * NOTE: this must be sent as a VALUE-BEARING tx — the tx's `value` field is
 * the amount moved into the contract escrow (spec D4).
 */
export function encodeFundContract(id: bigint | number): Hex {
  return encodeFunctionData({
    abi: FUND_CONTRACT_ABI,
    functionName: "fundContract",
    args: [BigInt(id)],
  });
}

/**
 * ABI-encode an `invokeContract(id, triggerRef)` call.
 * `triggerRef` is a 32-byte commitment to the trigger input (no prose on-chain — I6).
 */
export function encodeInvokeContract(id: bigint | number, triggerRef: Hex): Hex {
  return encodeFunctionData({
    abi: INVOKE_CONTRACT_ABI,
    functionName: "invokeContract",
    args: [BigInt(id), triggerRef],
  });
}

/**
 * ABI-encode a `submitEffect(caseId, ops)` call.
 * `ops` is the canonical effect blob (use `encodeEffectBlob` to build it).
 */
export function encodeSubmitEffect(caseId: bigint | number, ops: Hex): Hex {
  return encodeFunctionData({
    abi: SUBMIT_EFFECT_ABI,
    functionName: "submitEffect",
    args: [BigInt(caseId), ops],
  });
}

// ---------------------------------------------------------------------------
// Typed read shapes (matching JSON from ubi_* methods in crates/rpc/src/lib.rs)
// ---------------------------------------------------------------------------

/** Contract lifecycle status. */
export type ContractStatus = "Active" | "Terminated";

/** A single canonical op inside a committed effect. */
export type ContractOp =
  | { type: "Transfer"; to: string; amount: string }
  | { type: "Refund"; party: string; amount: string }
  | { type: "OpenStream"; to: string; rate: string; deposit: string }
  | { type: "StopStream"; id: number }
  | { type: "SetVar"; key: string; value: string }
  | { type: "Abort"; reason_hash: string };

/** A committed canonical effect — the quorum-agreed state delta. */
export interface CanonicalEffect {
  ops: ContractOp[];
  effect_hash: string;
}

/** Exec-case status tagged union: Open | Committed(effect) | Aborted. */
export type ExecStatus =
  | { type: "Open" }
  | { type: "Committed"; effect: CanonicalEffect }
  | { type: "Aborted" };

/**
 * A compact exec-case summary as it appears inside `ContractView.cases` (from `ubi_getContract`):
 * one invocation of the contract and its outcome, without the full jury / per-juror submissions.
 */
export interface ExecCaseSummary {
  id: number;
  /** Who invoked the contract. */
  invoker: string;
  /** 32-byte hex commitment to the trigger input. */
  trigger_ref: string;
  /** Open | Committed(effect) | Aborted. For Committed, `effect` holds the resulting ops. */
  status: ExecStatus;
  /** Block height the case opened at. */
  opened_at: number;
  /** Block height the case resolved (committed/aborted) in, or null while still Open. */
  resolved_at: number | null;
}

/**
 * The FULL prompt-contract detail as returned by `ubi_getContract(id)`. Everything about the contract
 * lives on-chain now: the plain-language `text`, its `text_ref` commitment, escrow, parties, vars,
 * status, where it was deployed (`deploy_block`/`deploy_tx`), and the list of its exec `cases`.
 * `ubi_getContractsOf` returns the same shape minus `cases` (it is omitted for the list view).
 */
export interface ContractView {
  id: number;
  /** The FULL plain-language contract text, stored on-chain (transparency). */
  text: string;
  /** 32-byte hex content commitment `keccak256(utf8(text))`. */
  text_ref: string;
  /** Escrow balance in hex base units (0x-prefixed). */
  escrow: string;
  /** Derived escrow address (unique per contract id). */
  escrow_address: string;
  /** Declared parties (their authority/escrow scope). */
  parties: string[];
  /** Contract-local variables (SetVar). */
  vars: Array<{ key: string; value: string }>;
  status: ContractStatus;
  /** Block height the contract was deployed at. */
  deploy_block: number;
  /** 32-byte hex hash of the deploy tx. */
  deploy_tx: string;
  /** The contract's exec cases with their outcomes. Present on `ubi_getContract`, omitted on lists. */
  cases?: ExecCaseSummary[];
}

/** A single interpreter effect submission inside an exec case. */
export interface EffectSubmission {
  interpreter: string;
  effect: CanonicalEffect;
}

/** An exec case as returned by `ubi_getExecCase(id)`. */
export interface ExecCaseView {
  id: number;
  contract: number;
  trigger_ref: string;
  invoker: string;
  jury: string[];
  effects: EffectSubmission[];
  status: ExecStatus;
  opened_at: number;
  /** Block height the case resolved (committed/aborted) in, or null while still Open. */
  resolved_at: number | null;
}

// ---------------------------------------------------------------------------
// Reader class
// ---------------------------------------------------------------------------

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * Contract-aware reads layered over any object that exposes a JSON-RPC `call`
 * (the existing `Ubi2Client` qualifies). Mirrors HumanityReader / StreamReader.
 */
export class ContractReader {
  constructor(private readonly rpc: JsonRpcCaller) {}

  /**
   * `ubi_getContract(id)` → the FULL contract detail (text, text_ref, escrow, parties, vars, status,
   * deploy_block/deploy_tx, and the list of exec `cases` with their outcomes) or `null` if unknown.
   */
  async getContract(id: number | string): Promise<ContractView | null> {
    return this.rpc.call<ContractView | null>("ubi_getContract", [id]);
  }

  /**
   * `ubi_getExecCase(id)` → a single exec case or `null`.
   * Accepts both hex string and number ids.
   */
  async getExecCase(id: number | string): Promise<ExecCaseView | null> {
    return this.rpc.call<ExecCaseView | null>("ubi_getExecCase", [id]);
  }

  /** `ubi_getContractsOf(address)` → all contracts the address is a party of, sorted by id. */
  async getContractsOf(address: string): Promise<ContractView[]> {
    return this.rpc.call<ContractView[]>("ubi_getContractsOf", [address]);
  }
}

// ---------------------------------------------------------------------------
// Sending contract ops
// ---------------------------------------------------------------------------

/** The minimal ubi2 viem `Chain` definition. */
function ubi2ContractChain(rpcUrl: string): Chain {
  return defineChain({
    id: 0x5542,
    name: "ubi2 devnet",
    nativeCurrency: { name: "UBI", symbol: "UBI", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

/** Result of submitting a contract op. */
export interface ContractTxResult {
  hash: Hex;
}

/** Options for `sendContractTx`. Provide exactly one signer (`provider` or `privateKey`). */
export interface SendContractOptions {
  /** ContractHub calldata (from an `encode*` function above). */
  data: Hex;
  /** Sender address. Required for the injected-provider path; derived from the key otherwise. */
  from?: string;
  /** An injected EIP-1193 provider (e.g. `window.ethereum`). */
  provider?: EIP1193Provider;
  /** A local private key (devnet/tests). */
  privateKey?: Hex;
  /** RPC URL (required for the private-key path). */
  rpcUrl?: string;
  /**
   * Value in base units (only for `fundContract` which is a value-bearing tx).
   * Defaults to 0n.
   */
  value?: bigint;
}

/**
 * Build + send a ContractHub transaction two ways:
 *  - **injected provider**: `eth_sendTransaction` to CONTRACT_HUB.
 *  - **local private key**: a viem wallet client signs via `eth_sendRawTransaction`.
 *
 * For `fundContract`, pass `value` equal to the escrow deposit amount.
 */
export async function sendContractTx(opts: SendContractOptions): Promise<ContractTxResult> {
  const value = opts.value ?? 0n;

  if (opts.provider) {
    if (!opts.from)
      throw new Error("sendContractTx: `from` is required with an injected provider");
    const hash = (await opts.provider.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: opts.from as Hex,
          to: CONTRACT_HUB,
          value: `0x${value.toString(16)}`,
          data: opts.data,
        },
      ],
    })) as Hex;
    return { hash };
  }

  if (opts.privateKey) {
    if (!opts.rpcUrl)
      throw new Error("sendContractTx: `rpcUrl` is required with a private key");
    const account = privateKeyToAccount(opts.privateKey);
    const chain = ubi2ContractChain(opts.rpcUrl);
    const wallet = createWalletClient({ account, chain, transport: http(opts.rpcUrl) });
    const hash = await wallet.sendTransaction({
      to: CONTRACT_HUB,
      value,
      data: opts.data,
      gas: 300000n,
      gasPrice: 0n,
    });
    return { hash };
  }

  throw new Error("sendContractTx: provide either `provider` or `privateKey`");
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/**
 * @deprecated The full contract text now lives on-chain: pass the plain-language string directly to
 * `encodeDeployContract(text, parties)` and let the NODE derive `text_ref = keccak256(utf8(text))`.
 * This client-side stand-in is no longer used on the deploy path and is kept only for back-compat; it
 * will be removed once the wallet UI migrates to the string-text deploy.
 *
 * Derive a deterministic 32-byte `textRef` from a plain-language contract string (legacy devnet
 * stand-in: UTF-8 encode + pad/truncate to 32 bytes; NOT keccak).
 */
export function deriveTextRef(text: string): Hex {
  const encoder = new TextEncoder();
  const bytes = encoder.encode("ubi2-contract-text:" + text);
  const buf = new Uint8Array(32);
  for (let i = 0; i < Math.min(bytes.length, 32); i++) {
    buf[i] = bytes[i];
  }
  const hex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `0x${hex}` as Hex;
}

/**
 * Derive a deterministic 32-byte `triggerRef` from a trigger input string.
 * Same pattern as `deriveTextRef`.
 */
export function deriveTriggerRef(trigger: string): Hex {
  const encoder = new TextEncoder();
  const bytes = encoder.encode("ubi2-contract-trigger:" + trigger);
  const buf = new Uint8Array(32);
  for (let i = 0; i < Math.min(bytes.length, 32); i++) {
    buf[i] = bytes[i];
  }
  const hex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `0x${hex}` as Hex;
}

/** Human-readable label for a contract status. */
export function contractStatusLabel(status: ContractStatus): string {
  return status === "Active" ? "Active" : "Terminated";
}

/** Human-readable label for an exec-case status. */
export function execStatusLabel(status: ExecStatus): string {
  if (status.type === "Open") return "Open";
  if (status.type === "Committed") return "Committed";
  return "Aborted";
}
