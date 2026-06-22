/**
 * @ubi2/sdk/explorer — EXPL-1 address-indexer reads + EXPL-2 deep block/tx reads.
 *
 * EXPL-1 (M4 indexer):
 *  - `ubi_getAddressActivity(address, limit?)` — per-address tx history (newest-first).
 *  - `ubi_getAccount(address)` — at-a-glance account summary card.
 *
 * EXPL-2 (cycle-5 deep explorer):
 *  - `ubi_getBlock(tag)` — fully decoded block: header fields + decoded tx list.
 *  - `ubi_getTransaction(hash)` — fully decoded tx: from/to/fee, decoded hub call,
 *    decoded logs, and the resulting effect/verdict/status.
 */

/** The human status of an address as it appears in the account summary. */
export type AccountHumanStatus =
  | "Unverified"
  | "Pending"
  | "Verified"
  | "Challenged"
  | "Revoked"
  | null;

/**
 * An at-a-glance account summary returned by `ubi_getAccount(address)`.
 * All numeric fields come back as 0x-hex strings (standard EVM quantity encoding).
 */
export interface AccountSummary {
  address: string;
  /** Live streaming balance at server read-time, hex base units. */
  balance: string;
  /** Account nonce (number of confirmed txs from this address). */
  nonce: string;
  /** Proof-of-humanity status, null if never registered. */
  human_status: AccountHumanStatus;
  /** Number of streams where this address is the sender. */
  streams_out: number;
  /** Number of streams where this address is the recipient. */
  streams_in: number;
  /** Number of prompt contracts the address is a declared party of. */
  contracts: number;
  /** Total number of txs that have touched this address. */
  tx_count: number;
}

/**
 * One row in the per-address activity feed returned by `ubi_getAddressActivity`.
 */
export interface ActivityRow {
  hash: string;
  /** Hex block number. */
  blockNumber: string;
  /** Stable string label: Transfer | OpenStream | StopStream | RequestVerification |
   *  Vouch | Challenge | SubmitVerdict | DeployContract | FundContract |
   *  InvokeContract | SubmitEffect | HumanitySystem | ContractHub | Call | Create */
  kind: string;
  from: string;
  to: string | null;
  /** The other side of the tx from the queried address's perspective. */
  counterparty: string | null;
  /** Hex base units moved by the tx (0x0 for hub-calldata ops). */
  value: string;
  /** UBI fee this tx paid (hex base units). */
  fee?: string;
  /** Raw calldata (0x for plain transfers). */
  input: string;
}

// ---- EXPL-2: decoded block / transaction types -------------------------------------------

/** A decoded log entry from `ubi_getTransaction`. */
export interface DecodedLog {
  /** Event name (e.g. "StreamOpened", "CaseOpened", "EffectCommitted") or null for unknown. */
  name: string | null;
  /** Hub name ("StreamHub" | "HumanityHub" | "ContractHub") or null for unknown. */
  hub?: string;
  /** Decoded arguments. */
  args?: Record<string, unknown>;
  /** Raw fields for unknown events. */
  address?: string;
  topics?: string[];
  data?: string;
}

/** Decoded system-hub call description from `ubi_getTransaction`. */
export interface DecodedCall {
  /** "Transfer" | "HubCall" | "System" | "Create" | null */
  kind: string | null;
  hub?: string;
  method?: string | null;
  args?: Record<string, unknown>;
  to?: string;
  value?: string;
}

/** The tx-result object from `ubi_getTransaction` — what the tx *produced* in state. */
export interface TxResult {
  kind: "ExecCase" | "HumanityCase" | "Transfer";
  [key: string]: unknown;
}

/** A fully decoded transaction from `ubi_getTransaction`. */
export interface DecodedTransaction {
  hash: string;
  blockNumber: string;
  blockHash: string;
  transactionIndex: string;
  from: string;
  to: string | null;
  value: string;
  nonce: string;
  gasUsed: string;
  gasPrice: string;
  /** UBI fee in base units (hex). gasUsed * gasPrice. */
  fee: string;
  input: string;
  /** Decoded system-hub call (the "what it did" description). */
  call: DecodedCall | null;
  /** Decoded event logs emitted by this tx. */
  logs: DecodedLog[];
  /** The resulting state effect / verdict / status (null for plain transfers). */
  result: TxResult | null;
}

/** A fully decoded block from `ubi_getBlock`. */
export interface DecodedBlock {
  number: string;
  hash: string;
  parentHash: string;
  timestamp: string;
  txCount: number;
  gasUsed: string;
  gasLimit: string;
  baseFeePerGas: string;
  stateRoot: string;
  transactionsRoot: string;
  receiptsRoot: string;
  miner: string;
  /** Full decoded tx list (each tx is the `ubi_getTransaction` shape). */
  transactions: DecodedTransaction[];
}

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * Explorer reads (EXPL-1 + EXPL-2) layered over any object exposing a JSON-RPC `call`.
 */
export class ExplorerReader {
  constructor(private readonly rpc: JsonRpcCaller) {}

  // ---- EXPL-1 ----

  /**
   * `ubi_getAccount(address)` — at-a-glance account summary.
   * Always returns a record (zero-valued if the address has never been seen).
   */
  async getAccount(address: string): Promise<AccountSummary> {
    return this.rpc.call<AccountSummary>("ubi_getAccount", [address]);
  }

  /**
   * `ubi_getAddressActivity(address, limit?)` — most-recent txs touching the address,
   * newest first.  `limit` defaults to 50; the node caps it at 1000.
   */
  async getAddressActivity(address: string, limit = 50): Promise<ActivityRow[]> {
    return this.rpc.call<ActivityRow[]>("ubi_getAddressActivity", [address, limit]);
  }

  // ---- EXPL-2 ----

  /**
   * `ubi_getBlock(tag)` — fully decoded block with header fields + decoded tx list.
   * `tag` can be "latest", "earliest", a hex block number (`"0x1"`), or a 32-byte block hash.
   * Returns `null` if the block is not found.
   */
  async getBlock(tag: string | number): Promise<DecodedBlock | null> {
    const param = typeof tag === "number" ? `0x${tag.toString(16)}` : tag;
    return this.rpc.call<DecodedBlock | null>("ubi_getBlock", [param]);
  }

  /**
   * `ubi_getTransaction(hash)` — fully decoded transaction: hub call + logs + result.
   * Returns `null` if the tx is not found.
   */
  async getDecodedTransaction(hash: string): Promise<DecodedTransaction | null> {
    return this.rpc.call<DecodedTransaction | null>("ubi_getTransaction", [hash]);
  }
}
