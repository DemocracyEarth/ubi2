/**
 * @ubi2/sdk/explorer — EXPL-1 address-indexer reads + account summary.
 *
 * Implements the two new M4 indexer methods from `docs/specs/04-prompt-contracts.md`:
 *  - `ubi_getAddressActivity(address, limit?)` — per-address tx history (newest-first).
 *  - `ubi_getAccount(address)` — at-a-glance account summary card.
 *
 * Both are pure reads over the node's EXPL-1 append-only per-address index;
 * no signing is required. Mirrors the HumanityReader / ContractReader pattern.
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
 * `kind` is a stable string label for the tx type (Transfer, OpenStream, Vouch, etc.).
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
  /** Raw calldata (0x for plain transfers). */
  input: string;
}

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * Explorer reads (EXPL-1) layered over any object exposing a JSON-RPC `call`.
 * The existing `Ubi2Client` qualifies.
 */
export class ExplorerReader {
  constructor(private readonly rpc: JsonRpcCaller) {}

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
}
