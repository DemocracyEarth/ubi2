/**
 * @ubi2/sdk/oracle — SDK helpers for the localhost-only oracle-config admin RPC:
 *   - `ubi_getOracleConfig` — read current provider/model/health (secrets already redacted).
 *   - `ubi_setOracleConfig` — hot-swap the node's LLM backend (Anthropic / Ollama / OpenAI).
 *
 * Both methods are rejected by the node for non-loopback callers; the wallet surfaces the
 * error gracefully.
 */

/** The persisted (secret-free) oracle config returned by `ubi_getOracleConfig`. */
export interface OracleConfig {
  /** `"anthropic"` | `"ollama"` | `"openai"`. Absent ⇒ Mock deterministic mode. */
  provider?: string;
  /** Pinned model id. Absent ⇒ the provider's default. */
  model?: string;
  /** Base URL override for Ollama / OpenAI-compatible. Absent ⇒ provider default. */
  base_url?: string;
  /**
   * The *name* of the env var the API key is read from (e.g. `"ANTHROPIC_API_KEY"`).
   * **Never the key value itself** — I6. Absent when no key is needed (Ollama).
   */
  api_key_env?: string;
}

/** Which implementation is currently active: the deterministic Mock or a live LLM backend. */
export type ActiveImpl = "mock" | "live";

/** Live health/reachability status shown in the Settings panel. */
export interface OracleHealth {
  /** Resolved provider (`"mock"` when running the deterministic impl). */
  provider: string;
  /** Resolved model id (empty for Mock). */
  model: string;
  /** Did the last probe reach the backend? Always `false` for Mock. */
  reachable: boolean;
  /** Secret-free error string for a failed live attempt; empty on success. */
  error?: string;
}

/** The full `ubi_getOracleConfig` response. */
export interface OracleConfigResponse {
  config: OracleConfig;
  active: ActiveImpl;
  health: OracleHealth;
}

/** Parameters for `ubi_setOracleConfig`. `api_key` is used in-memory and never persisted. */
export interface SetOracleConfigParams {
  /** `"anthropic"` | `"ollama"` | `"openai"`. Omit (or send `""`) to revert to Mock. */
  provider?: string;
  model?: string;
  base_url?: string;
  api_key_env?: string;
  /**
   * The raw API key (in-memory only, NEVER persisted to disk).
   * The node sets a process-env var from this; only `api_key_env` reaches the config file.
   */
  api_key?: string;
}

interface JsonRpcCaller {
  call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

/**
 * Oracle-admin reads/writes, layered over any JSON-RPC caller.
 * Both methods are localhost-only on the node; callers from non-loopback addresses get a
 * `-32099` error. Surface it as a human-readable warning rather than a crash.
 */
export class OracleAdminClient {
  constructor(private readonly rpc: JsonRpcCaller) {}

  /**
   * `ubi_getOracleConfig` — current config (secret-free) + live health.
   * Throws if the node rejects the call (non-loopback, node unreachable, etc.).
   */
  async getConfig(): Promise<OracleConfigResponse> {
    return this.rpc.call<OracleConfigResponse>("ubi_getOracleConfig", []);
  }

  /**
   * `ubi_setOracleConfig({provider?, model?, base_url?, api_key_env?, api_key?})` —
   * hot-swap the node's LLM backend. Returns the new config+health on success.
   * The `api_key` field (when present) is forwarded in the params object so the node can
   * construct the backend; the node never persists it (only `api_key_env` is written to disk).
   */
  async setConfig(params: SetOracleConfigParams): Promise<OracleConfigResponse> {
    return this.rpc.call<OracleConfigResponse>("ubi_setOracleConfig", [params]);
  }
}
