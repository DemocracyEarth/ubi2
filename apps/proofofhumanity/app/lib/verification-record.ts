import type { Address } from "viem";
import type { ZkSelfIssuanceArtifact } from "@ubi2/sdk";
import type { SerializedHumanCredential } from "./predicate";
import type { SerializedVoucher } from "./voucher";
import type { ZkSelfIssuanceGrant } from "./server/zk-self-issuance";

/** A v1 voucher signed for one specific chain. */
export interface SignedForChain {
  chainId: number;
  name: string;
  pohAddress: Address;
  voucher: SerializedVoucher;
  signature: `0x${string}`;
}

export interface RelayRecord {
  status: "ready" | "error";
  /** The proof's anonymous nullifier + validity epoch, for the v1 UI preview. */
  proof?: {
    nullifier: string;
    epoch: number;
  };
  vouchers?: SignedForChain[];
  /** Private v1 holder credential returned only to its address/session capability. */
  credential?: SerializedHumanCredential;
  credentialSig?: `0x${string}`;
  /** Public, subject-submitted v2 bridge artifact. */
  zkIssuance?: ZkSelfIssuanceArtifact;
  /** Server-private refresh capability. It must never cross the API boundary. */
  zkIssuanceGrant?: ZkSelfIssuanceGrant;
  issuer?: Address;
  error?: string;
  receivedAt: number;
}

export type PublicRelayRecord = Omit<RelayRecord, "zkIssuanceGrant">;

/** Explicit public allowlist so future private record fields fail closed. */
export function publicRelayRecord(record: RelayRecord): PublicRelayRecord {
  return {
    status: record.status,
    proof: record.proof,
    vouchers: record.vouchers,
    credential: record.credential,
    credentialSig: record.credentialSig,
    zkIssuance: record.zkIssuance,
    issuer: record.issuer,
    error: record.error,
    receivedAt: record.receivedAt,
  };
}
