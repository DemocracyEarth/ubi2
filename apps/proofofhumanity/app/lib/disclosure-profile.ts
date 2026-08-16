import type { VerificationConfig } from "@selfxyz/core";

export type AgeThreshold = 18 | 21 | null;

export interface DisclosureProfile {
  age: AgeThreshold;
  nationality: boolean;
}

export interface DisclosureRequest {
  profile: DisclosureProfile;
  /** 128-bit browser capability, hex encoded without 0x. */
  session: string;
  /**
   * Optional holder-generated v2 credential commitment, bound into the exact
   * Self proof through userDefinedData. Absence selects the existing v1 flow.
   */
  credentialCommitment?: `0x${string}`;
}

const PREFIX = "poh-predicates-v1";
const V2_ISSUANCE_PREFIX = "poh-v2-issuance";
const BN254_SCALAR_FIELD =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;

export function encodeDisclosureProfile(profile: DisclosureProfile): string {
  return `${PREFIX}:${profile.age ?? 0}:${profile.nationality ? 1 : 0}`;
}

/** Decode either the browser string or Self's hex-encoded userDefinedData. */
function decodeSelfString(value: string): string | null {
  let decoded = value;
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
    try {
      const bytes = Uint8Array.from(hex.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
      decoded = new TextDecoder().decode(bytes);
    } catch {
      return null;
    }
  }
  return decoded;
}

export function decodeDisclosureProfile(value: string): DisclosureProfile | null {
  const decoded = decodeSelfString(value);
  if (!decoded) return null;
  const match = /^poh-predicates-v1:(0|18|21):(0|1)$/.exec(decoded);
  if (!match) return null;
  return {
    age: match[1] === "18" ? 18 : match[1] === "21" ? 21 : null,
    nationality: match[2] === "1",
  };
}

export function encodeDisclosureRequest(profile: DisclosureProfile, session: string): string {
  if (!/^[0-9a-f]{32}$/.test(session)) throw new Error("verification session must be 128-bit lowercase hex");
  return `${encodeDisclosureProfile(profile)}:${session}`;
}

/**
 * Bind an already-generated private-credential commitment to the Self proof.
 * The commitment must come from the holder's isolated prover/vault; this codec
 * deliberately does not invent one from public or random browser state.
 */
export function encodeV2IssuanceRequest(
  profile: DisclosureProfile,
  session: string,
  credentialCommitment: `0x${string}`,
): string {
  if (!/^[0-9a-f]{32}$/.test(session)) throw new Error("verification session must be 128-bit lowercase hex");
  if (!/^0x[0-9a-f]{64}$/.test(credentialCommitment)) {
    throw new Error("credential commitment must be 32-byte lowercase hex");
  }
  const commitment = BigInt(credentialCommitment);
  if (commitment === 0n || commitment >= BN254_SCALAR_FIELD) {
    throw new Error("credential commitment must be a non-zero canonical BN254 field element");
  }
  return `${V2_ISSUANCE_PREFIX}:${profile.age ?? 0}:${profile.nationality ? 1 : 0}:${session}:${credentialCommitment.slice(2)}`;
}

export function decodeDisclosureRequest(value: string): DisclosureRequest | null {
  const decoded = decodeSelfString(value);
  if (!decoded) return null;
  const match = /^(poh-predicates-v1:(?:0|18|21):(?:0|1)):([0-9a-f]{32})$/.exec(decoded);
  if (match) {
    const profile = decodeDisclosureProfile(match[1]);
    return profile ? { profile, session: match[2] } : null;
  }

  const issuanceMatch = /^poh-v2-issuance:(0|18|21):(0|1):([0-9a-f]{32}):([0-9a-f]{64})$/.exec(decoded);
  if (!issuanceMatch) return null;
  const credentialCommitment = `0x${issuanceMatch[4]}` as const;
  const commitment = BigInt(credentialCommitment);
  if (commitment === 0n || commitment >= BN254_SCALAR_FIELD) return null;
  return {
    profile: {
      age: issuanceMatch[1] === "18" ? 18 : issuanceMatch[1] === "21" ? 21 : null,
      nationality: issuanceMatch[2] === "1",
    },
    session: issuanceMatch[3],
    credentialCommitment,
  };
}

export function verificationConfigFor(profile: DisclosureProfile): VerificationConfig {
  return {
    ...(profile.age ? { minimumAge: profile.age } : {}),
    ofac: true,
  };
}
