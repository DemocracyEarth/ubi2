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
}

const PREFIX = "poh-predicates-v1";

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

export function decodeDisclosureRequest(value: string): DisclosureRequest | null {
  const decoded = decodeSelfString(value);
  if (!decoded) return null;
  const match = /^(poh-predicates-v1:(?:0|18|21):(?:0|1)):([0-9a-f]{32})$/.exec(decoded);
  if (!match) return null;
  const profile = decodeDisclosureProfile(match[1]);
  return profile ? { profile, session: match[2] } : null;
}

export function verificationConfigFor(profile: DisclosureProfile): VerificationConfig {
  return {
    ...(profile.age ? { minimumAge: profile.age } : {}),
    ofac: true,
  };
}
