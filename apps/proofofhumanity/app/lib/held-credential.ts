import type { Hex } from "viem";
import type { SerializedHumanCredential } from "./predicate";

export const HELD_CREDENTIAL_KEY = "poh:humanCredential:v1";
export const HELD_CREDENTIAL_EVENT = "poh:humanCredential:updated";

export interface HeldCredential {
  credential: SerializedHumanCredential;
  credentialSig: Hex;
  issuer?: string;
}

export function saveHeldCredential(held: HeldCredential): boolean {
  try {
    sessionStorage.setItem(HELD_CREDENTIAL_KEY, JSON.stringify(held));
    window.dispatchEvent(new Event(HELD_CREDENTIAL_EVENT));
    return true;
  } catch {
    return false;
  }
}

export function clearHeldCredential(): void {
  try {
    sessionStorage.removeItem(HELD_CREDENTIAL_KEY);
    window.dispatchEvent(new Event(HELD_CREDENTIAL_EVENT));
  } catch {
    // Storage can be unavailable in privacy modes; in-memory mint state is
    // still cleared by the caller.
  }
}

export function loadHeldCredential(): HeldCredential | null {
  try {
    const raw = sessionStorage.getItem(HELD_CREDENTIAL_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw) as HeldCredential;
    if (!value.credential || !value.credentialSig) return null;
    return value;
  } catch {
    return null;
  }
}
