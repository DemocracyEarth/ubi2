import "server-only";

import type { Address } from "viem";

export interface VerificationCapability {
  address: Address;
  session: string;
}

interface CapabilityRequest {
  nextUrl: { searchParams: { get(name: string): string | null } };
  headers: { get(name: string): string | null };
}

/** Address + 128-bit browser session bearer capability shared by polling and sponsorship. */
export function verificationCapability(req: CapabilityRequest): VerificationCapability | null {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  const session = req.headers.get("x-poh-verification-session")?.toLowerCase();
  if (!address || !/^0x[0-9a-f]{40}$/.test(address) || !session || !/^[0-9a-f]{32}$/.test(session)) {
    return null;
  }
  return { address: address as Address, session };
}
