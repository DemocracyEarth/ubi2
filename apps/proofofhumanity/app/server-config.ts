import "server-only";

import type { Hex } from "viem";

const ANVIL_ISSUER_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;

/**
 * Return the issuer signer only from server code. Production fails closed when the secret is
 * missing; the well-known Anvil key is available solely to local development and tests.
 */
export function getIssuerPrivateKey(): Hex {
  const key = process.env.ISSUER_PRIVATE_KEY;
  if (key) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
      throw new Error("ISSUER_PRIVATE_KEY must be a 32-byte 0x-prefixed hex key.");
    }
    return key as Hex;
  }
  if (process.env.NODE_ENV !== "production") return ANVIL_ISSUER_KEY;
  throw new Error("ISSUER_PRIVATE_KEY is required in production.");
}
