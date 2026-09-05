"use strict";

// This preload is used only by `next build` inside the release Docker builder. Next generates
// otherwise-random preview metadata, an unused Server Actions key, and prerender request ids even
// when the application exposes neither preview mode nor Server Actions. The adjacent normalizer
// fails closed if either feature appears, so deterministic build-only bytes cannot become a runtime
// authentication secret. The runtime process does not load this file.
const crypto = require("node:crypto");

const revision = process.env.POH_SOURCE_REVISION;
if (!/^[0-9a-f]{40}$/.test(revision ?? "")) {
  throw new Error("POH_SOURCE_REVISION must be an exact lowercase Git commit");
}

function deterministicBytes(size, label) {
  if (!Number.isSafeInteger(size) || size < 0) throw new RangeError("invalid deterministic byte length");
  const chunks = [];
  let length = 0;
  for (let counter = 0; length < size; counter += 1) {
    const chunk = crypto
      .createHash("sha256")
      .update(`poh-quick-launch-next-build-v1\0${revision}\0${label}\0${counter}`)
      .digest();
    chunks.push(chunk);
    length += chunk.length;
  }
  return Buffer.concat(chunks, length).subarray(0, size);
}

crypto.randomBytes = function randomBytes(size, callback) {
  const bytes = deterministicBytes(size, "randomBytes");
  if (typeof callback === "function") {
    process.nextTick(callback, null, bytes);
    return undefined;
  }
  return bytes;
};

crypto.randomFillSync = function randomFillSync(buffer, offset = 0, size = buffer.byteLength - offset) {
  // Next's bundled Nano ID implementation pools bytes and allocates slices in scheduler-dependent
  // order. Repeating one revision-derived byte makes every response-scoped ID identical regardless
  // of which prerender worker consumes the first slice.
  const byte = deterministicBytes(1, "randomFillSync")[0];
  Buffer.from(buffer.buffer, buffer.byteOffset + offset, size).fill(byte);
  return buffer;
};

crypto.randomUUID = function randomUUID() {
  const bytes = deterministicBytes(16, "randomUUID");
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

// Next reads this only while producing the server-reference manifest. The normalizer rejects any
// non-empty action map, so this public, revision-derived value can never protect a real action.
process.env.NEXT_SERVER_ACTIONS_ENCRYPTION_KEY = deterministicBytes(
  32,
  "unused-server-actions-key",
).toString("base64");
