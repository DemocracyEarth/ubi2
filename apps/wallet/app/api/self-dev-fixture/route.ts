/**
 * M6 Stage C1 — dev/CI fixture endpoint (spec 06b §5.3).
 *
 * Serves the SAME recorded synthetic proof bundle the Rust arity-21 crypto tests load
 * (`crates/zkpoh/fixtures/self_synthetic_public.json` + `self_synthetic_proof.json`), reshaped
 * into a `SelfProofBundle` (`{ proof, publicSignals }`). This lets a developer or CI exercise the
 * FULL submit flow — parse → encode → sign → send — without a live Self app or phone.
 *
 * Reading straight off disk (rather than duplicating the JSON into the wallet package) keeps one
 * source of truth: if the fixture changes, this endpoint changes with it, with no drift risk
 * (mirrors the SDK↔Rust parity discipline in `packages/sdk/src/passport.test.ts`).
 *
 * NOT a trust surface: this is a synthetic, non-production proof (test-only BN254 field
 * elements). It verifies against the `MockZkVerifier` / staging VK in CI, never against a
 * production Self VK, and is clearly labeled "dev fixture" in the UI.
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { NextResponse } from "next/server";
import { validateProofBundle, type SelfProofBundle } from "@ubi2/sdk";

export const runtime = "nodejs";

// apps/wallet -> repo root is two levels up.
const FIXTURES_DIR = path.resolve(process.cwd(), "../../crates/zkpoh/fixtures");

export async function GET() {
  try {
    const [publicRaw, proofRaw] = await Promise.all([
      readFile(path.join(FIXTURES_DIR, "self_synthetic_public.json"), "utf8"),
      readFile(path.join(FIXTURES_DIR, "self_synthetic_proof.json"), "utf8"),
    ]);

    const publicSignals = JSON.parse(publicRaw) as string[];
    const proof = JSON.parse(proofRaw) as SelfProofBundle["proof"];

    const bundle: SelfProofBundle = { proof, publicSignals };
    const shapeErr = validateProofBundle(bundle);
    if (shapeErr) {
      return NextResponse.json(
        { ok: false, error: `Fixture failed its own shape check: ${shapeErr}` },
        { status: 500 },
      );
    }

    return NextResponse.json({
      ok: true,
      bundle,
      source: "crates/zkpoh/fixtures/self_synthetic_{public,proof}.json",
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json(
      { ok: false, error: `Could not load the dev fixture from ${FIXTURES_DIR}: ${msg}` },
      { status: 500 },
    );
  }
}
