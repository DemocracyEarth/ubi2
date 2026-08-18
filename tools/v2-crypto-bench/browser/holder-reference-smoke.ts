import {
  createZkHolderReferenceBrowserClient,
  ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
  ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
  ZkHolderReferenceProverError,
} from "../../../packages/sdk/src/index";

const output = document.querySelector("#result");
if (!(output instanceof HTMLElement)) throw new Error("reference browser smoke output is missing");

function finish(state: "pass" | "fail", value: unknown): void {
  document.documentElement.dataset.state = state;
  output.textContent = JSON.stringify(value);
}

const mode = new URL(location.href).searchParams.get("mode") ?? "prove";
const controller = new AbortController();
const client = createZkHolderReferenceBrowserClient({
  workerUrl: new URL("./holder-reference-worker.js", import.meta.url),
});

try {
  const receipt = await client.prove({
    fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
    expectedPublicSignals: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
    signal: controller.signal,
    onProgress(progress) {
      document.documentElement.dataset.phase = progress.phase;
      if (mode === "cancel" && progress.phase === "proving") controller.abort();
    },
  });
  if (mode !== "prove") throw new Error("cancel smoke unexpectedly completed");
  if (receipt.presentationReady !== false || receipt.proofVerified !== true) {
    throw new Error("reference browser receipt labels changed");
  }
  const serialized = JSON.stringify(receipt);
  for (const forbidden of ["privateCredential", "holderSecret", "proofBytes", "provingKey"]) {
    if (serialized.includes(forbidden)) throw new Error(`reference browser receipt exposed ${forbidden}`);
  }
  finish("pass", {
    mode,
    presentationReady: receipt.presentationReady,
    proofVerified: receipt.proofVerified,
    fixtureId: receipt.fixtureId,
    signalCount: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS.length,
    peakMemoryBytes: receipt.peakMemoryBytes,
  });
} catch (error) {
  if (
    mode === "cancel" &&
    error instanceof ZkHolderReferenceProverError &&
    error.code === "cancelled"
  ) {
    finish("pass", { mode, code: error.code, terminatedAtPhase: "proving" });
  } else {
    finish("fail", {
      mode,
      error: error instanceof Error ? error.name : "unknown-error",
    });
  }
}
