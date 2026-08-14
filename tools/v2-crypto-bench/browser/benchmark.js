const depths = [96, 128];
const fixtureArtifacts = Object.freeze({
  96: {
    bytes: 10_452_496,
    sha256: "5c6a3b3c2a5b6ec9076d4a693bbd6ca52b5efffb320ec25dc4ba83782e3bf62f",
  },
  128: {
    bytes: 15_022_608,
    sha256: "9298392aa0125509a7fdfce81ffa0fa4493721ac0e342ae30db58c6ed89304fa",
  },
});
const runButton = document.querySelector("#run");
const downloadButton = document.querySelector("#download");
const status = document.querySelector("#status");
let latestReport = null;

function runWorker(message, transfer = []) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./benchmark-worker.js", import.meta.url), { type: "module" });
    worker.onmessage = ({ data }) => {
      worker.terminate();
      if (data.ok) resolve(data);
      else reject(new Error(data.error));
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || "Browser benchmark worker failed"));
    };
    worker.postMessage(message, transfer);
  });
}

function formatDuration(milliseconds) {
  if (milliseconds < 1_000) return `${milliseconds.toFixed(0)} ms`;
  return `${(milliseconds / 1_000).toFixed(2)} s`;
}

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1_024 && unit < units.length - 1) {
    value /= 1_024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
}

function tableCell(text, { className, colSpan } = {}) {
  const cell = document.createElement("td");
  cell.textContent = String(text);
  if (className) cell.className = className;
  if (colSpan) cell.colSpan = colSpan;
  return cell;
}

function replaceResultRow(depth, cells) {
  document.querySelector(`[data-depth="${depth}"]`).replaceChildren(...cells);
}

function setRunningRow(depth, label) {
  replaceResultRow(depth, [
    tableCell(depth),
    tableCell(label, { className: "pending", colSpan: 7 }),
    tableCell("Running", { className: "pending" }),
  ]);
}

function setResultRow(result) {
  const { depth, setup, proof } = result;
  const report = proof.report;
  replaceResultRow(depth, [
    tableCell(depth),
    tableCell(formatDuration(setup.elapsedMs)),
    tableCell(formatBytes(setup.provingKeyBytes)),
    tableCell(formatBytes(setup.retainedMemoryBytes)),
    tableCell(formatDuration(report.key_deserialize_ms)),
    tableCell(formatDuration(report.prove_ms)),
    tableCell(formatDuration(report.verify_ms)),
    tableCell(formatBytes(proof.retainedMemoryBytes)),
    tableCell(report.proof_verified ? "Verified" : "Rejected", {
      className: report.proof_verified ? "pass" : "fail",
    }),
  ]);
}

function setFailedRow(depth, error) {
  replaceResultRow(depth, [
    tableCell(depth),
    tableCell(error.message, { className: "fail", colSpan: 7 }),
    tableCell("Failed", { className: "fail" }),
  ]);
}

async function runDepth(depth) {
  setRunningRow(depth, "Generating deterministic fixture key in a fresh worker…");
  const setup = await runWorker({ phase: "setup", depth });
  const expectedArtifact = fixtureArtifacts[depth];
  if (
    setup.provingKeyBytes !== expectedArtifact.bytes ||
    setup.provingKeySha256 !== expectedArtifact.sha256
  ) {
    throw new Error("Fixture proving key does not match the pinned artifact fingerprint");
  }
  setRunningRow(depth, "Loading the key and proving in a second fresh worker…");
  const provingKeyBuffer = setup.provingKeyBuffer;
  const proof = await runWorker(
    {
      phase: "prove",
      depth,
      provingKeyBuffer,
      expectedProvingKeySha256: setup.provingKeySha256,
    },
    [provingKeyBuffer],
  );
  const result = { depth, setup, proof };
  delete result.setup.provingKeyBuffer;
  setResultRow(result);
  return result;
}

async function runAll() {
  runButton.disabled = true;
  downloadButton.disabled = true;
  latestReport = null;
  status.dataset.state = "running";
  delete status.dataset.report;
  const results = [];
  try {
    for (const depth of depths) {
      status.textContent = `Running depth ${depth}…`;
      try {
        results.push(await runDepth(depth));
      } catch (error) {
        setFailedRow(depth, error);
        throw error;
      }
    }
    latestReport = {
      schema: "org.proofofhumanity.v2-browser-prover-run/1",
      warning: "single browser run; fixture setup and keys are not deployable",
      userAgent: navigator.userAgent,
      measuredAt: new Date().toISOString(),
      results,
    };
    status.textContent = "Complete. Both browser proofs verified.";
    status.dataset.state = "complete";
    status.dataset.report = JSON.stringify(latestReport);
    downloadButton.disabled = false;
  } catch (error) {
    status.textContent = `Stopped: ${error.message}`;
    status.dataset.state = "failed";
  } finally {
    runButton.disabled = false;
  }
}

runButton.addEventListener("click", runAll);
downloadButton.addEventListener("click", () => {
  if (!latestReport) return;
  const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "ubi2-v2-browser-prover-report.json";
  link.click();
  URL.revokeObjectURL(url);
});

if (new URLSearchParams(location.search).has("autorun")) runAll();
