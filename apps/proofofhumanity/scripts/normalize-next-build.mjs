import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const appDirectory = path.resolve(import.meta.dirname, "..");
const revision = process.env.POH_SOURCE_REVISION;
if (!/^[0-9a-f]{40}$/.test(revision ?? "")) {
  throw new Error("POH_SOURCE_REVISION must be an exact lowercase Git commit");
}

function walk(directory, visit, skip) {
  for (const name of readdirSync(directory).sort()) {
    const absolute = path.join(directory, name);
    if (skip?.(absolute)) continue;
    if (statSync(absolute).isDirectory()) walk(absolute, visit, skip);
    else visit(absolute);
  }
}

const forbiddenSource = [
  { pattern: /["']use server["']/u, label: "Server Actions" },
  { pattern: /\bdraftMode\s*\(/u, label: "draft mode" },
  { pattern: /\bsetPreviewData\s*\(/u, label: "preview mode" },
];
walk(path.join(appDirectory, "app"), (file) => {
  if (!/\.(?:[cm]?[jt]sx?)$/u.test(file)) return;
  const source = readFileSync(file, "utf8");
  for (const forbidden of forbiddenSource) {
    if (forbidden.pattern.test(source)) {
      throw new Error(`${forbidden.label} is incompatible with deterministic Quick Launch images: ${file}`);
    }
  }
});

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, child]) => [key, sortJson(child)]),
  );
}

const outputDirectories = [
  path.join(appDirectory, ".next"),
  path.join(appDirectory, ".next/standalone/apps/proofofhumanity/.next"),
];

for (const outputDirectory of outputDirectories) {
  const serverReferenceManifest = JSON.parse(
    readFileSync(path.join(outputDirectory, "server/server-reference-manifest.json"), "utf8"),
  );
  if (
    Object.keys(serverReferenceManifest.node ?? {}).length !== 0 ||
    Object.keys(serverReferenceManifest.edge ?? {}).length !== 0
  ) {
    throw new Error("Server Actions are forbidden in the deterministic Quick Launch image");
  }

  walk(
    outputDirectory,
    (file) => {
      if (!file.endsWith(".json")) return;
      const parsed = JSON.parse(readFileSync(file, "utf8"));
      writeFileSync(file, `${JSON.stringify(sortJson(parsed))}\n`, "utf8");
    },
    (candidate) => outputDirectory === outputDirectories[0] && candidate === path.join(outputDirectory, "standalone"),
  );
}
