import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "dist");
const port = Number.parseInt(process.env.HOLDER_HARNESS_PORT ?? "4174", 10);
const csp = [
  "default-src 'none'",
  "base-uri 'none'",
  "connect-src 'self'",
  "font-src 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "img-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "worker-src 'self'",
  "require-trusted-types-for 'script'",
  "trusted-types ubi2-holder-harness",
].join("; ");
const types = new Map([
  [".css", "text/css; charset=utf-8"], [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"], [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"], [".wasm", "application/wasm"], [".webmanifest", "application/manifest+json"],
]);

createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (url.pathname.startsWith("/private/")) {
    secureHeaders(response);
    response.writeHead(404, { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
    return;
  }
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); } catch { pathname = "/invalid"; }
  const candidate = resolve(root, `.${pathname === "/" ? "/index.html" : pathname}`);
  const safe = candidate === root || candidate.startsWith(`${root}${sep}`);
  const file = safe && existsSync(candidate) && statSync(candidate).isFile() ? candidate : resolve(root, "index.html");
  secureHeaders(response);
  const immutable = /(?:\.[A-Za-z0-9_-]{8,}\.(?:js|css)|\.[0-9a-f]{64}\.(?:js|wasm))$/u.test(file);
  response.writeHead(200, {
    "cache-control": immutable ? "public, max-age=31536000, immutable" : "no-store",
    "content-type": types.get(extname(file)) ?? "application/octet-stream",
  });
  createReadStream(file).pipe(response);
}).listen(port, "127.0.0.1", () => {
  process.stdout.write(`holder browser harness listening on http://127.0.0.1:${port}\n`);
});

function secureHeaders(response) {
  response.setHeader("content-security-policy", csp);
  response.setHeader("cross-origin-embedder-policy", "require-corp");
  response.setHeader("cross-origin-opener-policy", "same-origin");
  response.setHeader("cross-origin-resource-policy", "same-origin");
  response.setHeader("permissions-policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-content-type-options", "nosniff");
}
