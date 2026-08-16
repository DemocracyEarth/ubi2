import { createServer, type Server, type ServerResponse } from "node:http";
import {
  serializeZkIdentityStatusOperatorArtifact,
  serializeZkIdentityStatusOperatorHealth,
} from "./artifact";
import { ZkIdentityStatusOperatorStore } from "./storage";

function send(
  response: ServerResponse,
  status: number,
  body: string,
  cacheControl: string,
): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": cacheControl,
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

const NOT_FOUND = JSON.stringify({ error: "not_found" });
const UNAVAILABLE = JSON.stringify({ error: "unavailable" });
const METHOD_NOT_ALLOWED = JSON.stringify({ error: "method_not_allowed" });
const BAD_REQUEST = JSON.stringify({ error: "bad_request" });

/** Read-only loopback server; TLS and public ingress belong to a reverse proxy. */
export async function startZkIdentityStatusOperatorServer(input: {
  store: ZkIdentityStatusOperatorStore;
  host: "127.0.0.1" | "::1";
  port: number;
}): Promise<Server> {
  const server = createServer(async (request, response) => {
    if (request.method !== "GET") {
      send(response, 405, METHOD_NOT_ALLOWED, "no-store");
      return;
    }
    const requestTarget = request.url ?? "/";
    if (!/^\/(?!\/)/u.test(requestTarget)) {
      send(response, 400, BAD_REQUEST, "no-store");
      return;
    }
    let url: URL;
    try {
      url = new URL(requestTarget, "http://localhost");
    } catch {
      send(response, 400, BAD_REQUEST, "no-store");
      return;
    }
    if (url.search !== "") {
      send(response, 404, NOT_FOUND, "no-store");
      return;
    }
    const path = url.pathname;
    try {
      if (path === "/healthz") {
        const health = await input.store.readHealth();
        if (health === undefined) {
          send(response, 503, UNAVAILABLE, "no-store");
          return;
        }
        send(
          response,
          health.state === "healthy" ? 200 : 503,
          serializeZkIdentityStatusOperatorHealth(health),
          "no-store",
        );
        return;
      }
      if (path === "/readyz") {
        const [health, latest] = await Promise.all([
          input.store.readHealth(),
          input.store.readLatest(),
        ]);
        const ready = health?.state === "healthy" && latest !== undefined;
        send(response, ready ? 200 : 503, JSON.stringify({ ready }), "no-store");
        return;
      }
      if (path === "/latest") {
        const latest = await input.store.readLatest();
        if (latest === undefined) {
          send(response, 404, NOT_FOUND, "no-store");
          return;
        }
        send(
          response,
          200,
          serializeZkIdentityStatusOperatorArtifact(latest),
          "no-store",
        );
        return;
      }
      const match = /^\/artifacts\/(0x[0-9a-f]{64})$/u.exec(path);
      if (match !== null) {
        const artifact = await input.store.readArtifact(match[1]!);
        if (artifact === undefined) {
          send(response, 404, NOT_FOUND, "public, max-age=60");
          return;
        }
        send(response, 200, artifact, "public, max-age=31536000, immutable");
        return;
      }
      send(response, 404, NOT_FOUND, "no-store");
    } catch {
      send(response, 503, UNAVAILABLE, "no-store");
    }
  });
  server.maxHeadersCount = 64;
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(input.port, input.host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return server;
}
