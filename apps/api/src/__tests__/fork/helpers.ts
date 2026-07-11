import http from "node:http";
import type { AddressInfo } from "node:net";

export const TEST_API_KEY = "test-key-fork";

export type JsonHandler = (
  body: Record<string, unknown>,
  req: http.IncomingMessage,
  res: http.ServerResponse,
) => void | Promise<void>;

export function sendJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readJsonBody(
  req: http.IncomingMessage,
): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

export function createJsonStubServer(
  path: string,
  getHandler: () => JsonHandler,
): http.Server {
  return http.createServer((req, res) => {
    void (async () => {
      if (req.method === "POST" && req.url === path) {
        const body = await readJsonBody(req);
        await getHandler()(body, req, res);
        return;
      }
      sendJson(res, 404, { error: "not found", code: "NOT_FOUND" });
    })().catch(err => {
      sendJson(res, 500, {
        error: err instanceof Error ? err.message : "stub error",
        code: "INTERNAL_ERROR",
      });
    });
  });
}

export async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;
  return addr.port;
}

export async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close(err => (err ? reject(err) : resolve()));
  });
}

export function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function authHeader(key = TEST_API_KEY): { Authorization: string } {
  return { Authorization: `Bearer ${key}` };
}

export const SAMPLE_HTML =
  "<html><body><main><p>Hello fork scrape</p></main></body></html>";
export const SAMPLE_MARKDOWN = "Hello fork scrape";
export const SAMPLE_URL = "https://example.com/page";
export const SAMPLE_TITLE = "Example Page";
