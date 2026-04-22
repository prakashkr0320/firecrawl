import crypto from "crypto";
import WebSocket from "ws";
import { config } from "../../../config";
import { itIf, scrapeTimeout } from "../lib";
import {
  idmux,
  Identity,
  localBrowserCreateRaw,
  localBrowserDeleteRaw,
  scrapeRaw,
} from "./lib";

async function withCdpSession<T>(
  cdpUrl: string,
  run: (
    send: (method: string, params?: Record<string, unknown>) => Promise<any>,
  ) => Promise<T>,
): Promise<T> {
  const ws = new WebSocket(cdpUrl);
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
  });

  let id = 0;
  const pending = new Map<
    number,
    { resolve: (value: any) => void; reject: (reason: any) => void }
  >();

  ws.on("message", raw => {
    const payload = JSON.parse(String(raw));
    if (typeof payload?.id !== "number") return;
    const p = pending.get(payload.id);
    if (!p) return;
    pending.delete(payload.id);
    if (payload.error)
      p.reject(new Error(payload.error.message ?? "CDP request failed"));
    else p.resolve(payload.result);
  });

  const send = (method: string, params?: Record<string, unknown>) =>
    new Promise<any>((resolve, reject) => {
      const requestId = ++id;
      pending.set(requestId, { resolve, reject });
      ws.send(JSON.stringify({ id: requestId, method, params }));
    });

  try {
    return await run(send);
  } finally {
    ws.close();
  }
}

async function mutateSessionViaCdp(cdpUrl: string) {
  await withCdpSession(cdpUrl, async send => {
    const targets = await send("Target.getTargets");
    const target =
      targets?.targetInfos?.find(
        (x: any) =>
          x.type === "page" &&
          x.url !== "devtools://devtools/bundled/devtools_app.html",
      ) ?? targets?.targetInfos?.find((x: any) => x.type === "page");
    expect(target?.targetId).toBeTruthy();

    const attached = await send("Target.attachToTarget", {
      targetId: target.targetId,
      flatten: true,
    });
    const sessionId = attached.sessionId as string;

    const sessionSend = (method: string, params?: Record<string, unknown>) =>
      send(method, {
        sessionId,
        ...params,
      });

    await sessionSend("Runtime.evaluate", {
      expression: "window.__fcSessionMarker = 'Playwright-state-marker';",
    });
    await sessionSend("Runtime.evaluate", {
      expression:
        "document.body.innerHTML = '<main id=\"details-panel\" class=\"loaded\">Playwright-state-marker</main>'; history.replaceState({}, '', 'https://example.com/spa#state');",
    });
  });
}

describe("Local browser sessions", () => {
  let identity: Identity;

  beforeAll(async () => {
    identity = await idmux({
      name: "local-browser-sessions",
      concurrency: 10,
      credits: 1_000_000,
    });
  }, 10000 + scrapeTimeout);

  itIf(
    !!config.PLAYWRIGHT_MICROSERVICE_URL && !!process.env.BROWSERBASE_API_KEY,
  )(
    "scrapes current local browser session state without navigation",
    async () => {
      const created = await localBrowserCreateRaw(
        {
          ttl: 120,
          activityTtl: 60,
          playwright: {
            viewport: { width: 1024, height: 768 },
          },
        },
        identity,
      );

      expect(created.statusCode).toBe(200);
      expect(created.body.success).toBe(true);
      expect(typeof created.body.id).toBe("string");
      expect(typeof created.body.cdpUrl).toBe("string");

      const sessionId = created.body.id as string;
      const cdpUrl = created.body.cdpUrl as string;
      try {
        await mutateSessionViaCdp(cdpUrl);

        const scrapeResponse = await scrapeRaw(
          {
            sessionId,
            formats: ["markdown"],
          },
          identity,
        );

        expect(scrapeResponse.statusCode).toBe(200);
        expect(scrapeResponse.body.success).toBe(true);
        expect(scrapeResponse.body.data?.markdown).toContain(
          "Playwright-state-marker",
        );
      } finally {
        await localBrowserDeleteRaw(sessionId, identity);
      }
    },
    scrapeTimeout,
  );

  itIf(
    !!config.PLAYWRIGHT_MICROSERVICE_URL && !process.env.BROWSERBASE_API_KEY,
  )(
    "fails to create local browser session when Browserbase is not configured",
    async () => {
      const created = await localBrowserCreateRaw(
        {
          ttl: 120,
          activityTtl: 60,
        },
        identity,
      );

      expect(created.statusCode).toBe(500);
      expect(created.body.success).toBe(false);
      expect(typeof created.body.error).toBe("string");
      expect(created.body.error).toContain("BROWSERBASE_API_KEY");
    },
    scrapeTimeout,
  );

  itIf(!!config.PLAYWRIGHT_MICROSERVICE_URL)(
    "returns 404 for unknown session id",
    async () => {
      const response = await scrapeRaw(
        {
          sessionId: crypto.randomUUID(),
          formats: ["markdown"],
        },
        identity,
      );

      expect(response.statusCode).toBe(404);
      expect(response.body.success).toBe(false);
      expect(typeof response.body.error).toBe("string");
    },
    scrapeTimeout,
  );
});
