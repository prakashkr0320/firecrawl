import type { Express } from "express";
import type { Server } from "node:http";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  SAMPLE_HTML,
  SAMPLE_MARKDOWN,
  SAMPLE_TITLE,
  SAMPLE_URL,
  TEST_API_KEY,
  authHeader,
  closeServer,
  createJsonStubServer,
  delay,
  listen,
  sendJson,
  type JsonHandler,
} from "./helpers";

describe("fork CDP API", () => {
  let playwrightServer: Server;
  let markdownServer: Server;
  let playwrightHandler: JsonHandler;
  let markdownHandler: JsonHandler;
  let lastPlaywrightBody: Record<string, unknown> | null;
  let app: Express;

  beforeAll(async () => {
    playwrightHandler = (body, _req, res) => {
      lastPlaywrightBody = body;
      sendJson(res, 200, {
        html: SAMPLE_HTML,
        url: SAMPLE_URL,
        title: SAMPLE_TITLE,
      });
    };
    markdownHandler = (_body, _req, res) => {
      sendJson(res, 200, { success: true, markdown: SAMPLE_MARKDOWN });
    };

    playwrightServer = createJsonStubServer(
      "/cdp-snapshot",
      () => playwrightHandler,
    );
    markdownServer = createJsonStubServer("/convert", () => markdownHandler);

    const playwrightPort = await listen(playwrightServer);
    const markdownPort = await listen(markdownServer);

    process.env.FIRECRAWL_API_KEY = TEST_API_KEY;
    process.env.PLAYWRIGHT_MICROSERVICE_URL = `http://127.0.0.1:${playwrightPort}`;
    process.env.HTML_TO_MARKDOWN_SERVICE_URL = `http://127.0.0.1:${markdownPort}`;
    process.env.MAX_CONCURRENT_SCRAPES = "10";
    process.env.REQUEST_TIMEOUT_MS = "30000";

    // forkConfig / scrapeSemaphore are fixed at import — set env first.
    vi.resetModules();
    const fork = await import("../../fork/index");
    // Env was set before import; reload keeps config object in sync for clarity.
    fork.reloadForkConfig();
    app = fork.createApp();
  });

  afterAll(async () => {
    await Promise.all([
      closeServer(playwrightServer),
      closeServer(markdownServer),
    ]);
  });

  beforeEach(() => {
    lastPlaywrightBody = null;
    playwrightHandler = (body, _req, res) => {
      lastPlaywrightBody = body;
      sendJson(res, 200, {
        html: SAMPLE_HTML,
        url: SAMPLE_URL,
        title: SAMPLE_TITLE,
      });
    };
    markdownHandler = (_body, _req, res) => {
      sendJson(res, 200, { success: true, markdown: SAMPLE_MARKDOWN });
    };
  });

  const baseBody = {
    cdpUrl: "ws://127.0.0.1:9222/devtools/browser/test",
    targetId: "TARGET_1",
  };

  it("GET /health returns 200", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  describe("happy paths", () => {
    it("full-page CDP scrape returns markdown", async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send(baseBody);

      expect(res.status).toBe(200);
      expect(res.body.markdown).toBe(SAMPLE_MARKDOWN);
      expect(res.body.html).toBeUndefined();
      expect(res.body.metadata.url).toBe(SAMPLE_URL);
      expect(res.body.metadata.title).toBe(SAMPLE_TITLE);
      expect(res.body.metadata.timings).toMatchObject({
        queueWaitMs: expect.any(Number),
        snapshotMs: expect.any(Number),
        convertMs: expect.any(Number),
        totalMs: expect.any(Number),
      });
    });

    it("selector scrape succeeds with markdown", async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({
          ...baseBody,
          selector: "#main",
        });

      expect(res.status).toBe(200);
      expect(res.body.markdown).toBe(SAMPLE_MARKDOWN);
      expect(lastPlaywrightBody?.selector).toBe("#main");
    });

    it('formats: ["markdown","html"] returns both', async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({
          ...baseBody,
          formats: ["markdown", "html"],
        });

      expect(res.status).toBe(200);
      expect(res.body.markdown).toBe(SAMPLE_MARKDOWN);
      expect(typeof res.body.html).toBe("string");
      expect(res.body.html).toContain("Hello fork scrape");
    });

    it("allowMultipleSelectors is passed through to playwright", async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({
          ...baseBody,
          selector: ".item",
          allowMultipleSelectors: true,
        });

      expect(res.status).toBe(200);
      expect(lastPlaywrightBody?.allowMultipleSelectors).toBe(true);
    });
  });

  describe("failure paths", () => {
    it("missing API key returns 401 UNAUTHORIZED", async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .send(baseBody);

      expect(res.status).toBe(401);
      expect(res.body.code).toBe("UNAUTHORIZED");
    });

    it("bad API key returns 401 UNAUTHORIZED", async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader("wrong-key"))
        .send(baseBody);

      expect(res.status).toBe(401);
      expect(res.body.code).toBe("UNAUTHORIZED");
    });

    it("TARGET_NOT_FOUND from playwright is mapped through", async () => {
      playwrightHandler = (_body, _req, res) => {
        sendJson(res, 404, {
          error: "Target not found",
          code: "TARGET_NOT_FOUND",
        });
      };

      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send(baseBody);

      expect(res.status).toBe(404);
      expect(res.body.code).toBe("TARGET_NOT_FOUND");
    });

    it("SELECTOR_NO_MATCH returns 400", async () => {
      playwrightHandler = (_body, _req, res) => {
        sendJson(res, 400, {
          error: "Selector matched no elements",
          code: "SELECTOR_NO_MATCH",
        });
      };

      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({ ...baseBody, selector: "#missing" });

      expect(res.status).toBe(400);
      expect(res.body.code).toBe("SELECTOR_NO_MATCH");
    });

    it("SELECTOR_MULTIPLE_MATCHES returns 400", async () => {
      playwrightHandler = (_body, _req, res) => {
        sendJson(res, 400, {
          error: "Selector matched multiple elements",
          code: "SELECTOR_MULTIPLE_MATCHES",
        });
      };

      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({ ...baseBody, selector: ".dup" });

      expect(res.status).toBe(400);
      expect(res.body.code).toBe("SELECTOR_MULTIPLE_MATCHES");
    });

    it("unsupported format returns 400 VALIDATION_ERROR", async () => {
      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({
          ...baseBody,
          formats: ["pdf"],
        });

      expect(res.status).toBe(400);
      expect(res.body.code).toBe("VALIDATION_ERROR");
    });

    it("empty markdown for non-empty HTML returns EMPTY_MARKDOWN", async () => {
      markdownHandler = (_body, _req, res) => {
        sendJson(res, 200, { success: true, markdown: "" });
      };

      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send(baseBody);

      expect(res.status).toBe(502);
      expect(res.body.code).toBe("EMPTY_MARKDOWN");
    });

    it("slow playwright beyond timeout returns SNAPSHOT_TIMEOUT", async () => {
      playwrightHandler = async (_body, _req, res) => {
        await delay(1500);
        sendJson(res, 200, {
          html: SAMPLE_HTML,
          url: SAMPLE_URL,
          title: SAMPLE_TITLE,
        });
      };

      const res = await request(app)
        .post("/v2/cdp-browser-scrape")
        .set(authHeader())
        .send({
          ...baseBody,
          timeout: 200,
        });

      expect(res.status).toBe(504);
      expect(res.body.code).toBe("SNAPSHOT_TIMEOUT");
    });
  });
});
