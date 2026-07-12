/**
 * Isolated file so MAX_CONCURRENT_SCRAPES=1 is applied at module import
 * (scrapeSemaphore size is fixed when the controller module loads).
 */
import type { Express } from "express";
import type { Server } from "node:http";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  SAMPLE_HTML,
  SAMPLE_MARKDOWN,
  SAMPLE_TITLE,
  SAMPLE_URL,
  TEST_API_KEY,
  authHeader,
  closeServer,
  createJsonStubServer,
  listen,
  sendJson,
  type JsonHandler,
} from "./helpers";

describe("fork CDP QUEUE_TIMEOUT", () => {
  let playwrightServer: Server;
  let markdownServer: Server;
  let app: Express;
  let releaseSlow: (() => void) | null = null;
  let pwHandler: JsonHandler;

  beforeAll(async () => {
    pwHandler = (_body, _req, res) => {
      sendJson(res, 200, {
        html: SAMPLE_HTML,
        url: SAMPLE_URL,
        title: SAMPLE_TITLE,
      });
    };
    const markdownHandler: JsonHandler = (_body, _req, res) => {
      sendJson(res, 200, { success: true, markdown: SAMPLE_MARKDOWN });
    };

    playwrightServer = createJsonStubServer("/cdp-snapshot", () => pwHandler);
    markdownServer = createJsonStubServer("/convert", () => markdownHandler);

    const playwrightPort = await listen(playwrightServer);
    const markdownPort = await listen(markdownServer);

    process.env.FIRECRAWL_API_KEY = TEST_API_KEY;
    process.env.PLAYWRIGHT_MICROSERVICE_URL = `http://127.0.0.1:${playwrightPort}`;
    process.env.HTML_TO_MARKDOWN_SERVICE_URL = `http://127.0.0.1:${markdownPort}`;
    process.env.MAX_CONCURRENT_SCRAPES = "1";
    process.env.REQUEST_TIMEOUT_MS = "30000";

    vi.resetModules();
    const fork = await import("../../fork/index.js");
    fork.reloadForkConfig();
    // Belt-and-suspenders: semaphore size must be 1 for this suite.
    fork.resetScrapeSemaphoreForTests(1);
    app = fork.createApp();
  });

  afterAll(async () => {
    releaseSlow?.();
    await Promise.all([
      closeServer(playwrightServer),
      closeServer(markdownServer),
    ]);
  });

  it("second request times out waiting for scrape slot", async () => {
    let signalHolding: (() => void) | null = null;
    const holdingSlot = new Promise<void>(resolve => {
      signalHolding = resolve;
    });

    pwHandler = async (_body, _req, res) => {
      signalHolding?.();
      signalHolding = null;
      await new Promise<void>(resolve => {
        releaseSlow = resolve;
      });
      sendJson(res, 200, {
        html: SAMPLE_HTML,
        url: SAMPLE_URL,
        title: SAMPLE_TITLE,
      });
    };

    const baseBody = {
      cdpUrl: "ws://127.0.0.1:9222/devtools/browser/test",
      targetId: "TARGET_QUEUE",
    };

    // .then() starts the SuperTest request immediately (await alone would defer it).
    const firstDone = request(app)
      .post("/v2/cdp-browser-scrape")
      .set(authHeader())
      .send({ ...baseBody, timeout: 10_000 })
      .then(res => res);

    await holdingSlot;

    const second = await request(app)
      .post("/v2/cdp-browser-scrape")
      .set(authHeader())
      .send({ ...baseBody, timeout: 300 });

    expect(second.status).toBe(504);
    expect(second.body.code).toBe("QUEUE_TIMEOUT");

    releaseSlow?.();
    releaseSlow = null;
    const firstRes = await firstDone;
    expect(firstRes.status).toBe(200);
  });
});
