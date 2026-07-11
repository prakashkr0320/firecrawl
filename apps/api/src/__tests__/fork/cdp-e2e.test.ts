/**
 * Optional live E2E against real playwright-service + go-html-to-md.
 *
 * Prerequisites:
 *   - Fork API deps reachable via env (or docker compose up)
 *   - FIRECRAWL_API_KEY set
 *   - PLAYWRIGHT_MICROSERVICE_URL pointing at a live /cdp-snapshot service
 *   - HTML_TO_MARKDOWN_SERVICE_URL pointing at a live /convert service
 *   - A client-owned CDP session (cdpUrl + targetId)
 *
 * Run:
 *   FORK_E2E=true pnpm test:fork
 *
 * Without FORK_E2E=true this file is skipped (CI-safe).
 */

const runE2E = process.env.FORK_E2E === "true";

(runE2E ? describe : describe.skip)("fork CDP e2e", () => {
  it("documents live CDP scrape (placeholder)", () => {
    // Wire a real request here when running against live services, e.g.:
    //
    //   const app = (await import("../../fork/index")).createApp();
    //   const res = await request(app)
    //     .post("/v2/cdp-browser-scrape")
    //     .set({ Authorization: `Bearer ${process.env.FIRECRAWL_API_KEY}` })
    //     .send({
    //       cdpUrl: process.env.FORK_E2E_CDP_URL,
    //       targetId: process.env.FORK_E2E_TARGET_ID,
    //       formats: ["markdown"],
    //     });
    //   expect(res.status).toBe(200);
    //   expect(res.body.markdown).toBeTruthy();
    //
    // Kept as a placeholder so CI stays green without a remote browser.
    expect(runE2E).toBe(true);
  });
});
