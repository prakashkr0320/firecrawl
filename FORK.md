# Firecrawl Personal Fork

## Purpose

This repository is a personal-use fork of Firecrawl focused on a single workflow: scraping HTML from a client-owned remote Chrome DevTools Protocol (CDP) session and returning markdown and/or cleaned HTML. The client already owns the browser (e.g. Playwright + Browserbase); Firecrawl connects over CDP, snapshots HTML, optionally cleans it, and converts to markdown. It is not intended to be merged back upstream as a product feature.

## Runtime

The default runtime consists of **three services only** (see root `docker-compose.yaml`):

| Service | Role |
|---------|------|
| `api` | Slim fork entrypoint (`node dist/src/fork/index.js`) |
| `playwright-service` | CDP connect + HTML snapshot (`POST /cdp-snapshot`) |
| `go-html-to-md` | HTTP HTML → markdown (`POST /convert`) |

No Redis, Postgres, RabbitMQ, FoundationDB, or queue workers are required at runtime.

### Environment variables

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `FIRECRAWL_API_KEY` | Yes | — | Bearer token for API auth |
| `MAX_CONCURRENT_SCRAPES` | No | `10` | In-process API semaphore; excess requests wait until a slot or deadline |
| `REQUEST_TIMEOUT_MS` | No | `300000` | Default per-request timeout; also sets Go service ReadTimeout/WriteTimeout |
| `PLAYWRIGHT_MICROSERVICE_URL` | Yes (compose) | `http://playwright-service:3000` | **Base URL only** — fork appends `/cdp-snapshot` (upstream used a URL ending in `/scrape`) |
| `HTML_TO_MARKDOWN_SERVICE_URL` | Yes (compose) | `http://go-html-to-md:8080` | HTTP markdown converter base URL |

See also `.env.example`.

## Public API

### `POST /v2/cdp-browser-scrape`

**Auth:** `Authorization: Bearer <FIRECRAWL_API_KEY>`

**Request:**

```json
{
  "cdpUrl": "wss://...",
  "targetId": "...",
  "selector": "optional CSS",
  "allowMultipleSelectors": false,
  "timeout": 300000,
  "formats": ["markdown"],
  "onlyMainContent": true
}
```

| Field | Notes |
|-------|--------|
| `cdpUrl`, `targetId` | Required |
| `formats` | Only `"markdown"` and `"html"`; default `["markdown"]` |
| `onlyMainContent` | Default `true`; **forced `false` when `selector` is set** |
| `selector` | 0 matches → error; >1 without `allowMultipleSelectors` → error; >1 with flag → join `outerHTML` |
| `timeout` | ms; default `REQUEST_TIMEOUT_MS`; ceiling for the whole handler (queue wait + snapshot + convert) |

**Success (`200`)** — no `success` field:

```json
{
  "markdown": "...",
  "html": "...",
  "metadata": {
    "url": "https://...",
    "title": "...",
    "timings": {
      "queueWaitMs": 0,
      "snapshotMs": 0,
      "convertMs": 0,
      "totalMs": 0
    }
  }
}
```

`markdown` / `html` are included only when requested. `html` is **cleaned** HTML (after transform / `onlyMainContent`), not raw CDP HTML.

**Errors** — non-2xx with `{ "error": "...", "code": "..." }`. Suggested codes: `UNAUTHORIZED`, `VALIDATION_ERROR`, `CDP_CONNECT_FAILED`, `TARGET_NOT_FOUND`, `SELECTOR_NO_MATCH`, `SELECTOR_MULTIPLE_MATCHES`, `SELECTOR_INVALID`, `QUEUE_TIMEOUT`, `SNAPSHOT_TIMEOUT`, `CONVERT_TIMEOUT`, `CONVERT_FAILED`, `EMPTY_MARKDOWN`.

### SDK methods

| SDK | Method |
|-----|--------|
| Python (`apps/python-sdk`) | `scrape_cdp` / async `scrape_cdp` |
| JavaScript (`apps/js-sdk`) | `scrapeCdp` |

SDKs throw on non-2xx (propagate server `error` message). Other SDK methods remain in-tree but are unsupported on this fork’s runtime.

### Playwright service

`POST /cdp-snapshot` — request `{ cdpUrl, targetId, selector?, allowMultipleSelectors?, timeoutMs }` → `{ url, title?, html }` (raw snapshot HTML). Connect per request via `connectOverCDP`; no session store.

## Kept paths

- `apps/api/src/fork/*` — slim API (config, auth, semaphore, controller, HTML clean, markdown HTTP client)
- `apps/api/src/__tests__/fork/*` — fork tests
- `apps/playwright-service-ts` — including `cdp_snapshot.ts` / `POST /cdp-snapshot`
- `apps/go-html-to-md-service` — with `REQUEST_TIMEOUT_MS` and per-request converters
- `apps/python-sdk` — `scrape_cdp`
- `apps/js-sdk` — `scrapeCdp`
- Root `docker-compose.yaml`, `FORK.md`, `.env.example`

## Removed / disabled

Soft strip — code may remain in-tree but is **out of the default runtime** and public fork surface:

- [x] Redis, Postgres, RabbitMQ, FoundationDB, nuq workers removed from default `docker-compose.yaml`
- [x] Default compose no longer starts BullMQ/harness workers (`api` runs `node dist/src/fork/index.js`)
- [x] Crawl, map, search, extract, agent, batch, browser-session product APIs not mounted on the fork entrypoint
- [x] Billing, credits, teams, Autumn, Supabase auth DB not used by fork auth (shared bearer key only)
- [x] Other language SDKs (`rust-sdk`, `go-sdk`, `java-sdk`, `php-sdk`, `ruby-sdk`, `dot-net-sdk`, `elixir-sdk`) remain in-tree but unsupported
- [x] Upstream multi-service compose preserved only in git history

## Modified upstream behavior

- **Auth:** shared bearer `FIRECRAWL_API_KEY` (not `USE_DB_AUTHENTICATION` full bypass)
- **Concurrency:** in-process API semaphore (`MAX_CONCURRENT_SCRAPES`); unbounded wait queue; timeout only via client `timeout` / `REQUEST_TIMEOUT_MS` (`QUEUE_TIMEOUT`)
- **Timeouts:** `REQUEST_TIMEOUT_MS` sets Go `ReadTimeout`/`WriteTimeout`; outbound HTTP clients use remaining deadline
- **Playwright URL:** base URL in this fork (append `/cdp-snapshot`); upstream historically used `.../scrape`
- **Markdown:** HTTP `go-html-to-md` only for this endpoint — no FFI / Turndown fallback; empty markdown with visible HTML text → `EMPTY_MARKDOWN`
- **Go converter:** per-request converter instances (thread-safety)
- **HTML clean:** fork-local `html-clean.ts` (tries `@mendable/firecrawl-rs` `transformHtml`, cheerio fallback) — avoids Redis-dragging imports from the full scrape pipeline

## Merge policy for future upstream pulls

When pulling changes from upstream Firecrawl:

1. **Prefer upstream bugfixes** in: `go-html-to-md-service`, playwright CDP/connect utilities (`cdp_snapshot.ts` and related), and HTML transform/clean patterns used by this fork.
2. **Reject reintroduction** of crawl/map/billing/auth-DB/redis workers into the **default** runtime unless this `FORK.md` is explicitly updated.
3. **Always preserve** `POST /v2/cdp-browser-scrape`, playwright `POST /cdp-snapshot`, and SDK methods `scrape_cdp` / `scrapeCdp`.
4. **On conflicts in deleted/unused files:** keep the soft-strip (inert) state unless the file is now required by a kept path.
5. Update this file whenever you intentionally remove or change fork behavior.

## How to run

```bash
cp .env.example .env   # set FIRECRAWL_API_KEY
docker compose up --build
```

### curl

```bash
curl -X POST http://localhost:3002/v2/cdp-browser-scrape \
  -H "Authorization: Bearer $FIRECRAWL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "cdpUrl": "wss://your-remote-browser/cdp",
    "targetId": "your-target-id",
    "formats": ["markdown"]
  }'
```

### Python (obtain `targetId` from your browser session)

```python
from firecrawl import Firecrawl

# Example: with Playwright, target id is available via CDP session:
# session = await page.context.new_cdp_session(page)
# target_id = (await session.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
# Or in Python Playwright: page._impl_obj._guid / CDP Target.getTargetInfo

app = Firecrawl(api_key="...", api_url="http://localhost:3002")
result = app.scrape_cdp(
    cdp_url="wss://...",
    target_id="...",
    formats=["markdown", "html"],
)
print(result.markdown)
```

### JavaScript

```ts
import Firecrawl from "@mendable/firecrawl-js";

const app = new Firecrawl({ apiKey: "...", apiUrl: "http://localhost:3002" });
const result = await app.scrapeCdp({
  cdpUrl: "wss://...",
  targetId: "...",
  formats: ["markdown", "html"],
});
console.log(result.markdown);
```

### Tests

```bash
cd apps/api && pnpm test:fork
```

Optional real CDP E2E (requires local services + browser):

```bash
FORK_E2E=true pnpm test:fork
```

Fork tests use `pnpm test:fork` — **not** `pnpm harness` (harness starts Redis/workers unused by this fork).

### Local API without Docker

```bash
cd apps/api
FIRECRAWL_API_KEY=dev \
PLAYWRIGHT_MICROSERVICE_URL=http://127.0.0.1:3000 \
HTML_TO_MARKDOWN_SERVICE_URL=http://127.0.0.1:8080 \
pnpm dev:fork
```
