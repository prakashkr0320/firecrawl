# Playwright Scrape API

This is a simple web scraping service built with Express and Playwright.

## Features

- Scrapes HTML content from specified URLs.
- Blocks requests to known ad-serving domains.
- Blocks media files to reduce bandwidth usage.
- Uses random user-agent strings to avoid detection.
- Uses `playwright-extra` with `puppeteer-extra-plugin-stealth` to reduce automation fingerprints.
- Strategy to ensure the page is fully rendered.
- Local browser sessions with CDP URLs for external Playwright clients.

## Stealth Configuration

The service runs in stealth mode by default.

- `STEALTH_LOCALE` (default: `en-US`) sets Chromium language, Playwright locale, and
  `Accept-Language`. Values are normalized (`_` -> `-`) and invalid values fall back to `en-US`.
- `STEALTH_TIMEZONE_ID` (optional) sets Playwright context `timezoneId` (for example,
  `America/New_York`).
- `ENABLE_STEALTH_FALLBACKS` (default: `true`) controls lightweight init-script fallbacks for
  `navigator.webdriver`, `window.chrome`, and `navigator.languages`.
  Accepted truthy values: `1`, `true`, `yes`, `on`. Accepted falsy values: `0`, `false`, `no`, `off`.

## Install

```bash
npm install
npx playwright install
```

## RUN

```bash
npm run build
npm start
```

OR

```bash
npm run dev
```

## USE

```bash
curl -X POST http://localhost:3000/scrape \
-H "Content-Type: application/json" \
-d '{
  "url": "https://example.com",
  "wait_after_load": 1000,
  "timeout": 15000,
  "headers": {
    "Custom-Header": "value"
  },
  "check_selector": "#content"
}'
```

## USING WITH FIRECRAWL

Add `PLAYWRIGHT_MICROSERVICE_URL=http://localhost:3003/scrape` to `/apps/api/.env` to configure the API to use this Playwright microservice for scraping operations.

For local browser sessions (`POST /v2/local-browser`), this service now requires Browserbase credentials:

- `BROWSERBASE_API_KEY` (required)
- `BROWSERBASE_PROJECT_ID` (optional)
- `CUSTOM_PROXY_URL` (optional)
- `CUSTOM_PROXY_USER` (optional)
- `CUSTOM_PROXY_PASSWORD` (optional)

In production deployments, inject `BROWSERBASE_API_KEY` from a secret manager or Kubernetes Secret. Do not place Browserbase API keys in ConfigMaps or committed values files.

When all `CUSTOM_PROXY_*` variables are set, local Browserbase sessions are created with an external proxy configuration. If only some `CUSTOM_PROXY_*` values are provided, proxy settings are ignored and the session is created without a proxy.

## LOCAL BROWSER SESSIONS

Create a local browser session:

```bash
curl -X POST http://localhost:3003/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "ttl": 600,
    "activityTtl": 300,
    "playwright": {
      "viewport": { "width": 1280, "height": 720 }
    }
  }'
```

Get the current DOM snapshot from a live session (no navigation):

```bash
curl http://localhost:3003/sessions/<session-id>/snapshot
```

Delete a session:

```bash
curl -X DELETE http://localhost:3003/sessions/<session-id>
```
