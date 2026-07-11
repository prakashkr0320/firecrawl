function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function intEnv(name: string, defaultValue: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return defaultValue;
  }
  const parsed = parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid integer for environment variable ${name}: ${raw}`);
  }
  return parsed;
}

function readForkConfig() {
  return {
    FIRECRAWL_API_KEY: process.env.FIRECRAWL_API_KEY ?? "",
    MAX_CONCURRENT_SCRAPES: intEnv("MAX_CONCURRENT_SCRAPES", 10),
    REQUEST_TIMEOUT_MS: intEnv("REQUEST_TIMEOUT_MS", 300_000),
    PLAYWRIGHT_MICROSERVICE_URL: process.env.PLAYWRIGHT_MICROSERVICE_URL ?? "",
    HTML_TO_MARKDOWN_SERVICE_URL: process.env.HTML_TO_MARKDOWN_SERVICE_URL ?? "",
    PORT: intEnv("PORT", 3002),
    HOST: process.env.HOST ?? "0.0.0.0",
  };
}

export const forkConfig = readForkConfig();

/** Re-read env into the existing `forkConfig` object (tests / hot reload). */
export function reloadForkConfig(): typeof forkConfig {
  Object.assign(forkConfig, readForkConfig());
  return forkConfig;
}

export function validateBootConfig(): void {
  requireEnv("FIRECRAWL_API_KEY");
  // Keep the in-memory value in sync after requireEnv succeeds.
  forkConfig.FIRECRAWL_API_KEY = process.env.FIRECRAWL_API_KEY!;
}
