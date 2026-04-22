import { config } from "../config";

export interface LocalBrowserCreateResponse {
  sessionId: string;
  cdpUrl: string;
  expiresAt?: string;
}

export interface LocalBrowserSnapshotResponse {
  sessionId: string;
  url: string;
  html: string;
}

export class LocalBrowserServiceError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function getLocalBrowserServiceBaseUrl(): string {
  const configured = config.PLAYWRIGHT_MICROSERVICE_URL;
  if (!configured) {
    throw new LocalBrowserServiceError(
      503,
      "Local browser service is not configured (PLAYWRIGHT_MICROSERVICE_URL is missing).",
    );
  }

  const parsed = new URL(configured);
  if (parsed.pathname.endsWith("/scrape")) {
    parsed.pathname = parsed.pathname.slice(0, -"/scrape".length) || "/";
  }

  return parsed.toString().replace(/\/$/, "");
}

async function parseErrorMessage(res: Response): Promise<string> {
  const text = await res.text();
  if (!text) return `Request failed with status ${res.status}`;

  try {
    const parsed = JSON.parse(text);
    if (typeof parsed?.error === "string") return parsed.error;
  } catch {
    // ignore json parsing errors
  }

  return text;
}

export async function localBrowserServiceRequest<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const url = `${getLocalBrowserServiceBaseUrl()}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    throw new LocalBrowserServiceError(
      res.status,
      await parseErrorMessage(res),
    );
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}
