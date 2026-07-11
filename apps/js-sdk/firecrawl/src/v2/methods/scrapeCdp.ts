import type { CdpScrapeOptions, CdpScrapeResponse } from "../types";
import { HttpClient } from "../utils/httpClient";
import {
  throwForBadResponse,
  normalizeAxiosError,
} from "../utils/errorHandler";

export async function scrapeCdp(
  http: HttpClient,
  options: CdpScrapeOptions,
): Promise<CdpScrapeResponse> {
  if (!options.cdpUrl || !options.cdpUrl.trim()) {
    throw new Error("cdpUrl cannot be empty");
  }
  if (!options.targetId || !options.targetId.trim()) {
    throw new Error("targetId cannot be empty");
  }

  try {
    const res = await http.post<CdpScrapeResponse>(
      "/v2/cdp-browser-scrape",
      options,
      typeof options.timeout === "number"
        ? { timeoutMs: options.timeout + 5000 }
        : {},
    );
    if (res.status !== 200) throwForBadResponse(res, "scrape cdp");
    return res.data as CdpScrapeResponse;
  } catch (err: any) {
    if (err?.isAxiosError) return normalizeAxiosError(err, "scrape cdp");
    throw err;
  }
}
