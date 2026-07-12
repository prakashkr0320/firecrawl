import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import axios, { AxiosError } from "axios";
import { forkConfig } from "./config";
import { ForkError } from "./errors";
import { Semaphore } from "./semaphore";
import { cleanHtml, hasVisibleText } from "./html-clean";
import { convertHtmlToMarkdown } from "./markdown";

const formatSchema = z.enum(["markdown", "html"]);

const requestBodySchema = z
  .object({
    cdpUrl: z.string().min(1),
    targetId: z.string().min(1),
    selector: z.string().optional(),
    allowMultipleSelectors: z.boolean().optional().default(false),
    timeout: z
      .number()
      .int()
      .min(1)
      .optional()
      .default(forkConfig.REQUEST_TIMEOUT_MS),
    formats: z
      .array(formatSchema)
      .optional()
      .default(["markdown"]),
    onlyMainContent: z.boolean().optional().default(true),
    // SDKs inject this on every POST; ignored by the fork.
    origin: z.string().optional(),
  })
  .strict();

export let scrapeSemaphore = new Semaphore(forkConfig.MAX_CONCURRENT_SCRAPES);

/** Recreate the scrape semaphore (for tests that need a specific concurrency). */
export function resetScrapeSemaphoreForTests(size: number): void {
  scrapeSemaphore = new Semaphore(size);
}

interface SnapshotResponse {
  html: string;
  url: string;
  title?: string;
  error?: string;
  code?: string;
}

function mapAxiosToForkError(
  error: unknown,
  timeoutCode: string,
  timeoutMessage: string,
  fallbackCode: string,
  fallbackMessage: string,
): ForkError {
  if (error instanceof ForkError) {
    return error;
  }

  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<{ error?: string; code?: string }>;
    if (
      axiosError.code === "ECONNABORTED" ||
      axiosError.code === "ETIMEDOUT" ||
      /timeout/i.test(axiosError.message)
    ) {
      return new ForkError(timeoutCode, timeoutMessage);
    }

    const data = axiosError.response?.data;
    if (data?.code && data?.error) {
      return new ForkError(data.code, data.error);
    }

    return new ForkError(
      fallbackCode,
      data?.error || axiosError.message || fallbackMessage,
    );
  }

  return new ForkError(
    fallbackCode,
    error instanceof Error ? error.message : fallbackMessage,
  );
}

export async function cdpBrowserScrapeController(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const startedAt = Date.now();
  let acquired = false;
  let queueWaitMs = 0;
  let snapshotMs = 0;
  let convertMs = 0;

  try {
    if (!forkConfig.PLAYWRIGHT_MICROSERVICE_URL) {
      throw new ForkError(
        "CDP_CONNECT_FAILED",
        "PLAYWRIGHT_MICROSERVICE_URL is not configured",
      );
    }

    const parsed = requestBodySchema.safeParse(req.body);
    if (!parsed.success) {
      const message = parsed.error.issues
        .map(i => `${i.path.join(".") || "body"}: ${i.message}`)
        .join("; ");
      throw new ForkError("VALIDATION_ERROR", message);
    }

    const {
      cdpUrl,
      targetId,
      selector,
      allowMultipleSelectors,
      timeout,
      formats,
      onlyMainContent,
    } = parsed.data;

    // Zod enum already rejects unknown formats; double-check for clarity.
    const invalidFormats = formats.filter(
      f => f !== "markdown" && f !== "html",
    );
    if (invalidFormats.length > 0) {
      throw new ForkError(
        "VALIDATION_ERROR",
        `Unknown formats: ${invalidFormats.join(", ")}`,
      );
    }

    const deadline = Date.now() + timeout;

    const queueStarted = Date.now();
    try {
      await scrapeSemaphore.acquire(deadline);
    } catch (err) {
      if (err instanceof ForkError && err.code === "QUEUE_TIMEOUT") {
        throw err;
      }
      throw err;
    }
    acquired = true;
    queueWaitMs = Date.now() - queueStarted;

    const remainingBeforeSnapshot = deadline - Date.now();
    if (remainingBeforeSnapshot <= 0) {
      throw new ForkError("SNAPSHOT_TIMEOUT", "Timed out before snapshot");
    }

    const snapshotStarted = Date.now();
    let snapshot: SnapshotResponse;
    try {
      const response = await axios.post<SnapshotResponse>(
        `${forkConfig.PLAYWRIGHT_MICROSERVICE_URL}/cdp-snapshot`,
        {
          cdpUrl,
          targetId,
          selector,
          allowMultipleSelectors,
          timeoutMs: remainingBeforeSnapshot,
        },
        {
          timeout: remainingBeforeSnapshot,
          headers: { "Content-Type": "application/json" },
          validateStatus: () => true,
        },
      );

      if (response.status >= 400 || response.data?.error) {
        const code = response.data?.code ?? "CDP_CONNECT_FAILED";
        const message =
          response.data?.error ??
          `Playwright snapshot failed with status ${response.status}`;
        throw new ForkError(code, message);
      }

      snapshot = response.data;
    } catch (error) {
      throw mapAxiosToForkError(
        error,
        "SNAPSHOT_TIMEOUT",
        "Playwright snapshot timed out",
        "CDP_CONNECT_FAILED",
        "Playwright snapshot failed",
      );
    }
    snapshotMs = Date.now() - snapshotStarted;

    if (!snapshot?.html) {
      throw new ForkError(
        "CDP_CONNECT_FAILED",
        "Playwright snapshot returned empty HTML",
      );
    }

    const onlyMainContentForced = selector ? false : onlyMainContent;
    const cleanedHtml = await cleanHtml(
      snapshot.html,
      snapshot.url || "",
      onlyMainContentForced,
    );

    const wantsMarkdown = formats.includes("markdown");
    const wantsHtml = formats.includes("html");

    let markdown: string | undefined;
    if (wantsMarkdown) {
      const remainingBeforeConvert = deadline - Date.now();
      const convertStarted = Date.now();
      markdown = await convertHtmlToMarkdown(
        cleanedHtml,
        remainingBeforeConvert,
      );
      convertMs = Date.now() - convertStarted;

      if (
        (!markdown || markdown.trim() === "") &&
        hasVisibleText(cleanedHtml)
      ) {
        throw new ForkError(
          "EMPTY_MARKDOWN",
          "Markdown conversion produced empty output for non-empty HTML",
        );
      }
    } else {
      convertMs = 0;
    }

    const body: {
      markdown?: string;
      html?: string;
      metadata: {
        url: string;
        title?: string;
        timings: {
          queueWaitMs: number;
          snapshotMs: number;
          convertMs: number;
          totalMs: number;
        };
      };
    } = {
      metadata: {
        url: snapshot.url ?? "",
        timings: {
          queueWaitMs,
          snapshotMs,
          convertMs,
          totalMs: Date.now() - startedAt,
        },
      },
    };

    if (snapshot.title !== undefined && snapshot.title !== "") {
      body.metadata.title = snapshot.title;
    }
    if (wantsMarkdown) {
      body.markdown = markdown ?? "";
    }
    if (wantsHtml) {
      body.html = cleanedHtml;
    }

    res.status(200).json(body);
  } catch (error) {
    next(error);
  } finally {
    if (acquired) {
      scrapeSemaphore.release();
    }
  }
}
