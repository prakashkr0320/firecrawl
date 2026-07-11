import axios, { AxiosError } from "axios";
import { forkConfig } from "./config";
import { ForkError } from "./errors";

interface ConvertResponse {
  markdown: string;
  success: boolean;
}

export async function convertHtmlToMarkdown(
  html: string,
  timeoutMs: number,
): Promise<string> {
  const baseUrl = forkConfig.HTML_TO_MARKDOWN_SERVICE_URL;
  if (!baseUrl) {
    throw new ForkError(
      "CONVERT_FAILED",
      "HTML_TO_MARKDOWN_SERVICE_URL is not configured",
    );
  }

  if (!html || html.trim() === "") {
    return "";
  }

  if (timeoutMs <= 0) {
    throw new ForkError("CONVERT_TIMEOUT", "HTML to Markdown conversion timed out");
  }

  let markdown: string;
  try {
    const response = await axios.post<ConvertResponse>(
      `${baseUrl}/convert`,
      { html },
      {
        timeout: timeoutMs,
        headers: { "Content-Type": "application/json" },
      },
    );

    if (!response.data.success) {
      throw new ForkError(
        "CONVERT_FAILED",
        "HTML to Markdown conversion was not successful",
      );
    }

    markdown = response.data.markdown ?? "";
  } catch (error) {
    if (error instanceof ForkError) {
      throw error;
    }

    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;
      if (
        axiosError.code === "ECONNABORTED" ||
        axiosError.code === "ETIMEDOUT" ||
        /timeout/i.test(axiosError.message)
      ) {
        throw new ForkError(
          "CONVERT_TIMEOUT",
          "HTML to Markdown conversion timed out",
        );
      }

      const message =
        (axiosError.response?.data as { error?: string } | undefined)?.error ||
        axiosError.message;
      throw new ForkError(
        "CONVERT_FAILED",
        `HTML to Markdown conversion failed: ${message}`,
      );
    }

    throw new ForkError(
      "CONVERT_FAILED",
      error instanceof Error
        ? error.message
        : "HTML to Markdown conversion failed",
    );
  }

  try {
    const { postProcessMarkdown } = await import("@mendable/firecrawl-rs");
    markdown = await postProcessMarkdown(markdown);
  } catch {
    // Optional post-process; skip if unavailable.
  }

  return markdown;
}
