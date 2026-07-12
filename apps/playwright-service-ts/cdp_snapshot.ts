import { chromium, Browser, Page } from 'playwright';

export type CdpSnapshotRequest = {
  cdpUrl: string;
  targetId: string;
  selector?: string;
  allowMultipleSelectors?: boolean;
  timeoutMs: number;
};

export type CdpSnapshotSuccess = {
  url: string;
  title?: string;
  html: string;
};

export type CdpSnapshotErrorCode =
  | 'CDP_CONNECT_FAILED'
  | 'TARGET_NOT_FOUND'
  | 'SELECTOR_INVALID'
  | 'SELECTOR_NO_MATCH'
  | 'SELECTOR_MULTIPLE_MATCHES'
  | 'SNAPSHOT_TIMEOUT';

export class CdpSnapshotError extends Error {
  constructor(
    public readonly code: CdpSnapshotErrorCode,
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'CdpSnapshotError';
  }
}

const remainingMs = (deadline: number): number =>
  Math.max(0, deadline - Date.now());

const assertWithinBudget = (deadline: number): void => {
  if (Date.now() >= deadline) {
    throw new CdpSnapshotError(
      'SNAPSHOT_TIMEOUT',
      'CDP snapshot timed out',
      504,
    );
  }
};

const isSelectorSyntaxError = (error: unknown): boolean => {
  if (!(error instanceof Error)) return false;
  const msg = error.message.toLowerCase();
  return (
    msg.includes('syntax') ||
    msg.includes('failed to execute') ||
    msg.includes('is not a valid selector') ||
    msg.includes('invalid selector') ||
    error.name === 'SyntaxError'
  );
};

/**
 * Find the Playwright Page whose CDP targetId matches.
 * Opens a short-lived CDP session per page and detaches after checking.
 */
export const findPageByTargetId = async (
  browser: Browser,
  targetId: string,
): Promise<Page | null> => {
  for (const context of browser.contexts()) {
    for (const page of context.pages()) {
      let session;
      try {
        session = await context.newCDPSession(page);
        const { targetInfo } = await session.send('Target.getTargetInfo');
        if (targetInfo?.targetId === targetId) {
          return page;
        }
      } catch {
        // Page may have closed or CDP session failed — skip and continue.
      } finally {
        if (session) {
          await session.detach().catch(() => {});
        }
      }
    }
  }
  return null;
};

const captureHtml = async (
  page: Page,
  selector: string | undefined,
  allowMultipleSelectors: boolean,
): Promise<string> => {
  if (!selector) {
    return page.content();
  }

  let matchCount: number;
  try {
    matchCount = await page.$$eval(selector, (els) => els.length);
  } catch (error) {
    if (isSelectorSyntaxError(error)) {
      throw new CdpSnapshotError(
        'SELECTOR_INVALID',
        `Invalid CSS selector: ${selector}`,
        400,
      );
    }
    throw error;
  }

  if (matchCount === 0) {
    throw new CdpSnapshotError(
      'SELECTOR_NO_MATCH',
      `No elements matched selector: ${selector}`,
      400,
    );
  }

  if (matchCount > 1 && !allowMultipleSelectors) {
    throw new CdpSnapshotError(
      'SELECTOR_MULTIPLE_MATCHES',
      `Selector matched ${matchCount} elements; set allowMultipleSelectors to join them`,
      400,
    );
  }

  try {
    if (matchCount === 1) {
      return await page.$eval(selector, (el) => (el as Element).outerHTML);
    }
    return await page.$$eval(selector, (els) =>
      els.map((el) => (el as Element).outerHTML).join(''),
    );
  } catch (error) {
    if (isSelectorSyntaxError(error)) {
      throw new CdpSnapshotError(
        'SELECTOR_INVALID',
        `Invalid CSS selector: ${selector}`,
        400,
      );
    }
    throw error;
  }
};

/**
 * Connect over CDP, resolve the page by targetId, and capture raw HTML.
 *
 * Intentionally does not call browser.close(): for connectOverCDP that drops
 * the CDP WebSocket, and many remote providers end the session on disconnect.
 * The client owns the remote browser lifecycle and must close the session.
 */
export const captureCdpSnapshot = async (
  req: CdpSnapshotRequest,
): Promise<CdpSnapshotSuccess> => {
  const {
    cdpUrl,
    targetId,
    selector,
    allowMultipleSelectors = false,
    timeoutMs,
  } = req;

  const deadline = Date.now() + timeoutMs;
  let browser: Browser;

  try {
    browser = await chromium.connectOverCDP(cdpUrl, {
      timeout: timeoutMs,
    });
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.toLowerCase().includes('timeout') ||
        error.name === 'TimeoutError')
    ) {
      throw new CdpSnapshotError(
        'SNAPSHOT_TIMEOUT',
        'Timed out connecting over CDP',
        504,
      );
    }
    throw new CdpSnapshotError(
      'CDP_CONNECT_FAILED',
      error instanceof Error
        ? error.message
        : 'Failed to connect over CDP',
      502,
    );
  }

  assertWithinBudget(deadline);

  const page = await findPageByTargetId(browser, targetId);
  if (!page) {
    throw new CdpSnapshotError(
      'TARGET_NOT_FOUND',
      `No page found for targetId: ${targetId}`,
      404,
    );
  }

  assertWithinBudget(deadline);

  // Race snapshot work against remaining budget.
  const budget = remainingMs(deadline);
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    const html = await Promise.race([
      captureHtml(page, selector, allowMultipleSelectors),
      new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          reject(
            new CdpSnapshotError(
              'SNAPSHOT_TIMEOUT',
              'CDP snapshot timed out',
              504,
            ),
          );
        }, budget);
      }),
    ]);

    const url = page.url();
    let title: string | undefined;
    try {
      title = await page.title();
    } catch {
      title = undefined;
    }

    const result: CdpSnapshotSuccess = { url, html };
    if (title !== undefined) {
      result.title = title;
    }
    return result;
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  }
};
