import express, { Request, Response } from 'express';
import { Browser, BrowserContext, BrowserContextOptions, Route, Request as PlaywrightRequest, Page } from 'playwright';
import { chromium } from 'playwright-extra';
import { Browserbase } from '@browserbasehq/sdk';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import dotenv from 'dotenv';
import UserAgent from 'user-agents';
import { getError } from './helpers/get_error';
import { lookup } from 'dns/promises';
import IPAddr from 'ipaddr.js';
import crypto from 'crypto';

dotenv.config();

const app = express();
const port = process.env.PORT || 3003;

app.use(express.json());

const BLOCK_MEDIA = (process.env.BLOCK_MEDIA || 'False').toUpperCase() === 'TRUE';
const MAX_CONCURRENT_PAGES = Math.max(1, Number.parseInt(process.env.MAX_CONCURRENT_PAGES ?? '10', 10) || 10);
const ALLOW_LOCAL_WEBHOOKS = (process.env.ALLOW_LOCAL_WEBHOOKS || 'False').toUpperCase() === 'TRUE';
const DNS_CACHE_TTL_MS = 30_000;
const BROWSERBASE_PROJECT_ID = process.env.BROWSERBASE_PROJECT_ID?.trim() || undefined;
const MAX_ACTIVE_LOCAL_SESSIONS = Math.max(
  1,
  Number.parseInt(process.env.MAX_ACTIVE_LOCAL_SESSIONS ?? '25', 10) || 25,
);

const normalizeOptionalEnv = (value: string | undefined): string | undefined => {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
};

const PROXY_SERVER = process.env.PROXY_SERVER || null;
const PROXY_USERNAME = process.env.PROXY_USERNAME || null;
const PROXY_PASSWORD = process.env.PROXY_PASSWORD || null;
const CUSTOM_PROXY_URL = normalizeOptionalEnv(process.env.CUSTOM_PROXY_URL);
const CUSTOM_PROXY_USER = normalizeOptionalEnv(process.env.CUSTOM_PROXY_USER);
const CUSTOM_PROXY_PASSWORD = normalizeOptionalEnv(process.env.CUSTOM_PROXY_PASSWORD);
const normalizeStealthLocale = (value: string | undefined): string => {
  const normalized = (value ?? 'en-US').trim().replace(/_/g, '-');
  if (!normalized) return 'en-US';
  if (!/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(normalized)) {
    console.warn(`Invalid STEALTH_LOCALE "${value}", defaulting to "en-US"`);
    return 'en-US';
  }
  return normalized;
};

const getLocaleLanguage = (locale: string): string => {
  const [language] = locale.split('-');
  return (language || 'en').toLowerCase();
};

const buildAcceptLanguageHeader = (locale: string): string => {
  const language = getLocaleLanguage(locale);
  if (locale.toLowerCase() === language) return locale;
  return `${locale},${language};q=0.9`;
};

const buildNavigatorLanguages = (locale: string): string[] => {
  const language = getLocaleLanguage(locale);
  return locale.toLowerCase() === language ? [locale] : [locale, language];
};

const parseBooleanEnv = (value: string | undefined, defaultValue: boolean): boolean => {
  if (!value) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return defaultValue;
};

const STEALTH_LOCALE = normalizeStealthLocale(process.env.STEALTH_LOCALE);
const STEALTH_ACCEPT_LANGUAGE = buildAcceptLanguageHeader(STEALTH_LOCALE);
const STEALTH_NAVIGATOR_LANGUAGES = buildNavigatorLanguages(STEALTH_LOCALE);
const STEALTH_TIMEZONE_ID = process.env.STEALTH_TIMEZONE_ID || null;
const ENABLE_STEALTH_FALLBACKS = parseBooleanEnv(process.env.ENABLE_STEALTH_FALLBACKS, true);
const dnsLookupCache = new Map<string, { addresses: string[]; expiresAt: number }>();
let stealthPluginRegistered = false;

const ensureStealthPlugin = () => {
  if (stealthPluginRegistered) return;
  chromium.use(StealthPlugin());
  stealthPluginRegistered = true;
};

class InsecureConnectionError extends Error {
  constructor(public readonly blockedUrl: string, reason: string) {
    super(`Blocked insecure target URL "${blockedUrl}": ${reason}`);
    this.name = 'InsecureConnectionError';
  }
}

const normalizeHostname = (hostname: string): string => hostname.toLowerCase().replace(/\.$/, '');

const isHttpProtocol = (protocol: string): boolean => protocol === 'http:' || protocol === 'https:';

const isIPPrivate = (address: string): boolean => {
  if (!IPAddr.isValid(address)) return false;
  const parsedAddress = IPAddr.parse(address);
  return parsedAddress.range() !== 'unicast';
};

const isLocalHostname = (hostname: string): boolean =>
  hostname === 'localhost' || hostname.endsWith('.localhost');

const lookupWithCache = async (hostname: string): Promise<string[]> => {
  const cached = dnsLookupCache.get(hostname);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.addresses;
  }

  const resolvedAddresses = await lookup(hostname, { all: true, verbatim: true });
  const uniqueAddresses = [...new Set(resolvedAddresses.map(x => x.address))];
  dnsLookupCache.set(hostname, {
    addresses: uniqueAddresses,
    expiresAt: Date.now() + DNS_CACHE_TTL_MS,
  });
  return uniqueAddresses;
};

const assertSafeTargetUrl = async (urlString: string): Promise<void> => {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    throw new InsecureConnectionError(urlString, 'URL is invalid');
  }

  if (!isHttpProtocol(parsedUrl.protocol)) {
    throw new InsecureConnectionError(urlString, `unsupported protocol "${parsedUrl.protocol}"`);
  }

  if (ALLOW_LOCAL_WEBHOOKS) {
    return;
  }

  const hostname = normalizeHostname(parsedUrl.hostname);
  if (!hostname) {
    throw new InsecureConnectionError(urlString, 'hostname is missing');
  }

  if (isLocalHostname(hostname)) {
    throw new InsecureConnectionError(urlString, 'localhost targets are not allowed');
  }

  if (IPAddr.isValid(hostname)) {
    if (isIPPrivate(hostname)) {
      throw new InsecureConnectionError(urlString, `private IP "${hostname}" is not allowed`);
    }
    return;
  }

  let resolvedAddresses: string[];
  try {
    resolvedAddresses = await lookupWithCache(hostname);
  } catch {
    throw new InsecureConnectionError(
      urlString,
      `DNS lookup failed for "${hostname}", cannot verify target is safe`,
    );
  }

  if (resolvedAddresses.length === 0) {
    throw new InsecureConnectionError(
      urlString,
      `hostname "${hostname}" did not resolve to any IP address`,
    );
  }

  if (resolvedAddresses.some(address => isIPPrivate(address))) {
    throw new InsecureConnectionError(urlString, `hostname "${hostname}" resolves to a private IP`);
  }
};

type ContextSecurityState = {
  blockedNavigationRequestUrl: string | null;
};

type LocalBrowserSession = {
  sessionId: string;
  browserbaseSessionId: string;
  cdpUrl: string;
  browser: Browser;
  context: BrowserContext;
  page: Page;
  createdAt: number;
  expiresAt: number;
  ttlMs: number;
  activityTtlMs: number;
  lastActivity: number;
  ttlTimer: NodeJS.Timeout;
  activityTimer: NodeJS.Timeout;
};

const localSessions = new Map<string, LocalBrowserSession>();
let browserbaseClient: Browserbase | null = null;

const getBrowserbaseClient = (): Browserbase => {
  if (browserbaseClient) return browserbaseClient;
  const apiKey = process.env.BROWSERBASE_API_KEY?.trim();
  if (!apiKey) {
    throw new Error('BROWSERBASE_API_KEY is required for local browser sessions.');
  }
  browserbaseClient = new Browserbase({ apiKey });
  return browserbaseClient;
};

const requestBrowserbaseSessionRelease = async (browserbaseSessionId: string) => {
  let client: Browserbase;
  try {
    client = getBrowserbaseClient();
  } catch (err) {
    console.warn('Failed to initialize Browserbase client for session release', {
      browserbaseSessionId,
      error: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  await client.sessions.update(browserbaseSessionId, {
    status: 'REQUEST_RELEASE',
    projectId: BROWSERBASE_PROJECT_ID,
  }).catch(err => {
    console.warn('Failed to request Browserbase session release', {
      browserbaseSessionId,
      error: err instanceof Error ? err.message : String(err),
    });
  });
};
class Semaphore {
  private permits: number;
  private queue: (() => void)[] = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    this.permits++;
    if (this.queue.length > 0) {
      const nextResolve = this.queue.shift();
      if (nextResolve) {
        this.permits--;
        nextResolve();
      }
    }
  }

  getAvailablePermits(): number {
    return this.permits;
  }

  getQueueLength(): number {
    return this.queue.length;
  }
}
const pageSemaphore = new Semaphore(MAX_CONCURRENT_PAGES);

const AD_SERVING_DOMAINS = [
  'doubleclick.net',
  'adservice.google.com',
  'googlesyndication.com',
  'googletagservices.com',
  'googletagmanager.com',
  'google-analytics.com',
  'adsystem.com',
  'adservice.com',
  'adnxs.com',
  'ads-twitter.com',
  'facebook.net',
  'fbcdn.net',
  'amazon-adsystem.com'
];

interface UrlModel {
  url: string;
  wait_after_load?: number;
  timeout?: number;
  headers?: { [key: string]: string };
  check_selector?: string;
  skip_tls_verification?: boolean;
}

interface LocalSessionCreateModel {
  ttl?: number;
  activityTtl?: number;
  playwright?: Record<string, unknown>;
}

let browser: Browser;

const buildChromeLaunchArgs = (): string[] => {
  const args = [
    '--headless=new',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--no-first-run',
    '--no-default-browser-check',
    '--no-zygote',
    '--disable-gpu',
    '--disable-blink-features=AutomationControlled',
    '--disable-infobars',
    '--window-size=1280,800',
    `--lang=${STEALTH_LOCALE}`,
    '--remote-debugging-port=0'
  ];

  return args;
};

const applyStealthFallbacks = async (context: BrowserContext) => {
  if (!ENABLE_STEALTH_FALLBACKS) return;
  await context.addInitScript(({ languages }) => {
    const safeDefine = (target: object, property: string, descriptor: PropertyDescriptor) => {
      try {
        Object.defineProperty(target, property, descriptor);
      } catch {
        // Ignore properties that cannot be redefined in this runtime.
      }
    };

    if ('webdriver' in navigator) {
      safeDefine(navigator, 'webdriver', {
        get: () => undefined,
      });
    }

    if (!('chrome' in window)) {
      safeDefine(window, 'chrome', {
        configurable: true,
        value: { runtime: {} },
      });
    }

    if (!navigator.languages || navigator.languages.length === 0) {
      safeDefine(navigator, 'languages', {
        get: () => languages,
      });
    }
  }, { languages: STEALTH_NAVIGATOR_LANGUAGES });
};

const buildContextOptions = (
  skipTlsVerification: boolean,
  userAgent: string,
): BrowserContextOptions => {
  const contextOptions: BrowserContextOptions = {
    userAgent,
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: skipTlsVerification,
    serviceWorkers: 'block',
    locale: STEALTH_LOCALE,
    extraHTTPHeaders: {
      'Accept-Language': STEALTH_ACCEPT_LANGUAGE,
    },
  };

  if (STEALTH_TIMEZONE_ID) {
    contextOptions.timezoneId = STEALTH_TIMEZONE_ID;
  }

  if (PROXY_SERVER && PROXY_USERNAME && PROXY_PASSWORD) {
    contextOptions.proxy = {
      server: PROXY_SERVER,
      username: PROXY_USERNAME,
      password: PROXY_PASSWORD,
    };
  } else if (PROXY_SERVER) {
    contextOptions.proxy = {
      server: PROXY_SERVER,
    };
  }

  return contextOptions;
};

const createConfiguredContext = async (options: BrowserContextOptions): Promise<BrowserContext> => {
  const context = await browser.newContext(options);
  await applyStealthFallbacks(context);
  return context;
};

const applyLocalSessionStealthContextConfig = async (context: BrowserContext) => {
  await applyStealthFallbacks(context);
  await context.setExtraHTTPHeaders({
    'Accept-Language': STEALTH_ACCEPT_LANGUAGE,
  }).catch(() => {});
};

const createCdpContextOptions = (): BrowserContextOptions => {
  const options: BrowserContextOptions = {
    locale: STEALTH_LOCALE,
    extraHTTPHeaders: {
      'Accept-Language': STEALTH_ACCEPT_LANGUAGE,
    },
  };

  if (STEALTH_TIMEZONE_ID) {
    options.timezoneId = STEALTH_TIMEZONE_ID;
  }

  return options;
};

const createOrConfigureLocalSessionContext = async (connectedBrowser: Browser): Promise<BrowserContext> => {
  const existingContext = connectedBrowser.contexts()[0];
  if (existingContext) {
    await applyLocalSessionStealthContextConfig(existingContext);
    return existingContext;
  }

  const context = await connectedBrowser.newContext(createCdpContextOptions());
  await applyLocalSessionStealthContextConfig(context);
  return context;
};

const createContext = async (skipTlsVerification: boolean = false, userAgentOverride?: string): Promise<{ context: BrowserContext; securityState: ContextSecurityState }> => {
  const userAgent = userAgentOverride || new UserAgent().toString();
  const securityState: ContextSecurityState = {
    blockedNavigationRequestUrl: null,
  };

  const newContext = await createConfiguredContext(buildContextOptions(skipTlsVerification, userAgent));
  if (BLOCK_MEDIA) {
    await newContext.route('**/*.{png,jpg,jpeg,gif,svg,mp3,mp4,avi,flac,ogg,wav,webm}', async (route: Route, request: PlaywrightRequest) => {
      await route.abort();
    });
  }

  // Intercept all requests to avoid loading ads
  await newContext.route('**/*', async (route: Route, request: PlaywrightRequest) => {
    const requestUrlString = request.url();
    try {
      await assertSafeTargetUrl(requestUrlString);
    } catch (error) {
      if (error instanceof InsecureConnectionError) {
        if (request.isNavigationRequest()) {
          securityState.blockedNavigationRequestUrl = requestUrlString;
        }
        console.warn(`Blocked request: ${requestUrlString}`);
        return route.abort('blockedbyclient');
      }
      throw error;
    }

    const requestUrl = new URL(requestUrlString);
    const hostname = normalizeHostname(requestUrl.hostname);

    if (AD_SERVING_DOMAINS.some(domain => hostname.includes(domain))) {
      console.log(hostname);
      return route.abort();
    }
    return route.continue();
  });

  return { context: newContext, securityState };
};

const initializeBrowser = async () => {
  ensureStealthPlugin();

  browser = await chromium.launch({
    headless: true,
    ignoreDefaultArgs: ['--enable-automation'],
    args: buildChromeLaunchArgs(),
  });
};

const parseSessionTiming = (value: unknown, fallbackMs: number, minSeconds: number, maxSeconds: number): number => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallbackMs;
  }
  const bounded = Math.min(Math.max(value, minSeconds), maxSeconds);
  return Math.floor(bounded * 1000);
};

const buildBrowserbaseProxyConfig = ():
  | Array<{ type: 'external'; server: string; username: string; password: string }>
  | undefined => {
  if (CUSTOM_PROXY_URL && CUSTOM_PROXY_USER && CUSTOM_PROXY_PASSWORD) {
    return [{
      type: 'external',
      server: CUSTOM_PROXY_URL,
      username: CUSTOM_PROXY_USER,
      password: CUSTOM_PROXY_PASSWORD,
    }];
  }

  const hasAnyProxyValue = CUSTOM_PROXY_URL || CUSTOM_PROXY_USER || CUSTOM_PROXY_PASSWORD;
  if (hasAnyProxyValue) {
    const missingVars = [
      !CUSTOM_PROXY_URL ? 'CUSTOM_PROXY_URL' : null,
      !CUSTOM_PROXY_USER ? 'CUSTOM_PROXY_USER' : null,
      !CUSTOM_PROXY_PASSWORD ? 'CUSTOM_PROXY_PASSWORD' : null,
    ].filter((name): name is string => Boolean(name));
    console.warn(
      `Ignoring partial Browserbase proxy configuration. Missing required env vars: ${missingVars.join(', ')}`,
    );
  }

  return undefined;
};

const getPreferredSessionPage = async (session: LocalBrowserSession): Promise<Page> => {
  const pages = session.context.pages();
  if (pages.length === 0) {
    session.page = await session.context.newPage();
    return session.page;
  }

  const preferred = pages.find(candidate => {
    const url = candidate.url();
    return url && url !== 'about:blank';
  }) || pages[0];
  session.page = preferred;
  return preferred;
};

const applyPlaywrightParams = async (
  session: LocalBrowserSession,
  playwright: Record<string, unknown> | undefined,
) => {
  if (!playwright || typeof playwright !== 'object') return;

  const page = await getPreferredSessionPage(session);
  const context = session.context;

  try {
    const viewport = playwright.viewport;
    if (
      viewport &&
      typeof viewport === 'object' &&
      typeof (viewport as any).width === 'number' &&
      typeof (viewport as any).height === 'number'
    ) {
      await page.setViewportSize({
        width: (viewport as any).width,
        height: (viewport as any).height,
      });
    }
  } catch (error) {
    console.warn('Failed to apply viewport parameter', { error });
  }

  try {
    const extraHeaders = playwright.extraHTTPHeaders ?? playwright.headers;
    if (extraHeaders && typeof extraHeaders === 'object') {
      await page.setExtraHTTPHeaders(extraHeaders as Record<string, string>);
    }
  } catch (error) {
    console.warn('Failed to apply header parameters', { error });
  }

  try {
    const geolocation = playwright.geolocation;
    if (
      geolocation &&
      typeof geolocation === 'object' &&
      typeof (geolocation as any).latitude === 'number' &&
      typeof (geolocation as any).longitude === 'number'
    ) {
      await context.grantPermissions(['geolocation']).catch(() => {});
      await context.setGeolocation({
        latitude: (geolocation as any).latitude,
        longitude: (geolocation as any).longitude,
      });
    }
  } catch (error) {
    console.warn('Failed to apply geolocation parameter', { error });
  }
};

const scheduleActivityTimer = (session: LocalBrowserSession) => {
  clearTimeout(session.activityTimer);
  session.activityTimer = setTimeout(() => {
    destroyLocalSession(session.sessionId).catch(err => {
      console.error('Failed to destroy local session after inactivity timeout', err);
    });
  }, session.activityTtlMs);
};

const touchLocalSession = (session: LocalBrowserSession) => {
  session.lastActivity = Date.now();
  scheduleActivityTimer(session);
};

const destroyLocalSession = async (sessionId: string): Promise<number | null> => {
  const session = localSessions.get(sessionId);
  if (!session) return null;

  localSessions.delete(sessionId);
  clearTimeout(session.ttlTimer);
  clearTimeout(session.activityTimer);
  const durationMs = Date.now() - session.createdAt;

  await session.browser.close().catch(() => {});
  await requestBrowserbaseSessionRelease(session.browserbaseSessionId);
  return durationMs;
};

const createLocalSession = async (
  ttlSeconds: number,
  activityTtlSeconds: number,
  playwright: Record<string, unknown> | undefined,
): Promise<LocalBrowserSession> => {
  const sessionId = crypto.randomUUID();
  let connectedBrowser: Browser | null = null;
  let browserbaseSessionId: string | null = null;
  try {
    ensureStealthPlugin();
    const ttlMs = parseSessionTiming(ttlSeconds, 600_000, 30, 3600);
    const activityTtlMs = parseSessionTiming(activityTtlSeconds, 300_000, 10, 3600);
    const browserbaseProxies = buildBrowserbaseProxyConfig();
    const browserbaseSession = await getBrowserbaseClient().sessions.create({
      timeout: Math.floor(ttlMs / 1000),
      projectId: BROWSERBASE_PROJECT_ID,
      ...(browserbaseProxies ? { proxies: browserbaseProxies } : {}),
    });
    browserbaseSessionId = browserbaseSession.id;
    const cdpUrl = browserbaseSession.connectUrl;
    connectedBrowser = await chromium.connectOverCDP(cdpUrl);
    const context = await createOrConfigureLocalSessionContext(connectedBrowser);
    const page = context.pages()[0] ?? await context.newPage();
    await page.setContent(
      '<!doctype html><html><body><main id="firecrawl-local-session-root">Local browser session ready</main></body></html>',
      { waitUntil: 'domcontentloaded' },
    );

    const now = Date.now();
    const parsedExpiresAt = Date.parse(browserbaseSession.expiresAt);
    const expiresAt = Number.isFinite(parsedExpiresAt) ? parsedExpiresAt : now + ttlMs;
    const ttlTimer = setTimeout(() => {
      destroyLocalSession(sessionId).catch(err => {
        console.error('Failed to destroy local session after ttl timeout', err);
      });
    }, ttlMs);
    const activityTimer = setTimeout(() => {
      destroyLocalSession(sessionId).catch(err => {
        console.error('Failed to destroy local session after inactivity timeout', err);
      });
    }, activityTtlMs);

    const session: LocalBrowserSession = {
      sessionId,
      browserbaseSessionId,
      cdpUrl,
      browser: connectedBrowser,
      context,
      page,
      createdAt: now,
      expiresAt,
      ttlMs,
      activityTtlMs,
      lastActivity: now,
      ttlTimer,
      activityTimer,
    };

    localSessions.set(sessionId, session);
    await applyPlaywrightParams(session, playwright);
    return session;
  } catch (error) {
    await connectedBrowser?.close().catch(() => {});
    if (browserbaseSessionId) {
      await requestBrowserbaseSessionRelease(browserbaseSessionId);
    }
    throw error;
  }
};

const shutdownBrowser = async () => {
  const sessionIds = [...localSessions.keys()];
  await Promise.all(sessionIds.map(id => destroyLocalSession(id).catch(() => {})));
  if (browser) {
    await browser.close();
  }
};

const isValidUrl = (urlString: string): boolean => {
  try {
    new URL(urlString);
    return true;
  } catch (_) {
    return false;
  }
};

const scrapePage = async (
  page: Page,
  url: string,
  waitUntil: 'load' | 'networkidle',
  waitAfterLoad: number,
  timeout: number,
  checkSelector: string | undefined,
  securityState: ContextSecurityState,
) => {
  console.log(`Navigating to ${url} with waitUntil: ${waitUntil} and timeout: ${timeout}ms`);
  let response;
  try {
    response = await page.goto(url, { waitUntil, timeout });
  } catch (error) {
    if (securityState.blockedNavigationRequestUrl) {
      throw new InsecureConnectionError(
        securityState.blockedNavigationRequestUrl,
        'navigation to private/internal resource is not allowed',
      );
    }
    throw error;
  }

  if (waitAfterLoad > 0) {
    await page.waitForTimeout(waitAfterLoad);
  }

  if (checkSelector) {
    try {
      await page.waitForSelector(checkSelector, { timeout });
    } catch (error) {
      throw new Error('Required selector not found');
    }
  }

  let headers = null, content = await page.content();
  let ct: string | undefined = undefined;
  if (response) {
    headers = await response.allHeaders();
    ct = Object.entries(headers).find(([key]) => key.toLowerCase() === "content-type")?.[1];
    if (ct && (ct.toLowerCase().includes("application/json") || ct.toLowerCase().includes("text/plain"))) {
      content = (await response.body()).toString("utf8"); // TODO: determine real encoding
    }
  }

  return {
    content,
    status: response ? response.status() : null,
    headers,
    contentType: ct,
  };
};

app.post('/sessions', async (req: Request, res: Response) => {
  const { ttl = 600, activityTtl = 300, playwright }: LocalSessionCreateModel = req.body || {};
  if (localSessions.size >= MAX_ACTIVE_LOCAL_SESSIONS) {
    return res.status(429).json({
      error: `Too many active local browser sessions. Limit is ${MAX_ACTIVE_LOCAL_SESSIONS}.`,
    });
  }
  try {
    const session = await createLocalSession(ttl, activityTtl, playwright);
    return res.status(200).json({
      sessionId: session.sessionId,
      cdpUrl: session.cdpUrl,
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
  } catch (error) {
    console.error('Failed to create local browser session', error);
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to create local browser session',
    });
  }
});

app.get('/sessions/:sessionId/snapshot', async (req: Request, res: Response) => {
  const sessionId = String(req.params.sessionId);
  const selectorRaw = req.query.selector;
  const selector =
    typeof selectorRaw === "string" && selectorRaw.trim() !== ""
      ? selectorRaw.trim()
      : undefined;
  const session = localSessions.get(sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Local browser session not found.' });
  }

  try {
    const page = await getPreferredSessionPage(session);
    touchLocalSession(session);
    let html = await page.content();
    if (selector) {
      try {
        html = await page.evaluate((cssSelector: string) => {
          const matches = [...document.querySelectorAll(cssSelector)];
          return matches.map(node => node.outerHTML).join("\n");
        }, selector);
      } catch (error) {
        return res.status(400).json({
          error: error instanceof Error ? error.message : "Invalid selector.",
        });
      }
    }

    const url = page.url();
    return res.status(200).json({
      sessionId: session.sessionId,
      url,
      html,
    });
  } catch (error) {
    console.error('Failed to snapshot local browser session', error);
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to snapshot local browser session',
    });
  }
});

app.delete('/sessions/:sessionId', async (req: Request, res: Response) => {
  const durationMs = await destroyLocalSession(String(req.params.sessionId));
  if (durationMs === null) {
    return res.status(404).json({ error: 'Local browser session not found.' });
  }

  return res.status(200).json({
    ok: true,
    sessionDurationMs: durationMs,
  });
});

app.get('/health', async (req: Request, res: Response) => {
  try {
    if (!browser) {
      await initializeBrowser();
    }
    
    const { context: testContext } = await createContext();
    const testPage = await testContext.newPage();
    await testPage.close();
    await testContext.close();
    
    res.status(200).json({ 
      status: 'healthy',
      maxConcurrentPages: MAX_CONCURRENT_PAGES,
      activePages: MAX_CONCURRENT_PAGES - pageSemaphore.getAvailablePermits()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({ 
      status: 'unhealthy', 
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    });
  }
});

app.post('/scrape', async (req: Request, res: Response) => {
  const { url, wait_after_load = 0, timeout = 15000, headers, check_selector, skip_tls_verification = false }: UrlModel = req.body;

  console.log(`================= Scrape Request =================`);
  console.log(`URL: ${url}`);
  console.log(`Wait After Load: ${wait_after_load}`);
  console.log(`Timeout: ${timeout}`);
  console.log(`Headers: ${headers ? JSON.stringify(headers) : 'None'}`);
  console.log(`Check Selector: ${check_selector ? check_selector : 'None'}`);
  console.log(`Skip TLS Verification: ${skip_tls_verification}`);
  console.log(`==================================================`);

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  if (!isValidUrl(url)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  try {
    await assertSafeTargetUrl(url);
  } catch (error) {
    if (error instanceof InsecureConnectionError) {
      return res.json({
        content: '',
        pageStatusCode: 403,
        pageError: error.message,
      });
    }
    throw error;
  }

  if (!PROXY_SERVER) {
    console.warn('⚠️ WARNING: No proxy server provided. Your IP address may be blocked.');
  }

  if (!browser) {
    await initializeBrowser();
  }

  await pageSemaphore.acquire();
  
  let requestContext: BrowserContext | null = null;
  let securityState: ContextSecurityState | null = null;
  let page: Page | null = null;

  try {
    // Extract user-agent from request headers (case-insensitive) so it can
    // be applied at the context level.  Playwright ignores user-agent in
    // setExtraHTTPHeaders when the context already defines one (#2802).
    const userAgentOverride = headers
      ? Object.entries(headers).find(([k]) => k.toLowerCase() === 'user-agent')?.[1]
      : undefined;

    const contextBundle = await createContext(skip_tls_verification, userAgentOverride);
    requestContext = contextBundle.context;
    securityState = contextBundle.securityState;
    page = await requestContext.newPage();

    if (headers) {
      // Remove the user-agent key before calling setExtraHTTPHeaders since
      // we already forwarded it to the context-level userAgent option.
      const filteredHeaders = Object.fromEntries(
        Object.entries(headers).filter(([k]) => k.toLowerCase() !== 'user-agent')
      );
      if (Object.keys(filteredHeaders).length > 0) {
        await page.setExtraHTTPHeaders(filteredHeaders);
      }
    }

    const result = await scrapePage(
      page,
      url,
      'load',
      wait_after_load,
      timeout,
      check_selector,
      securityState,
    );
    const pageError = result.status !== 200 ? getError(result.status) : undefined;

    if (!pageError) {
      console.log(`✅ Scrape successful!`);
    } else {
      console.log(`🚨 Scrape failed with status code: ${result.status} ${pageError}`);
    }

    res.json({
      content: result.content,
      pageStatusCode: result.status,
      contentType: result.contentType,
      ...(pageError && { pageError })
    });

  } catch (error) {
    if (error instanceof InsecureConnectionError) {
      return res.json({
        content: '',
        pageStatusCode: 403,
        pageError: error.message,
      });
    }
    console.error('Scrape error:', error);
    res.status(500).json({ error: 'An error occurred while fetching the page.' });
  } finally {
    if (page) await page.close();
    if (requestContext) await requestContext.close();
    pageSemaphore.release();
  }
});

app.listen(port, () => {
  initializeBrowser().then(() => {
    console.log(`Server is running on port ${port}`);
  });
});

if (require.main === module) {
  process.on('SIGINT', () => {
    shutdownBrowser().then(() => {
      console.log('Browser closed');
      process.exit(0);
    });
  });
}
