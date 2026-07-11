import express, {
  Express,
  Request,
  Response,
  NextFunction,
  ErrorRequestHandler,
} from "express";
import { forkConfig, validateBootConfig } from "./config";
import { requireApiKey } from "./auth";
import {
  cdpBrowserScrapeController,
  resetScrapeSemaphoreForTests,
  scrapeSemaphore,
} from "./controller";
import { ForkError } from "./errors";

export { scrapeSemaphore, resetScrapeSemaphoreForTests };
export { forkConfig, reloadForkConfig } from "./config";

export function createApp(): Express {
  const app = express();

  app.use(express.json({ limit: "200mb" }));

  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ status: "ok" });
  });

  app.post(
    "/v2/cdp-browser-scrape",
    requireApiKey,
    (req, res, next) => {
      void cdpBrowserScrapeController(req, res, next);
    },
  );

  const errorHandler: ErrorRequestHandler = (
    err: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ) => {
    if (err instanceof ForkError) {
      res.status(err.statusCode).json({
        error: err.message,
        code: err.code,
      });
      return;
    }

    const message =
      err instanceof Error ? err.message : "Internal server error";
    res.status(500).json({
      error: message,
      code: "INTERNAL_ERROR",
    });
  };

  app.use(errorHandler);

  return app;
}

export function startServer(): void {
  validateBootConfig();
  const app = createApp();
  app.listen(forkConfig.PORT, forkConfig.HOST, () => {
    console.log(
      `Fork API listening on http://${forkConfig.HOST}:${forkConfig.PORT}`,
    );
  });
}

if (require.main === module) {
  startServer();
}
