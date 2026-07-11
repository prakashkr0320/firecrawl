import { Request, Response, NextFunction } from "express";
import { forkConfig } from "./config";

export function requireApiKey(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;
  const expected =
    process.env.FIRECRAWL_API_KEY || forkConfig.FIRECRAWL_API_KEY;

  if (!header || !header.startsWith("Bearer ")) {
    res.status(401).json({
      error: "Unauthorized: missing or invalid API key",
      code: "UNAUTHORIZED",
    });
    return;
  }

  const token = header.slice("Bearer ".length).trim();
  if (!expected || token !== expected) {
    res.status(401).json({
      error: "Unauthorized: missing or invalid API key",
      code: "UNAUTHORIZED",
    });
    return;
  }

  next();
}
