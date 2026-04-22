import { Response } from "express";
import { z } from "zod";
import { RequestWithAuth } from "./types";
import {
  localBrowserServiceRequest,
  LocalBrowserCreateResponse,
  LocalBrowserServiceError,
} from "../../lib/local-browser-service-client";

const localBrowserCreateRequestSchema = z.object({
  ttl: z.number().min(30).max(3600).default(600),
  activityTtl: z.number().min(10).max(3600).default(300),
  playwright: z.record(z.string(), z.unknown()).optional(),
});

type LocalBrowserCreateRequest = z.infer<
  typeof localBrowserCreateRequestSchema
>;

interface LocalBrowserCreateApiResponse {
  success: boolean;
  id?: string;
  cdpUrl?: string;
  expiresAt?: string;
  error?: string;
}

interface LocalBrowserDeleteApiResponse {
  success: boolean;
  error?: string;
}

export async function localBrowserCreateController(
  req: RequestWithAuth<
    {},
    LocalBrowserCreateApiResponse,
    LocalBrowserCreateRequest
  >,
  res: Response<LocalBrowserCreateApiResponse>,
) {
  req.body = localBrowserCreateRequestSchema.parse(req.body ?? {});

  try {
    const created =
      await localBrowserServiceRequest<LocalBrowserCreateResponse>(
        "POST",
        "/sessions",
        req.body,
      );
    return res.status(200).json({
      success: true,
      id: created.sessionId,
      cdpUrl: created.cdpUrl,
      expiresAt: created.expiresAt,
    });
  } catch (error) {
    if (error instanceof LocalBrowserServiceError) {
      return res.status(error.status).json({
        success: false,
        error: error.message,
      });
    }

    return res.status(502).json({
      success: false,
      error: "Failed to create local browser session.",
    });
  }
}

export async function localBrowserDeleteController(
  req: RequestWithAuth<{ sessionId: string }, LocalBrowserDeleteApiResponse>,
  res: Response<LocalBrowserDeleteApiResponse>,
) {
  const { sessionId } = req.params;
  const parsedSessionId = z.string().uuid().safeParse(sessionId);
  if (!parsedSessionId.success) {
    return res.status(400).json({
      success: false,
      error: "Invalid session ID format. Session ID must be a valid UUID.",
    });
  }

  try {
    await localBrowserServiceRequest(
      "DELETE",
      `/sessions/${encodeURIComponent(sessionId)}`,
    );
    return res.status(200).json({ success: true });
  } catch (error) {
    if (error instanceof LocalBrowserServiceError) {
      return res.status(error.status).json({
        success: false,
        error: error.message,
      });
    }

    return res.status(502).json({
      success: false,
      error: "Failed to delete local browser session.",
    });
  }
}
