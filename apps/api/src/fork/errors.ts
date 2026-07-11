type ForkErrorCode =
  | "UNAUTHORIZED"
  | "VALIDATION_ERROR"
  | "SELECTOR_INVALID"
  | "SELECTOR_NO_MATCH"
  | "SELECTOR_MULTIPLE_MATCHES"
  | "TARGET_NOT_FOUND"
  | "CDP_CONNECT_FAILED"
  | "CONVERT_FAILED"
  | "EMPTY_MARKDOWN"
  | "QUEUE_TIMEOUT"
  | "SNAPSHOT_TIMEOUT"
  | "CONVERT_TIMEOUT"
  | "INTERNAL_ERROR";

function statusForCode(code: string): number {
  switch (code) {
    case "UNAUTHORIZED":
      return 401;
    case "VALIDATION_ERROR":
    case "SELECTOR_INVALID":
    case "SELECTOR_NO_MATCH":
    case "SELECTOR_MULTIPLE_MATCHES":
      return 400;
    case "TARGET_NOT_FOUND":
      return 404;
    case "CDP_CONNECT_FAILED":
    case "CONVERT_FAILED":
    case "EMPTY_MARKDOWN":
      return 502;
    case "QUEUE_TIMEOUT":
    case "SNAPSHOT_TIMEOUT":
    case "CONVERT_TIMEOUT":
      return 504;
    default:
      return 500;
  }
}

export class ForkError extends Error {
  code: string;
  statusCode: number;

  constructor(code: string, message: string, statusCode?: number) {
    super(message);
    this.name = "ForkError";
    this.code = code;
    this.statusCode = statusCode ?? statusForCode(code);
  }
}
