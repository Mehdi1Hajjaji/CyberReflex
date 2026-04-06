import { parse as parseDomain } from "tldts";
import type {
  Finding,
  FindingStatus,
  ScanCategory,
  ScanCategoryId,
} from "./types";

export type CookieDescriptor = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  raw: string;
};

type CategoryInput = {
  id: ScanCategoryId;
  label: string;
  score: number;
  maxScore: number;
  summary: string;
  findings: Finding[];
  data?: Record<string, unknown>;
};

const statusPriority: Record<FindingStatus, number> = {
  pass: 0,
  info: 1,
  warning: 2,
  fail: 3,
};

export function createCategory(input: CategoryInput): ScanCategory {
  return {
    ...input,
    score: clamp(input.score, 0, input.maxScore),
    status: deriveCategoryStatus(input.findings),
  };
}

export function deriveCategoryStatus(findings: Finding[]): FindingStatus {
  let current: FindingStatus = "pass";

  for (const finding of findings) {
    if (statusPriority[finding.status] > statusPriority[current]) {
      current = finding.status;
    }
  }

  return current;
}

export function normalizeUrl(input: string) {
  const trimmed = input.trim();
  const candidate = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  const url = new URL(candidate);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http:// and https:// targets are supported.");
  }

  return url;
}

export function scoreToGrade(score: number) {
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 77) return "C+";
  if (score >= 73) return "C";
  if (score >= 70) return "C-";
  if (score >= 67) return "D+";
  if (score >= 63) return "D";
  if (score >= 60) return "D-";
  return "F";
}

export function requestTimeoutSignal(timeoutMs: number) {
  if (typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(timeoutMs);
  }

  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

export async function readBodySnippet(response: Response, maxBytes = 120_000) {
  if (!response.body) {
    return "";
  }

  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let collected = 0;

  while (collected < maxBytes) {
    const { done, value } = await reader.read();

    if (done || !value) {
      break;
    }

    const remaining = maxBytes - collected;
    const nextChunk =
      value.byteLength > remaining ? value.slice(0, remaining) : value;

    chunks.push(Buffer.from(nextChunk));
    collected += nextChunk.byteLength;

    if (nextChunk.byteLength < value.byteLength) {
      break;
    }
  }

  await reader.cancel().catch(() => undefined);
  return Buffer.concat(chunks).toString("utf8");
}

export function getSetCookieHeaders(headers: Headers) {
  const enriched = headers as Headers & {
    getSetCookie?: () => string[];
  };

  if (typeof enriched.getSetCookie === "function") {
    return enriched.getSetCookie();
  }

  const single = headers.get("set-cookie");
  return single ? [single] : [];
}

export function parseSetCookie(raw: string): CookieDescriptor {
  const segments = raw.split(";").map((segment) => segment.trim());
  const [nameValue = "", ...attributes] = segments;
  const [name] = nameValue.split("=");
  const lowered = attributes.map((attribute) => attribute.toLowerCase());
  const sameSite =
    attributes
      .find((attribute) => attribute.toLowerCase().startsWith("samesite="))
      ?.split("=")[1] ?? null;

  return {
    name: name || "unknown",
    secure: lowered.includes("secure"),
    httpOnly: lowered.includes("httponly"),
    sameSite,
    raw,
  };
}

export function toMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }

  return "Unknown error";
}

export function getRegisteredDomain(hostname: string) {
  return parseDomain(hostname).domain ?? hostname;
}

export function briefList(items: string[], limit = 4) {
  if (!items.length) {
    return "";
  }

  const visible = items.slice(0, limit);
  const suffix =
    items.length > limit ? ` and ${items.length - limit} more` : "";

  return `${visible.join(", ")}${suffix}`;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
