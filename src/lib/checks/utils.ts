import dns from "node:dns/promises";
import net from "node:net";
import { parse as parseDomain } from "tldts";
import type {
  CheckFinding,
  CheckId,
  CheckStatus,
  JsonObject,
  NormalizedTarget,
  ScanCheckResult,
} from "./types";

export const USER_AGENT = "CyberReflex/0.2 (+https://cyberreflex.com)";

const LOCAL_HOSTNAMES = new Set(["localhost", "localhost.localdomain"]);

export function normalizeScanUrl(input: string): NormalizedTarget {
  const trimmed = input.trim();

  if (!trimmed || trimmed.length > 2048) {
    throw new Error("Enter a valid URL or hostname to scan.");
  }

  const candidate = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  const parsed = new URL(candidate);

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http:// and https:// targets are supported.");
  }

  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";

  const hostname = parsed.hostname.toLowerCase();

  if (!hostname || LOCAL_HOSTNAMES.has(hostname) || hostname.endsWith(".localhost")) {
    throw new Error("Local or private targets cannot be scanned.");
  }

  if (isPrivateIp(hostname)) {
    throw new Error("Local or private targets cannot be scanned.");
  }

  return {
    input,
    url: parsed.toString(),
    origin: parsed.origin,
    hostname,
    protocol: parsed.protocol as "http:" | "https:",
    registeredDomain: parseDomain(hostname).domain ?? hostname,
  };
}

export async function assertPubliclyResolvable(hostname: string) {
  const records = await dns.lookup(hostname, { all: true });

  if (!records.length) {
    throw new Error("The target hostname could not be resolved.");
  }

  if (records.some((record) => isPrivateIp(record.address))) {
    throw new Error("The target resolves to a local or private network address.");
  }
}

export function createCheckResult(input: {
  id: CheckId;
  name: string;
  findings: CheckFinding[];
  raw?: JsonObject;
  summary?: string;
  status?: CheckStatus;
}): ScanCheckResult {
  return {
    id: input.id,
    name: input.name,
    status: input.status ?? deriveStatus(input.findings),
    summary: input.summary ?? summarizeFindings(input.findings),
    findings: input.findings,
    raw: input.raw ?? {},
  };
}

export function errorCheck(
  id: CheckId,
  name: string,
  error: unknown,
  raw: JsonObject = {},
): ScanCheckResult {
  const message = toMessage(error);

  return createCheckResult({
    id,
    name,
    status: "error",
    summary: `${name} could not be completed.`,
    findings: [
      {
        id: `${id}-technical-error`,
        title: "Technical check error",
        status: "error",
        severity: "medium",
        summary: message,
      },
    ],
    raw: {
      ...raw,
      error: message,
    },
  });
}

export function timeoutSignal(timeoutMs: number) {
  if (typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(timeoutMs);
  }

  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

export async function fetchWithTimeout(
  url: string | URL,
  init: RequestInit = {},
  timeoutMs = 5_000,
) {
  return fetch(url, {
    ...init,
    signal: init.signal ?? timeoutSignal(timeoutMs),
    headers: {
      "user-agent": USER_AGENT,
      accept: "text/html,application/xhtml+xml,*/*;q=0.8",
      ...Object.fromEntries(new Headers(init.headers).entries()),
    },
  });
}

export async function readBodySnippet(response: Response, maxBytes = 100_000) {
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

    const next = value.byteLength > maxBytes - collected
      ? value.slice(0, maxBytes - collected)
      : value;
    chunks.push(Buffer.from(next));
    collected += next.byteLength;

    if (next.byteLength < value.byteLength) {
      break;
    }
  }

  await reader.cancel().catch(() => undefined);
  return Buffer.concat(chunks).toString("utf8");
}

export function headersToObject(headers: Headers) {
  return Object.fromEntries(headers.entries());
}

export function getSetCookieHeaders(headers: Headers) {
  const nodeHeaders = headers as Headers & { getSetCookie?: () => string[] };

  if (typeof nodeHeaders.getSetCookie === "function") {
    return nodeHeaders.getSetCookie();
  }

  const single = headers.get("set-cookie");
  return single ? [single] : [];
}

export function toMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unknown error";
}

export function briefList(items: string[], limit = 4) {
  const visible = items.slice(0, limit);
  const suffix = items.length > limit ? ` and ${items.length - limit} more` : "";
  return `${visible.join(", ")}${suffix}`;
}

export function probeTcpPort(hostname: string, port: number, timeoutMs = 900) {
  return new Promise<"open" | "closed" | "timeout" | "error">((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (state: "open" | "closed" | "timeout" | "error") => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(state);
    };

    socket.setTimeout(timeoutMs, () => finish("timeout"));
    socket.once("connect", () => finish("open"));
    socket.once("error", () => finish("closed"));
    socket.connect(port, hostname);
  });
}

function deriveStatus(findings: CheckFinding[]): CheckStatus {
  const priority: Record<CheckStatus, number> = {
    pass: 0,
    info: 1,
    warning: 2,
    fail: 3,
    error: 4,
  };

  return findings.reduce<CheckStatus>(
    (current, finding) =>
      priority[finding.status] > priority[current] ? finding.status : current,
    "pass",
  );
}

function summarizeFindings(findings: CheckFinding[]) {
  if (findings.some((finding) => finding.status === "fail")) {
    return "One or more security weaknesses were detected.";
  }

  if (findings.some((finding) => finding.status === "warning")) {
    return "The check completed with hardening recommendations.";
  }

  if (findings.some((finding) => finding.status === "error")) {
    return "The check could not be completed reliably.";
  }

  return "The check completed without confirmed issues.";
}

function isPrivateIp(value: string) {
  const ipVersion = net.isIP(value);

  if (ipVersion === 4) {
    const parts = value.split(".").map(Number);
    const [a, b] = parts;

    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 0
    );
  }

  if (ipVersion === 6) {
    const normalized = value.toLowerCase();
    return (
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe80:") ||
      normalized === "::"
    );
  }

  return false;
}

