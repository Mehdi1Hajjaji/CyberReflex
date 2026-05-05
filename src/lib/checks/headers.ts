import type { CheckFinding, NormalizedTarget } from "./types";
import { createCheckResult, errorCheck, fetchWithTimeout, headersToObject } from "./utils";

export async function checkHeaders(target: NormalizedTarget) {
  try {
    const response = await fetchWithTimeout(target.url, { method: "GET", redirect: "manual" }, 5_000);
    const findings: CheckFinding[] = [];
    const headers = response.headers;

    const hsts = headers.get("strict-transport-security");
    if (target.protocol === "https:") {
      findings.push(
        hsts
          ? {
              id: "hsts",
              title: "HSTS present",
              status: /max-age=(\d+)/i.test(hsts) ? "pass" : "warning",
              severity: "low",
              summary: "Strict-Transport-Security is present.",
              evidence: hsts,
            }
          : {
              id: "hsts",
              title: "Missing HSTS",
              status: "fail",
              severity: "medium",
              summary: "HTTPS is used, but no HSTS header was observed.",
              recommendation: "Add Strict-Transport-Security after HTTPS is stable.",
            },
      );
    }

    evaluateHeader(findings, headers, "content-security-policy", "csp", "Content Security Policy", "medium");
    evaluateHeader(findings, headers, "x-frame-options", "x-frame-options", "Frame embedding control", "low");
    evaluateHeader(findings, headers, "x-content-type-options", "nosniff", "MIME sniffing control", "low", "nosniff");
    evaluateHeader(findings, headers, "referrer-policy", "referrer-policy", "Referrer policy", "low");
    evaluateHeader(findings, headers, "permissions-policy", "permissions-policy", "Permissions policy", "low");

    if (response.body) {
      await response.body.cancel().catch(() => undefined);
    }

    return createCheckResult({
      id: "headers",
      name: "HTTP Security Headers",
      findings,
      summary: findings.some((finding) => finding.status === "fail")
        ? "Important browser security headers are missing."
        : "Core security headers are present or only need minor hardening.",
      raw: {
        status: response.status,
        headers: headersToObject(headers),
      },
    });
  } catch (error) {
    return errorCheck("headers", "HTTP Security Headers", error, { url: target.url });
  }
}

function evaluateHeader(
  findings: CheckFinding[],
  headers: Headers,
  headerName: string,
  id: string,
  label: string,
  severity: "low" | "medium",
  expectedValue?: string,
) {
  const value = headers.get(headerName);
  const matches = expectedValue ? value?.toLowerCase() === expectedValue : Boolean(value);

  findings.push(
    matches
      ? {
          id,
          title: `${label} present`,
          status: "pass",
          severity: "info",
          summary: `${headerName} was observed.`,
          evidence: value,
        }
      : {
          id,
          title: `${label} missing or weak`,
          status: headerName === "content-security-policy" ? "fail" : "warning",
          severity,
          summary: expectedValue
            ? `${headerName} was not set to ${expectedValue}.`
            : `${headerName} was not observed.`,
          recommendation: `Add a deliberate ${headerName} policy.`,
          evidence: value,
        },
  );
}

