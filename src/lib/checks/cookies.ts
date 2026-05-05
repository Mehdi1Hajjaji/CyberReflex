import type { CheckFinding, NormalizedTarget } from "./types";
import { briefList, createCheckResult, errorCheck, fetchWithTimeout, getSetCookieHeaders } from "./utils";

type CookieFlags = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
};

export async function checkCookies(target: NormalizedTarget) {
  try {
    const response = await fetchWithTimeout(target.url, { method: "GET", redirect: "manual" }, 5_000);
    const cookies = getSetCookieHeaders(response.headers).map(parseCookie);
    const findings: CheckFinding[] = [];

    if (response.body) {
      await response.body.cancel().catch(() => undefined);
    }

    if (!cookies.length) {
      return createCheckResult({
        id: "cookies",
        name: "Cookie Security",
        summary: "No cookies were set by the initial response.",
        findings: [
          {
            id: "no-cookies",
            title: "No Set-Cookie headers observed",
            status: "pass",
            severity: "info",
            summary: "The initial response did not set cookies.",
          },
        ],
        raw: { status: response.status, cookies },
      });
    }

    const missingSecure = cookies.filter((cookie) => !cookie.secure);
    const missingHttpOnly = cookies.filter((cookie) => !cookie.httpOnly);
    const missingSameSite = cookies.filter((cookie) => !cookie.sameSite);

    if (missingSecure.length) {
      findings.push({
        id: "secure",
        title: "Cookies missing Secure",
        status: target.protocol === "https:" ? "fail" : "warning",
        severity: "medium",
        summary: `${briefList(missingSecure.map((cookie) => cookie.name))} did not include Secure.`,
        recommendation: "Set Secure on cookies that should only be sent over HTTPS.",
      });
    }

    if (missingHttpOnly.length) {
      findings.push({
        id: "httponly",
        title: "Cookies missing HttpOnly",
        status: "warning",
        severity: "low",
        summary: `${briefList(missingHttpOnly.map((cookie) => cookie.name))} did not include HttpOnly.`,
        recommendation: "Set HttpOnly on session and authentication cookies.",
      });
    }

    if (missingSameSite.length) {
      findings.push({
        id: "samesite",
        title: "Cookies missing SameSite",
        status: "warning",
        severity: "low",
        summary: `${briefList(missingSameSite.map((cookie) => cookie.name))} did not include SameSite.`,
        recommendation: "Use SameSite=Lax or Strict unless cross-site cookie delivery is required.",
      });
    }

    if (!findings.length) {
      findings.push({
        id: "cookie-flags",
        title: "Cookie flags present",
        status: "pass",
        severity: "info",
        summary: "Observed cookies include Secure, HttpOnly, and SameSite.",
      });
    }

    return createCheckResult({
      id: "cookies",
      name: "Cookie Security",
      findings,
      summary: findings.some((finding) => finding.status === "fail")
        ? "One or more cookies are missing important security flags."
        : "Observed cookies are reasonably hardened.",
      raw: { status: response.status, cookies },
    });
  } catch (error) {
    return errorCheck("cookies", "Cookie Security", error, { url: target.url });
  }
}

function parseCookie(raw: string): CookieFlags {
  const [nameValue = "", ...attributes] = raw.split(";").map((part) => part.trim());
  const lowered = attributes.map((attribute) => attribute.toLowerCase());
  const sameSite = attributes.find((attribute) => attribute.toLowerCase().startsWith("samesite="));

  return {
    name: nameValue.split("=")[0] || "unknown",
    secure: lowered.includes("secure"),
    httpOnly: lowered.includes("httponly"),
    sameSite: sameSite?.split("=")[1] ?? null,
  };
}

