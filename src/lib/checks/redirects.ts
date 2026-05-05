import type { CheckFinding, NormalizedTarget, RedirectHop } from "./types";
import { createCheckResult, errorCheck, fetchWithTimeout } from "./utils";

export async function checkRedirects(target: NormalizedTarget) {
  try {
    const trace = await traceRedirects(target.url);
    const findings: CheckFinding[] = [];
    const redirectCount = trace.hops.filter((hop) => hop.location).length;
    const finalUrl = new URL(trace.finalUrl);

    findings.push(
      finalUrl.protocol === "https:"
        ? {
            id: "ends-https",
            title: "Redirect chain ends on HTTPS",
            status: "pass",
            severity: "info",
            summary: "The final destination uses HTTPS.",
          }
        : {
            id: "ends-https",
            title: "Redirect chain does not end on HTTPS",
            status: "fail",
            severity: "high",
            summary: "The final destination uses HTTP.",
            recommendation: "Make HTTPS the canonical destination.",
          },
    );

    findings.push(
      redirectCount <= 1
        ? {
            id: "redirect-depth",
            title: "Redirect depth is minimal",
            status: "pass",
            severity: "info",
            summary: "The target reached its final response in zero or one redirect.",
          }
        : {
            id: "redirect-depth",
            title: "Redirect chain is longer than ideal",
            status: redirectCount > 3 ? "fail" : "warning",
            severity: redirectCount > 3 ? "medium" : "low",
            summary: `${redirectCount} redirects were observed before the final response.`,
            recommendation: "Collapse unnecessary redirect hops.",
          },
    );

    if (trace.error) {
      findings.push({
        id: "redirect-error",
        title: "Redirect trace issue",
        status: "warning",
        severity: "low",
        summary: trace.error,
      });
    }

    return createCheckResult({
      id: "redirects",
      name: "Redirect Chain",
      findings,
      summary: redirectCount > 1 || finalUrl.protocol !== "https:"
        ? "Redirect handling works, but the chain can be safer or shorter."
        : "Redirect handling is short and resolves to HTTPS.",
      raw: {
        finalUrl: trace.finalUrl,
        hops: trace.hops.map((hop) => ({
          url: hop.url,
          status: hop.status,
          location: hop.location,
        })),
        error: trace.error ?? null,
      },
    });
  } catch (error) {
    return errorCheck("redirects", "Redirect Chain", error, { url: target.url });
  }
}

async function traceRedirects(startUrl: string) {
  const hops: RedirectHop[] = [];
  const visited = new Set<string>();
  let currentUrl = startUrl;

  for (let index = 0; index < 6; index += 1) {
    if (visited.has(currentUrl)) {
      return { finalUrl: currentUrl, hops, error: "Redirect loop detected." };
    }

    visited.add(currentUrl);
    const response = await fetchWithTimeout(currentUrl, { method: "GET", redirect: "manual" }, 4_000);
    const location = response.headers.get("location");
    hops.push({ url: currentUrl, status: response.status, location });

    if (response.body) {
      await response.body.cancel().catch(() => undefined);
    }

    if (response.status >= 300 && response.status < 400 && location) {
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    return { finalUrl: currentUrl, hops };
  }

  return { finalUrl: currentUrl, hops, error: "Too many redirects." };
}
