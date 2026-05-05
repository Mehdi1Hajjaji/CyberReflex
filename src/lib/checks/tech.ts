import type { CheckFinding, NormalizedTarget } from "./types";
import { briefList, createCheckResult, errorCheck, fetchWithTimeout, headersToObject, readBodySnippet } from "./utils";

export async function checkTech(target: NormalizedTarget) {
  try {
    const response = await fetchWithTimeout(target.url, { method: "GET", redirect: "manual" }, 5_000);
    const html = (await readBodySnippet(response, 90_000)).toLowerCase();
    const server = response.headers.get("server");
    const poweredBy = response.headers.get("x-powered-by");
    const detected = new Set<string>();
    const findings: CheckFinding[] = [];

    if (server?.toLowerCase().includes("cloudflare") || response.headers.get("cf-ray")) detected.add("Cloudflare");
    if (response.headers.get("x-vercel-id")) detected.add("Vercel");
    if (server?.toLowerCase().includes("nginx")) detected.add("nginx");
    if (server?.toLowerCase().includes("apache")) detected.add("Apache");
    if (html.includes("__next_data__") || html.includes("/_next/")) detected.add("Next.js");
    if (html.includes("wp-content") || html.includes("wp-includes")) detected.add("WordPress");
    if (html.includes("cdn.shopify.com") || html.includes("shopify")) detected.add("Shopify");
    if (html.includes("wixstatic.com") || html.includes("wix-code")) detected.add("Wix");

    findings.push(
      poweredBy
        ? {
            id: "x-powered-by",
            title: "X-Powered-By exposed",
            status: "warning",
            severity: "low",
            summary: "The response exposes framework details through X-Powered-By.",
            recommendation: "Remove X-Powered-By in production.",
            evidence: poweredBy,
          }
        : {
            id: "x-powered-by",
            title: "X-Powered-By not observed",
            status: "pass",
            severity: "info",
            summary: "No X-Powered-By header was observed.",
          },
    );

    if (server && /\d/.test(server)) {
      findings.push({
        id: "server-version",
        title: "Server version disclosure",
        status: "warning",
        severity: "low",
        summary: "The Server header appears to include version details.",
        recommendation: "Trim overly specific server banners when possible.",
        evidence: server,
      });
    }

    findings.push({
      id: "detected-technologies",
      title: "Technology clues",
      status: "info",
      severity: "info",
      summary: detected.size
        ? `Detected clues for ${briefList([...detected])}.`
        : "Only limited technology clues were detected.",
    });

    return createCheckResult({
      id: "tech",
      name: "Technology Detection",
      findings,
      summary: "Technology detection used response headers and initial HTML only.",
      raw: {
        status: response.status,
        server,
        poweredBy,
        detectedTechnologies: [...detected],
        headers: headersToObject(response.headers),
      },
    });
  } catch (error) {
    return errorCheck("tech", "Technology Detection", error, { url: target.url });
  }
}

