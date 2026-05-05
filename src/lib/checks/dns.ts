import dns from "node:dns/promises";
import type { CheckFinding, NormalizedTarget } from "./types";
import { createCheckResult, errorCheck } from "./utils";

export async function checkDns(target: NormalizedTarget) {
  try {
    const domain = target.registeredDomain;
    const [txtRecords, dmarcRecords, mxRecords] = await Promise.all([
      resolveTxt(domain),
      resolveTxt(`_dmarc.${domain}`),
      dns.resolveMx(domain).catch(() => []),
    ]);
    const findings: CheckFinding[] = [];
    const spf = txtRecords.find((record) => record.toLowerCase().startsWith("v=spf1"));
    const dmarc = dmarcRecords.find((record) => record.toLowerCase().startsWith("v=dmarc1"));
    const dkimSelectors = ["default", "selector1", "selector2", "google", "k1"];
    const dkimRecords = await Promise.all(
      dkimSelectors.map(async (selector) => ({
        selector,
        records: await resolveTxt(`${selector}._domainkey.${domain}`),
      })),
    );
    const dkim = dkimRecords.filter((record) =>
      record.records.some((value) => /v=dkim1/i.test(value)),
    );

    if (!mxRecords.length) {
      findings.push({
        id: "mx",
        title: "No MX records detected",
        status: "info",
        severity: "info",
        summary: "No MX records were found, so email authentication checks may be less relevant.",
      });
    }

    findings.push(
      spf
        ? {
            id: "spf",
            title: "SPF record present",
            status: spf.includes("-all") || spf.includes("~all") ? "pass" : "warning",
            severity: "low",
            summary: "An SPF TXT record was found.",
            evidence: spf,
          }
        : {
            id: "spf",
            title: "SPF record missing",
            status: mxRecords.length ? "fail" : "warning",
            severity: "medium",
            summary: "No SPF record was found on the registered domain.",
            recommendation: "Publish an SPF record for domains that send mail.",
          },
    );

    findings.push(
      dmarc
        ? {
            id: "dmarc",
            title: "DMARC record present",
            status: /p=(quarantine|reject)/i.test(dmarc) ? "pass" : "warning",
            severity: "medium",
            summary: "A DMARC policy was found.",
            evidence: dmarc,
          }
        : {
            id: "dmarc",
            title: "DMARC record missing",
            status: mxRecords.length ? "fail" : "warning",
            severity: "medium",
            summary: "No DMARC policy was found.",
            recommendation: "Publish a DMARC record and move toward quarantine or reject.",
          },
    );

    findings.push(
      dkim.length
        ? {
            id: "dkim",
            title: "DKIM selector detected",
            status: "pass",
            severity: "info",
            summary: `Detected DKIM records for ${dkim.map((record) => record.selector).join(", ")}.`,
          }
        : {
            id: "dkim",
            title: "DKIM not confirmed",
            status: "info",
            severity: "info",
            summary: "No DKIM record was found for the small default selector list.",
          },
    );

    return createCheckResult({
      id: "dns",
      name: "DNS Records",
      findings,
      summary: "DNS email authentication records were inspected with common selectors.",
      raw: {
        domain,
        mxRecords: mxRecords.map((record) => ({
          exchange: record.exchange,
          priority: record.priority,
        })),
        txtRecords,
        dmarcRecords,
        dkimSelectorsChecked: dkimSelectors,
        dkimSelectorsFound: dkim.map((record) => record.selector),
      },
    });
  } catch (error) {
    return errorCheck("dns", "DNS Records", error, { hostname: target.hostname });
  }
}

async function resolveTxt(name: string) {
  try {
    const records = await dns.resolveTxt(name);
    return records.map((parts) => parts.join(""));
  } catch {
    return [] as string[];
  }
}
