import type { CheckFinding, NormalizedTarget } from "./types";
import { briefList, createCheckResult, errorCheck, probeTcpPort } from "./utils";

const PORTS = [
  { port: 21, label: "FTP", sensitive: true },
  { port: 22, label: "SSH", sensitive: false },
  { port: 25, label: "SMTP", sensitive: false },
  { port: 80, label: "HTTP", sensitive: false },
  { port: 443, label: "HTTPS", sensitive: false },
  { port: 3306, label: "MySQL", sensitive: true },
  { port: 6379, label: "Redis", sensitive: true },
  { port: 8080, label: "Alternative HTTP", sensitive: false },
] as const;

export async function checkPorts(target: NormalizedTarget) {
  try {
    const results = await Promise.all(
      PORTS.map(async (entry) => ({
        ...entry,
        state: await probeTcpPort(target.hostname, entry.port),
      })),
    );
    const open = results.filter((result) => result.state === "open");
    const sensitiveOpen = open.filter((result) => result.sensitive);
    const findings: CheckFinding[] = [];

    if (sensitiveOpen.length) {
      findings.push({
        id: "sensitive-ports",
        title: "Sensitive public ports open",
        status: "fail",
        severity: "high",
        summary: `${briefList(sensitiveOpen.map((item) => `${item.label} (${item.port})`))} accepted TCP connections.`,
        recommendation: "Restrict administrative and database services to private networks or VPN access.",
      });
    } else {
      findings.push({
        id: "sensitive-ports",
        title: "No sensitive ports confirmed",
        status: "pass",
        severity: "info",
        summary: "The small default probe set did not confirm public database or file-transfer ports.",
      });
    }

    if (open.length) {
      findings.push({
        id: "open-web-ports",
        title: "Reachable public services",
        status: "info",
        severity: "info",
        summary: `Open ports detected: ${briefList(open.map((item) => `${item.label} (${item.port})`))}.`,
      });
    }

    return createCheckResult({
      id: "ports",
      name: "Basic Port Exposure",
      findings,
      summary: sensitiveOpen.length
        ? "Unexpected public service exposure was detected."
        : "No high-risk port exposure was confirmed by the lightweight probe.",
      raw: {
        results,
        note: "Best-effort TCP reachability from the serverless/runtime location.",
      },
    });
  } catch (error) {
    return errorCheck("ports", "Basic Port Exposure", error, { hostname: target.hostname });
  }
}

