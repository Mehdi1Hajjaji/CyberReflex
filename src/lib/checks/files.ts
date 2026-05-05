import type { CheckFinding, NormalizedTarget } from "./types";
import { createCheckResult, errorCheck, fetchWithTimeout, readBodySnippet } from "./utils";

const PROBES = [
  { path: "/.env", signature: /^[A-Z0-9_]{2,}=.+/m, severity: "high" as const },
  { path: "/.git/HEAD", signature: /ref:\s*refs\/heads\//i, severity: "high" as const },
  { path: "/.git/config", signature: /\[core\]/i, severity: "high" as const },
  { path: "/phpinfo.php", signature: /phpinfo\(\)|<title>phpinfo\(\)/i, severity: "high" as const },
  { path: "/server-status", signature: /apache server status|server version:/i, severity: "medium" as const },
  { path: "/wp-config.php.bak", signature: /DB_NAME|DB_USER|table_prefix|<\?php/i, severity: "high" as const },
] as const;

export async function checkFiles(target: NormalizedTarget) {
  try {
    const probes = await Promise.all(
      PROBES.map(async (probe) => {
        try {
          const url = new URL(probe.path, target.origin);
          const head = await fetchWithTimeout(url, { method: "HEAD", redirect: "manual" }, 2_500);

          if (![200, 206, 403, 405].includes(head.status)) {
            return { path: probe.path, status: head.status, exposed: false };
          }

          const response = await fetchWithTimeout(url, { method: "GET", redirect: "manual" }, 2_500);
          const snippet = await readBodySnippet(response, 4_096);
          const exposed = [200, 206].includes(response.status) && probe.signature.test(snippet);

          return { path: probe.path, status: response.status, exposed };
        } catch {
          return { path: probe.path, status: null, exposed: false };
        }
      }),
    );
    const exposed = probes.filter((probe) => probe.exposed);
    const findings: CheckFinding[] = exposed.length
      ? exposed.map((probe) => ({
          id: probe.path,
          title: `${probe.path} appears exposed`,
          status: "fail",
          severity: PROBES.find((item) => item.path === probe.path)?.severity ?? "high",
          summary: `${probe.path} returned content matching a sensitive-file signature.`,
          recommendation: "Block sensitive files and debug endpoints at the web server or edge.",
        }))
      : [
          {
            id: "no-sensitive-files",
            title: "No sensitive files confirmed",
            status: "pass",
            severity: "info",
            summary: "The small predefined probe list did not confirm public sensitive files.",
          },
        ];

    return createCheckResult({
      id: "files",
      name: "Exposed Files",
      findings,
      summary: exposed.length
        ? "Sensitive public files or debug endpoints were confirmed."
        : "No common sensitive files were confirmed.",
      raw: {
        origin: target.origin,
        probes,
      },
    });
  } catch (error) {
    return errorCheck("files", "Exposed Files", error, { origin: target.origin });
  }
}

