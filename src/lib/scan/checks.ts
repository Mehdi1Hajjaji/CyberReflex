import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import type { Finding, RedirectHop, ScanCategory } from "./types";
import type { CookieDescriptor } from "./utils";
import {
  briefList,
  createCategory,
  getRegisteredDomain,
  getSetCookieHeaders,
  parseSetCookie,
  readBodySnippet,
  requestTimeoutSignal,
  toMessage,
} from "./utils";

const USER_AGENT = "CyberReflex/0.1 (+https://cyberreflex.com)";

const CATEGORY_POINTS = {
  ssl: 18,
  headers: 18,
  dns: 12,
  ports: 10,
  technology: 10,
  cookies: 10,
  "exposed-files": 12,
  redirects: 10,
} as const;

const PORTS = [
  { port: 21, label: "FTP", severity: "high" },
  { port: 22, label: "SSH", severity: "medium" },
  { port: 25, label: "SMTP", severity: "medium" },
  { port: 80, label: "HTTP", severity: "info" },
  { port: 443, label: "HTTPS", severity: "info" },
  { port: 3306, label: "MySQL", severity: "high" },
  { port: 6379, label: "Redis", severity: "high" },
  { port: 8080, label: "Alt HTTP", severity: "low" },
] as const;

const EXPOSURE_PROBES = [
  {
    path: "/.env",
    title: "Public environment file",
    severity: "high",
    recommendation:
      "Block access to dotfiles at the web server and rotate any secrets that may have been exposed.",
    confirm: (snippet: string) => /^[A-Z0-9_]{2,}=.+/m.test(snippet),
  },
  {
    path: "/.git/HEAD",
    title: "Git metadata exposed",
    severity: "high",
    recommendation:
      "Deny public access to the `.git` directory and review whether repository contents can be reconstructed remotely.",
    confirm: (snippet: string) => /ref:\s*refs\/heads\//i.test(snippet),
  },
  {
    path: "/.git/config",
    title: "Git config exposed",
    severity: "high",
    recommendation:
      "Block `.git` access and purge any cached copies from intermediaries.",
    confirm: (snippet: string) => /\[core\]/i.test(snippet),
  },
  {
    path: "/phpinfo.php",
    title: "phpinfo endpoint exposed",
    severity: "high",
    recommendation:
      "Remove `phpinfo()` from public environments or protect it behind authentication and IP controls.",
    confirm: (snippet: string) => /phpinfo\(\)|<title>phpinfo\(\)/i.test(snippet),
  },
  {
    path: "/server-status",
    title: "Apache server-status exposed",
    severity: "medium",
    recommendation:
      "Disable `mod_status` on public interfaces or restrict it tightly with allowlists and authentication.",
    confirm: (snippet: string) =>
      /apache server status|server version:/i.test(snippet),
  },
  {
    path: "/wp-config.php.bak",
    title: "Backup config exposed",
    severity: "high",
    recommendation:
      "Remove backup copies from the web root and rotate any credentials stored inside them.",
    confirm: (snippet: string) =>
      /DB_NAME|DB_USER|table_prefix|<\?php/i.test(snippet),
  },
  {
    path: "/actuator/health",
    title: "Spring actuator health endpoint exposed",
    severity: "low",
    recommendation:
      "Disable unauthenticated actuator endpoints or keep them behind internal-only routing.",
    confirm: (snippet: string) =>
      /\"status\"\s*:\s*\"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)\"/i.test(snippet),
  },
  {
    path: "/backup.zip",
    title: "Backup archive exposed",
    severity: "high",
    recommendation:
      "Remove archives from public storage and review whether any sensitive contents were downloaded.",
    confirm: (snippet: string, contentType: string | null) =>
      (contentType ?? "").toLowerCase().includes("zip") ||
      snippet.startsWith("PK"),
  },
] as const;

export type RedirectTrace = {
  finalUrl: string;
  hops: RedirectHop[];
  tooManyHops?: boolean;
  error?: string;
};

export type PageSnapshot = {
  targetUrl: string;
  status: number | null;
  headers: Headers;
  cookies: CookieDescriptor[];
  htmlSnippet: string;
  contentType: string | null;
  error?: string;
};

type PortProbeResult = {
  port: number;
  label: string;
  state: "open" | "closed" | "timeout" | "error";
  error?: string;
};

type TlsProbeResult = {
  authorized: boolean;
  authorizationError?: string | null;
  protocol: string | null;
  validFrom: string | null;
  validTo: string | null;
  subject: string | null;
  issuer: string | null;
};

export async function traceRedirectChain(startUrl: string): Promise<RedirectTrace> {
  const hops: RedirectHop[] = [];
  const visited = new Set<string>();
  let currentUrl = startUrl;

  for (let index = 0; index < 6; index += 1) {
    if (visited.has(currentUrl)) {
      return {
        finalUrl: currentUrl,
        hops,
        error: "Redirect loop detected.",
      };
    }

    visited.add(currentUrl);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: requestTimeoutSignal(4_500),
        headers: {
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,*/*;q=0.8",
        },
      });

      const location = response.headers.get("location");
      hops.push({
        url: currentUrl,
        status: response.status,
        location,
      });

      if (response.body) {
        void response.body.cancel().catch(() => undefined);
      }

      if (response.status >= 300 && response.status < 400 && location) {
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }

      return {
        finalUrl: currentUrl,
        hops,
      };
    } catch (error) {
      hops.push({
        url: currentUrl,
        status: null,
      });

      return {
        finalUrl: currentUrl,
        hops,
        error: toMessage(error),
      };
    }
  }

  return {
    finalUrl: currentUrl,
    hops,
    tooManyHops: true,
    error: "Too many redirects.",
  };
}

export async function fetchPageSnapshot(targetUrl: string): Promise<PageSnapshot> {
  try {
    const response = await fetch(targetUrl, {
      method: "GET",
      redirect: "manual",
      signal: requestTimeoutSignal(6_000),
      headers: {
        "user-agent": USER_AGENT,
        accept: "text/html,application/xhtml+xml,*/*;q=0.8",
      },
    });

    const htmlSnippet = await readBodySnippet(response, 120_000);
    const cookies = getSetCookieHeaders(response.headers).map(parseSetCookie);

    return {
      targetUrl,
      status: response.status,
      headers: response.headers,
      cookies,
      htmlSnippet,
      contentType: response.headers.get("content-type"),
    };
  } catch (error) {
    return {
      targetUrl,
      status: null,
      headers: new Headers(),
      cookies: [],
      htmlSnippet: "",
      contentType: null,
      error: toMessage(error),
    };
  }
}

export async function lookupIpAddress(hostname: string) {
  try {
    const result = await dns.lookup(hostname);
    return result.address;
  } catch {
    return null;
  }
}

export async function analyzeSslTls(
  hostname: string,
  finalProtocol: string,
): Promise<ScanCategory> {
  const findings: Finding[] = [];

  try {
    const result = await probeTls(hostname);
    let score = 0;

    if (finalProtocol === "https:") {
      findings.push({
        id: "https-enabled",
        title: "HTTPS reachable",
        status: "pass",
        severity: "info",
        summary: "The target answered on port 443 with a TLS certificate.",
      });
      score += 2;
    } else {
      findings.push({
        id: "https-not-enforced",
        title: "HTTPS is not the final destination",
        status: "fail",
        severity: "high",
        summary:
          "The scan resolved to an HTTP endpoint instead of ending on HTTPS.",
        recommendation:
          "Force HTTPS as the canonical destination and redirect all HTTP traffic to it.",
      });
    }

    if (result.authorized) {
      findings.push({
        id: "cert-trust",
        title: "Certificate trust",
        status: "pass",
        severity: "info",
        summary: "The certificate chain was accepted by the runtime trust store.",
        details: result.issuer ? [`issuer: ${result.issuer}`] : undefined,
      });
      score += 8;
    } else {
      findings.push({
        id: "cert-trust",
        title: "Certificate trust issue",
        status: "fail",
        severity: "high",
        summary:
          result.authorizationError ??
          "The certificate chain could not be validated cleanly.",
        recommendation:
          "Install a valid certificate chain from a trusted issuer and verify intermediate certificates are served.",
      });
    }

    const expirationDetails = buildExpirationFinding(result.validTo);
    findings.push(expirationDetails.finding);
    score += expirationDetails.points;

    if (result.protocol && ["TLSv1.2", "TLSv1.3"].includes(result.protocol)) {
      findings.push({
        id: "tls-version",
        title: "TLS protocol version",
        status: "pass",
        severity: "info",
        summary: `The server negotiated ${result.protocol}, which is acceptable for modern clients.`,
      });
      score += 4;
    } else {
      findings.push({
        id: "tls-version",
        title: "Outdated TLS negotiation",
        status: "fail",
        severity: "medium",
        summary:
          result.protocol !== null
            ? `The probe negotiated ${result.protocol}, which is below current expectations.`
            : "The TLS protocol could not be determined cleanly.",
        recommendation:
          "Disable TLS 1.0/1.1 and keep the server limited to TLS 1.2 or TLS 1.3.",
      });
    }

    const summary =
      findings.some((finding) => finding.status === "fail")
        ? "TLS is present, but the certificate or HTTPS posture still needs attention."
        : "TLS posture looks healthy from the external probe.";

    return createCategory({
      id: "ssl",
      label: "SSL / TLS",
      score,
      maxScore: CATEGORY_POINTS.ssl,
      summary,
      findings,
      data: {
        protocol: result.protocol,
        authorized: result.authorized,
        authorizationError: result.authorizationError ?? null,
        validFrom: result.validFrom,
        validTo: result.validTo,
        subject: result.subject,
        issuer: result.issuer,
      },
    });
  } catch (error) {
    return createCategory({
      id: "ssl",
      label: "SSL / TLS",
      score: 0,
      maxScore: CATEGORY_POINTS.ssl,
      summary: "The TLS probe failed, which usually means HTTPS is unavailable or blocked.",
      findings: [
        {
          id: "tls-unreachable",
          title: "TLS probe failed",
          status: "fail",
          severity: "high",
          summary: toMessage(error),
          recommendation:
            "Verify the target serves HTTPS on port 443 and presents a valid certificate chain.",
        },
      ],
      data: {
        hostname,
      },
    });
  }
}

export function analyzeSecurityHeaders(
  snapshot: PageSnapshot,
  finalUrl: URL,
): ScanCategory {
  if (snapshot.error) {
    return createCategory({
      id: "headers",
      label: "HTTP Security Headers",
      score: 0,
      maxScore: CATEGORY_POINTS.headers,
      summary: "The page could not be fetched, so header analysis is incomplete.",
      findings: [
        {
          id: "fetch-error",
          title: "Unable to inspect response headers",
          status: "warning",
          severity: "medium",
          summary: snapshot.error,
          recommendation:
            "Confirm the target is reachable from a standard HTTP client and does not block server-side fetch requests.",
        },
      ],
    });
  }

  const findings: Finding[] = [];
  let score = 0;
  const hsts = snapshot.headers.get("strict-transport-security");

  if (finalUrl.protocol === "https:") {
    if (!hsts) {
      findings.push({
        id: "hsts",
        title: "Missing HSTS",
        status: "fail",
        severity: "medium",
        summary:
          "The site uses HTTPS but does not send a Strict-Transport-Security header.",
        recommendation:
          "Add `Strict-Transport-Security` with a long max-age and only after HTTPS is fully stable.",
      });
    } else {
      const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? "0");

      if (maxAge >= 15_552_000) {
        findings.push({
          id: "hsts",
          title: "HSTS configured",
          status: "pass",
          severity: "info",
          summary: "HSTS is present with a meaningful max-age.",
          details: [hsts],
        });
        score += 4;
      } else {
        findings.push({
          id: "hsts",
          title: "Weak HSTS max-age",
          status: "warning",
          severity: "low",
          summary: "HSTS exists, but the max-age is shorter than typically recommended.",
          recommendation:
            "Raise the HSTS max-age to at least six months once HTTPS is fully enforced.",
          details: [hsts],
        });
        score += 2;
      }
    }
  }

  const csp = snapshot.headers.get("content-security-policy");

  if (!csp) {
    findings.push({
      id: "csp",
      title: "Missing Content Security Policy",
      status: "fail",
      severity: "medium",
      summary:
        "No Content-Security-Policy header was observed on the initial response.",
      recommendation:
        "Add a restrictive CSP and avoid permissive directives like `unsafe-inline` where possible.",
    });
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    findings.push({
      id: "csp",
      title: "Permissive Content Security Policy",
      status: "warning",
      severity: "low",
      summary:
        "A CSP is present, but it still allows risky inline or eval-based execution.",
      recommendation:
        "Tighten the CSP to remove `unsafe-inline` and `unsafe-eval` where possible.",
      details: [csp],
    });
    score += 3;
  } else {
    findings.push({
      id: "csp",
      title: "Content Security Policy present",
      status: "pass",
      severity: "info",
      summary: "A CSP was observed on the initial response.",
      details: [csp],
    });
    score += 4;
  }

  const framed = snapshot.headers.get("x-frame-options");
  findings.push(
    framed
      ? {
          id: "x-frame-options",
          title: "Frame embedding control present",
          status: "pass",
          severity: "info",
          summary: "The response includes an X-Frame-Options header.",
          details: [framed],
        }
      : {
          id: "x-frame-options",
          title: "Missing frame embedding control",
          status: "warning",
          severity: "low",
          summary:
            "No X-Frame-Options header was observed on the initial response.",
          recommendation:
            "Send `X-Frame-Options: DENY` or `SAMEORIGIN`, or enforce equivalent `frame-ancestors` rules in CSP.",
        },
  );
  score += framed ? 3 : 0;

  const nosniff = snapshot.headers.get("x-content-type-options");
  findings.push(
    nosniff?.toLowerCase() === "nosniff"
      ? {
          id: "nosniff",
          title: "MIME sniffing disabled",
          status: "pass",
          severity: "info",
          summary:
            "The response includes `X-Content-Type-Options: nosniff`.",
        }
      : {
          id: "nosniff",
          title: "Missing nosniff protection",
          status: "warning",
          severity: "low",
          summary:
            "The response does not explicitly disable MIME sniffing.",
          recommendation: "Send `X-Content-Type-Options: nosniff`.",
        },
  );
  score += nosniff?.toLowerCase() === "nosniff" ? 2 : 0;

  const referrerPolicy = snapshot.headers.get("referrer-policy");
  findings.push(
    referrerPolicy
      ? {
          id: "referrer-policy",
          title: "Referrer policy present",
          status: "pass",
          severity: "info",
          summary: "A Referrer-Policy header was observed.",
          details: [referrerPolicy],
        }
      : {
          id: "referrer-policy",
          title: "Missing Referrer-Policy",
          status: "warning",
          severity: "low",
          summary:
            "Browsers were not given an explicit referrer handling policy.",
          recommendation:
            "Set a deliberate Referrer-Policy such as `strict-origin-when-cross-origin`.",
        },
  );
  score += referrerPolicy ? 2 : 0;

  const permissionsPolicy = snapshot.headers.get("permissions-policy");
  findings.push(
    permissionsPolicy
      ? {
          id: "permissions-policy",
          title: "Permissions policy present",
          status: "pass",
          severity: "info",
          summary: "A Permissions-Policy header was observed.",
          details: [permissionsPolicy],
        }
      : {
          id: "permissions-policy",
          title: "Missing Permissions-Policy",
          status: "warning",
          severity: "low",
          summary:
            "The response does not restrict optional browser capabilities.",
          recommendation:
            "Define a Permissions-Policy so unused browser features stay disabled by default.",
        },
  );
  score += permissionsPolicy ? 3 : 0;

  return createCategory({
    id: "headers",
    label: "HTTP Security Headers",
    score,
    maxScore: CATEGORY_POINTS.headers,
    summary:
      findings.some((finding) => finding.status !== "pass")
        ? "Several browser hardening headers are missing or weak on the initial response."
        : "Core browser hardening headers are present on the initial response.",
    findings,
    data: {
      headers: Object.fromEntries(snapshot.headers.entries()),
    },
  });
}

export async function analyzeDnsConfiguration(
  hostname: string,
): Promise<ScanCategory> {
  const findings: Finding[] = [];
  const domain = getRegisteredDomain(hostname);

  const [mxRecords, txtRecords, dmarcRecords, nsRecords] = await Promise.all([
    safeResolveMx(domain),
    safeResolveTxt(domain),
    safeResolveTxt(`_dmarc.${domain}`),
    safeResolveNs(domain),
  ]);

  let score = 0;

  if (nsRecords.length >= 2) {
    findings.push({
      id: "ns-redundancy",
      title: "Nameserver redundancy",
      status: "pass",
      severity: "info",
      summary: `The domain advertises ${nsRecords.length} nameservers.`,
      details: nsRecords,
    });
    score += 2;
  } else {
    findings.push({
      id: "ns-redundancy",
      title: "Limited nameserver redundancy",
      status: "warning",
      severity: "low",
      summary:
        "The domain advertises fewer than two nameservers, which reduces DNS resilience.",
      recommendation:
        "Use at least two authoritative nameservers unless your provider guarantees managed redundancy elsewhere.",
      details: nsRecords,
    });
  }

  const spfRecord = txtRecords.find((record) =>
    record.toLowerCase().startsWith("v=spf1"),
  );
  const dmarcRecord = dmarcRecords.find((record) =>
    record.toLowerCase().startsWith("v=dmarc1"),
  );

  if (mxRecords.length === 0) {
    findings.push({
      id: "mail-posture",
      title: "No MX records detected",
      status: "info",
      severity: "info",
      summary:
        "No MX records were detected, so SPF and DMARC are less critical for this hostname.",
    });
    score += 8;
  } else {
    if (!spfRecord) {
      findings.push({
        id: "spf",
        title: "Missing SPF",
        status: "warning",
        severity: "medium",
        summary:
          "Mail appears enabled through MX records, but no SPF record was detected.",
        recommendation:
          "Publish an SPF record that authorizes only the services allowed to send mail for this domain.",
      });
    } else if (/[+?]all/i.test(spfRecord)) {
      findings.push({
        id: "spf",
        title: "Permissive SPF policy",
        status: "warning",
        severity: "low",
        summary:
          "An SPF record exists, but it ends with `+all` or `?all`, which is too permissive.",
        recommendation:
          "Tighten the SPF policy so unauthorized senders are not effectively allowed.",
        details: [spfRecord],
      });
      score += 2;
    } else {
      findings.push({
        id: "spf",
        title: "SPF present",
        status: "pass",
        severity: "info",
        summary: "An SPF record was detected for the registered domain.",
        details: [spfRecord],
      });
      score += 4;
    }

    if (!dmarcRecord) {
      findings.push({
        id: "dmarc",
        title: "Missing DMARC",
        status: "warning",
        severity: "medium",
        summary:
          "Mail appears enabled through MX records, but no DMARC policy was detected.",
        recommendation:
          "Publish a DMARC record so spoofed mail can be monitored or rejected.",
      });
    } else if (/p=none/i.test(dmarcRecord)) {
      findings.push({
        id: "dmarc",
        title: "Monitoring-only DMARC policy",
        status: "warning",
        severity: "low",
        summary:
          "A DMARC record exists, but it is configured with `p=none`, which monitors without enforcement.",
        recommendation:
          "Move toward `quarantine` or `reject` once mail flows are validated.",
        details: [dmarcRecord],
      });
      score += 2;
    } else {
      findings.push({
        id: "dmarc",
        title: "DMARC present",
        status: "pass",
        severity: "info",
        summary: "A DMARC record was detected for the registered domain.",
        details: [dmarcRecord],
      });
      score += 4;
    }
  }

  return createCategory({
    id: "dns",
    label: "DNS Hygiene",
    score,
    maxScore: CATEGORY_POINTS.dns,
    summary:
      findings.some((finding) => finding.status === "warning")
        ? "DNS posture is serviceable, but mail authentication or redundancy can be tightened."
        : "DNS posture looks healthy for the checks covered here.",
    findings,
    data: {
      domain,
      mxRecords,
      nameservers: nsRecords,
      spfRecord: spfRecord ?? null,
      dmarcRecord: dmarcRecord ?? null,
    },
  });
}

export async function analyzeOpenPorts(hostname: string): Promise<ScanCategory> {
  const results = await Promise.all(
    PORTS.map(async ({ port, label }) => ({
      ...(await probePort(hostname, port)),
      label,
    })),
  );

  const sensitiveOpen = results
    .filter((result) => [21, 22, 25, 3306, 6379].includes(result.port))
    .filter((result) => result.state === "open");

  const altWebOpen = results.filter(
    (result) => result.port === 8080 && result.state === "open",
  );

  const standardWeb = results
    .filter((result) => [80, 443].includes(result.port))
    .filter((result) => result.state === "open");

  let score = CATEGORY_POINTS.ports;
  const findings: Finding[] = [];

  if (sensitiveOpen.length) {
    score -= Math.min(8, sensitiveOpen.length * 4);
    findings.push({
      id: "sensitive-ports",
      title: "Sensitive ports exposed",
      status: "fail",
      severity: "high",
      summary: `The probe reached ${briefList(
        sensitiveOpen.map((item) => `${item.label} (${item.port})`),
      )}.`,
      recommendation:
        "Close or firewall sensitive services that do not need to be publicly reachable.",
    });
  } else {
    findings.push({
      id: "sensitive-ports",
      title: "No sensitive ports confirmed",
      status: "pass",
      severity: "info",
      summary:
        "The probe did not confirm public exposure for SSH, FTP, SMTP, MySQL, or Redis.",
    });
  }

  if (altWebOpen.length) {
    score -= 2;
    findings.push({
      id: "alt-web-port",
      title: "Alternate web port exposed",
      status: "warning",
      severity: "low",
      summary: "Port 8080 answered publicly during the scan.",
      recommendation:
        "Confirm whether the alternate web interface is intended to be public, and hide it if not.",
    });
  }

  if (standardWeb.length) {
    findings.push({
      id: "standard-web",
      title: "Standard web ports reachable",
      status: "info",
      severity: "info",
      summary: `The probe reached ${briefList(
        standardWeb.map((item) => `${item.label} (${item.port})`),
      )}.`,
    });
  }

  return createCategory({
    id: "ports",
    label: "Basic Port Exposure",
    score,
    maxScore: CATEGORY_POINTS.ports,
    summary:
      sensitiveOpen.length || altWebOpen.length
        ? "Some public service exposure was confirmed."
        : "No unexpected public services were confirmed from the default probe set.",
    findings,
    data: {
      results,
      note: "This is a best-effort TCP reachability check from the scanning runtime.",
    },
  });
}

export function analyzeTechnologyDisclosure(
  snapshot: PageSnapshot,
): ScanCategory {
  if (snapshot.error) {
    return createCategory({
      id: "technology",
      label: "Technology Footprints",
      score: 0,
      maxScore: CATEGORY_POINTS.technology,
      summary: "Technology disclosure could not be assessed because the page fetch failed.",
      findings: [
        {
          id: "fingerprint-error",
          title: "Unable to fingerprint the target",
          status: "warning",
          severity: "low",
          summary: snapshot.error,
        },
      ],
    });
  }

  let score = CATEGORY_POINTS.technology;
  const findings: Finding[] = [];
  const detected = new Set<string>();
  const server = snapshot.headers.get("server");
  const poweredBy = snapshot.headers.get("x-powered-by");
  const html = snapshot.htmlSnippet.toLowerCase();

  if (poweredBy) {
    score -= 4;
    findings.push({
      id: "x-powered-by",
      title: "X-Powered-By exposed",
      status: "warning",
      severity: "low",
      summary:
        "The response exposes framework information through the X-Powered-By header.",
      recommendation:
        "Remove the X-Powered-By header in production to reduce unnecessary stack disclosure.",
      details: [poweredBy],
    });
  } else {
    findings.push({
      id: "x-powered-by",
      title: "X-Powered-By suppressed",
      status: "pass",
      severity: "info",
      summary: "No X-Powered-By header was observed.",
    });
  }

  if (server) {
    if (/\d/.test(server)) {
      score -= 2;
      findings.push({
        id: "server-header",
        title: "Server version disclosure",
        status: "warning",
        severity: "low",
        summary:
          "The Server header appears to expose product or version details.",
        recommendation:
          "Trim overly specific Server headers when possible to reduce passive fingerprinting.",
        details: [server],
      });
    } else {
      findings.push({
        id: "server-header",
        title: "Server header present",
        status: "info",
        severity: "info",
        summary: "A generic Server header was observed.",
        details: [server],
      });
    }
  }

  if (server?.toLowerCase().includes("cloudflare") || snapshot.headers.get("cf-ray")) {
    detected.add("Cloudflare");
  }
  if (snapshot.headers.get("x-vercel-id")) detected.add("Vercel");
  if (server?.toLowerCase().includes("nginx")) detected.add("nginx");
  if (server?.toLowerCase().includes("apache")) detected.add("Apache");
  if (html.includes("__next_data__") || html.includes("/_next/")) detected.add("Next.js");
  if (html.includes("wp-content") || html.includes("wp-includes")) detected.add("WordPress");
  if (html.includes("cdn.shopify.com") || html.includes("shopify")) detected.add("Shopify");
  if (html.includes("wixstatic.com") || html.includes("wix-code")) detected.add("Wix");
  if (html.includes("drupal-settings-json")) detected.add("Drupal");

  findings.push({
    id: "detected-stack",
    title: "Visible stack clues",
    status: "info",
    severity: "info",
    summary: detected.size
      ? `The initial response exposes clues for ${briefList([...detected])}.`
      : "The initial response exposed only limited framework clues.",
  });

  return createCategory({
    id: "technology",
    label: "Technology Footprints",
    score,
    maxScore: CATEGORY_POINTS.technology,
    summary:
      score < CATEGORY_POINTS.technology
        ? "The site leaks some implementation details that make passive fingerprinting easier."
        : "Only limited implementation details were exposed by the first response.",
    findings,
    data: {
      server,
      poweredBy,
      detectedTechnologies: [...detected],
    },
  });
}

export function analyzeCookies(
  snapshot: PageSnapshot,
  finalUrl: URL,
): ScanCategory {
  if (snapshot.error) {
    return createCategory({
      id: "cookies",
      label: "Cookie Security",
      score: 0,
      maxScore: CATEGORY_POINTS.cookies,
      summary: "Cookie analysis is incomplete because the initial page fetch failed.",
      findings: [
        {
          id: "cookie-fetch-error",
          title: "Unable to inspect cookies",
          status: "warning",
          severity: "medium",
          summary: snapshot.error,
        },
      ],
    });
  }

  if (!snapshot.cookies.length) {
    return createCategory({
      id: "cookies",
      label: "Cookie Security",
      score: CATEGORY_POINTS.cookies,
      maxScore: CATEGORY_POINTS.cookies,
      summary: "No Set-Cookie headers were observed on the initial response.",
      findings: [
        {
          id: "no-cookies",
          title: "No cookies observed",
          status: "pass",
          severity: "info",
          summary:
            "The initial response did not set any cookies, which reduces session-related attack surface on first load.",
        },
      ],
    });
  }

  let score = CATEGORY_POINTS.cookies;
  const findings: Finding[] = [];
  const insecure = snapshot.cookies.filter((cookie) => !cookie.secure);
  const missingHttpOnly = snapshot.cookies.filter((cookie) => !cookie.httpOnly);
  const missingSameSite = snapshot.cookies.filter((cookie) => !cookie.sameSite);
  const sameSiteNoneWithoutSecure = snapshot.cookies.filter(
    (cookie) => cookie.sameSite?.toLowerCase() === "none" && !cookie.secure,
  );

  if (insecure.length) {
    score -= 4;
    findings.push({
      id: "cookie-secure",
      title: "Cookies missing Secure",
      status: finalUrl.protocol === "https:" ? "fail" : "warning",
      severity: "medium",
      summary: `The response set cookies without the Secure attribute: ${briefList(
        insecure.map((cookie) => cookie.name),
      )}.`,
      recommendation:
        "Set the Secure attribute on cookies that should only travel over HTTPS.",
    });
  }

  if (missingHttpOnly.length) {
    score -= 3;
    findings.push({
      id: "cookie-httponly",
      title: "Cookies missing HttpOnly",
      status: "warning",
      severity: "low",
      summary: `Client-side scripts can read some cookies: ${briefList(
        missingHttpOnly.map((cookie) => cookie.name),
      )}.`,
      recommendation:
        "Mark session and authentication cookies as HttpOnly so JavaScript cannot read them.",
    });
  }

  if (missingSameSite.length) {
    score -= 2;
    findings.push({
      id: "cookie-samesite",
      title: "Cookies missing SameSite",
      status: "warning",
      severity: "low",
      summary: `Some cookies do not define a SameSite policy: ${briefList(
        missingSameSite.map((cookie) => cookie.name),
      )}.`,
      recommendation:
        "Set SameSite=Lax or SameSite=Strict for cookies that do not require cross-site requests.",
    });
  }

  if (sameSiteNoneWithoutSecure.length) {
    score -= 2;
    findings.push({
      id: "cookie-samesite-none",
      title: "SameSite=None without Secure",
      status: "fail",
      severity: "medium",
      summary:
        "Some cookies use SameSite=None without Secure, which modern browsers treat as unsafe.",
      recommendation:
        "Pair SameSite=None with Secure, or use a stricter SameSite mode if cross-site delivery is unnecessary.",
      details: sameSiteNoneWithoutSecure.map((cookie) => cookie.name),
    });
  }

  if (!findings.length) {
    findings.push({
      id: "cookie-baseline",
      title: "Cookie flags look reasonable",
      status: "pass",
      severity: "info",
      summary:
        "Observed cookies were sent with Secure, HttpOnly, and SameSite protections.",
    });
  }

  return createCategory({
    id: "cookies",
    label: "Cookie Security",
    score,
    maxScore: CATEGORY_POINTS.cookies,
    summary:
      findings.some((finding) => finding.status === "fail")
        ? "The initial response sets cookies with one or more unsafe defaults."
        : "Observed cookies are mostly aligned with safer browser defaults.",
    findings,
    data: {
      cookies: snapshot.cookies,
    },
  });
}

export async function analyzeExposedFiles(origin: string): Promise<ScanCategory> {
  const results = await Promise.all(
    EXPOSURE_PROBES.map((probe) => probeExposure(origin, probe)),
  );

  const confirmed = results.filter((result) => result.exposed);
  let score = CATEGORY_POINTS["exposed-files"];
  const findings: Finding[] = [];

  for (const result of confirmed) {
    score -= result.severity === "high" ? 4 : 2;
    findings.push({
      id: result.path,
      title: result.title,
      status: result.severity === "low" ? "warning" : "fail",
      severity: result.severity,
      summary: `${result.path} returned a response that matched the expected exposure signature.`,
      recommendation: result.recommendation,
    });
  }

  if (!confirmed.length) {
    findings.push({
      id: "no-exposures",
      title: "No sensitive paths confirmed",
      status: "pass",
      severity: "info",
      summary:
        "The default probe list did not confirm public access to common sensitive files or debug endpoints.",
    });
  }

  return createCategory({
    id: "exposed-files",
    label: "Exposed Files",
    score,
    maxScore: CATEGORY_POINTS["exposed-files"],
    summary:
      confirmed.length > 0
        ? "The probe confirmed publicly reachable sensitive files or debug endpoints."
        : "No common sensitive files were confirmed from the default probe set.",
    findings,
    data: {
      origin,
      probes: results.map((result) => ({
        path: result.path,
        status: result.status,
        exposed: result.exposed,
      })),
    },
  });
}

export function analyzeRedirects(trace: RedirectTrace): ScanCategory {
  const findings: Finding[] = [];
  let score = 0;
  const redirectCount = trace.hops.filter((hop) => hop.location).length;

  let finalProtocol = "unknown";

  try {
    finalProtocol = new URL(trace.finalUrl).protocol;
  } catch {
    finalProtocol = "unknown";
  }

  if (trace.error) {
    findings.push({
      id: "redirect-error",
      title: "Redirect trace issue",
      status: trace.tooManyHops ? "fail" : "warning",
      severity: trace.tooManyHops ? "medium" : "low",
      summary: trace.error,
      recommendation:
        trace.tooManyHops
          ? "Simplify redirect rules so the final destination is reached in fewer hops."
          : "Review redirect rules to ensure a clean path to the final origin.",
    });
  }

  if (finalProtocol === "https:") {
    findings.push({
      id: "redirect-https",
      title: "Redirect chain ends on HTTPS",
      status: "pass",
      severity: "info",
      summary: "The final destination uses HTTPS.",
    });
    score += 6;
  } else {
    findings.push({
      id: "redirect-https",
      title: "Redirect chain does not end on HTTPS",
      status: "fail",
      severity: "high",
      summary: "The final destination does not use HTTPS.",
      recommendation:
        "Force the canonical destination to HTTPS and redirect all HTTP traffic to it.",
    });
  }

  if (redirectCount <= 1) {
    findings.push({
      id: "redirect-depth",
      title: "Redirect depth is minimal",
      status: "pass",
      severity: "info",
      summary: "The target resolves with zero or one redirect hop.",
    });
    score += 4;
  } else if (redirectCount === 2) {
    findings.push({
      id: "redirect-depth",
      title: "Redirect depth is slightly high",
      status: "warning",
      severity: "low",
      summary: "Two redirect hops were required before the final destination.",
      recommendation:
        "Collapse unnecessary redirects so the canonical URL resolves faster.",
    });
    score += 2;
  } else {
    findings.push({
      id: "redirect-depth",
      title: "Redirect depth is high",
      status: "warning",
      severity: "medium",
      summary:
        "More than two redirect hops were needed before the final destination.",
      recommendation:
        "Simplify the chain to reduce latency and eliminate brittle routing rules.",
    });
  }

  return createCategory({
    id: "redirects",
    label: "Redirect Chain",
    score,
    maxScore: CATEGORY_POINTS.redirects,
    summary:
      redirectCount > 2 || finalProtocol !== "https:"
        ? "Redirect handling works, but the chain can be tightened or made safer."
        : "Redirect handling is short and resolves to HTTPS.",
    findings,
    data: {
      finalUrl: trace.finalUrl,
      redirectCount,
      hops: trace.hops,
    },
  });
}

async function probeTls(hostname: string): Promise<TlsProbeResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
    });

    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) {
        return;
      }

      settled = true;
      callback();
      socket.end();
      socket.destroy();
    };

    socket.setTimeout(5_000, () => {
      finish(() => reject(new Error("TLS probe timed out.")));
    });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();

      finish(() =>
        resolve({
          authorized: socket.authorized,
          authorizationError:
            typeof socket.authorizationError === "string"
              ? socket.authorizationError
              : null,
          protocol: socket.getProtocol() ?? null,
          validFrom: certificate.valid_from ?? null,
          validTo: certificate.valid_to ?? null,
          subject:
            typeof certificate.subject === "object"
              ? pickCertificateName(certificate.subject.CN)
              : null,
          issuer:
            typeof certificate.issuer === "object"
              ? pickCertificateName(certificate.issuer.CN)
              : null,
        }),
      );
    });

    socket.once("error", (error) => {
      finish(() => reject(error));
    });
  });
}

function buildExpirationFinding(validTo: string | null) {
  if (!validTo) {
    return {
      points: 0,
      finding: {
        id: "cert-expiration",
        title: "Certificate expiry unavailable",
        status: "warning" as const,
        severity: "low" as const,
        summary:
          "The certificate was reachable, but the expiry date could not be parsed cleanly.",
      },
    };
  }

  const expiry = new Date(validTo);
  const daysRemaining = Math.round(
    (expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
  );

  if (Number.isNaN(daysRemaining)) {
    return {
      points: 0,
      finding: {
        id: "cert-expiration",
        title: "Certificate expiry unavailable",
        status: "warning" as const,
        severity: "low" as const,
        summary:
          "The certificate was reachable, but the expiry date could not be parsed cleanly.",
      },
    };
  }

  if (daysRemaining < 14) {
    return {
      points: 0,
      finding: {
        id: "cert-expiration",
        title: "Certificate expires soon",
        status: "fail" as const,
        severity: "medium" as const,
        summary: `The certificate expires in ${daysRemaining} days.`,
        recommendation:
          "Renew the certificate before it expires and verify automated renewal is working.",
      },
    };
  }

  if (daysRemaining < 45) {
    return {
      points: 3,
      finding: {
        id: "cert-expiration",
        title: "Certificate renewal window is approaching",
        status: "warning" as const,
        severity: "low" as const,
        summary: `The certificate expires in ${daysRemaining} days.`,
        recommendation:
          "Check your renewal pipeline so the certificate rolls over cleanly before expiry.",
      },
    };
  }

  return {
    points: 6,
    finding: {
      id: "cert-expiration",
      title: "Certificate validity window looks healthy",
      status: "pass" as const,
      severity: "info" as const,
      summary: `The certificate has ${daysRemaining} days remaining before expiry.`,
    },
  };
}

async function safeResolveTxt(name: string) {
  try {
    const records = await dns.resolveTxt(name);
    return records.map((parts) => parts.join(""));
  } catch {
    return [] as string[];
  }
}

async function safeResolveMx(name: string) {
  try {
    return await dns.resolveMx(name);
  } catch {
    return [] as Awaited<ReturnType<typeof dns.resolveMx>>;
  }
}

async function safeResolveNs(name: string) {
  try {
    return await dns.resolveNs(name);
  } catch {
    return [] as string[];
  }
}

async function probePort(hostname: string, port: number): Promise<PortProbeResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (state: PortProbeResult["state"], error?: string) => {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      resolve({
        port,
        label: PORTS.find((entry) => entry.port === port)?.label ?? String(port),
        state,
        error,
      });
    };

    socket.setTimeout(900, () => finish("timeout"));
    socket.once("connect", () => finish("open"));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (
        ["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH", "ECONNRESET"].includes(
          error.code ?? "",
        )
      ) {
        finish("closed", error.message);
        return;
      }

      finish("error", error.message);
    });

    socket.connect(port, hostname);
  });
}

async function probeExposure(
  origin: string,
  probe: (typeof EXPOSURE_PROBES)[number],
) {
  try {
    const response = await fetch(new URL(probe.path, origin), {
      method: "GET",
      redirect: "manual",
      signal: requestTimeoutSignal(3_000),
      headers: {
        "user-agent": USER_AGENT,
        accept: "*/*",
      },
    });

    const snippet = await readBodySnippet(response, 4_096);
    const contentType = response.headers.get("content-type");
    const exposed =
      [200, 206].includes(response.status) && probe.confirm(snippet, contentType);

    return {
      path: probe.path,
      title: probe.title,
      severity: probe.severity,
      status: response.status,
      recommendation: probe.recommendation,
      exposed,
    };
  } catch {
    return {
      path: probe.path,
      title: probe.title,
      severity: probe.severity,
      status: null,
      recommendation: probe.recommendation,
      exposed: false,
    };
  }
}

function pickCertificateName(value: string | string[] | undefined) {
  if (typeof value === "string") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return null;
}
