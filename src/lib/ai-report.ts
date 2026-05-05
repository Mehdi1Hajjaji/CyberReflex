import OpenAI from "openai";
import type {
  CheckId,
  CheckStatus,
  FindingSeverity,
  NormalizedTarget,
  ScanCheckResult,
} from "@/lib/checks/types";

export type AiPriority = {
  title: string;
  reason: string;
  recommendation: string;
  severity: "low" | "medium" | "high" | "critical";
  relatedCheckId: CheckId | "overall";
};

export type AiRecommendation = {
  title: string;
  rationale: string;
  action: string;
  severity: "low" | "medium" | "high" | "critical";
  relatedCheckId: CheckId | "overall";
};

export type AiCheckAssessment = {
  id: CheckId;
  name: string;
  status: CheckStatus;
  explanation: string;
  fixGuidance: string;
};

export type AiReport = {
  executiveSummary: string;
  riskOverview: string;
  topPriorities: AiPriority[];
  recommendations: AiRecommendation[];
  checks: AiCheckAssessment[];
  aiEnhanced: boolean;
  generatedAt: string;
  priorities?: AiPriority[];
};

type AiReportInput = {
  target: NormalizedTarget;
  score: number;
  grade: string;
  checks: ScanCheckResult[];
};

const REPORT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "executiveSummary",
    "riskOverview",
    "topPriorities",
    "recommendations",
    "checks",
  ],
  properties: {
    executiveSummary: {
      type: "string",
      minLength: 80,
      maxLength: 900,
    },
    riskOverview: {
      type: "string",
      minLength: 40,
      maxLength: 900,
    },
    topPriorities: {
      type: "array",
      minItems: 0,
      maxItems: 3,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "reason", "recommendation", "severity", "relatedCheckId"],
        properties: {
          title: { type: "string", minLength: 3, maxLength: 140 },
          reason: { type: "string", minLength: 10, maxLength: 320 },
          recommendation: { type: "string", minLength: 10, maxLength: 320 },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          relatedCheckId: {
            type: "string",
            enum: [
              "ssl",
              "headers",
              "dns",
              "ports",
              "tech",
              "cookies",
              "files",
              "redirects",
              "overall",
            ],
          },
        },
      },
    },
    recommendations: {
      type: "array",
      minItems: 1,
      maxItems: 6,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "rationale", "action", "severity", "relatedCheckId"],
        properties: {
          title: { type: "string", minLength: 3, maxLength: 140 },
          rationale: { type: "string", minLength: 10, maxLength: 320 },
          action: { type: "string", minLength: 10, maxLength: 320 },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          relatedCheckId: {
            type: "string",
            enum: [
              "ssl",
              "headers",
              "dns",
              "ports",
              "tech",
              "cookies",
              "files",
              "redirects",
              "overall",
            ],
          },
        },
      },
    },
    checks: {
      type: "array",
      minItems: 8,
      maxItems: 8,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "name", "status", "explanation", "fixGuidance"],
        properties: {
          id: {
            type: "string",
            enum: [
              "ssl",
              "headers",
              "dns",
              "ports",
              "tech",
              "cookies",
              "files",
              "redirects",
            ],
          },
          name: { type: "string", minLength: 3, maxLength: 120 },
          status: {
            type: "string",
            enum: ["pass", "warning", "fail", "info", "error"],
          },
          explanation: { type: "string", minLength: 20, maxLength: 520 },
          fixGuidance: { type: "string", minLength: 20, maxLength: 520 },
        },
      },
    },
  },
} as const;

export async function generateAiReport(input: AiReportInput): Promise<AiReport> {
  const fallback = buildDeterministicAiReport(input);

  if (!process.env.OPENAI_API_KEY) {
    return fallback;
  }

  try {
    const client = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });
    const response = await client.responses.create({
      model: process.env.OPENAI_MODEL ?? "gpt-4o-mini",
      instructions:
        "You are a concise website security analyst. Produce a practical security assessment for a non-expert site owner. Do not invent findings. Base every priority, recommendation, and per-check explanation only on the supplied scan data. Keep the tone direct, calm, and action-oriented.",
      input: [
        {
          role: "user",
          content: [
            {
              type: "input_text",
              text: JSON.stringify(toModelPayload(input)),
            },
          ],
        },
      ],
      text: {
        format: {
          type: "json_schema",
          name: "cyberreflex_security_report",
          strict: true,
          schema: REPORT_SCHEMA,
        },
      },
      max_output_tokens: 1_500,
    });
    const parsed = parseAiReport(response.output_text, input.checks);

    if (!parsed) {
      return fallback;
    }

    return {
      ...parsed,
      priorities: parsed.topPriorities,
      aiEnhanced: true,
      generatedAt: new Date().toISOString(),
    };
  } catch {
    return fallback;
  }
}

export function buildDeterministicAiReport(input: AiReportInput): AiReport {
  const top = topFindings(input.checks);
  const topPriorities = top.map((item) => ({
    title: item.finding.title,
    reason: item.finding.summary,
    recommendation:
      item.finding.recommendation ??
      defaultRecommendation(item.check, item.finding.title),
    severity: normalizeSeverity(item.finding.severity),
    relatedCheckId: item.check.id,
  }));
  const recommendations = topPriorities.length
    ? topPriorities.map((priority) => ({
        title: priority.title,
        rationale: priority.reason,
        action: priority.recommendation,
        severity: priority.severity,
        relatedCheckId: priority.relatedCheckId,
      }))
    : [
        {
          title: "Maintain the current security baseline",
          rationale:
            "The lightweight scan did not confirm urgent issues across the enabled checks.",
          action:
            "Keep TLS renewal, DNS policy, browser headers, cookie flags, redirects, and exposure probes in your release checklist.",
          severity: "low" as const,
          relatedCheckId: "overall" as const,
        },
      ];
  const issueText = topPriorities.length
    ? `The most important fixes are ${topPriorities
        .map((priority) => priority.title)
        .join(", ")}.`
    : "No urgent issues were confirmed by this lightweight scan.";
  const checks = input.checks.map((check) => buildCheckAssessment(check));

  return {
    executiveSummary: `CyberReflex assessed ${input.target.hostname} and assigned grade ${input.grade} with a score of ${input.score}/100. ${issueText} The report below uses deterministic guidance because OpenAI is not configured or the AI request failed.`,
    riskOverview: buildRiskOverview(input.grade, input.score, input.checks),
    topPriorities,
    priorities: topPriorities,
    recommendations,
    checks,
    aiEnhanced: false,
    generatedAt: new Date().toISOString(),
  };
}

function toModelPayload(input: AiReportInput) {
  return {
    hostname: input.target.hostname,
    normalizedUrl: input.target.url,
    score: input.score,
    grade: input.grade,
    instructions: {
      executiveSummary:
        "Write 2-3 sentences. Mention overall posture and the most important risk areas.",
      riskOverview:
        "Explain the practical risk level in plain English without overstating certainty.",
      topPriorities:
        "Choose the top 3 urgent issues from fail/warning findings only.",
      recommendations:
        "Give concrete next steps that a site owner or developer can act on.",
      checks:
        "Return one explanation and one fix guidance item for every supplied check.",
    },
    checks: input.checks.map((check) => ({
      id: check.id,
      name: check.name,
      status: check.status,
      summary: check.summary,
      findings: check.findings.map((finding) => ({
        title: finding.title,
        status: finding.status,
        severity: finding.severity,
        summary: finding.summary,
        recommendation: finding.recommendation ?? null,
      })),
    })),
  };
}

function topFindings(checks: ScanCheckResult[]) {
  return checks
    .flatMap((check) =>
      check.findings
        .filter(
          (finding) =>
            finding.status === "fail" ||
            finding.status === "warning" ||
            finding.status === "error",
        )
        .map((finding) => ({ check, finding })),
    )
    .sort(
      (a, b) =>
        statusRank[b.finding.status] - statusRank[a.finding.status] ||
        severityRank[b.finding.severity] - severityRank[a.finding.severity],
    )
    .slice(0, 3);
}

const severityRank: Record<FindingSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const statusRank: Record<CheckStatus, number> = {
  fail: 4,
  error: 3,
  warning: 2,
  info: 1,
  pass: 0,
};

function buildRiskOverview(
  grade: string,
  score: number,
  checks: ScanCheckResult[],
) {
  const failed = checks.filter((check) => check.status === "fail").length;
  const warnings = checks.filter((check) => check.status === "warning").length;
  const errors = checks.filter((check) => check.status === "error").length;

  if (score >= 90) {
    return `The site has a strong baseline for this lightweight scan, with grade ${grade}. Remaining work is mostly hardening: reduce warnings, keep renewal processes healthy, and periodically re-run the scan after deployments.`;
  }

  if (score >= 75) {
    return `The site has a usable baseline, but ${failed} failed checks, ${warnings} warning checks, and ${errors} incomplete checks keep it from being a clean report. Focus first on controls that affect browser protection, public exposure, and trust signals.`;
  }

  return `The site needs attention before this should be treated as a mature security posture. The scan found enough failed or weak controls that visitors, administrators, or the domain reputation could face avoidable risk.`;
}

function buildCheckAssessment(check: ScanCheckResult): AiCheckAssessment {
  const issueFindings = check.findings.filter(
    (finding) =>
      finding.status === "fail" ||
      finding.status === "warning" ||
      finding.status === "error",
  );
  const firstIssue = issueFindings[0];

  if (!firstIssue) {
    return {
      id: check.id,
      name: check.name,
      status: check.status,
      explanation: `${check.name} did not show a confirmed weakness in this lightweight scan. ${check.summary}`,
      fixGuidance:
        "Keep this control in your normal release and monitoring checklist, and re-test after infrastructure or application changes.",
    };
  }

  return {
    id: check.id,
    name: check.name,
    status: check.status,
    explanation: `${check.name} needs attention because ${firstIssue.summary}`,
    fixGuidance:
      firstIssue.recommendation ?? defaultRecommendation(check, firstIssue.title),
  };
}

function defaultRecommendation(check: ScanCheckResult, findingTitle: string) {
  const defaults: Record<CheckId, string> = {
    ssl: "Verify HTTPS redirects, certificate trust, supported TLS versions, and renewal automation.",
    headers:
      "Add missing browser security headers carefully, then test them in report-only or staging where appropriate.",
    dns: "Review domain mail-authentication records and tighten SPF, DMARC, and DKIM where the domain sends email.",
    ports:
      "Restrict non-web services from the public internet and keep only intended HTTP/HTTPS endpoints exposed.",
    tech: "Reduce unnecessary stack disclosure in headers and page output where your platform allows it.",
    cookies:
      "Set Secure, HttpOnly, and SameSite flags on cookies according to how each cookie is used.",
    files:
      "Block sensitive files, debug endpoints, backups, and repository metadata at the edge or web server.",
    redirects:
      "Make HTTPS canonical and simplify redirect rules so visitors reach the final URL quickly.",
  };

  return `${defaults[check.id]} This recommendation is tied to: ${findingTitle}.`;
}

function normalizeSeverity(severity: FindingSeverity) {
  return severity === "info" ? "low" : severity;
}

function parseAiReport(
  value: string,
  sourceChecks: ScanCheckResult[],
): Omit<AiReport, "aiEnhanced" | "generatedAt" | "priorities"> | null {
  try {
    const parsed = JSON.parse(value) as Partial<AiReport>;

    if (
      typeof parsed.executiveSummary !== "string" ||
      typeof parsed.riskOverview !== "string" ||
      !Array.isArray(parsed.topPriorities) ||
      !Array.isArray(parsed.recommendations) ||
      !Array.isArray(parsed.checks)
    ) {
      return null;
    }

    const sourceIds = new Set(sourceChecks.map((check) => check.id));
    const checks = parsed.checks.filter(
      (check): check is AiCheckAssessment =>
        Boolean(check) &&
        sourceIds.has(check.id) &&
        typeof check.name === "string" &&
        isCheckStatus(check.status) &&
        typeof check.explanation === "string" &&
        typeof check.fixGuidance === "string",
    );

    if (checks.length !== sourceChecks.length) {
      return null;
    }

    return {
      executiveSummary: parsed.executiveSummary,
      riskOverview: parsed.riskOverview,
      topPriorities: parsed.topPriorities
        .filter(isAiPriority)
        .slice(0, 3),
      recommendations: parsed.recommendations
        .filter(isAiRecommendation)
        .slice(0, 6),
      checks,
    };
  } catch {
    return null;
  }
}

function isAiPriority(value: unknown): value is AiPriority {
  const priority = value as Partial<AiPriority>;

  return (
    typeof priority?.title === "string" &&
    typeof priority.reason === "string" &&
    typeof priority.recommendation === "string" &&
    isReportSeverity(priority.severity) &&
    isRelatedCheckId(priority.relatedCheckId)
  );
}

function isAiRecommendation(value: unknown): value is AiRecommendation {
  const recommendation = value as Partial<AiRecommendation>;

  return (
    typeof recommendation?.title === "string" &&
    typeof recommendation.rationale === "string" &&
    typeof recommendation.action === "string" &&
    isReportSeverity(recommendation.severity) &&
    isRelatedCheckId(recommendation.relatedCheckId)
  );
}

function isCheckStatus(value: unknown): value is CheckStatus {
  return (
    value === "pass" ||
    value === "warning" ||
    value === "fail" ||
    value === "info" ||
    value === "error"
  );
}

function isReportSeverity(value: unknown): value is AiPriority["severity"] {
  return (
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  );
}

function isRelatedCheckId(value: unknown): value is AiPriority["relatedCheckId"] {
  return (
    value === "overall" ||
    value === "ssl" ||
    value === "headers" ||
    value === "dns" ||
    value === "ports" ||
    value === "tech" ||
    value === "cookies" ||
    value === "files" ||
    value === "redirects"
  );
}
