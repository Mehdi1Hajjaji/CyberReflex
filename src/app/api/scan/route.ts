import { NextResponse } from "next/server";
import { z } from "zod";
import type { Prisma } from "@/generated/prisma/client";
import { auth } from "@/auth";
import { buildDeterministicAiReport, generateAiReport } from "@/lib/ai-report";
import { checkCookies } from "@/lib/checks/cookies";
import { checkDns } from "@/lib/checks/dns";
import { checkFiles } from "@/lib/checks/files";
import { checkHeaders } from "@/lib/checks/headers";
import { checkPorts } from "@/lib/checks/ports";
import { checkRedirects } from "@/lib/checks/redirects";
import { checkSsl } from "@/lib/checks/ssl";
import { checkTech } from "@/lib/checks/tech";
import type { CheckId, NormalizedTarget, ScanCheckResult } from "@/lib/checks/types";
import {
  assertPubliclyResolvable,
  errorCheck,
  normalizeScanUrl,
  toMessage,
} from "@/lib/checks/utils";
import { DatabaseEnvError } from "@/lib/database-env";
import { getPrisma } from "@/lib/prisma";
import { scoreScan } from "@/lib/scoring";

export const runtime = "nodejs";
export const maxDuration = 45;

const requestSchema = z.object({
  url: z.string().trim().min(1).max(2048),
});

const CHECKS = [
  { id: "ssl", run: checkSsl },
  { id: "headers", run: checkHeaders },
  { id: "dns", run: checkDns },
  { id: "ports", run: checkPorts },
  { id: "tech", run: checkTech },
  { id: "cookies", run: checkCookies },
  { id: "files", run: checkFiles },
  { id: "redirects", run: checkRedirects },
] satisfies Array<{
  id: CheckId;
  run: (target: NormalizedTarget) => Promise<ScanCheckResult>;
}>;

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const parsed = requestSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Enter a valid URL or hostname to scan." },
        { status: 400 },
      );
    }

    const target = normalizeScanUrl(parsed.data.url);
    const session = await auth();
    await withTimeout(
      assertPubliclyResolvable(target.hostname),
      5_000,
      "Hostname resolution timed out.",
    );

    const settled = await Promise.allSettled(
      CHECKS.map((check) =>
        withTimeout(
          check.run(target),
          12_000,
          `${checkName(check.id)} check timed out.`,
        ).catch((error) =>
          errorCheck(check.id, checkName(check.id), error, {
            normalizedUrl: target.url,
          }),
        ),
      ),
    );
    const checks = settled.map((result, index) => {
      if (result.status === "fulfilled") {
        return result.value;
      }

      const fallback = CHECKS[index];
      return errorCheck(
        fallback.id,
        checkName(fallback.id),
        result.reason,
        { normalizedUrl: target.url },
      );
    });
    const { score, grade } = scoreScan(checks);
    const generatedAt = new Date().toISOString();
    const aiReport = await withTimeout(
      generateAiReport({ target, score, grade, checks }),
      6_000,
      "AI report generation timed out.",
    ).catch(() => buildDeterministicAiReport({ target, score, grade, checks }));
    const scanResults = buildScanResults(
      target,
      checks,
      score,
      grade,
      generatedAt,
      aiReport,
    );
    let prisma;

    try {
      prisma = getPrisma();
    } catch (error) {
      return databaseConfigurationResponse(error);
    }

    if (!prisma) {
      return NextResponse.json(
        { error: "DATABASE_URL is required before scans can be saved." },
        { status: 503 },
      );
    }

    const requestIp =
      request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
      request.headers.get("x-real-ip");
    let stored;
    let persistenceFailure: ReturnType<typeof classifyPersistenceError> | null = null;
    const persistableResults = toPrismaJson(scanResults);

    try {
      stored = await withTimeout(
        prisma.scan.create({
          data: {
            url: target.url,
            score,
            grade,
            results: persistableResults,
            aiSummary: aiReport.executiveSummary,
            ipAddress: requestIp ?? undefined,
            userId: session?.user?.id,
          },
          select: {
            id: true,
            createdAt: true,
          },
        }),
        12_000,
        "Database operation timed out.",
      );
    } catch (error) {
      persistenceFailure = classifyPersistenceError(error);
      console.error("Scan persistence failed:", persistenceFailure);
      stored = null;
    }

    if (!stored) {
      return NextResponse.json(
        {
          error: "The scan completed, but it could not be saved.",
          failureType: persistenceFailure?.type ?? "unknown",
          diagnosticUrl: "/api/diagnostics/database",
        },
        { status: 503 },
      );
    }

    return NextResponse.json({
      ...buildLegacyResponse(
        target,
        checks,
        score,
        grade,
        generatedAt,
        stored.id,
        aiReport,
      ),
      id: stored.id,
      reportUrl: `/scan/${stored.id}`,
      normalizedUrl: target.url,
      score,
      grade,
      results: scanResults,
    });
  } catch (error) {
    const message = toMessage(error);
    const status =
      message.includes("valid URL") ||
      message.includes("supported") ||
      message.includes("private") ||
      message.includes("resolved")
        ? 400
        : 500;

    return NextResponse.json({ error: message }, { status });
  }
}

function buildScanResults(
  target: NormalizedTarget,
  checks: ScanCheckResult[],
  score: number,
  grade: string,
  generatedAt: string,
  aiReport: Awaited<ReturnType<typeof generateAiReport>>,
) {
  return {
    target: {
      input: target.input,
      normalizedUrl: target.url,
      origin: target.origin,
      hostname: target.hostname,
      registeredDomain: target.registeredDomain,
    },
    generatedAt,
    score,
    grade,
    aiReport,
    checks,
    checksById: Object.fromEntries(checks.map((check) => [check.id, check])),
  };
}

function buildLegacyResponse(
  target: NormalizedTarget,
  checks: ScanCheckResult[],
  score: number,
  grade: string,
  generatedAt: string,
  id: string,
  aiReport: Awaited<ReturnType<typeof generateAiReport>>,
) {
  const categories = checks.map((check) => ({
    id: legacyCategoryId(check.id),
    label: check.name,
    score: scoreForStatus(check.status),
    maxScore: 10,
    status: check.status === "error" ? "warning" : check.status,
    summary: check.summary,
    findings: check.findings.map((finding) => ({
      id: finding.id,
      title: finding.title,
      status: finding.status === "error" ? "warning" : finding.status,
      severity: finding.severity === "critical" ? "high" : finding.severity,
      summary: finding.summary,
      recommendation: finding.recommendation,
      details:
        finding.evidence === undefined
          ? undefined
          : [typeof finding.evidence === "string" ? finding.evidence : JSON.stringify(finding.evidence)],
    })),
    data: check.raw,
  }));
  const redirectRaw = checks.find((check) => check.id === "redirects")?.raw;
  const redirectChain = Array.isArray(redirectRaw?.hops) ? redirectRaw.hops : [];

  return {
    scanId: id,
    targetUrl: target.input,
    normalizedUrl: target.url,
    hostname: target.hostname,
    generatedAt,
    summary: `Grade ${grade} (${score}/100). ${buildSummary(checks)}`,
    aiSummary: aiReport.executiveSummary,
    aiEnhanced: aiReport.aiEnhanced,
    aiReport,
    stored: true,
    categories,
    redirectChain,
  };
}

function buildSummary(checks: ScanCheckResult[]) {
  const issues = checks
    .flatMap((check) =>
      check.findings
        .filter((finding) => finding.status === "fail" || finding.status === "warning")
        .map((finding) => finding.title),
    )
    .slice(0, 3);

  if (!issues.length) {
    return "No major issues were confirmed by the lightweight scan.";
  }

  return `Top findings: ${issues.join(", ")}.`;
}

function checkName(id: CheckId) {
  const names: Record<CheckId, string> = {
    ssl: "SSL/TLS Certificate",
    headers: "HTTP Security Headers",
    dns: "DNS Records",
    ports: "Basic Port Exposure",
    tech: "Technology Detection",
    cookies: "Cookie Security",
    files: "Exposed Files",
    redirects: "Redirect Chain",
  };

  return names[id];
}

function legacyCategoryId(id: CheckId) {
  const ids: Record<CheckId, string> = {
    ssl: "ssl",
    headers: "headers",
    dns: "dns",
    ports: "ports",
    tech: "technology",
    cookies: "cookies",
    files: "exposed-files",
    redirects: "redirects",
  };

  return ids[id];
}

function scoreForStatus(status: ScanCheckResult["status"]) {
  if (status === "pass") return 10;
  if (status === "info") return 9;
  if (status === "warning") return 6;
  if (status === "error") return 5;
  return 2;
}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message = "Operation timed out.",
) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error(message)), timeoutMs);
    }),
  ]);
}

function databaseConfigurationResponse(error: unknown) {
  if (error instanceof DatabaseEnvError) {
    return NextResponse.json(
      {
        error: error.message,
        issues: error.issues,
        diagnosticUrl: "/api/diagnostics/database",
      },
      { status: 503 },
    );
  }

  return NextResponse.json(
    {
      error: "Database configuration is invalid.",
      diagnosticUrl: "/api/diagnostics/database",
    },
    { status: 503 },
  );
}

function toPrismaJson(value: unknown): Prisma.InputJsonValue {
  const converted = toJsonCompatible(value);

  if (converted === null) {
    throw new Error("Scan results must be a JSON object.");
  }

  return converted;
}

function toJsonCompatible(value: unknown): Prisma.InputJsonValue | null {
  if (value === null) {
    return null;
  }

  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  if (Array.isArray(value)) {
    return value.map((item) =>
      item === undefined ? null : toJsonCompatible(item),
    );
  }

  if (typeof value === "object") {
    if (value instanceof Date) {
      return value.toISOString();
    }

    const output: Record<string, Prisma.InputJsonValue | null> = {};

    for (const [key, item] of Object.entries(value)) {
      if (item !== undefined) {
        output[key] = toJsonCompatible(item);
      }
    }

    return output as Prisma.InputJsonObject;
  }

  return null;
}

function classifyPersistenceError(error: unknown) {
  const message = toMessage(error);
  const lowered = message.toLowerCase();

  if (lowered.includes("timed out")) {
    return {
      type: "timeout",
      message,
    };
  }

  if (
    lowered.includes("tenant") ||
    lowered.includes("password authentication failed") ||
    lowered.includes("authentication")
  ) {
    return {
      type: "postgres_rejection",
      message,
    };
  }

  if (
    lowered.includes("invalid") ||
    lowered.includes("json") ||
    lowered.includes("data")
  ) {
    return {
      type: "query_or_data_error",
      message,
    };
  }

  return {
    type: "prisma_create_error",
    message,
  };
}
