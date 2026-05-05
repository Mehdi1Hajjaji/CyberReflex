import Link from "next/link";
import {
  ArrowLeft,
  Bot,
  CalendarClock,
  ClipboardCheck,
  Flame,
  Globe2,
  ShieldCheck,
} from "lucide-react";
import type { ComponentType } from "react";
import type { AiReport } from "@/lib/ai-report";
import type { ScanCheckResult } from "@/lib/checks/types";
import { CheckCard } from "@/components/check-card";
import { GradeBadge } from "@/components/grade-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

export type StoredScanResults = {
  target?: {
    input?: string;
    normalizedUrl?: string;
    origin?: string;
    hostname?: string;
    registeredDomain?: string;
  };
  generatedAt?: string;
  score?: number;
  grade?: string;
  aiReport?: AiReport;
  checks?: ScanCheckResult[];
};

export type SavedScanPayload = {
  id: string;
  normalizedUrl: string;
  score: number | null;
  grade: string | null;
  aiSummary?: string | null;
  createdAt: string;
  results: StoredScanResults | null;
};

type ScanResultsProps = {
  scan: SavedScanPayload;
};

export function ScanResults({ scan }: ScanResultsProps) {
  const results = scan.results;
  const checks = results?.checks ?? [];
  const score = scan.score ?? results?.score ?? null;
  const grade = scan.grade ?? results?.grade ?? null;
  const aiReport = results?.aiReport;
  const topPriorities = aiReport?.topPriorities ?? aiReport?.priorities ?? [];
  const assessments = new Map(
    (aiReport?.checks ?? []).map((assessment) => [assessment.id, assessment]),
  );
  const hostname = results?.target?.hostname ?? safeHostname(scan.normalizedUrl);
  const generatedAt = results?.generatedAt ?? scan.createdAt;

  return (
    <main className="relative z-10 min-h-screen px-5 py-8 md:px-8 lg:px-10">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
        <Link
          href="/"
          className="inline-flex w-fit items-center gap-2 rounded-full border border-line bg-white/5 px-4 py-2 text-sm text-muted hover:border-accent/40 hover:text-white"
        >
          <ArrowLeft className="h-4 w-4" />
          New scan
        </Link>

        <section className="glass-panel terminal-edge scan-glow rounded-[32px] p-5 md:p-7">
          <div className="grid gap-6 lg:grid-cols-[auto_1fr] lg:items-center">
            <GradeBadge grade={grade} score={score} className="lg:h-full" />

            <div className="space-y-5">
              <div>
                <div className="mb-3 flex flex-wrap gap-2">
                  <Badge variant="outline" className="font-mono uppercase">
                    Saved report
                  </Badge>
                  <Badge variant="success" className="font-mono uppercase">
                    {checks.length} checks
                  </Badge>
                </div>
                <h1 className="break-words text-3xl font-semibold leading-tight text-white md:text-5xl">
                  {hostname}
                </h1>
                <p className="mt-3 max-w-4xl break-words text-sm leading-7 text-muted">
                  {buildSummary(checks, grade, score)}
                </p>
              </div>

              <div className="grid gap-3 md:grid-cols-3">
                <MetaCard
                  icon={Globe2}
                  label="Target"
                  value={scan.normalizedUrl}
                />
                <MetaCard
                  icon={ShieldCheck}
                  label="Scan ID"
                  value={scan.id}
                />
                <MetaCard
                  icon={CalendarClock}
                  label="Generated"
                  value={formatDate(generatedAt)}
                />
              </div>
            </div>
          </div>
        </section>

        {aiReport || scan.aiSummary ? (
          <Card className="border-accent/18 bg-slate-950/55">
            <CardContent className="p-5 md:p-6">
              <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
                <div>
                  <div className="mb-3 flex flex-wrap items-center gap-2 text-sm font-medium text-white">
                    <Bot className="h-4 w-4 text-accent" />
                    Executive summary
                    <Badge
                      variant={aiReport?.aiEnhanced ? "success" : "outline"}
                      className="font-mono uppercase"
                    >
                      {aiReport?.aiEnhanced ? "AI enhanced" : "Fallback"}
                    </Badge>
                  </div>
                  <p className="text-sm leading-7 text-muted">
                    {aiReport?.executiveSummary ?? scan.aiSummary}
                  </p>

                  {aiReport?.riskOverview ? (
                    <div className="mt-5 rounded-2xl border border-line/80 bg-white/4 p-4">
                      <div className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.24em] text-accent/80">
                        <ShieldCheck className="h-4 w-4" />
                        Risk overview
                      </div>
                      <p className="text-sm leading-7 text-muted">
                        {aiReport.riskOverview}
                      </p>
                    </div>
                  ) : null}
                </div>

                <div className="rounded-2xl border border-accent/20 bg-accent/6 p-4">
                  <div className="mb-3 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.24em] text-accent/80">
                    <Flame className="h-4 w-4" />
                    Fix first
                  </div>
                  {topPriorities.length ? (
                    <div className="space-y-3">
                      {topPriorities.map((priority, index) => (
                        <div
                          key={`${priority.title}-${index}`}
                          className="rounded-2xl border border-line/70 bg-slate-950/45 p-3"
                        >
                          <div className="mb-1 flex flex-wrap items-center gap-2">
                            <div className="text-sm font-medium text-white">
                              {index + 1}. {priority.title}
                            </div>
                            <Badge variant="outline" className="font-mono uppercase">
                              {priority.severity}
                            </Badge>
                          </div>
                          <p className="text-sm leading-6 text-muted">
                            {priority.reason}
                          </p>
                          <p className="mt-2 text-sm leading-6 text-accent/90">
                            {priority.recommendation}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm leading-7 text-muted">
                      No urgent priorities were confirmed by this scan. Keep monitoring certificate renewal, headers, DNS, cookies, and exposure checks after each deployment.
                    </p>
                  )}
                </div>
              </div>

              {aiReport?.recommendations.length ? (
                <div className="mt-6">
                  <div className="mb-3 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.24em] text-accent/80">
                    <ClipboardCheck className="h-4 w-4" />
                    Recommended next steps
                  </div>
                  <div className="grid gap-3 lg:grid-cols-3">
                    {aiReport.recommendations.map((recommendation, index) => (
                    <div
                      key={`${recommendation.title}-${index}`}
                      className="rounded-2xl border border-line/80 bg-white/4 p-4"
                    >
                      <div className="mb-2 flex flex-wrap items-center gap-2">
                        <div className="text-sm font-medium text-white">
                          {recommendation.title}
                        </div>
                        <Badge variant="outline" className="font-mono uppercase">
                          {recommendation.severity}
                        </Badge>
                      </div>
                      <p className="text-sm leading-6 text-muted">
                        {recommendation.rationale}
                      </p>
                      <p className="mt-2 text-sm leading-6 text-accent/90">
                        {recommendation.action}
                      </p>
                    </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </CardContent>
          </Card>
        ) : null}

        {checks.length ? (
          <section className="grid gap-4 xl:grid-cols-2">
            {checks.map((check) => (
              <CheckCard
                key={check.id}
                check={check}
                assessment={assessments.get(check.id)}
              />
            ))}
          </section>
        ) : (
          <Card className="bg-slate-950/55">
            <CardContent className="p-6">
              <p className="text-sm leading-7 text-muted">
                This saved scan does not contain check details. Run the scan again to generate the current report shape.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  );
}

function MetaCard({
  icon: Icon,
  label,
  value,
}: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  value: string;
}) {
  return (
    <div className="min-w-0 rounded-2xl border border-line/80 bg-white/4 p-4">
      <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.24em] text-accent/80">
        <Icon className="h-4 w-4" />
        {label}
      </div>
      <div className="mt-2 truncate text-sm text-white/90">{value}</div>
    </div>
  );
}

function buildSummary(
  checks: ScanCheckResult[],
  grade: string | null,
  score: number | null,
) {
  const issues = checks
    .flatMap((check) =>
      check.findings
        .filter((finding) => finding.status === "fail" || finding.status === "warning")
        .map((finding) => finding.title),
    )
    .slice(0, 3);
  const prefix =
    grade && typeof score === "number" ? `Grade ${grade} (${score}/100). ` : "";

  if (!checks.length) {
    return `${prefix}No check details are available for this saved scan.`;
  }

  if (!issues.length) {
    return `${prefix}No major issues were confirmed by the lightweight scan.`;
  }

  return `${prefix}Top findings: ${issues.join(", ")}.`;
}

function safeHostname(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}
