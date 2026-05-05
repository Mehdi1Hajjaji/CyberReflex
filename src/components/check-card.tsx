import {
  AlertTriangle,
  CheckCircle2,
  Info,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import type { ComponentType } from "react";
import type { AiCheckAssessment } from "@/lib/ai-report";
import type { CheckFinding, CheckStatus, ScanCheckResult } from "@/lib/checks/types";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type CheckCardProps = {
  check: ScanCheckResult;
  assessment?: AiCheckAssessment;
};

const statusLabel: Record<CheckStatus, string> = {
  pass: "Pass",
  info: "Info",
  warning: "Warning",
  fail: "Fail",
  error: "Error",
};

const statusIcons = {
  pass: CheckCircle2,
  info: Info,
  warning: AlertTriangle,
  fail: XCircle,
  error: ShieldAlert,
} satisfies Record<CheckStatus, ComponentType<{ className?: string }>>;

export function CheckCard({ check, assessment }: CheckCardProps) {
  const Icon = statusIcons[check.status];

  return (
    <Card className={cn("bg-slate-950/55", statusBorder(check.status))}>
      <CardHeader className="pb-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <div
              className={cn(
                "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border",
                statusIconTone(check.status),
              )}
            >
              <Icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <CardTitle className="text-white">{check.name}</CardTitle>
              <p className="mt-2 text-sm leading-6 text-muted">{check.summary}</p>
            </div>
          </div>
          <StatusBadge status={check.status} />
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {assessment ? (
          <div className="rounded-2xl border border-accent/20 bg-accent/6 p-4">
            <div className="font-mono text-[11px] uppercase tracking-[0.24em] text-accent/80">
              Plain-English assessment
            </div>
            <p className="mt-2 text-sm leading-6 text-white/88">
              {assessment.explanation}
            </p>
            <div className="mt-4 font-mono text-[11px] uppercase tracking-[0.24em] text-accent/80">
              Fix guidance
            </div>
            <p className="mt-2 text-sm leading-6 text-muted">
              {assessment.fixGuidance}
            </p>
          </div>
        ) : (
          <div className="rounded-2xl border border-line/80 bg-white/4 p-4">
            <div className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted">
              Assessment
            </div>
            <p className="mt-2 text-sm leading-6 text-muted">
              AI-assisted explanation is unavailable for this saved check. The technical findings below are still available.
            </p>
          </div>
        )}

        {check.findings.map((finding) => (
          <FindingRow key={finding.id} finding={finding} />
        ))}
      </CardContent>
    </Card>
  );
}

function FindingRow({ finding }: { finding: CheckFinding }) {
  return (
    <div className="rounded-2xl border border-line/80 bg-white/4 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-sm font-medium text-white">{finding.title}</div>
        <StatusBadge status={finding.status} compact />
        <Badge variant="outline" className="font-mono uppercase">
          {finding.severity}
        </Badge>
      </div>
      <p className="mt-2 text-sm leading-6 text-muted">{finding.summary}</p>
      {finding.recommendation ? (
        <p className="mt-2 text-sm leading-6 text-accent/90">
          Fix: {finding.recommendation}
        </p>
      ) : null}
    </div>
  );
}

function StatusBadge({
  status,
  compact = false,
}: {
  status: CheckStatus;
  compact?: boolean;
}) {
  const variant =
    status === "pass"
      ? "success"
      : status === "warning"
        ? "warning"
        : status === "fail" || status === "error"
          ? "destructive"
          : "outline";

  return (
    <Badge
      variant={variant}
      className={cn("shrink-0 font-mono uppercase", compact && "px-2 py-0.5 text-[10px]")}
    >
      {statusLabel[status]}
    </Badge>
  );
}

function statusBorder(status: CheckStatus) {
  if (status === "pass") return "border-success/20";
  if (status === "warning") return "border-warning/25";
  if (status === "fail" || status === "error") return "border-danger/25";
  return "border-accent-2/18";
}

function statusIconTone(status: CheckStatus) {
  if (status === "pass") return "border-success/25 bg-success/10 text-success";
  if (status === "warning") return "border-warning/25 bg-warning/10 text-warning";
  if (status === "fail" || status === "error") {
    return "border-danger/25 bg-danger/10 text-danger";
  }

  return "border-accent-2/25 bg-accent-2/10 text-accent-2";
}
