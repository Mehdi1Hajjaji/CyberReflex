import type { CheckStatus, ScanCheckResult } from "@/lib/checks/types";

const CHECK_WEIGHTS: Record<ScanCheckResult["id"], number> = {
  ssl: 18,
  headers: 18,
  dns: 12,
  ports: 10,
  tech: 10,
  cookies: 10,
  files: 12,
  redirects: 10,
};

const STATUS_PENALTY: Record<CheckStatus, number> = {
  pass: 0,
  info: 0,
  warning: 0.35,
  fail: 0.8,
  error: 0.45,
};

const SEVERITY_PENALTY = {
  info: 0,
  low: 0.15,
  medium: 0.35,
  high: 0.7,
  critical: 1,
} as const;

export function scoreScan(checks: ScanCheckResult[]) {
  const weightedScore = checks.reduce((total, check) => {
    const weight = CHECK_WEIGHTS[check.id];
    const findingPenalty = check.findings.reduce((sum, finding) => {
      const statusPenalty = STATUS_PENALTY[finding.status];
      const severityPenalty = SEVERITY_PENALTY[finding.severity];
      return sum + Math.max(statusPenalty, severityPenalty);
    }, 0);
    const normalizedPenalty = Math.min(1, findingPenalty / Math.max(1, check.findings.length));

    return total + weight * (1 - normalizedPenalty);
  }, 0);

  const maxScore = Object.values(CHECK_WEIGHTS).reduce((sum, value) => sum + value, 0);
  const score = Math.max(0, Math.min(100, Math.round((weightedScore / maxScore) * 100)));

  return {
    score,
    grade: gradeFromScore(score),
  };
}

export function gradeFromScore(score: number) {
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 77) return "C+";
  if (score >= 73) return "C";
  if (score >= 70) return "C-";
  if (score >= 60) return "D";
  return "F";
}

