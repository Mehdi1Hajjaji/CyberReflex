import { cn } from "@/lib/utils";

type GradeBadgeProps = {
  grade: string | null;
  score?: number | null;
  className?: string;
};

export function GradeBadge({ grade, score, className }: GradeBadgeProps) {
  const normalizedGrade = grade ?? "N/A";

  return (
    <div
      className={cn(
        "inline-flex min-w-28 flex-col items-center justify-center rounded-[24px] border px-5 py-4 text-center mono-digits",
        gradeTone(normalizedGrade),
        className,
      )}
    >
      <div className="font-mono text-[11px] uppercase tracking-[0.28em] opacity-80">
        Grade
      </div>
      <div className="mt-1 text-4xl font-semibold leading-none">{normalizedGrade}</div>
      {typeof score === "number" ? (
        <div className="mt-2 font-mono text-xs opacity-80">{score}/100</div>
      ) : null}
    </div>
  );
}

function gradeTone(grade: string) {
  if (grade.startsWith("A")) {
    return "border-success/35 bg-success/12 text-success";
  }

  if (grade.startsWith("B")) {
    return "border-accent/35 bg-accent/12 text-accent";
  }

  if (grade.startsWith("C")) {
    return "border-warning/35 bg-warning/12 text-warning";
  }

  return "border-danger/35 bg-danger/12 text-danger";
}

