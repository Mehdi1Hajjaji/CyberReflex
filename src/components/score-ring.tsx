import { cn } from "@/lib/utils";

type ScoreRingProps = {
  score: number;
  grade: string;
  className?: string;
};

function getTone(score: number) {
  if (score >= 90) {
    return "#39d98a";
  }

  if (score >= 75) {
    return "#2cf1c1";
  }

  if (score >= 55) {
    return "#f8cf4c";
  }

  return "#ff7a7a";
}

export function ScoreRing({ score, grade, className }: ScoreRingProps) {
  const tone = getTone(score);
  const degrees = Math.max(0, Math.min(100, score)) * 3.6;

  return (
    <div
      className={cn(
        "relative flex h-28 w-28 items-center justify-center rounded-full",
        className,
      )}
      style={{
        background: `conic-gradient(${tone} ${degrees}deg, rgba(255,255,255,0.08) ${degrees}deg 360deg)`,
      }}
    >
      <div className="absolute inset-[10px] flex flex-col items-center justify-center rounded-full border border-line bg-slate-950/90">
        <span className="font-mono text-xs uppercase tracking-[0.28em] text-muted">
          {grade}
        </span>
        <span className="mono-digits mt-1 text-2xl font-semibold text-white">
          {score}
        </span>
      </div>
    </div>
  );
}
