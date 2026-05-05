import Link from "next/link";
import { redirect } from "next/navigation";
import { CalendarClock, ExternalLink, FileSearch, Shield } from "lucide-react";
import { auth } from "@/auth";
import { getPrisma } from "@/lib/prisma";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ScanHistoryRow = {
  id: string;
  url: string;
  grade: string | null;
  score: number | null;
  createdAt: Date;
};

export default async function MyScansPage() {
  const session = await auth();

  if (!session?.user?.id) {
    redirect("/signin?callbackUrl=/scans");
  }

  const prisma = getPrisma();
  if (!prisma) {
    throw new Error("Database configuration is unavailable.");
  }

  const scans = await withTimeout(
    prisma.$queryRaw<ScanHistoryRow[]>`
      SELECT id, url, grade, score, "createdAt"
      FROM "Scan"
      WHERE "userId" = ${session.user.id}
      ORDER BY "createdAt" DESC
      LIMIT 100
    `,
    12_000,
  );

  return (
    <main className="relative z-10 min-h-screen px-5 py-8 md:px-8 lg:px-10">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <Link
              href="/"
              className="mb-5 inline-flex w-fit items-center gap-2 rounded-full border border-line bg-white/5 px-4 py-2 text-sm text-muted hover:border-accent/40 hover:text-white"
            >
              <Shield className="h-4 w-4" />
              CyberReflex
            </Link>
            <p className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
              Saved history
            </p>
            <h1 className="mt-3 text-4xl font-semibold text-white md:text-5xl">
              My Scans
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-7 text-muted">
              Reports you ran while signed in are saved here. Anonymous scans remain public by link but are not attached to your account.
            </p>
          </div>
          <Badge variant="outline" className="w-fit font-mono uppercase">
            {scans.length} saved
          </Badge>
        </div>

        {scans.length ? (
          <div className="space-y-3">
            {scans.map((scan) => (
              <Link
                key={scan.id}
                href={`/scan/${scan.id}`}
                className="block rounded-[28px] border border-line/80 bg-card transition hover:border-accent/35 hover:bg-white/6"
              >
                <div className="grid gap-4 p-5 md:grid-cols-[1fr_auto_auto_auto] md:items-center">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-white">
                      <FileSearch className="h-4 w-4 shrink-0 text-accent" />
                      <span className="truncate">{scan.url}</span>
                    </div>
                    <div className="mt-2 flex items-center gap-2 text-xs text-muted">
                      <CalendarClock className="h-3.5 w-3.5" />
                      {formatDate(scan.createdAt)}
                    </div>
                  </div>

                  <GradePill grade={scan.grade} />
                  <div className="font-mono text-sm text-muted">
                    {typeof scan.score === "number" ? `${scan.score}/100` : "N/A"}
                  </div>
                  <div className="flex items-center gap-2 text-sm text-accent">
                    Open report
                    <ExternalLink className="h-4 w-4" />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <Card className="glass-panel terminal-edge">
            <CardContent className="flex flex-col items-center justify-center px-6 py-14 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-accent/25 bg-accent/10 text-accent">
                <FileSearch className="h-6 w-6" />
              </div>
              <h2 className="mt-5 text-2xl font-semibold text-white">
                No saved scans yet
              </h2>
              <p className="mt-3 max-w-xl text-sm leading-7 text-muted">
                Run a scan while signed in and it will appear here automatically.
              </p>
              <Link
                href="/"
                className="mt-6 inline-flex h-12 items-center justify-center rounded-2xl bg-accent px-5 text-sm font-medium text-slate-950 hover:-translate-y-0.5 hover:bg-accent/90"
              >
                Run a scan
              </Link>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  );
}

function GradePill({ grade }: { grade: string | null }) {
  const value = grade ?? "N/A";
  const tone = value.startsWith("A")
    ? "border-success/25 bg-success/10 text-success"
    : value.startsWith("B")
      ? "border-accent/25 bg-accent/10 text-accent"
      : value.startsWith("C")
        ? "border-warning/25 bg-warning/10 text-warning"
        : "border-danger/25 bg-danger/10 text-danger";

  return (
    <div
      className={`inline-flex w-fit items-center justify-center rounded-full border px-3 py-1 font-mono text-sm ${tone}`}
    >
      {value}
    </div>
  );
}

function formatDate(value: Date) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(value);
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("Scan history lookup timed out.")), timeoutMs);
    }),
  ]);
}
