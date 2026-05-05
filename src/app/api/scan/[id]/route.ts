import { NextResponse } from "next/server";
import { DatabaseEnvError } from "@/lib/database-env";
import { getPrisma } from "@/lib/prisma";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;

  if (!/^[a-z0-9_-]{8,64}$/i.test(id)) {
    return NextResponse.json({ error: "Invalid scan id." }, { status: 400 });
  }

  let prisma;

  try {
    prisma = getPrisma();
  } catch (error) {
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

  if (!prisma) {
    return NextResponse.json(
      { error: "DATABASE_URL is required to read saved scans." },
      { status: 503 },
    );
  }

  let scans;

  try {
    scans = await withTimeout(
      prisma.$queryRaw<
        Array<{
          id: string;
          url: string;
          score: number | null;
          grade: string | null;
          results: unknown;
          aiSummary: string | null;
          createdAt: Date;
        }>
      >`
        SELECT id, url, score, grade, results, "aiSummary", "createdAt"
        FROM "Scan"
        WHERE id = ${id}
        LIMIT 1
      `,
      12_000,
    );
  } catch (error) {
    console.error(
      "Saved scan lookup failed:",
      error instanceof Error ? error.message : "Unknown error",
    );
    return NextResponse.json(
      { error: "Saved scan storage is currently unavailable." },
      { status: 503 },
    );
  }

  const scan = scans[0];

  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

  return NextResponse.json({
    id: scan.id,
    normalizedUrl: scan.url,
    score: scan.score,
    grade: scan.grade,
    aiSummary: scan.aiSummary,
    results: scan.results,
    createdAt: scan.createdAt.toISOString(),
  });
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("Database operation timed out.")), timeoutMs);
    }),
  ]);
}
