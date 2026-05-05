import { NextResponse } from "next/server";
import { DatabaseEnvError, validateDatabaseEnvironment } from "@/lib/database-env";
import { getPrisma } from "@/lib/prisma";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const environment = validateDatabaseEnvironment();

  if (!environment.runtime.valid) {
    return NextResponse.json(
      {
        ok: false,
        environment,
        connection: {
          tested: false,
          ok: false,
          message: "Runtime connection test skipped because DATABASE_URL is invalid.",
        },
      },
      { status: 503 },
    );
  }

  try {
    const prisma = getPrisma();

    if (!prisma) {
      return NextResponse.json(
        {
          ok: false,
          environment,
          connection: {
            tested: false,
            ok: false,
            message: "Prisma client was not created.",
          },
        },
        { status: 503 },
      );
    }

    await withTimeout(prisma.$queryRaw`SELECT 1`, 10_000);

    return NextResponse.json({
      ok: environment.ok,
      environment,
      connection: {
        tested: true,
        ok: true,
        message: "Runtime DATABASE_URL accepted a simple query.",
      },
    });
  } catch (error) {
    const message =
      error instanceof DatabaseEnvError
        ? error.message
        : error instanceof Error
          ? error.message
          : "Unknown database connection error.";

    return NextResponse.json(
      {
        ok: false,
        environment,
        connection: {
          tested: true,
          ok: false,
          message,
        },
      },
      { status: 503 },
    );
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("Database diagnostic query timed out.")), timeoutMs);
    }),
  ]);
}
