import { hash } from "bcryptjs";
import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { z } from "zod";
import { DatabaseEnvError } from "@/lib/database-env";
import { getPrisma } from "@/lib/prisma";

export const runtime = "nodejs";

const registerSchema = z.object({
  name: z.string().trim().max(80).optional(),
  email: z.string().trim().email().transform((value) => value.toLowerCase()),
  password: z.string().min(8).max(128),
});

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  const parsed = registerSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Enter a valid email and a password with at least 8 characters." },
      { status: 400 },
    );
  }

  let prisma;

  try {
    prisma = getPrisma();
  } catch (error) {
    return authStorageErrorResponse(error);
  }

  if (!prisma) {
    return NextResponse.json(
      { error: "Database configuration is unavailable." },
      { status: 503 },
    );
  }

  let existing;

  try {
    existing = await withTimeout(
      prisma.$queryRaw<Array<{ id: string }>>`
        SELECT id
        FROM "User"
        WHERE email = ${parsed.data.email}
        LIMIT 1
      `,
      10_000,
    );
  } catch (error) {
    console.error("Account lookup failed:", toErrorMessage(error));
    return NextResponse.json(
      { error: "Account storage is currently unavailable." },
      { status: 503 },
    );
  }

  if (!existing) {
    return NextResponse.json(
      { error: "Account storage is currently unavailable." },
      { status: 503 },
    );
  }

  if (existing.length) {
    return NextResponse.json(
      { error: "An account already exists for this email." },
      { status: 409 },
    );
  }

  const passwordHash = await hash(parsed.data.password, 12);
  let created;

  try {
    created = await withTimeout(
      prisma.$executeRaw`
        INSERT INTO "User" (id, email, name, "passwordHash", plan, "createdAt")
        VALUES (
          ${randomUUID()},
          ${parsed.data.email},
          ${parsed.data.name || null},
          ${passwordHash},
          'free',
          NOW()
        )
      `,
      10_000,
    );
  } catch (error) {
    console.error("Account creation failed:", toErrorMessage(error));
    return NextResponse.json(
      { error: "Account could not be created right now." },
      { status: 503 },
    );
  }

  if (created === null) {
    return NextResponse.json(
      { error: "Account could not be created right now." },
      { status: 503 },
    );
  }

  return NextResponse.json({ ok: true }, { status: 201 });
}

function authStorageErrorResponse(error: unknown) {
  if (error instanceof DatabaseEnvError) {
    console.error("Auth database configuration failed:", error.issues);
    return NextResponse.json(
      {
        error: "There is a problem with the server database configuration.",
        diagnosticUrl: "/api/diagnostics/database",
      },
      { status: 503 },
    );
  }

  console.error("Auth database initialization failed:", toErrorMessage(error));
  return NextResponse.json(
    {
      error: "Account storage is currently unavailable.",
      diagnosticUrl: "/api/diagnostics/database",
    },
    { status: 503 },
  );
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("Auth database operation timed out.")), timeoutMs);
    }),
  ]);
}

function toErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unknown error";
}
