import { Pool } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";
import { getRuntimeDatabaseUrl } from "@/lib/database-env";

declare global {
  var prismaGlobal: PrismaClient | undefined;
  var prismaAdapterGlobal: PrismaPg | undefined;
  var prismaConnectionStringGlobal: string | undefined;
  var pgPoolGlobal: Pool | undefined;
}

export function getPrisma() {
  const connectionString = getRuntimeDatabaseUrl();

  if (!connectionString) {
    return null;
  }

  if (
    !globalThis.prismaAdapterGlobal ||
    globalThis.prismaConnectionStringGlobal !== connectionString
  ) {
    globalThis.pgPoolGlobal = new Pool({
      connectionString,
      connectionTimeoutMillis: 10_000,
      idleTimeoutMillis: 10_000,
      max: process.env.VERCEL ? 1 : 5,
    });
    globalThis.prismaAdapterGlobal = new PrismaPg(globalThis.pgPoolGlobal);
    globalThis.prismaGlobal = undefined;
    globalThis.prismaConnectionStringGlobal = connectionString;
  }

  if (!globalThis.prismaGlobal) {
    globalThis.prismaGlobal = new PrismaClient({
      adapter: globalThis.prismaAdapterGlobal,
    });
  }

  return globalThis.prismaGlobal;
}
