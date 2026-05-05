import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";
import { getRuntimeDatabaseUrl } from "@/lib/database-env";

declare global {
  var prismaGlobal: PrismaClient | undefined;
  var prismaAdapterGlobal: PrismaPg | undefined;
  var prismaConnectionStringGlobal: string | undefined;
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
    globalThis.prismaAdapterGlobal = new PrismaPg({
      connectionString,
      connectionTimeoutMillis: 10_000,
      idleTimeoutMillis: 10_000,
      max: process.env.VERCEL ? 1 : 5,
    });
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
