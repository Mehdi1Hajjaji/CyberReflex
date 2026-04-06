import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";

declare global {
  var prismaGlobal: PrismaClient | undefined;
  var prismaAdapterGlobal: PrismaPg | undefined;
}

export function getPrisma() {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    return null;
  }

  if (!globalThis.prismaAdapterGlobal) {
    globalThis.prismaAdapterGlobal = new PrismaPg({
      connectionString,
    });
  }

  if (!globalThis.prismaGlobal) {
    globalThis.prismaGlobal = new PrismaClient({
      adapter: globalThis.prismaAdapterGlobal,
    });
  }

  return globalThis.prismaGlobal;
}
