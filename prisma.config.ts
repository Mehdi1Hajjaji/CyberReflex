import "dotenv/config";
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url: getRequiredDirectUrl(),
  },
});

function getRequiredDirectUrl() {
  const directUrl = process.env.DIRECT_URL;

  if (!directUrl) {
    throw new Error(
      "DIRECT_URL is required for Prisma CLI and migrations. Use postgresql://postgres:[PASSWORD]@db.hrjdwtaccgthqzwrnkqt.supabase.co:5432/postgres",
    );
  }

  try {
    const parsed = new URL(directUrl);

    if (parsed.protocol !== "postgresql:" && parsed.protocol !== "postgres:") {
      throw new Error("DIRECT_URL must use postgresql://.");
    }

    if (!parsed.password || parsed.password === "[YOUR-PASSWORD]") {
      throw new Error("DIRECT_URL is missing the database password.");
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("DIRECT_URL")) {
      throw error;
    }

    throw new Error(
      "DIRECT_URL is malformed. If the password contains @, #, ?, &, %, or /, URL-encode the password.",
    );
  }

  return directUrl;
}
