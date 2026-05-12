import "dotenv/config";
import { defineConfig } from "prisma/config";

const SUPABASE_PROJECT_REF = "hrjdwtaccgthqzwrnkqt";
const DIRECT_HOST = `db.${SUPABASE_PROJECT_REF}.supabase.co`;
const DATABASE_NAME = "postgres";

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

    if (!parsed.password || isPlaceholderValue(parsed.password)) {
      throw new Error("DIRECT_URL is missing the database password.");
    }

    if (parsed.hostname !== DIRECT_HOST) {
      throw new Error(
        `DIRECT_URL must use the direct Supabase host ${DIRECT_HOST}, not ${parsed.hostname}.`,
      );
    }

    if (parsed.username !== "postgres") {
      throw new Error("DIRECT_URL must use the direct postgres database user.");
    }

    if (parsed.port !== "5432") {
      throw new Error("DIRECT_URL must use port 5432.");
    }

    if (parsed.pathname.replace(/^\//, "") !== DATABASE_NAME) {
      throw new Error(`DIRECT_URL must use the ${DATABASE_NAME} database.`);
    }

    if (parsed.searchParams.get("pgbouncer") === "true") {
      throw new Error("DIRECT_URL must not include pgbouncer=true.");
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

function isPlaceholderValue(value: string) {
  const decodedValue = safeDecodeURIComponent(value);

  return (
    decodedValue === "[YOUR-PASSWORD]" ||
    decodedValue.startsWith("<") ||
    decodedValue.endsWith(">") ||
    decodedValue.startsWith("[") ||
    decodedValue.endsWith("]")
  );
}

function safeDecodeURIComponent(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
