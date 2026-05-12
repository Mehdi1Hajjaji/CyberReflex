const SUPABASE_PROJECT_REF = "hrjdwtaccgthqzwrnkqt";
const RUNTIME_POOLER_HOST = "aws-1-eu-west-3.pooler.supabase.com";
const DIRECT_HOST = `db.${SUPABASE_PROJECT_REF}.supabase.co`;
const DATABASE_NAME = "postgres";

export type DatabaseEnvIssue = {
  variable: "DATABASE_URL" | "DIRECT_URL";
  code: string;
  message: string;
  hint: string;
};

export type DatabaseEnvDetails = {
  variable: "DATABASE_URL" | "DIRECT_URL";
  present: boolean;
  valid: boolean;
  host?: string;
  port?: string;
  username?: string;
  database?: string;
  usesPgbouncer?: boolean;
  expectedUse: string;
  issues: DatabaseEnvIssue[];
};

export class DatabaseEnvError extends Error {
  issues: DatabaseEnvIssue[];

  constructor(message: string, issues: DatabaseEnvIssue[]) {
    super(message);
    this.name = "DatabaseEnvError";
    this.issues = issues;
  }
}

export function getRuntimeDatabaseUrl() {
  const details = validateDatabaseUrl("DATABASE_URL", process.env.DATABASE_URL, {
    required: true,
    expectedUse: "Runtime app queries through Supabase transaction pooler.",
    expectedHost: RUNTIME_POOLER_HOST,
    expectedUsername: `postgres.${SUPABASE_PROJECT_REF}`,
    expectedPort: "6543",
    expectedDatabase: DATABASE_NAME,
    requirePgbouncer: true,
    expectedConnectionLimit: "1",
  });

  if (!details.valid) {
    throw new DatabaseEnvError(
      "DATABASE_URL is missing or invalid for runtime database access.",
      details.issues,
    );
  }

  return process.env.DATABASE_URL as string;
}

export function validateDatabaseEnvironment() {
  const runtime = validateDatabaseUrl("DATABASE_URL", process.env.DATABASE_URL, {
    required: true,
    expectedUse: "Runtime app queries through Supabase transaction pooler.",
    expectedHost: RUNTIME_POOLER_HOST,
    expectedUsername: `postgres.${SUPABASE_PROJECT_REF}`,
    expectedPort: "6543",
    expectedDatabase: DATABASE_NAME,
    requirePgbouncer: true,
    expectedConnectionLimit: "1",
  });
  const direct = validateDatabaseUrl("DIRECT_URL", process.env.DIRECT_URL, {
    required: true,
    expectedUse: "Prisma CLI and migrations through the direct Postgres endpoint.",
    expectedHost: DIRECT_HOST,
    expectedUsername: "postgres",
    expectedPort: "5432",
    expectedDatabase: DATABASE_NAME,
    requirePgbouncer: false,
  });
  const issues = [...runtime.issues, ...direct.issues];

  return {
    ok: issues.length === 0,
    projectRef: SUPABASE_PROJECT_REF,
    runtime,
    direct,
    issues,
  };
}

function validateDatabaseUrl(
  variable: "DATABASE_URL" | "DIRECT_URL",
  value: string | undefined,
  options: {
    required: boolean;
    expectedUse: string;
    expectedHost: string;
    expectedUsername: string;
    expectedPort: string;
    expectedDatabase: string;
    requirePgbouncer: boolean;
    expectedConnectionLimit?: string;
  },
): DatabaseEnvDetails {
  const issues: DatabaseEnvIssue[] = [];

  if (!value) {
    if (options.required) {
      issues.push({
        variable,
        code: "missing",
        message: `${variable} is required.`,
        hint:
          variable === "DATABASE_URL"
            ? "Set DATABASE_URL to the Supabase transaction pooler URL on port 6543."
            : "Set DIRECT_URL to the direct Supabase Postgres URL on port 5432 for Prisma CLI commands.",
      });
    }

    return {
      variable,
      present: false,
      valid: issues.length === 0,
      expectedUse: options.expectedUse,
      issues,
    };
  }

  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch {
    issues.push({
      variable,
      code: "malformed",
      message: `${variable} is not a valid Postgres connection string.`,
      hint: "Check for unescaped special characters in the password. Encode characters like @, #, ?, &, %, and /.",
    });

    return {
      variable,
      present: true,
      valid: false,
      expectedUse: options.expectedUse,
      issues,
    };
  }

  if (parsed.protocol !== "postgresql:" && parsed.protocol !== "postgres:") {
    issues.push({
      variable,
      code: "invalid_protocol",
      message: `${variable} must use the postgresql:// protocol.`,
      hint: "Copy the Postgres connection string from Supabase, not the Supabase HTTP project URL.",
    });
  }

  if (parsed.hostname !== options.expectedHost) {
    issues.push({
      variable,
      code: "unexpected_host",
      message: `${variable} points to ${parsed.hostname}, not the expected Supabase host.`,
      hint: `Expected host: ${options.expectedHost}.`,
    });
  }

  if (parsed.username !== options.expectedUsername) {
    issues.push({
      variable,
      code: "unexpected_username",
      message: `${variable} uses an unexpected database username.`,
      hint: `Expected username: ${options.expectedUsername}.`,
    });
  }

  if (parsed.port !== options.expectedPort) {
    issues.push({
      variable,
      code: "unexpected_port",
      message: `${variable} uses port ${parsed.port || "(default)"}.`,
      hint: `Expected port: ${options.expectedPort}.`,
    });
  }

  if (!parsed.password || isPlaceholderValue(parsed.password)) {
    issues.push({
      variable,
      code: "missing_password",
      message: `${variable} is missing the database password.`,
      hint: "Replace the password placeholder with the Supabase database password. URL-encode it if it contains reserved URL characters.",
    });
  }

  const database = parsed.pathname.replace(/^\//, "");

  if (database !== options.expectedDatabase) {
    issues.push({
      variable,
      code: "unexpected_database",
      message: `${variable} points to database ${database || "(missing)"}, not the expected database.`,
      hint: `Expected database: ${options.expectedDatabase}.`,
    });
  }

  if (options.requirePgbouncer && parsed.searchParams.get("pgbouncer") !== "true") {
    issues.push({
      variable,
      code: "missing_pgbouncer",
      message: `${variable} must include pgbouncer=true for the transaction pooler.`,
      hint: "Append ?pgbouncer=true, or &pgbouncer=true if the URL already has query parameters.",
    });
  }

  if (
    options.expectedConnectionLimit &&
    parsed.searchParams.get("connection_limit") !== options.expectedConnectionLimit
  ) {
    issues.push({
      variable,
      code: "unexpected_connection_limit",
      message: `${variable} must include connection_limit=${options.expectedConnectionLimit} for serverless runtime connections.`,
      hint: `Append connection_limit=${options.expectedConnectionLimit}, or set it to ${options.expectedConnectionLimit} if the URL already has this query parameter.`,
    });
  }

  if (!options.requirePgbouncer && parsed.searchParams.get("pgbouncer") === "true") {
    issues.push({
      variable,
      code: "unexpected_pgbouncer",
      message: `${variable} should not use the transaction-pooler pgbouncer flag.`,
      hint: "Use the direct Supabase Postgres URL for Prisma CLI and migrations.",
    });
  }

  return {
    variable,
    present: true,
    valid: issues.length === 0,
    host: parsed.hostname,
    port: parsed.port,
    username: parsed.username,
    database,
    usesPgbouncer: parsed.searchParams.get("pgbouncer") === "true",
    expectedUse: options.expectedUse,
    issues,
  };
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
