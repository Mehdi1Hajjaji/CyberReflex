# CyberReflex

CyberReflex is a Next.js security scanner for public websites. Users submit a URL and receive a readable report covering TLS, HTTP security headers, DNS posture, redirect hygiene, cookie flags, technology disclosure, exposed files, and basic public port exposure.

## Stack

- Next.js 16 App Router
- Tailwind CSS v4
- Prisma 7
- PostgreSQL / Supabase-ready schema
- Optional OpenAI summary layer

## Local setup

1. Install dependencies:

```bash
npm install
```

2. Copy the environment template and fill in the values you have:

```bash
cp .env.example .env
```

3. Generate the Prisma client:

```bash
npx prisma generate
```

4. Start development:

```bash
npm run dev
```

## Environment variables

- `DATABASE_URL`
  Runtime Prisma connection. For Supabase, use the pooled Supavisor transaction URL on port `6543` with `?pgbouncer=true`.
- `DIRECT_URL`
  Direct database URL for Prisma CLI commands such as `prisma generate`, `prisma db push`, and migrations.
- `NEXT_PUBLIC_SUPABASE_URL`
  Optional for the current MVP. Only needed when you start using Supabase auth or client-side features.
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_DEFAULT_KEY`
  Optional for the current MVP. Only needed when you start using Supabase auth or client-side features.
- `OPENAI_API_KEY`
  Optional. If omitted, CyberReflex falls back to a rules-based summary.
- `OPENAI_MODEL`
  Optional. Defaults to `gpt-4o-mini`.

## Prisma notes

- Prisma 7 now reads the direct datasource URL from `prisma.config.ts`.
- The generated client lives in `src/generated/prisma`.
- Runtime queries use `DATABASE_URL` through `@prisma/adapter-pg`.
- Prisma CLI commands use `DIRECT_URL`.
- The app only initializes Prisma when `DATABASE_URL` is present, so scanning still works without a database.

## Scan coverage

- SSL / TLS certificate and protocol checks
- HTTP security header grading
- SPF / DMARC / nameserver checks
- Best-effort public port probing
- Technology disclosure and framework fingerprinting
- Cookie flag analysis
- Exposed file and debug endpoint probes
- Redirect chain tracing

## Validation

The current build has been validated with:

```bash
npm run lint
npx prisma generate
npm run build
```
