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
  Runtime Prisma connection. For this Supabase project, use `postgresql://postgres.hrjdwtaccgthqzwrnkqt:<SUPABASE_DB_PASSWORD>@aws-1-eu-west-3.pooler.supabase.com:6543/postgres?pgbouncer=true&connection_limit=1`.
- `DIRECT_URL`
  Direct database URL for Prisma CLI commands such as `prisma generate`, `prisma db push`, and migrations.
- `AUTH_SECRET`
  Required Auth.js secret. `NEXTAUTH_SECRET` is also supported as an alias.
- `NEXTAUTH_URL`
  Production canonical URL. Use `https://cyberreflex.com` in production.
- `AUTH_TRUST_HOST`
  Set to `true` on Vercel/proxied production hosting.
- `NEXT_PUBLIC_SUPABASE_URL`
  Supabase frontend URL for this project: `https://hrjdwtaccgthqzwrnkqt.supabase.co`.
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_DEFAULT_KEY`
  Supabase publishable key for frontend Supabase usage.
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
  Enables Google sign-in when both values are present. `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` are also supported aliases.
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
  Enables GitHub sign-in when both values are present. `AUTH_GITHUB_ID` / `AUTH_GITHUB_SECRET` are also supported aliases.
- `OPENAI_API_KEY`
  Optional. If omitted, CyberReflex falls back to a rules-based summary.
- `OPENAI_MODEL`
  Optional. Defaults to `gpt-4o-mini`.

## OAuth callback URLs

Google:

- `http://localhost:3000/api/auth/callback/google`
- `https://cyber-reflex.vercel.app/api/auth/callback/google`
- `https://cyberreflex.com/api/auth/callback/google`

GitHub:

- `http://localhost:3000/api/auth/callback/github`
- `https://cyber-reflex.vercel.app/api/auth/callback/github`
- `https://cyberreflex.com/api/auth/callback/github`

## Prisma notes

- Prisma 7 now reads the direct datasource URL from `prisma.config.ts`.
- The generated client lives in `src/generated/prisma`.
- Runtime queries use `DATABASE_URL` through `@prisma/adapter-pg`.
- Prisma CLI commands use `DIRECT_URL`.
- The app validates the runtime Supabase pooler host, user, port, database, `pgbouncer=true`, and `connection_limit=1` before initializing Prisma.

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
