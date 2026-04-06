import {
  Bot,
  DatabaseZap,
  FileSearch,
  Lock,
  Network,
  RefreshCcw,
  ScanSearch,
  Shield,
} from "lucide-react";
import { ScannerExperience } from "@/components/scanner-experience";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const workflow = [
  {
    title: "Submit Any URL",
    description:
      "Drop in a production domain, staging site, or client hostname. CyberReflex normalizes the target and starts the probe chain immediately.",
  },
  {
    title: "Run Security Checks",
    description:
      "The scan executes TLS, header, DNS, redirect, cookie, exposure, and basic port checks in parallel to keep response times tight.",
  },
  {
    title: "Read the Fix Plan",
    description:
      "Results come back as a plain-English scorecard with severity, reasoning, and remediation guidance instead of raw headers alone.",
  },
] as const;

const checks = [
  {
    icon: Lock,
    title: "SSL / TLS",
    description:
      "Certificate validity, issuer trust, protocol version, and near-expiry risk.",
  },
  {
    icon: Shield,
    title: "HTTP Security Headers",
    description:
      "HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
  },
  {
    icon: Network,
    title: "DNS Hygiene",
    description:
      "SPF, DMARC, mail exposure context, and nameserver redundancy.",
  },
  {
    icon: ScanSearch,
    title: "Basic Port Exposure",
    description:
      "Best-effort checks for public SSH, FTP, SMTP, database, Redis, and alternate web ports.",
  },
  {
    icon: DatabaseZap,
    title: "Technology Footprints",
    description:
      "Framework and platform clues from headers and markup, including overexposed server signatures.",
  },
  {
    icon: Bot,
    title: "Cookie Security",
    description:
      "Secure, HttpOnly, SameSite, and cross-site cookie combinations that expand session risk.",
  },
  {
    icon: FileSearch,
    title: "Exposed Files",
    description:
      "Probes for `.env`, `.git`, backup archives, phpinfo, server-status, and common debug endpoints.",
  },
  {
    icon: RefreshCcw,
    title: "Redirect Chain",
    description:
      "Too many hops, HTTP-to-HTTPS enforcement, canonical routing, and loop detection.",
  },
] as const;

export default function Home() {
  return (
    <main className="relative flex-1 overflow-hidden">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-20 px-6 py-8 lg:px-10 lg:py-10">
        <header className="reveal-up flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-accent/25 bg-accent/10 text-accent shadow-[0_0_40px_rgba(44,241,193,0.15)]">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.36em] text-accent/80">
                cyberreflex
              </div>
              <div className="text-sm text-muted">
                Instant website security scans
              </div>
            </div>
          </div>

          <nav className="hidden items-center gap-6 text-sm text-muted md:flex">
            <a href="#how-it-works" className="hover:text-foreground">
              How it works
            </a>
            <a href="#checks" className="hover:text-foreground">
              Checks
            </a>
            <a href="#why" className="hover:text-foreground">
              Why CyberReflex
            </a>
          </nav>
        </header>

        <section className="grid gap-10 lg:grid-cols-[1.04fr_0.96fr] lg:items-start">
          <div className="space-y-8">
            <div className="reveal-up">
              <Badge variant="outline" className="mb-5 font-mono text-[11px]">
                AI-powered remediation guidance
              </Badge>
              <h1 className="max-w-3xl text-balance text-5xl font-semibold leading-[1.02] tracking-tight text-white md:text-6xl lg:text-7xl">
                Scan Your Website&apos;s Security in 30 Seconds
              </h1>
              <p className="mt-5 max-w-2xl text-lg leading-8 text-muted md:text-xl">
                CyberReflex checks the surface area most teams miss first: TLS
                health, headers, DNS posture, public exposures, cookies,
                redirect hygiene, and stack disclosures. The output is written
                for humans, not just scanners.
              </p>
            </div>

            <div className="reveal-up delay-100 flex flex-wrap gap-3">
              <Badge className="bg-accent/10 text-accent hover:bg-accent/10">
                8 parallel checks
              </Badge>
              <Badge className="bg-accent-2/10 text-accent-2 hover:bg-accent-2/10">
                AI summary + fix plan
              </Badge>
              <Badge className="bg-white/5 text-white/85 hover:bg-white/5">
                Supabase-ready history storage
              </Badge>
            </div>

            <div className="reveal-up delay-200 grid gap-4 sm:grid-cols-3">
              <Card className="glass-panel terminal-edge">
                <CardContent className="p-5">
                  <div className="font-mono text-xs uppercase tracking-[0.28em] text-accent/70">
                    Coverage
                  </div>
                  <div className="mt-3 text-3xl font-semibold text-white">
                    8
                  </div>
                  <p className="mt-2 text-sm leading-6 text-muted">
                    Security lenses stitched into one scorecard.
                  </p>
                </CardContent>
              </Card>

              <Card className="glass-panel terminal-edge">
                <CardContent className="p-5">
                  <div className="font-mono text-xs uppercase tracking-[0.28em] text-accent/70">
                    Output
                  </div>
                  <div className="mt-3 text-3xl font-semibold text-white">
                    A+ to F
                  </div>
                  <p className="mt-2 text-sm leading-6 text-muted">
                    Weighted grading with visible issue severity.
                  </p>
                </CardContent>
              </Card>

              <Card className="glass-panel terminal-edge">
                <CardContent className="p-5">
                  <div className="font-mono text-xs uppercase tracking-[0.28em] text-accent/70">
                    Audience
                  </div>
                  <div className="mt-3 text-3xl font-semibold text-white">
                    Ops
                  </div>
                  <p className="mt-2 text-sm leading-6 text-muted">
                    Clear enough for clients, useful enough for engineers.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>

          <div className="reveal-up delay-300">
            <ScannerExperience />
          </div>
        </section>

        <section id="how-it-works" className="space-y-6">
          <div className="max-w-2xl">
            <p className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
              How It Works
            </p>
            <h2 className="mt-3 text-3xl font-semibold text-white md:text-4xl">
              One input, one scan, one readable plan.
            </h2>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            {workflow.map((item, index) => (
              <Card key={item.title} className="glass-panel terminal-edge">
                <CardHeader className="pb-3">
                  <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-2xl border border-accent/20 bg-accent/10 font-mono text-sm text-accent">
                    0{index + 1}
                  </div>
                  <CardTitle className="text-xl text-white">
                    {item.title}
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0 text-sm leading-7 text-muted">
                  {item.description}
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section id="checks" className="space-y-6">
          <div className="max-w-3xl">
            <p className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
              What We Check
            </p>
            <h2 className="mt-3 text-3xl font-semibold text-white md:text-4xl">
              Built for the problems that actually show up in external reviews.
            </h2>
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {checks.map(({ icon: Icon, title, description }) => (
              <Card key={title} className="glass-panel terminal-edge">
                <CardHeader className="pb-3">
                  <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-2xl border border-accent/20 bg-white/5 text-accent">
                    <Icon className="h-5 w-5" />
                  </div>
                  <CardTitle className="text-lg text-white">{title}</CardTitle>
                </CardHeader>
                <CardContent className="pt-0 text-sm leading-7 text-muted">
                  {description}
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section id="why" className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
          <Card className="glass-panel terminal-edge">
            <CardContent className="flex h-full flex-col justify-between gap-6 p-8">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
                  Why CyberReflex
                </p>
                <h2 className="mt-3 max-w-2xl text-3xl font-semibold text-white md:text-4xl">
                  Security headers alone do not explain what to fix next.
                </h2>
              </div>

              <p className="max-w-3xl text-base leading-8 text-muted">
                The scanner is opinionated about triage. It keeps technical
                detail visible, but it also translates findings into a short
                remediation narrative so teams can move from “something is
                wrong” to “here is the next change to ship.”
              </p>
            </CardContent>
          </Card>

          <Card className="glass-panel terminal-edge">
            <CardContent className="p-8">
              <div className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
                Deployment
              </div>
              <div className="mt-5 space-y-4 text-sm leading-7 text-muted">
                <p>Next.js App Router frontend and API routes.</p>
                <p>Optional Supabase persistence through Prisma.</p>
                <p>Optional OpenAI summary layer for human-readable reporting.</p>
                <p>Designed for Vercel deployment and custom-domain launch.</p>
              </div>
            </CardContent>
          </Card>
        </section>
      </div>
    </main>
  );
}
