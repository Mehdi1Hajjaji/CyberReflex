"use client";

import { useState, useTransition } from "react";
import {
  AlertTriangle,
  Bot,
  FileSearch,
  Globe,
  Lock,
  Network,
  RefreshCcw,
  ScanSearch,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import type { ScanCategory, ScanResult } from "@/lib/scan/types";
import { cn } from "@/lib/utils";
import { ScoreRing } from "@/components/score-ring";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

const sampleTargets = [
  "https://stripe.com",
  "https://vercel.com",
  "https://github.com",
];

const categoryIcons = {
  ssl: Lock,
  headers: ShieldCheck,
  dns: Network,
  ports: ScanSearch,
  technology: Sparkles,
  cookies: Bot,
  "exposed-files": FileSearch,
  redirects: RefreshCcw,
} as const;

export function ScannerExperience() {
  const [url, setUrl] = useState("https://");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextTarget = url.trim();

    if (!nextTarget) {
      setError("Enter a domain or full URL to scan.");
      return;
    }

    setError(null);

    startTransition(() => {
      void scanTarget(nextTarget);
    });
  }

  async function scanTarget(target: string) {
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({ url: target }),
      });

      const payload = (await response.json()) as
        | ScanResult
        | { error?: string };

      if (!response.ok) {
        throw new Error(
          "error" in payload ? payload.error ?? "The scan failed." : "The scan failed.",
        );
      }

      setResult(payload as ScanResult);
    } catch (scanError) {
      setResult(null);
      setError(
        scanError instanceof Error
          ? scanError.message
          : "The scan failed unexpectedly.",
      );
    }
  }

  return (
    <div className="glass-panel terminal-edge scan-glow scroll-shell rounded-[32px] p-5 md:p-6">
      <div className="mb-6 flex items-center justify-between gap-3">
        <div>
          <div className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
            Live scanner
          </div>
          <p className="mt-2 text-sm leading-6 text-muted">
            Enter a URL and get a weighted report with practical next steps.
          </p>
        </div>
        <Badge variant="outline" className="hidden md:inline-flex">
          Node runtime checks
        </Badge>
      </div>

      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="space-y-2">
          <label
            htmlFor="target-url"
            className="font-mono text-xs uppercase tracking-[0.28em] text-muted"
          >
            Target URL
          </label>
          <div className="flex flex-col gap-3 md:flex-row">
            <Input
              id="target-url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              className="md:flex-1"
            />
            <Button type="submit" className="md:w-40" disabled={isPending}>
              {isPending ? "Scanning..." : "Scan Now"}
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {sampleTargets.map((target) => (
            <button
              key={target}
              type="button"
              className="rounded-full border border-line bg-white/5 px-3 py-1.5 font-mono text-xs text-muted hover:border-accent/30 hover:text-white"
              onClick={() => setUrl(target)}
            >
              {target}
            </button>
          ))}
        </div>
      </form>

      {error ? (
        <div className="mt-5 flex items-start gap-3 rounded-3xl border border-danger/20 bg-danger/10 p-4 text-sm text-white">
          <AlertTriangle className="mt-0.5 h-4 w-4 text-danger" />
          <p>{error}</p>
        </div>
      ) : null}

      {isPending ? (
        <div className="mt-6 rounded-[28px] border border-line bg-slate-950/45 p-5">
          <div className="flex items-center gap-3">
            <div className="h-2.5 w-2.5 animate-pulse rounded-full bg-accent" />
            <div className="font-mono text-xs uppercase tracking-[0.28em] text-accent/80">
              Scan in progress
            </div>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {[
              "Tracing redirects and final origin",
              "Inspecting TLS certificate and protocol",
              "Reviewing headers, cookies, and stack signals",
              "Checking DNS posture and public exposures",
            ].map((step) => (
              <div
                key={step}
                className="rounded-2xl border border-line/80 bg-white/4 px-4 py-3 text-sm text-muted"
              >
                {step}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {result ? <ScanReport result={result} /> : null}
    </div>
  );
}

function ScanReport({ result }: { result: ScanResult }) {
  return (
    <div className="mt-6 space-y-6">
      <Card className="border-line bg-slate-950/55">
        <CardContent className="grid gap-6 p-6 lg:grid-cols-[auto_1fr]">
          <div className="flex items-center justify-center">
            <ScoreRing score={result.score} grade={result.grade} />
          </div>

          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <Badge
                variant={result.aiEnhanced ? "success" : "outline"}
                className="font-mono uppercase"
              >
                {result.aiEnhanced ? "AI-enhanced summary" : "Rules-based summary"}
              </Badge>
              <Badge variant={result.stored ? "success" : "outline"}>
                {result.stored ? "Scan saved" : "Storage not configured"}
              </Badge>
            </div>

            <div>
              <h3 className="text-2xl font-semibold text-white">
                {result.hostname}
              </h3>
              <p className="mt-2 max-w-3xl text-sm leading-7 text-muted">
                {result.summary}
              </p>
            </div>

            <div className="rounded-3xl border border-line bg-white/4 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
                <Bot className="h-4 w-4 text-accent" />
                AI report narrative
              </div>
              <p className="whitespace-pre-line text-sm leading-7 text-muted">
                {result.aiSummary}
              </p>
            </div>

            <div className="flex flex-wrap gap-2 text-xs text-muted">
              <MetaPill label="Target" value={result.normalizedUrl} />
              <MetaPill
                label="Resolved IP"
                value={result.resolvedIpAddress ?? "Unavailable"}
              />
              <MetaPill label="Generated" value={formatDate(result.generatedAt)} />
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        {result.categories.map((category) => (
          <CategoryCard key={category.id} category={category} />
        ))}
      </div>

      <Card className="border-line bg-slate-950/55">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-lg text-white">
            <Globe className="h-5 w-5 text-accent-2" />
            Redirect trace
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {result.redirectChain.map((hop, index) => (
            <div
              key={`${hop.url}-${index}`}
              className="flex flex-col gap-2 rounded-2xl border border-line/80 bg-white/4 p-4 text-sm md:flex-row md:items-center md:justify-between"
            >
              <div className="font-mono text-xs text-accent/80">
                STEP {index + 1}
              </div>
              <div className="min-w-0 flex-1 text-white md:px-4">
                <div className="truncate">{hop.url}</div>
                {hop.location ? (
                  <div className="mt-1 truncate text-xs text-muted">
                    Location: {hop.location}
                  </div>
                ) : null}
              </div>
              <Badge
                variant={hop.status && hop.status >= 400 ? "destructive" : "outline"}
              >
                {hop.status ?? "ERR"}
              </Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function CategoryCard({ category }: { category: ScanCategory }) {
  const Icon = categoryIcons[category.id];
  const progress = `${Math.round((category.score / category.maxScore) * 100)}%`;

  return (
    <Card className="border-line bg-slate-950/55">
      <CardHeader className="pb-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="mt-1 flex h-11 w-11 items-center justify-center rounded-2xl border border-line bg-white/5 text-accent">
              <Icon className="h-5 w-5" />
            </div>
            <div>
              <CardTitle className="text-xl text-white">
                {category.label}
              </CardTitle>
              <p className="mt-2 text-sm leading-7 text-muted">
                {category.summary}
              </p>
            </div>
          </div>
          <StatusBadge status={category.status} />
        </div>

        <div className="mt-4">
          <div className="mb-2 flex items-center justify-between text-xs text-muted">
            <span className="font-mono uppercase tracking-[0.28em]">Score</span>
            <span className="font-mono">{progress}</span>
          </div>
          <div className="h-2 rounded-full bg-white/8">
            <div
              className={cn(
                "h-2 rounded-full",
                category.status === "pass" && "bg-success",
                category.status === "info" && "bg-accent-2",
                category.status === "warning" && "bg-warning",
                category.status === "fail" && "bg-danger",
              )}
              style={{
                width: progress,
              }}
            />
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {category.findings.map((finding) => (
          <div
            key={finding.id}
            className="rounded-2xl border border-line/80 bg-white/4 p-4"
          >
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-sm font-medium text-white">
                {finding.title}
              </div>
              <StatusBadge status={finding.status} compact />
            </div>
            <p className="mt-2 text-sm leading-7 text-muted">
              {finding.summary}
            </p>
            {finding.recommendation ? (
              <p className="mt-2 text-sm leading-7 text-accent/90">
                Fix: {finding.recommendation}
              </p>
            ) : null}
            {finding.details?.length ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {finding.details.map((detail) => (
                  <div
                    key={detail}
                    className="rounded-full border border-line bg-slate-950/55 px-3 py-1 font-mono text-[11px] text-muted"
                  >
                    {detail}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ))}

        {category.data ? (
          <details className="rounded-2xl border border-line/80 bg-slate-950/60 p-4">
            <summary className="cursor-pointer text-sm font-medium text-white">
              Technical details
            </summary>
            <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs leading-6 text-muted">
              {JSON.stringify(category.data, null, 2)}
            </pre>
          </details>
        ) : null}
      </CardContent>
    </Card>
  );
}

function MetaPill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-full border border-line bg-white/4 px-3 py-1.5">
      <span className="font-mono uppercase tracking-[0.24em] text-accent/75">
        {label}
      </span>
      <span className="ml-2 text-white/90">{value}</span>
    </div>
  );
}

function StatusBadge({
  status,
  compact = false,
}: {
  status: ScanCategory["status"];
  compact?: boolean;
}) {
  const labels = {
    pass: "Pass",
    info: "Info",
    warning: "Warn",
    fail: "Fail",
  } as const;

  const variant =
    status === "pass"
      ? "success"
      : status === "warning"
        ? "warning"
        : status === "fail"
          ? "destructive"
          : "outline";

  return (
    <Badge
      variant={variant}
      className={cn("font-mono uppercase", compact && "px-2 py-0.5 text-[10px]")}
    >
      {labels[status]}
    </Badge>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}
