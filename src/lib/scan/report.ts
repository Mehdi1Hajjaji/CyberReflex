import {
  analyzeCookies,
  analyzeDnsConfiguration,
  analyzeExposedFiles,
  analyzeOpenPorts,
  analyzeRedirects,
  analyzeSecurityHeaders,
  analyzeSslTls,
  analyzeTechnologyDisclosure,
  fetchPageSnapshot,
  lookupIpAddress,
  traceRedirectChain,
} from "./checks";
import { generateAiSummary } from "./ai";
import type { ScanCategory, ScanResult } from "./types";
import { normalizeUrl, scoreToGrade } from "./utils";

export async function runSecurityScan(targetUrl: string): Promise<ScanResult> {
  const initialUrl = normalizeUrl(targetUrl);
  const redirectTrace = await traceRedirectChain(initialUrl.toString());
  const finalUrl = normalizeUrl(redirectTrace.finalUrl);

  const [snapshot, resolvedIpAddress] = await Promise.all([
    fetchPageSnapshot(finalUrl.toString()),
    lookupIpAddress(finalUrl.hostname),
  ]);

  const [
    sslCategory,
    dnsCategory,
    portsCategory,
    exposedFilesCategory,
  ] = await Promise.all([
    analyzeSslTls(finalUrl.hostname, finalUrl.protocol),
    analyzeDnsConfiguration(finalUrl.hostname),
    analyzeOpenPorts(finalUrl.hostname),
    analyzeExposedFiles(finalUrl.origin),
  ]);

  const categories: ScanCategory[] = [
    sslCategory,
    analyzeSecurityHeaders(snapshot, finalUrl),
    dnsCategory,
    portsCategory,
    analyzeTechnologyDisclosure(snapshot),
    analyzeCookies(snapshot, finalUrl),
    exposedFilesCategory,
    analyzeRedirects(redirectTrace),
  ];

  const totalPoints = categories.reduce(
    (sum, category) => sum + category.maxScore,
    0,
  );
  const earnedPoints = categories.reduce((sum, category) => sum + category.score, 0);
  const score = Math.round((earnedPoints / totalPoints) * 100);
  const grade = scoreToGrade(score);
  const summary = buildRulesSummary(categories, grade, score);
  const { text: aiSummary, aiEnhanced } = await generateAiSummary({
    hostname: finalUrl.hostname,
    score,
    grade,
    categories,
  });

  return {
    targetUrl,
    normalizedUrl: finalUrl.toString(),
    hostname: finalUrl.hostname,
    resolvedIpAddress,
    generatedAt: new Date().toISOString(),
    score,
    grade,
    summary,
    aiSummary,
    aiEnhanced,
    stored: false,
    categories,
    redirectChain: redirectTrace.hops,
  };
}

function buildRulesSummary(
  categories: ScanCategory[],
  grade: string,
  score: number,
) {
  const topIssues = categories
    .flatMap((category) =>
      category.findings
        .filter((finding) => finding.status === "fail" || finding.status === "warning")
        .map((finding) => finding.title),
    )
    .slice(0, 3);

  if (!topIssues.length) {
    return `Grade ${grade} (${score}/100). The initial scan did not confirm major weaknesses across TLS, headers, DNS, cookies, exposure probes, or redirect handling.`;
  }

  return `Grade ${grade} (${score}/100). The main issues surfaced in this pass are ${topIssues.join(
    ", ",
  )}.`;
}
