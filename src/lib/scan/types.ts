export type FindingStatus = "pass" | "warning" | "fail" | "info";
export type Severity = "info" | "low" | "medium" | "high";

export type ScanCategoryId =
  | "ssl"
  | "headers"
  | "dns"
  | "ports"
  | "technology"
  | "cookies"
  | "exposed-files"
  | "redirects";

export interface Finding {
  id: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  summary: string;
  recommendation?: string;
  details?: string[];
}

export interface ScanCategory {
  id: ScanCategoryId;
  label: string;
  score: number;
  maxScore: number;
  status: FindingStatus;
  summary: string;
  findings: Finding[];
  data?: Record<string, unknown>;
}

export interface RedirectHop {
  url: string;
  status: number | null;
  location?: string | null;
}

export interface ScanResult {
  targetUrl: string;
  normalizedUrl: string;
  hostname: string;
  resolvedIpAddress?: string | null;
  generatedAt: string;
  score: number;
  grade: string;
  summary: string;
  aiSummary: string;
  aiEnhanced: boolean;
  stored: boolean;
  categories: ScanCategory[];
  redirectChain: RedirectHop[];
}
