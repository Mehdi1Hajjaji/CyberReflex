export type CheckStatus = "pass" | "warning" | "fail" | "info" | "error";

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type CheckId =
  | "ssl"
  | "headers"
  | "dns"
  | "ports"
  | "tech"
  | "cookies"
  | "files"
  | "redirects";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface CheckFinding {
  id: string;
  title: string;
  status: CheckStatus;
  severity: FindingSeverity;
  summary: string;
  recommendation?: string;
  evidence?: JsonValue;
}

export interface ScanCheckResult {
  id: CheckId;
  name: string;
  status: CheckStatus;
  summary: string;
  findings: CheckFinding[];
  raw: JsonObject;
}

export interface NormalizedTarget {
  input: string;
  url: string;
  origin: string;
  hostname: string;
  protocol: "http:" | "https:";
  registeredDomain: string;
}

export interface RedirectHop {
  url: string;
  status: number | null;
  location: string | null;
}

