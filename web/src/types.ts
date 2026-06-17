export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ModuleName =
  | "recon"
  | "identification"
  | "headers"
  | "fuzzer"
  | "fingerprint";

export interface ScanConfig {
  headers?: Record<string, string>;
  excludePaths?: string[];
  maxRps?: number;
  modules?: ModuleName[];
}

export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";

export interface Vulnerability {
  id: string;
  module: string;
  type: string;
  severity: Severity;
  description: string;
  evidence: string | null;
}

export interface ScanReport {
  scanId: string;
  url: string;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  vulnerabilities: Vulnerability[];
}

export interface Health {
  status: "ok" | "degraded";
  checks: { db: boolean; redis: boolean };
}
