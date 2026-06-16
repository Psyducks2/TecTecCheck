import type { Severity, Vulnerability } from "./types";

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export interface SeverityGroupData {
  severity: Severity;
  items: Vulnerability[];
}

export function groupBySeverity(items: Vulnerability[]): SeverityGroupData[] {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    items: items.filter((v) => v.severity === severity),
  }));
}
