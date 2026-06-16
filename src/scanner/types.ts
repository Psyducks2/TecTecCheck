export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Finding {
  module: string;
  type: string;
  severity: Severity;
  description: string;
  evidence?: string;
}

export interface ScanContext {
  url: string;
  scanId: string;
}

export interface IScannerModule {
  name: string;
  execute(ctx: ScanContext): Promise<Finding[]>;
}
