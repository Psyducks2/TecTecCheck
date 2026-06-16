export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Finding {
  module: string;
  type: string;
  severity: Severity;
  description: string;
  evidence?: string;
}

export interface InitialResponse {
  status: number;
  headers: Record<string, string>;
  data: string;
}

export interface ScanContext {
  url: string;
  scanId: string;
  initialResponse?: InitialResponse;
}

export interface IScannerModule {
  name: string;
  execute(ctx: ScanContext): Promise<Finding[]>;
}
