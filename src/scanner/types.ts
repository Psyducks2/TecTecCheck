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

export interface SiteIdentification {
  finalUrl: string;
  httpVersion: string;
  statusCode: number;
  headers: Record<string, string>;
  server?: string;
  poweredBy?: string;
  contentType?: string;
  redirectChain: { url: string; status: number; headers: Record<string, string> }[];
  tls?: { protocol: string; cipher: string };
  title?: string;
  metaDescription?: string;
  technologies: string[];
}

export interface ScanContext {
  url: string;
  scanId: string;
  initialResponse?: InitialResponse;
  siteIdentification?: SiteIdentification;
}

export interface IScannerModule {
  name: string;
  execute(ctx: ScanContext): Promise<Finding[]>;
}
