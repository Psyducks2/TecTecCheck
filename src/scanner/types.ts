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

export interface ScanContext {
  url: string;
  scanId: string;
  config?: ScanConfig;
  initialResponse?: InitialResponse;
  siteIdentification?: SiteIdentification;
}

export interface IScannerModule {
  name: string;
  execute(ctx: ScanContext): Promise<Finding[]>;
}
