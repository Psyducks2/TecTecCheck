import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

interface HeaderRule {
  header: string;
  type: string;
  severity: Finding["severity"];
  description: string;
}

const REQUIRED_HEADERS: HeaderRule[] = [
  {
    header: "strict-transport-security",
    type: "MISSING_HSTS",
    severity: "MEDIUM",
    description:
      "Header Strict-Transport-Security ausente. Permite ataques de downgrade HTTP.",
  },
  {
    header: "content-security-policy",
    type: "MISSING_CONTENT_SECURITY_POLICY",
    severity: "HIGH",
    description:
      "Header Content-Security-Policy ausente. Aumenta superfície de ataques XSS.",
  },
  {
    header: "x-frame-options",
    type: "MISSING_X_FRAME_OPTIONS",
    severity: "MEDIUM",
    description:
      "Header X-Frame-Options ausente. Permite ataques de Clickjacking.",
  },
  {
    header: "x-content-type-options",
    type: "MISSING_X_CONTENT_TYPE_OPTIONS",
    severity: "LOW",
    description:
      "Header X-Content-Type-Options ausente. Permite MIME-type sniffing.",
  },
  {
    header: "referrer-policy",
    type: "MISSING_REFERRER_POLICY",
    severity: "LOW",
    description:
      "Header Referrer-Policy ausente. Pode vazar URLs sensíveis via Referer.",
  },
];

export class HeadersModule implements IScannerModule {
  name = "headers";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    const response = await axios.get(ctx.url, { timeout: 5000 });
    const responseHeaders = response.headers as Record<string, string>;
    const findings: Finding[] = [];

    for (const rule of REQUIRED_HEADERS) {
      if (!responseHeaders[rule.header]) {
        findings.push({
          module: this.name,
          type: rule.type,
          severity: rule.severity,
          description: rule.description,
          evidence: `Header '${rule.header}' não encontrado na resposta de GET ${ctx.url}`,
        });
      }
    }

    return findings;
  }
}
