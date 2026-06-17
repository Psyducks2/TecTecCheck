import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

interface HeaderRule {
  header: string;
  type: string;
  severity: Finding["severity"];
  description: string;
}

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const REQUIRED_HEADERS: HeaderRule[] = [
  {
    header: "strict-transport-security",
    type: "MISSING_HSTS",
    severity: "MEDIUM",
    description: "Header Strict-Transport-Security ausente. Permite ataques de downgrade HTTP.",
  },
  {
    header: "content-security-policy",
    type: "MISSING_CONTENT_SECURITY_POLICY",
    severity: "HIGH",
    description: "Header Content-Security-Policy ausente. Aumenta superfície de ataques XSS.",
  },
  {
    header: "x-frame-options",
    type: "MISSING_X_FRAME_OPTIONS",
    severity: "MEDIUM",
    description: "Header X-Frame-Options ausente. Permite ataques de Clickjacking.",
  },
  {
    header: "x-content-type-options",
    type: "MISSING_X_CONTENT_TYPE_OPTIONS",
    severity: "LOW",
    description: "Header X-Content-Type-Options ausente. Permite MIME-type sniffing.",
  },
  {
    header: "referrer-policy",
    type: "MISSING_REFERRER_POLICY",
    severity: "LOW",
    description: "Header Referrer-Policy ausente. Pode vazar URLs sensíveis via Referer.",
  },
  {
    header: "permissions-policy",
    type: "MISSING_PERMISSIONS_POLICY",
    severity: "LOW",
    description: "Header Permissions-Policy ausente. Não restringe acesso a features do browser (câmera, microfone, etc.).",
  },
  {
    header: "cross-origin-opener-policy",
    type: "MISSING_COOP",
    severity: "LOW",
    description: "Header Cross-Origin-Opener-Policy ausente. Permite ataques de Spectre via janelas cross-origin.",
  },
  {
    header: "cross-origin-resource-policy",
    type: "MISSING_CORP",
    severity: "LOW",
    description: "Header Cross-Origin-Resource-Policy ausente. Permite embedding de recursos cross-origin não autorizado.",
  },
  {
    header: "cross-origin-embedder-policy",
    type: "MISSING_COEP",
    severity: "LOW",
    description: "Header Cross-Origin-Embedder-Policy ausente. Necessário para isolar contexto de navegação.",
  },
];

export class HeadersModule implements IScannerModule {
  name = "headers";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    let responseHeaders: Record<string, string>;

    if (ctx.initialResponse) {
      responseHeaders = ctx.initialResponse.headers;
    } else {
      const response = await axios.get(ctx.url, {
        timeout: 30000,
        validateStatus: () => true,
        headers: { "User-Agent": UA, ...(ctx.config?.headers ?? {}) },
      });
      responseHeaders = response.headers as Record<string, string>;
    }

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
