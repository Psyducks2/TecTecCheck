import axios from "axios";
import * as cheerio from "cheerio";
import type { Finding, IScannerModule, ScanContext } from "../types";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

interface HtmlSignature {
  name: string;
  pattern: RegExp;
}

const HTML_SIGNATURES: HtmlSignature[] = [
  { name: "WordPress", pattern: /wp-content|wp-includes/i },
  { name: "Joomla", pattern: /\/components\/com_/i },
  { name: "Drupal", pattern: /sites\/default\/files|drupal\.js/i },
  { name: "Laravel", pattern: /laravel_session/i },
  { name: "Django", pattern: /csrfmiddlewaretoken/i },
  { name: "React", pattern: /__REACT_DEVTOOLS_GLOBAL_HOOK__|react\.development\.js/i },
  { name: "Next.js", pattern: /__NEXT_DATA__/i },
];

interface CookieSignature {
  cookie: string;
  label: string;
}

const COOKIE_SIGNATURES: CookieSignature[] = [
  { cookie: "PHPSESSID", label: "PHP" },
  { cookie: "JSESSIONID", label: "Java (Servlet/JSP)" },
  { cookie: "_rails_session", label: "Ruby on Rails" },
  { cookie: "ASP.NET_SessionId", label: "ASP.NET" },
  { cookie: "connect.sid", label: "Node.js (Express/connect)" },
];

interface CdnSignature {
  header: string;
  label: string;
}

const CDN_SIGNATURES: CdnSignature[] = [
  { header: "cf-ray", label: "Cloudflare" },
  { header: "x-amz-cf-id", label: "Amazon CloudFront" },
  { header: "x-akamai-request-id", label: "Akamai" },
  { header: "x-fastly-request-id", label: "Fastly" },
];

export class FingerprintModule implements IScannerModule {
  name = "fingerprint";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    let headers: Record<string, string>;
    let html: string;

    if (ctx.initialResponse) {
      headers = ctx.initialResponse.headers;
      html = ctx.initialResponse.data;
    } else {
      const response = await axios.get(ctx.url, {
        timeout: 30000,
        validateStatus: () => true,
        headers: { "User-Agent": UA },
      });
      headers = response.headers as Record<string, string>;
      html = response.data as string;
    }

    const findings: Finding[] = [];

    // Server / X-Powered-By header
    const poweredBy = headers["x-powered-by"] ?? headers["server"];
    if (poweredBy) {
      findings.push({
        module: this.name,
        type: "TECHNOLOGY_DISCLOSURE",
        severity: "LOW",
        description: `Tecnologia exposta via header: ${poweredBy}`,
        evidence: `Header '${headers["x-powered-by"] ? "X-Powered-By" : "Server"}': ${poweredBy}`,
      });
    }

    // HTML body signatures
    const $ = cheerio.load(html);
    const bodyHtml = $.html();

    for (const sig of HTML_SIGNATURES) {
      if (sig.pattern.test(bodyHtml)) {
        findings.push({
          module: this.name,
          type: "TECHNOLOGY_DISCLOSURE",
          severity: "LOW",
          description: `${sig.name} detectado por assinatura no HTML`,
          evidence: `Padrão '${sig.pattern.source}' encontrado em ${ctx.url}`,
        });
      }
    }

    // Meta generator tag
    const generator = $('meta[name="generator"]').attr("content");
    if (generator) {
      findings.push({
        module: this.name,
        type: "TECHNOLOGY_DISCLOSURE",
        severity: "LOW",
        description: `Tecnologia detectada via meta generator: ${generator}`,
        evidence: `<meta name="generator" content="${generator}">`,
      });
    }

    // Cookie-based detection
    const setCookie = headers["set-cookie"] ?? "";
    for (const sig of COOKIE_SIGNATURES) {
      if (setCookie.includes(sig.cookie)) {
        findings.push({
          module: this.name,
          type: "TECHNOLOGY_DISCLOSURE",
          severity: "LOW",
          description: `${sig.label} detectado via cookie de sessão (${sig.cookie})`,
          evidence: `Set-Cookie contém '${sig.cookie}'`,
        });
      }
    }

    // CDN detection
    for (const sig of CDN_SIGNATURES) {
      if (headers[sig.header]) {
        findings.push({
          module: this.name,
          type: "TECHNOLOGY_DISCLOSURE",
          severity: "LOW",
          description: `CDN detectado: ${sig.label}`,
          evidence: `Header '${sig.header}': ${headers[sig.header]}`,
        });
      }
    }

    return findings;
  }
}
