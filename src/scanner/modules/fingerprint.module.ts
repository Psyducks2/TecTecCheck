import axios from "axios";
import * as cheerio from "cheerio";
import type { Finding, IScannerModule, ScanContext } from "../types";

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
  {
    name: "React",
    pattern: /__REACT_DEVTOOLS_GLOBAL_HOOK__|react\.development\.js/i,
  },
  { name: "Next.js", pattern: /__NEXT_DATA__/i },
];

export class FingerprintModule implements IScannerModule {
  name = "fingerprint";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    const response = await axios.get(ctx.url, { timeout: 5000 });
    const headers = response.headers as Record<string, string>;
    const html = response.data as string;
    const findings: Finding[] = [];

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

    return findings;
  }
}
