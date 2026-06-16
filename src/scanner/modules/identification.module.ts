import axios, { type AxiosResponse } from "axios";
import * as cheerio from "cheerio";
import type { Finding, IScannerModule, ScanContext, SiteIdentification } from "../types";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const CHAIN_LIMIT = 10;

async function followRedirects(
  url: string,
  maxRedirects = CHAIN_LIMIT
): Promise<{ finalResponse: AxiosResponse; chain: SiteIdentification["redirectChain"] }> {
  const chain: SiteIdentification["redirectChain"] = [];
  let currentUrl = url;
  let response: AxiosResponse | null = null;

  for (let i = 0; i <= maxRedirects; i++) {
    response = await axios.get(currentUrl, {
      timeout: 30000,
      validateStatus: () => true,
      maxRedirects: 0,
      headers: { "User-Agent": UA },
    });

    const status = response.status;
    if (status >= 300 && status < 400) {
      const location = response.headers["location"] as string | undefined;
      if (!location) break;

      chain.push({
        url: currentUrl,
        status,
        headers: response.headers as Record<string, string>,
      });

      currentUrl = location.startsWith("http")
        ? location
        : new URL(location, currentUrl).href;
    } else {
      break;
    }
  }

  return { finalResponse: response!, chain };
}

export class IdentificationModule implements IScannerModule {
  name = "identification";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    const { finalResponse, chain } = await followRedirects(ctx.url);

    const headers = finalResponse.headers as Record<string, string>;
    const html = typeof finalResponse.data === "string" ? finalResponse.data : "";

    let httpVersion = "HTTP/1.1";
    const raw = finalResponse.request?.res?.httpVersion;
    if (raw) httpVersion = `HTTP/${raw}`;

    const tlsProtocol = finalResponse.request?.connection?.encrypted ? "TLS" : undefined;
    const tlsCipher = finalResponse.request?.connection?.getCipher?.()?.name;

    const $ = cheerio.load(html);
    const title = $("title").first().text().trim() || undefined;
    const metaDesc = $('meta[name="description"]').attr("content")?.trim() || undefined;

    const technologies: string[] = [];
    const poweredBy = headers["x-powered-by"];
    if (poweredBy) technologies.push(poweredBy);
    const serverHeader = headers["server"];
    if (serverHeader) technologies.push(serverHeader);

    const cdnHeaders: [string, string][] = [
      ["cf-ray", "Cloudflare"],
      ["x-amz-cf-id", "Amazon CloudFront"],
      ["x-akamai-request-id", "Akamai"],
      ["x-fastly-request-id", "Fastly"],
    ];
    for (const [h, label] of cdnHeaders) {
      if (headers[h]) technologies.push(label);
    }

    const id: SiteIdentification = {
      finalUrl: finalResponse.request?.res?.responseUrl || finalResponse.config?.url || ctx.url,
      httpVersion,
      statusCode: finalResponse.status,
      headers,
      server: serverHeader,
      poweredBy,
      contentType: headers["content-type"],
      redirectChain: chain,
      tls: tlsProtocol
        ? { protocol: tlsProtocol, cipher: tlsCipher ?? "unknown" }
        : undefined,
      title,
      metaDescription: metaDesc,
      technologies,
    };

    ctx.siteIdentification = id;

    const findings: Finding[] = [];

    findings.push({
      module: this.name,
      type: "SITE_IDENTIFICATION",
      severity: "LOW",
      description: this.buildSummary(id),
      evidence: this.buildEvidence(id),
    });

    if (poweredBy) {
      findings.push({
        module: this.name,
        type: "SERVER_DISCLOSURE",
        severity: "LOW",
        description: `Tecnologia exposta via header X-Powered-By: ${poweredBy}`,
        evidence: `X-Powered-By: ${poweredBy}`,
      });
    }

    if (serverHeader && /\d/.test(serverHeader)) {
      findings.push({
        module: this.name,
        type: "SERVER_VERSION_DISCLOSURE",
        severity: "LOW",
        description: `Versão do servidor exposta via header Server: ${serverHeader}`,
        evidence: `Server: ${serverHeader}`,
      });
    }

    return findings;
  }

  private buildSummary(id: SiteIdentification): string {
    const parts: string[] = [];
    parts.push(`URL final: ${id.finalUrl}`);
    parts.push(`Status: ${id.statusCode}`);
    if (id.server) parts.push(`Server: ${id.server}`);
    if (id.poweredBy) parts.push(`Powered-By: ${id.poweredBy}`);
    if (id.title) parts.push(`Título: ${id.title}`);
    if (id.redirectChain.length > 0) parts.push(`Redirects: ${id.redirectChain.length}`);
    if (id.tls) parts.push(`TLS: ${id.tls.protocol}`);
    if (id.technologies.length > 0) parts.push(`Tecnologias: ${id.technologies.join(", ")}`);
    return parts.join(" | ");
  }

  private buildEvidence(id: SiteIdentification): string {
    const lines: string[] = [];
    lines.push(`< HTTP/1.1 ${id.statusCode}`);
    for (const [key, value] of Object.entries(id.headers)) {
      if (key.startsWith("cf-") || key.startsWith("x-amz-") || key.startsWith("x-akamai-") || key.startsWith("x-fastly-")) continue;
      lines.push(`< ${key}: ${value}`);
    }
    if (id.redirectChain.length > 0) {
      lines.push("");
      lines.push("--- Redirecionamentos ---");
      for (const r of id.redirectChain) {
        lines.push(`${r.url} → ${r.status} → ${r.headers["location"] ?? "?"}`);
      }
    }
    return lines.join("\n");
  }
}
