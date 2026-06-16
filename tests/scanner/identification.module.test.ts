import { describe, it, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import { IdentificationModule } from "../../src/scanner/modules/identification.module";
import type { ScanContext } from "../../src/scanner/types";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("IdentificationModule", () => {
  let ctx: ScanContext;

  beforeEach(() => {
    ctx = { url: "https://example.com", scanId: "scan-001" };
    vi.clearAllMocks();
  });

  it("extrai informações básicas do site", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: {
        server: "nginx/1.24.0",
        "content-type": "text/html; charset=UTF-8",
        "x-powered-by": "PHP/8.2.10",
      },
      data: '<html><head><title>Meu Site</title><meta name="description" content="Site example"></head><body></body></html>',
      request: { res: { httpVersion: "1.1", responseUrl: "https://example.com" } },
    });

    const findings = await new IdentificationModule().execute(ctx);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const idFinding = findings.find((f) => f.type === "SITE_IDENTIFICATION");
    expect(idFinding).toBeDefined();
    expect(idFinding!.description).toContain("Meu Site");
    expect(idFinding!.description).toContain("nginx/1.24.0");
    expect(idFinding!.description).toContain("PHP/8.2.10");

    expect(ctx.siteIdentification).toBeDefined();
    expect(ctx.siteIdentification!.title).toBe("Meu Site");
    expect(ctx.siteIdentification!.server).toBe("nginx/1.24.0");
    expect(ctx.siteIdentification!.poweredBy).toBe("PHP/8.2.10");
    expect(ctx.siteIdentification!.metaDescription).toBe("Site example");
  });

  it("reporta SERVER_DISCLOSURE quando X-Powered-By está presente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: { "x-powered-by": "Express" },
      data: "<html></html>",
      request: { res: { httpVersion: "1.1", responseUrl: "https://example.com" } },
    });

    const findings = await new IdentificationModule().execute(ctx);
    const disclosure = findings.find((f) => f.type === "SERVER_DISCLOSURE");
    expect(disclosure).toBeDefined();
    expect(disclosure!.severity).toBe("LOW");
    expect(disclosure!.evidence).toContain("Express");
  });

  it("reporta SERVER_VERSION_DISCLOSURE quando Server contém número", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: { server: "Apache/2.4.57" },
      data: "<html></html>",
      request: { res: { httpVersion: "1.1", responseUrl: "https://example.com" } },
    });

    const findings = await new IdentificationModule().execute(ctx);
    const versionFinding = findings.find((f) => f.type === "SERVER_VERSION_DISCLOSURE");
    expect(versionFinding).toBeDefined();
    expect(versionFinding!.severity).toBe("LOW");
    expect(versionFinding!.evidence).toContain("Apache/2.4.57");
  });

  it("segue redirecionamentos e registra a cadeia", async () => {
    mockedAxios.get = vi.fn()
      .mockResolvedValueOnce({
        status: 301,
        headers: { location: "https://www.example.com/" },
        data: "",
        request: { res: { httpVersion: "1.1" } },
      })
      .mockResolvedValueOnce({
        status: 200,
        headers: { server: "nginx" },
        data: "<html><title>Example</title></html>",
        request: { res: { httpVersion: "1.1", responseUrl: "https://www.example.com/" } },
      });

    const findings = await new IdentificationModule().execute(ctx);

    expect(ctx.siteIdentification).toBeDefined();
    expect(ctx.siteIdentification!.redirectChain).toHaveLength(1);
    expect(ctx.siteIdentification!.redirectChain[0].status).toBe(301);
    expect(ctx.siteIdentification!.statusCode).toBe(200);
    expect(ctx.siteIdentification!.finalUrl).toBe("https://www.example.com/");
  });

  it("detecta Cloudflare via header cf-ray", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: { server: "cloudflare", "cf-ray": "abc123-GRU" },
      data: "<html></html>",
      request: { res: { httpVersion: "1.1", responseUrl: "https://example.com" } },
    });

    const findings = await new IdentificationModule().execute(ctx);
    expect(ctx.siteIdentification!.technologies).toContain("Cloudflare");
    expect(ctx.siteIdentification!.technologies).toContain("cloudflare");
  });

  it("evidência contém formato curl -I style", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: {
        server: "nginx",
        "content-type": "text/html",
        "x-powered-by": "PHP/8.2",
      },
      data: "<html></html>",
      request: { res: { httpVersion: "1.1", responseUrl: "https://example.com" } },
    });

    const findings = await new IdentificationModule().execute(ctx);
    const idFinding = findings.find((f) => f.type === "SITE_IDENTIFICATION");
    expect(idFinding!.evidence).toContain("< HTTP/1.1 200");
    expect(idFinding!.evidence).toContain("< server: nginx");
    expect(idFinding!.evidence).toContain("< content-type: text/html");
    expect(idFinding!.evidence).toContain("< x-powered-by: PHP/8.2");
  });

  it("armazena ctx.siteIdentification para uso por outros módulos", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: {},
      data: "<html></html>",
      request: { res: { httpVersion: "1.1", responseUrl: "https://example.com" } },
    });

    await new IdentificationModule().execute(ctx);

    expect(ctx.siteIdentification).toBeDefined();
    expect(ctx.siteIdentification!.statusCode).toBe(200);
    expect(ctx.siteIdentification!.httpVersion).toBe("HTTP/1.1");
  });
});
