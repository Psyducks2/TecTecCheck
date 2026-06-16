import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { FingerprintModule } from "../../src/scanner/modules/fingerprint.module";
import type { ScanContext } from "../../src/scanner/types";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("FingerprintModule", () => {
  const ctx: ScanContext = { url: "https://example.com", scanId: "scan-001" };

  it("detecta PHP via header X-Powered-By (axios path)", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: { "x-powered-by": "PHP/7.4.33" },
      data: "<html></html>",
    });
    const findings = await new FingerprintModule().execute(ctx);
    const phpFinding = findings.find((f) => f.description.includes("PHP/7.4.33"));
    expect(phpFinding).toBeDefined();
    expect(phpFinding!.severity).toBe("LOW");
  });

  it("detecta WordPress via assinatura no HTML (axios path)", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {},
      data: '<link rel="stylesheet" href="/wp-content/themes/twentyone/style.css">',
    });
    const findings = await new FingerprintModule().execute(ctx);
    const wpFinding = findings.find((f) => f.description.includes("WordPress"));
    expect(wpFinding).toBeDefined();
  });

  it("não reporta findings quando sem assinaturas conhecidas", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {},
      data: "<html><body>Hello</body></html>",
    });
    const findings = await new FingerprintModule().execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("usa ctx.initialResponse em vez de fazer request HTTP", async () => {
    const axiosSpy = vi.spyOn(axios, "get");
    vi.clearAllMocks();
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: { status: 200, headers: {}, data: "<html></html>" },
    };
    await new FingerprintModule().execute(ctxWithResponse);
    expect(axiosSpy).not.toHaveBeenCalled();
  });

  it("detecta tecnologia via meta generator", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: {
        status: 200,
        headers: {},
        data: '<html><head><meta name="generator" content="WordPress 6.3" /></head></html>',
      },
    };
    const findings = await new FingerprintModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.description.includes("WordPress 6.3"))).toBe(true);
  });

  it("detecta PHP via cookie PHPSESSID", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: {
        status: 200,
        headers: { "set-cookie": "PHPSESSID=abc123; path=/" },
        data: "",
      },
    };
    const findings = await new FingerprintModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.description.toLowerCase().includes("php"))).toBe(true);
  });

  it("detecta Java via cookie JSESSIONID", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: {
        status: 200,
        headers: { "set-cookie": "JSESSIONID=xyz; path=/" },
        data: "",
      },
    };
    const findings = await new FingerprintModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.description.toLowerCase().includes("java"))).toBe(true);
  });

  it("detecta Cloudflare via header cf-ray", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: {
        status: 200,
        headers: { "cf-ray": "7d123abc-GRU" },
        data: "",
      },
    };
    const findings = await new FingerprintModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.description.includes("Cloudflare"))).toBe(true);
  });

  it("detecta Amazon CloudFront via header x-amz-cf-id", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: {
        status: 200,
        headers: { "x-amz-cf-id": "abc123" },
        data: "",
      },
    };
    const findings = await new FingerprintModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.description.includes("CloudFront"))).toBe(true);
  });
});
