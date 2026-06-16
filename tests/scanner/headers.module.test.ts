import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { HeadersModule } from "../../src/scanner/modules/headers.module";
import type { ScanContext } from "../../src/scanner/types";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("HeadersModule", () => {
  const ctx: ScanContext = { url: "https://example.com", scanId: "scan-001" };

  it("não reporta findings quando todos os headers estão presentes (via axios)", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
      },
    });
    const findings = await new HeadersModule().execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("reporta finding MEDIUM para header HSTS ausente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ headers: {} });
    const findings = await new HeadersModule().execute(ctx);
    const hstsFinding = findings.find((f) => f.type === "MISSING_HSTS");
    expect(hstsFinding).toBeDefined();
    expect(hstsFinding!.severity).toBe("MEDIUM");
  });

  it("reporta finding HIGH para CSP ausente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ headers: {} });
    const findings = await new HeadersModule().execute(ctx);
    const cspFinding = findings.find((f) => f.type === "MISSING_CONTENT_SECURITY_POLICY");
    expect(cspFinding).toBeDefined();
    expect(cspFinding!.severity).toBe("HIGH");
  });

  it("usa ctx.initialResponse em vez de fazer request HTTP", async () => {
    vi.clearAllMocks();
    const axiosSpy = vi.spyOn(axios, "get");
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: { status: 200, headers: {}, data: "" },
    };
    await new HeadersModule().execute(ctxWithResponse);
    expect(axiosSpy).not.toHaveBeenCalled();
  });

  it("reporta MISSING_PERMISSIONS_POLICY quando ausente", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: { status: 200, headers: {}, data: "" },
    };
    const findings = await new HeadersModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.type === "MISSING_PERMISSIONS_POLICY")).toBe(true);
  });

  it("reporta MISSING_COOP quando ausente", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: { status: 200, headers: {}, data: "" },
    };
    const findings = await new HeadersModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.type === "MISSING_COOP")).toBe(true);
  });

  it("reporta MISSING_CORP quando ausente", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: { status: 200, headers: {}, data: "" },
    };
    const findings = await new HeadersModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.type === "MISSING_CORP")).toBe(true);
  });

  it("reporta MISSING_COEP quando ausente", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: { status: 200, headers: {}, data: "" },
    };
    const findings = await new HeadersModule().execute(ctxWithResponse);
    expect(findings.some((f) => f.type === "MISSING_COEP")).toBe(true);
  });

  it("não reporta findings quando todos headers presentes via ctx.initialResponse", async () => {
    const ctxWithResponse: ScanContext = {
      ...ctx,
      initialResponse: {
        status: 200,
        headers: {
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "permissions-policy": "camera=()",
          "cross-origin-opener-policy": "same-origin",
          "cross-origin-resource-policy": "same-origin",
          "cross-origin-embedder-policy": "require-corp",
        },
        data: "",
      },
    };
    const findings = await new HeadersModule().execute(ctxWithResponse);
    expect(findings).toHaveLength(0);
  });
});
