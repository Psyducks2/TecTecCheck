import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { HeadersModule } from "../../src/scanner/modules/headers.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("HeadersModule", () => {
  const module = new HeadersModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("não reporta findings quando todos os headers estão presentes", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("reporta finding MEDIUM para header HSTS ausente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ headers: {} });
    const findings = await module.execute(ctx);
    const hstsFinding = findings.find((f) => f.type === "MISSING_HSTS");
    expect(hstsFinding).toBeDefined();
    expect(hstsFinding!.severity).toBe("MEDIUM");
  });

  it("reporta finding HIGH para CSP ausente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ headers: {} });
    const findings = await module.execute(ctx);
    const cspFinding = findings.find(
      (f) => f.type === "MISSING_CONTENT_SECURITY_POLICY"
    );
    expect(cspFinding).toBeDefined();
    expect(cspFinding!.severity).toBe("HIGH");
  });
});
