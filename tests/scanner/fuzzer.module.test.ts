import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { FuzzerModule } from "../../src/scanner/modules/fuzzer.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("FuzzerModule", () => {
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("reporta finding HIGH para rota /admin com status 200", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/admin")) return Promise.resolve({ status: 200, headers: {} });
      return Promise.resolve({ status: 404, headers: {} });
    });
    const findings = await new FuzzerModule().execute(ctx);
    const adminFinding = findings.find((f) => f.evidence?.includes("/admin"));
    expect(adminFinding).toBeDefined();
    expect(adminFinding!.severity).toBe("HIGH");
  });

  it("reporta finding CRITICAL para /.env com status 200", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/.env")) return Promise.resolve({ status: 200, headers: {} });
      return Promise.resolve({ status: 404, headers: {} });
    });
    const findings = await new FuzzerModule().execute(ctx);
    const envFinding = findings.find((f) => f.evidence?.includes("/.env"));
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe("CRITICAL");
  });

  it("não reporta findings para status 404", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ status: 404, headers: {} });
    const findings = await new FuzzerModule().execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("reporta finding AUTH_REQUIRED para rota /admin com status 401", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/admin")) return Promise.resolve({ status: 401, headers: {} });
      return Promise.resolve({ status: 404, headers: {} });
    });
    const findings = await new FuzzerModule().execute(ctx);
    const authFinding = findings.find((f) => f.evidence?.includes("/admin") && f.type === "AUTH_REQUIRED");
    expect(authFinding).toBeDefined();
    expect(authFinding!.type).toBe("AUTH_REQUIRED");
  });

  it("reporta finding REDIRECT para rota com status 301", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/admin")) return Promise.resolve({ status: 301, headers: { location: "/login" } });
      return Promise.resolve({ status: 404, headers: {} });
    });
    const findings = await new FuzzerModule().execute(ctx);
    const redirectFinding = findings.find((f) => f.type === "REDIRECT" && f.evidence?.includes("301"));
    expect(redirectFinding).toBeDefined();
    expect(redirectFinding!.evidence).toContain("/login");
  });

  it("reporta finding REDIRECT para rota com status 302", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/dashboard")) return Promise.resolve({ status: 302, headers: { location: "/auth" } });
      return Promise.resolve({ status: 404, headers: {} });
    });
    const findings = await new FuzzerModule().execute(ctx);
    const redirectFinding = findings.find((f) => f.type === "REDIRECT" && f.evidence?.includes("302"));
    expect(redirectFinding).toBeDefined();
  });
});
