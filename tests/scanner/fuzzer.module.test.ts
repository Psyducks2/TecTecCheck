import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { FuzzerModule } from "../../src/scanner/modules/fuzzer.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("FuzzerModule", () => {
  const module = new FuzzerModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("reporta finding HIGH para rota /admin com status 200", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/admin")) return Promise.resolve({ status: 200 });
      return Promise.resolve({ status: 404 });
    });
    const findings = await module.execute(ctx);
    const adminFinding = findings.find((f) => f.evidence?.includes("/admin"));
    expect(adminFinding).toBeDefined();
    expect(adminFinding!.severity).toBe("HIGH");
  });

  it("reporta finding CRITICAL para /.env com status 200", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/.env")) return Promise.resolve({ status: 200 });
      return Promise.resolve({ status: 404 });
    });
    const findings = await module.execute(ctx);
    const envFinding = findings.find((f) => f.evidence?.includes("/.env"));
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe("CRITICAL");
  });

  it("não reporta findings para status 404", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ status: 404 });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });
});
