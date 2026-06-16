import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { FingerprintModule } from "../../src/scanner/modules/fingerprint.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("FingerprintModule", () => {
  const module = new FingerprintModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("detecta PHP via header X-Powered-By", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: { "x-powered-by": "PHP/7.4.33" },
      data: "<html></html>",
    });
    const findings = await module.execute(ctx);
    const phpFinding = findings.find((f) =>
      f.description.includes("PHP/7.4.33")
    );
    expect(phpFinding).toBeDefined();
    expect(phpFinding!.severity).toBe("LOW");
  });

  it("detecta WordPress via assinatura no HTML", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {},
      data: '<link rel="stylesheet" href="/wp-content/themes/twentyone/style.css">',
    });
    const findings = await module.execute(ctx);
    const wpFinding = findings.find((f) => f.description.includes("WordPress"));
    expect(wpFinding).toBeDefined();
  });

  it("não reporta findings quando sem assinaturas conhecidas", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {},
      data: "<html><body>Hello</body></html>",
    });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });
});
