import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { ReconModule } from "../../src/scanner/modules/recon.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("ReconModule", () => {
  const module = new ReconModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("retorna vazio quando alvo está online", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ status: 200 });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("retorna finding CRITICAL quando alvo não responde", async () => {
    mockedAxios.get = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("CRITICAL");
    expect(findings[0]!.type).toBe("TARGET_UNREACHABLE");
  });
});
