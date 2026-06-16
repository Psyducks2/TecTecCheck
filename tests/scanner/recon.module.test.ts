import { describe, it, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import { ReconModule } from "../../src/scanner/modules/recon.module";
import type { ScanContext } from "../../src/scanner/types";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("ReconModule", () => {
  let ctx: ScanContext;

  beforeEach(() => {
    ctx = { url: "https://example.com", scanId: "scan-001" };
  });

  it("retorna vazio quando alvo está online", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ status: 200, headers: {}, data: "" });
    const module = new ReconModule();
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("retorna finding CRITICAL quando alvo não responde após retry", async () => {
    mockedAxios.get = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const module = new ReconModule();
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("CRITICAL");
    expect(findings[0]!.type).toBe("TARGET_UNREACHABLE");
  });

  it("armazena initialResponse em ctx após sucesso", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      status: 200,
      headers: { server: "nginx" },
      data: "<html></html>",
    });
    const module = new ReconModule();
    await module.execute(ctx);
    expect(ctx.initialResponse).toBeDefined();
    expect(ctx.initialResponse!.status).toBe(200);
    expect(ctx.initialResponse!.headers["server"]).toBe("nginx");
    expect(ctx.initialResponse!.data).toBe("<html></html>");
  });

  it("tenta novamente uma vez em erro de rede antes de falhar", async () => {
    const mockGet = vi.fn()
      .mockRejectedValueOnce(new Error("ETIMEDOUT"))
      .mockRejectedValueOnce(new Error("ETIMEDOUT"));
    mockedAxios.get = mockGet;
    const module = new ReconModule();
    const findings = await module.execute(ctx);
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(findings[0]!.type).toBe("TARGET_UNREACHABLE");
  });

  it("sucede na segunda tentativa se o primeiro request falhar", async () => {
    const mockGet = vi.fn()
      .mockRejectedValueOnce(new Error("ETIMEDOUT"))
      .mockResolvedValueOnce({ status: 200, headers: {}, data: "" });
    mockedAxios.get = mockGet;
    const module = new ReconModule();
    const findings = await module.execute(ctx);
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(findings).toHaveLength(0);
    expect(ctx.initialResponse).toBeDefined();
  });
});
