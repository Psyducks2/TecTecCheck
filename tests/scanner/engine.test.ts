import { describe, it, expect, vi } from "vitest";
import { ScanEngine } from "../../src/scanner/engine";
import type {
  IScannerModule,
  ScanContext,
  Finding,
} from "../../src/scanner/types";

function makeModule(name: string, findings: Finding[]): IScannerModule {
  return {
    name,
    execute: vi.fn().mockResolvedValue(findings),
  };
}

describe("ScanEngine", () => {
  const ctx: ScanContext = { url: "https://example.com", scanId: "scan-001" };

  it("agrega findings de todos os módulos", async () => {
    const engine = new ScanEngine([
      makeModule("mod-a", [
        { module: "mod-a", type: "T1", severity: "LOW", description: "d1" },
      ]),
      makeModule("mod-b", [
        { module: "mod-b", type: "T2", severity: "HIGH", description: "d2" },
      ]),
    ]);

    const findings = await engine.run(ctx);
    expect(findings).toHaveLength(2);
  });

  it("cancela módulos subsequentes se recon retorna TARGET_UNREACHABLE", async () => {
    const reconModule = makeModule("recon", [
      {
        module: "recon",
        type: "TARGET_UNREACHABLE",
        severity: "CRITICAL",
        description: "down",
      },
    ]);
    const headersModule = makeModule("headers", []);

    const engine = new ScanEngine([reconModule, headersModule]);
    const findings = await engine.run(ctx);

    expect(findings).toHaveLength(1);
    expect(headersModule.execute).not.toHaveBeenCalled();
  });
});
