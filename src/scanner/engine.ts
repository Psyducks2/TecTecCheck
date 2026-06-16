import type { Finding, IScannerModule, ScanContext } from "./types";

export class ScanEngine {
  constructor(private modules: IScannerModule[]) {}

  async run(ctx: ScanContext): Promise<Finding[]> {
    const allFindings: Finding[] = [];

    for (const mod of this.modules) {
      const findings = await mod.execute(ctx);
      allFindings.push(...findings);

      const isUnreachable = findings.some(
        (f) => f.type === "TARGET_UNREACHABLE"
      );
      if (isUnreachable) break;
    }

    return allFindings;
  }
}
