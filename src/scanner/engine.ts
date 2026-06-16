import type { Finding, IScannerModule, ScanContext } from "./types";

export class ScanEngine {
  constructor(private modules: IScannerModule[]) {}

  async run(ctx: ScanContext): Promise<Finding[]> {
    const [first, ...rest] = this.modules;
    if (!first) return [];

    const firstFindings = await first.execute(ctx);
    if (firstFindings.some((f) => f.type === "TARGET_UNREACHABLE")) {
      return firstFindings;
    }

    const parallelFindings = await Promise.all(rest.map((m) => m.execute(ctx)));
    return [firstFindings, ...parallelFindings].flat();
  }
}
