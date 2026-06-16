import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

export class ReconModule implements IScannerModule {
  name = "recon";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    try {
      await axios.get(ctx.url, { timeout: 5000 });
      return [];
    } catch {
      return [
        {
          module: this.name,
          type: "TARGET_UNREACHABLE",
          severity: "CRITICAL",
          description: `Alvo ${ctx.url} não está acessível. Scan cancelado.`,
          evidence: `GET ${ctx.url} → Connection refused/timeout`,
        },
      ];
    }
  }
}
