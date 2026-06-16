import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

async function fetchWithRetry(url: string, retries = 1) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await axios.get(url, {
        timeout: 30000,
        validateStatus: () => true,
        headers: { "User-Agent": UA },
      });
    } catch (err: any) {
      if (attempt === retries) throw err;
    }
  }
}

export class ReconModule implements IScannerModule {
  name = "recon";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    try {
      const response = await fetchWithRetry(ctx.url);
      ctx.initialResponse = {
        status: response!.status,
        headers: response!.headers as Record<string, string>,
        data: response!.data as string,
      };
      return [];
    } catch (err: any) {
      return [
        {
          module: this.name,
          type: "TARGET_UNREACHABLE",
          severity: "CRITICAL",
          description: `Alvo ${ctx.url} não está acessível. Scan cancelado.`,
          evidence: `GET ${ctx.url} → ${err.message}`,
        },
      ];
    }
  }
}
