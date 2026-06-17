import { Worker } from "bullmq";
import { env } from "../config/env";
import { prisma } from "../db/client";
import { ScanEngine } from "../scanner/engine";
import { ReconModule } from "../scanner/modules/recon.module";
import { HeadersModule } from "../scanner/modules/headers.module";
import { FuzzerModule } from "../scanner/modules/fuzzer.module";
import { FingerprintModule } from "../scanner/modules/fingerprint.module";
import { IdentificationModule } from "../scanner/modules/identification.module";
import type { ScanJobData } from "./producer";
import type { IScannerModule, ModuleName } from "../scanner/types";

const connection = {
  url: env.redisUrl,
  maxRetriesPerRequest: null,
};

const MODULE_REGISTRY: Record<ModuleName, IScannerModule> = {
  recon: new ReconModule(),
  identification: new IdentificationModule(),
  headers: new HeadersModule(),
  fuzzer: new FuzzerModule(),
  fingerprint: new FingerprintModule(),
};

const DEFAULT_MODULE_ORDER: ModuleName[] = [
  "recon",
  "identification",
  "headers",
  "fuzzer",
  "fingerprint",
];

function buildEngine(modules?: ModuleName[]): ScanEngine {
  const order =
    modules && modules.length > 0 ? modules : DEFAULT_MODULE_ORDER;
  const instances = order
    .map((name) => MODULE_REGISTRY[name])
    .filter((m): m is IScannerModule => m != null);
  return new ScanEngine(instances);
}

const worker = new Worker<ScanJobData>(
  "scans",
  async (job) => {
    const { scanId, url, config } = job.data;

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "RUNNING", startedAt: new Date() },
    });

    try {
      const engine = buildEngine(config?.modules);
      const findings = await engine.run({ url, scanId, config });

      await prisma.vulnerability.createMany({
        data: findings.map((f) => ({
          scanId,
          module: f.module,
          type: f.type,
          severity: f.severity,
          description: f.description,
          evidence: f.evidence ?? null,
        })),
      });

      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "COMPLETED", finishedAt: new Date() },
      });
    } catch (err) {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "FAILED", finishedAt: new Date() },
      });
      throw err;
    }
  },
  { connection, concurrency: 3 }
);

worker.on("completed", (job) => {
  console.log(`[worker] Scan ${job.data.scanId} concluído.`);
});

worker.on("failed", (job, err) => {
  console.error(`[worker] Scan ${job?.data.scanId} falhou:`, err.message);
});

console.log("[worker] Aguardando jobs na fila 'scans'...");
