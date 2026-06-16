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

const connection = {
  url: env.redisUrl,
  maxRetriesPerRequest: null,
};

const engine = new ScanEngine([
  new ReconModule(),
  new IdentificationModule(),
  new HeadersModule(),
  new FuzzerModule(),
  new FingerprintModule(),
]);

const worker = new Worker<ScanJobData>(
  "scans",
  async (job) => {
    const { scanId, url } = job.data;

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "RUNNING", startedAt: new Date() },
    });

    try {
      const findings = await engine.run({ url, scanId });

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
