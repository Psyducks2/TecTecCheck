import { Queue } from "bullmq";
import { env } from "../config/env";
import type { ScanConfig } from "../scanner/types";

export interface ScanJobData {
  scanId: string;
  targetId: string;
  url: string;
  config?: ScanConfig;
}

const connection = {
  url: env.redisUrl,
  maxRetriesPerRequest: null,
};

export const scanQueue = new Queue<ScanJobData, void, "scan">("scans", {
  connection,
});

export async function enqueueScan(data: ScanJobData): Promise<void> {
  await scanQueue.add("scan", data, {
    attempts: 2,
    backoff: { type: "exponential", delay: 2000 },
  });
}
