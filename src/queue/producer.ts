import { Queue } from "bullmq";
import { env } from "../config/env";

export interface ScanJobData {
  scanId: string;
  targetId: string;
  url: string;
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
