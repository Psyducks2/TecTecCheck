import { Router, Request, Response } from "express";
import IORedis from "ioredis";
import { prisma } from "../../db/client";
import { env } from "../../config/env";

export const healthRouter = Router();

healthRouter.get("/", async (_req: Request, res: Response) => {
  const checks = { db: false, redis: false };

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.db = true;
  } catch {
    checks.db = false;
  }

  const redis = new IORedis(env.redisUrl, {
    maxRetriesPerRequest: 1,
    lazyConnect: true,
  });
  try {
    await redis.connect();
    await redis.ping();
    checks.redis = true;
  } catch {
    checks.redis = false;
  } finally {
    redis.disconnect();
  }

  const ok = checks.db && checks.redis;
  res.status(ok ? 200 : 503).json({
    status: ok ? "ok" : "degraded",
    checks,
  });
});
