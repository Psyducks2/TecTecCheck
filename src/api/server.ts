import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import { env } from "../config/env";
import { scanRouter } from "./routes/scan.routes";
import { healthRouter } from "./routes/health.routes";

const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;

const ipRequests = new Map<string, { count: number; resetAt: number }>();

export function rateLimiter(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip ?? "unknown";
  const now = Date.now();
  const entry = ipRequests.get(ip);

  if (!entry || now > entry.resetAt) {
    ipRequests.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return next();
  }

  entry.count++;
  if (entry.count > RATE_LIMIT) {
    res.status(429).json({ error: "Muitas requisições. Tente novamente em breve." });
    return;
  }
  next();
}

export const app = express();
app.use(express.json());
app.use("/api/scan", rateLimiter, scanRouter);
app.use("/api/health", healthRouter);

if (require.main === module) {
  app.listen(env.port, () => {
    console.log(`[api] TecTecCheck API rodando em http://localhost:${env.port}`);
  });
}
