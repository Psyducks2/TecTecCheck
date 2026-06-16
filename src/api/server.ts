import "dotenv/config";
import express from "express";
import { env } from "../config/env";
import { scanRouter } from "./routes/scan.routes";
import { healthRouter } from "./routes/health.routes";

const app = express();
app.use(express.json());
app.use("/api/scan", scanRouter);
app.use("/api/health", healthRouter);

app.listen(env.port, () => {
  console.log(`[api] TecTecCheck API rodando em http://localhost:${env.port}`);
});
