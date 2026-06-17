import { Router, Request, Response } from "express";
import { prisma } from "../../db/client";
import { enqueueScan } from "../../queue/producer";
import { scanRequestSchema } from "../validators/scan.validator";

export const scanRouter = Router();

scanRouter.post("/", async (req: Request, res: Response) => {
  const parsed = scanRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: parsed.error.issues[0]?.message ?? "URL inválida",
    });
    return;
  }

  const { url, config } = parsed.data;

  const target = await prisma.target.upsert({
    where: { url },
    update: {},
    create: { url },
  });
  const scan = await prisma.scan.create({ data: { targetId: target.id } });

  await enqueueScan({ scanId: scan.id, targetId: target.id, url, config });

  res.status(201).json({ scanId: scan.id, status: scan.status });
});

scanRouter.get("/:id/report", async (req: Request, res: Response) => {
  const id = req.params["id"];
  if (!id || Array.isArray(id)) {
    res.status(400).json({ error: "ID inválido" });
    return;
  }

  const scan = await prisma.scan.findUnique({
    where: { id },
    include: { target: true, vulnerabilities: true },
  });

  if (!scan) {
    res.status(404).json({ error: "Scan não encontrado" });
    return;
  }

  const identificationVuln = scan.vulnerabilities.find(
    (v) => v.type === "SITE_IDENTIFICATION"
  );

  res.json({
    scanId: scan.id,
    url: scan.target.url,
    status: scan.status,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    identification: identificationVuln
      ? {
          summary: identificationVuln.description,
          evidence: identificationVuln.evidence,
        }
      : null,
    vulnerabilities: scan.vulnerabilities.filter(
      (v) => v.type !== "SITE_IDENTIFICATION"
    ),
  });
});
