import { describe, it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../../src/db/client", () => ({
  prisma: {
    target: {
      create: vi.fn().mockResolvedValue({ id: "t1", url: "https://example.com" }),
    },
    scan: {
      create: vi.fn().mockResolvedValue({ id: "s1", status: "PENDING" }),
      findUnique: vi.fn(),
    },
  },
}));

vi.mock("../../src/queue/producer", () => ({
  enqueueScan: vi.fn().mockResolvedValue(undefined),
}));

import { scanRouter } from "../../src/api/routes/scan.routes";

const app = express();
app.use(express.json());
app.use("/api/scan", scanRouter);

describe("POST /api/scan", () => {
  it("retorna 201 e scanId para URL válida", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "https://example.com" });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("scanId");
  });

  it("retorna 400 para URL inválida", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "not-a-url" });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("retorna 400 para body sem url", async () => {
    const res = await request(app).post("/api/scan").send({});
    expect(res.status).toBe(400);
  });

  it("retorna 400 para URL com localhost (SSRF)", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "http://localhost/admin" });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("retorna 400 para URL com 127.0.0.1 (SSRF)", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "http://127.0.0.1/" });
    expect(res.status).toBe(400);
  });

  it("retorna 400 para URL com IP privado 192.168.x.x (SSRF)", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "http://192.168.1.1/" });
    expect(res.status).toBe(400);
  });

  it("retorna 400 para URL com IP privado 10.x.x.x (SSRF)", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "http://10.0.0.1/" });
    expect(res.status).toBe(400);
  });

  it("retorna 400 para URL com IP privado 172.16.x.x (SSRF)", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ url: "http://172.16.0.1/" });
    expect(res.status).toBe(400);
  });
});
