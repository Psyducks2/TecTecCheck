import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../../src/db/client", () => ({
  prisma: {
    $queryRaw: vi.fn(),
  },
}));

const redisMock = vi.hoisted(() => ({
  connect: vi.fn().mockResolvedValue(undefined),
  ping: vi.fn().mockResolvedValue("PONG"),
  disconnect: vi.fn(),
}));

vi.mock("ioredis", () => ({
  default: vi.fn(function () {
    return redisMock;
  }),
}));

import { prisma } from "../../src/db/client";
import { healthRouter } from "../../src/api/routes/health.routes";

const app = express();
app.use("/api/health", healthRouter);

describe("GET /api/health", () => {
  beforeEach(() => {
    vi.mocked(prisma.$queryRaw).mockReset();
    redisMock.connect.mockReset().mockResolvedValue(undefined);
    redisMock.ping.mockReset().mockResolvedValue("PONG");
  });

  it("retorna 200 e status ok quando DB e Redis respondem", async () => {
    vi.mocked(prisma.$queryRaw).mockResolvedValue([{ ok: 1 }]);
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      status: "ok",
      checks: { db: true, redis: true },
    });
  });

  it("retorna 503 e status degraded quando o DB falha", async () => {
    vi.mocked(prisma.$queryRaw).mockRejectedValue(new Error("db down"));
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(503);
    expect(res.body.status).toBe("degraded");
    expect(res.body.checks.db).toBe(false);
  });

  it("retorna 503 e status degraded quando o Redis falha", async () => {
    vi.mocked(prisma.$queryRaw).mockResolvedValue([{ ok: 1 }]);
    redisMock.connect.mockRejectedValue(new Error("redis down"));
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(503);
    expect(res.body.status).toBe("degraded");
    expect(res.body.checks).toEqual({ db: true, redis: false });
  });
});
