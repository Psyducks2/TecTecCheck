import type { Health, ScanReport } from "./types";

async function asJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ?? `Erro ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function postScan(url: string): Promise<{ scanId: string }> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  return asJson<{ scanId: string }>(res);
}

export async function getReport(scanId: string): Promise<ScanReport> {
  const res = await fetch(`/api/scan/${scanId}/report`);
  return asJson<ScanReport>(res);
}

export async function getHealth(): Promise<Health> {
  const res = await fetch("/api/health");
  return res.json() as Promise<Health>;
}
