import axios from "axios";
import { readFileSync } from "fs";
import { join } from "path";
import type { Finding, IScannerModule, ScanContext } from "../types";
import { env } from "../../config/env";

const SENSITIVE_PATHS = new Set([
  ".env",
  ".git",
  ".git/config",
  ".htaccess",
  "wp-config.php",
]);
const ADMIN_PATHS = new Set([
  "admin",
  "administrator",
  "dashboard",
  "panel",
  "cpanel",
  "phpmyadmin",
]);

function getSeverity(path: string, status: number): Finding["severity"] {
  if (SENSITIVE_PATHS.has(path)) return "CRITICAL";
  if (ADMIN_PATHS.has(path)) return "HIGH";
  if (status === 403 || status === 401) return "MEDIUM";
  return "LOW";
}

type PathResult = { path: string; status: number; location?: string };

async function checkPath(baseUrl: string, path: string): Promise<PathResult | null> {
  const url = `${baseUrl.replace(/\/$/, "")}/${path}`;
  try {
    const response = await axios.get(url, {
      timeout: env.fuzzerTimeoutMs,
      validateStatus: () => true,
      maxRedirects: 0,
    });
    const { status } = response;
    if (status === 200 || status === 403 || status === 401 || status === 301 || status === 302) {
      return {
        path,
        status,
        location: (response.headers as Record<string, string>)["location"],
      };
    }
    return null;
  } catch {
    return null;
  }
}

async function runConcurrent<T>(tasks: (() => Promise<T>)[], concurrency: number): Promise<T[]> {
  const results: T[] = [];
  const executing: Promise<void>[] = [];

  for (const task of tasks) {
    const p = task().then((r) => {
      results.push(r);
    });
    executing.push(p);
    if (executing.length >= concurrency) {
      await Promise.race(executing);
      executing.splice(0, executing.findIndex((e) => e === p) + 1);
    }
  }
  await Promise.all(executing);
  return results;
}

function buildFinding(
  module: string,
  path: string,
  status: number,
  baseUrl: string,
  location?: string
): Finding {
  const fullUrl = `${baseUrl.replace(/\/$/, "")}/${path}`;
  if (status === 401) {
    return {
      module,
      type: "AUTH_REQUIRED",
      severity: getSeverity(path, status),
      description: `Recurso protegido por autenticação: /${path} retornou HTTP 401`,
      evidence: `GET ${fullUrl} → 401`,
    };
  }
  if (status === 301 || status === 302) {
    return {
      module,
      type: "REDIRECT",
      severity: "LOW",
      description: `Redirect detectado: /${path} → ${location ?? "?"}`,
      evidence: `GET ${fullUrl} → ${status} Location: ${location ?? ""}`,
    };
  }
  return {
    module,
    type: "EXPOSED_PATH",
    severity: getSeverity(path, status),
    description: `Caminho exposto: /${path} retornou HTTP ${status}`,
    evidence: `GET ${fullUrl} → ${status}`,
  };
}

export class FuzzerModule implements IScannerModule {
  name = "fuzzer";
  private wordlist: string[];

  constructor() {
    const wordlistPath = join(__dirname, "../wordlists/common.txt");
    this.wordlist = readFileSync(wordlistPath, "utf-8")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
  }

  async execute(ctx: ScanContext): Promise<Finding[]> {
    const tasks = this.wordlist.map((path) => () => checkPath(ctx.url, path));
    const results = await runConcurrent(tasks, env.fuzzerConcurrency);

    return results
      .filter((r): r is PathResult => r !== null)
      .map((r) => buildFinding(this.name, r.path, r.status, ctx.url, r.location));
  }
}
