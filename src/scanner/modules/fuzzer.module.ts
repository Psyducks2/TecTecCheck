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
  if (status === 403) return "MEDIUM";
  return "LOW";
}

async function checkPath(
  baseUrl: string,
  path: string
): Promise<{ path: string; status: number } | null> {
  const url = `${baseUrl.replace(/\/$/, "")}/${path}`;
  try {
    const response = await axios.get(url, {
      timeout: env.fuzzerTimeoutMs,
      validateStatus: () => true,
      maxRedirects: 0,
    });
    if (response.status === 200 || response.status === 403) {
      return { path, status: response.status };
    }
    return null;
  } catch {
    return null;
  }
}

async function runConcurrent<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number
): Promise<T[]> {
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
    const findings: Finding[] = [];

    for (const result of results) {
      if (!result) continue;
      const { path, status } = result;
      const fullUrl = `${ctx.url.replace(/\/$/, "")}/${path}`;
      findings.push({
        module: this.name,
        type: "EXPOSED_PATH",
        severity: getSeverity(path, status),
        description: `Caminho exposto: /${path} retornou HTTP ${status}`,
        evidence: `GET ${fullUrl} → ${status}`,
      });
    }

    return findings;
  }
}
