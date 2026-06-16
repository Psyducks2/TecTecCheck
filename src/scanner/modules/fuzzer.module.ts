import axios from "axios";
import { readFileSync } from "fs";
import { join } from "path";
import type { Finding, IScannerModule, ScanContext } from "../types";
import { env } from "../../config/env";

const SENSITIVE_PATHS = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.backup",
  ".git",
  ".git/config",
  ".git/HEAD",
  ".htaccess",
  ".htpasswd",
  "wp-config.php",
  "wp-config.php.bak",
  "id_rsa",
  "id_rsa.pub",
  "id_dsa",
  "id_ecdsa",
  "credentials",
  "credentials.json",
  "secrets.yml",
  "secrets.json",
  "passwords.txt",
  "password.txt",
  "private.pem",
  "server.key",
  "server.crt",
]);
const ADMIN_PATHS = new Set([
  "admin",
  "administrator",
  "dashboard",
  "panel",
  "cpanel",
  "phpmyadmin",
  "admin/login",
  "admin/dashboard",
]);

const MAX_FINDINGS = 50;

function getSeverity(
  path: string,
  status: number,
  generic403: boolean
): Finding["severity"] {
  if (SENSITIVE_PATHS.has(path)) return "CRITICAL";
  if (ADMIN_PATHS.has(path)) {
    if (status === 403) return generic403 ? "MEDIUM" : "HIGH";
    return "HIGH";
  }
  if (status === 403) return generic403 ? "LOW" : "MEDIUM";
  if (status === 401) return "MEDIUM";
  return "LOW";
}

type PathResult = {
  path: string;
  status: number;
  location?: string;
};

async function checkPath(
  baseUrl: string,
  path: string
): Promise<PathResult | null> {
  const url = `${baseUrl.replace(/\/$/, "")}/${path}`;
  try {
    const response = await axios.get(url, {
      timeout: env.fuzzerTimeoutMs,
      validateStatus: () => true,
      maxRedirects: 0,
    });
    const { status } = response;
    if (
      status === 200 ||
      status === 403 ||
      status === 401 ||
      status === 301 ||
      status === 302
    ) {
      const headers = response.headers as Record<string, string>;
      return {
        path,
        status,
        location: headers["location"],
      };
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

function isGeneric404Page(html: string): boolean {
  const lower = html.toLowerCase();
  return (
    lower.includes("not found") ||
    lower.includes("404") ||
    lower.includes("page not found") ||
    lower.includes("does not exist") ||
    lower.includes("não encontrado") ||
    lower.includes("página não encontrada")
  );
}

function isGeneric403Page(html: string, contentType?: string): boolean {
  if (contentType && !contentType.includes("text/html")) return false;
  if (!html) return false;
  const lower = html.toLowerCase();
  if (lower.length > 5000) return false;

  const GENERIC_403_PATTERNS = [
    "access denied",
    "forbidden",
    "you don't have permission",
    "you do not have permission",
    "access to this resource",
    "not authorized",
    "unauthorized",
    "acesso negado",
    "acesso negado",
    "proibido",
    "negado",
    "restrito",
    "sem permissão",
    "sem permissao",
    "você não tem permissão",
    "voce nao tem permissao",
    "permission denied",
    "insufficient privileges",
    "not allowed",
    "blocked",
    "waf",
    "firewall",
    "mod_security",
    "modsecurity",
    "cloudflare",
    "incapsula",
    "imperva",
  ];

  for (const pattern of GENERIC_403_PATTERNS) {
    if (lower.includes(pattern)) return true;
  }

  if (lower.includes("403") && lower.length < 500) return true;

  return false;
}

async function detectGeneric403(baseUrl: string): Promise<boolean> {
  const gibberish = `__tecteccheck_probe_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  try {
    const response = await axios.get(`${baseUrl.replace(/\/$/, "")}/${gibberish}`, {
      timeout: env.fuzzerTimeoutMs,
      validateStatus: () => true,
      maxRedirects: 0,
    });
    return response.status === 403;
  } catch {
    return false;
  }
}

function buildFinding(
  module: string,
  path: string,
  status: number,
  baseUrl: string,
  generic403: boolean,
  location?: string
): Finding | null {
  const fullUrl = `${baseUrl.replace(/\/$/, "")}/${path}`;

  if (status === 403 && SENSITIVE_PATHS.has(path)) {
    return {
      module,
      type: "SENSITIVE_PATH_BLOCKED",
      severity: "MEDIUM",
      description: `Caminho sensível bloqueado: /${path} retornou HTTP 403 (recurso existe mas está protegido)`,
      evidence: `GET ${fullUrl} → 403 (acesso negado a recurso sensível)`,
    };
  }

  if (status === 403 && generic403) {
    return null;
  }

  if (status === 403) {
    return {
      module,
      type: "EXPOSED_PATH",
      severity: getSeverity(path, status, generic403),
      description: `Caminho bloqueado: /${path} retornou HTTP 403`,
      evidence: `GET ${fullUrl} → 403`,
    };
  }

  if (status === 401) {
    return {
      module,
      type: "AUTH_REQUIRED",
      severity: getSeverity(path, status, generic403),
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

  if (status === 200) {
    if (ADMIN_PATHS.has(path)) {
      return {
        module,
        type: "EXPOSED_PATH",
        severity: "HIGH",
        description: `Painel administrativo exposto: /${path} retornou HTTP 200`,
        evidence: `GET ${fullUrl} → 200`,
      };
    }
    return {
      module,
      type: "EXPOSED_PATH",
      severity: getSeverity(path, status, generic403),
      description: `Caminho exposto: /${path} retornou HTTP ${status}`,
      evidence: `GET ${fullUrl} → ${status}`,
    };
  }

  return null;
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
    const generic403 = await detectGeneric403(ctx.url);

    const tasks = this.wordlist.map(
      (path) => () => checkPath(ctx.url, path)
    );
    const results = await runConcurrent(tasks, env.fuzzerConcurrency);

    const findings: Finding[] = [];
    for (const result of results) {
      if (!result) continue;

      if (generic403 && result.status === 403) {
        const f = buildFinding(this.name, result.path, result.status, ctx.url, generic403);
        if (f) findings.push(f);
        continue;
      }

      if (result.status === 200) {
        const html = await this.fetchBody(ctx.url, result.path);
        if (html && isGeneric404Page(html)) continue;
      }

      const finding = buildFinding(
        this.name,
        result.path,
        result.status,
        ctx.url,
        generic403,
        result.location
      );
      if (finding) findings.push(finding);

      if (findings.length >= MAX_FINDINGS) break;
    }

    return findings;
  }

  private async fetchBody(baseUrl: string, path: string): Promise<string> {
    try {
      const url = `${baseUrl.replace(/\/$/, "")}/${path}`;
      const response = await axios.get(url, {
        timeout: env.fuzzerTimeoutMs,
        validateStatus: () => true,
        maxRedirects: 0,
      });
      return typeof response.data === "string" ? response.data : "";
    } catch {
      return "";
    }
  }
}
