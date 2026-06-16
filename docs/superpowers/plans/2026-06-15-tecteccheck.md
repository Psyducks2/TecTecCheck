# TecTecCheck — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir um scanner de vulnerabilidades web público e de código aberto, executável via CLI, que detecta problemas comuns de segurança em alvos HTTP/HTTPS.

**Architecture:** CLI → API REST local (Express) → Fila assíncrona (BullMQ + Redis) → Workers com módulos de scanner plugáveis (Strategy pattern) → PostgreSQL para persistência de scans e vulnerabilidades.

**Tech Stack:** Node.js 20+, TypeScript 5, Express, BullMQ, Redis, PostgreSQL, Prisma ORM, Commander.js, Chalk, Ora, Vitest, Axios, Cheerio

---

## Visão Geral das Waves

| Wave | Entrega | Depende de |
|------|---------|------------|
| **Wave 1** | Fundação: setup, DB schema, modelos Prisma | — |
| **Wave 2** | Motor de scanner: módulos Recon, Headers, Fuzzer, Fingerprint | Wave 1 |
| **Wave 3** | Fila assíncrona: BullMQ + Redis + Worker orquestrador | Wave 2 |
| **Wave 4** | API REST: endpoints POST /scan e GET /scan/:id/report | Wave 3 |
| **Wave 5** | CLI: interface de terminal com Commander.js + output formatado | Wave 4 |

---

## Estrutura de Arquivos (mapa completo)

```
TecTecCheck/
├── prisma/
│   └── schema.prisma                  # Modelos: Target, Scan, Vulnerability
├── src/
│   ├── config/
│   │   └── env.ts                     # Leitura e validação de variáveis de ambiente
│   ├── db/
│   │   └── client.ts                  # Singleton do Prisma Client
│   ├── scanner/
│   │   ├── types.ts                   # Interface IScannerModule + tipos compartilhados
│   │   ├── modules/
│   │   │   ├── recon.module.ts        # Módulo 0: DNS + HTTP reachability
│   │   │   ├── headers.module.ts      # Módulo 1: Auditoria de security headers
│   │   │   ├── fuzzer.module.ts       # Módulo 2: Directory/file fuzzing
│   │   │   └── fingerprint.module.ts  # Módulo 3: Tech fingerprinting
│   │   ├── wordlists/
│   │   │   └── common.txt             # Wordlist de diretórios/arquivos comuns
│   │   └── engine.ts                  # Orquestrador: roda todos os módulos
│   ├── queue/
│   │   ├── producer.ts                # Adiciona jobs à fila BullMQ
│   │   └── worker.ts                  # Consome jobs, chama engine, persiste resultados
│   ├── api/
│   │   ├── server.ts                  # Setup Express
│   │   ├── routes/
│   │   │   └── scan.routes.ts         # POST /api/scan, GET /api/scan/:id/report
│   │   └── validators/
│   │       └── scan.validator.ts      # Validação de URL com zod
│   └── cli/
│       ├── index.ts                   # Entry point do CLI (commander)
│       └── commands/
│           ├── scan.command.ts        # Comando: tecteccheck scan <url>
│           └── report.command.ts      # Comando: tecteccheck report <scan-id>
├── tests/
│   ├── scanner/
│   │   ├── recon.module.test.ts
│   │   ├── headers.module.test.ts
│   │   ├── fuzzer.module.test.ts
│   │   ├── fingerprint.module.test.ts
│   │   └── engine.test.ts
│   └── api/
│       └── scan.routes.test.ts
├── .env.example
├── docker-compose.yml                 # PostgreSQL + Redis para dev local
├── package.json
└── tsconfig.json
```

---

# WAVE 1 — Fundação do Projeto

## Task 1: Setup inicial do projeto

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `.env.example`
- Create: `docker-compose.yml`

- [ ] **Step 1: Inicializar projeto Node.js com TypeScript**

```bash
npm init -y
npm install typescript tsx @types/node --save-dev
npx tsc --init
```

- [ ] **Step 2: Instalar dependências de produção**

```bash
npm install express axios cheerio bullmq ioredis @prisma/client zod commander chalk ora
npm install --save-dev @types/express vitest prisma dotenv
```

- [ ] **Step 3: Criar `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

- [ ] **Step 4: Criar `.env.example`**

```env
DATABASE_URL="postgresql://tectec:tectec@localhost:5432/tecteccheck"
REDIS_URL="redis://localhost:6379"
PORT=3000
FUZZER_CONCURRENCY=5
FUZZER_TIMEOUT_MS=3000
```

- [ ] **Step 5: Criar `docker-compose.yml`**

```yaml
version: "3.8"
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: tectec
      POSTGRES_PASSWORD: tectec
      POSTGRES_DB: tecteccheck
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

- [ ] **Step 6: Atualizar scripts no `package.json`**

```json
{
  "scripts": {
    "dev": "tsx src/api/server.ts",
    "worker": "tsx src/queue/worker.ts",
    "cli": "tsx src/cli/index.ts",
    "test": "vitest run",
    "test:watch": "vitest",
    "build": "tsc",
    "db:migrate": "prisma migrate dev",
    "db:generate": "prisma generate",
    "docker:up": "docker-compose up -d"
  }
}
```

- [ ] **Step 7: Subir infra local**

```bash
npm run docker:up
```

Expected: containers `postgres` e `redis` rodando.

- [ ] **Step 8: Commit**

```bash
git init
git add .
git commit -m "chore: project foundation — TS, deps, docker-compose"
```

---

## Task 2: Schema do banco de dados (Prisma)

**Files:**
- Create: `prisma/schema.prisma`
- Create: `src/db/client.ts`

- [ ] **Step 1: Inicializar Prisma**

```bash
npx prisma init --datasource-provider postgresql
```

- [ ] **Step 2: Definir `prisma/schema.prisma`**

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model Target {
  id        String   @id @default(cuid())
  url       String
  createdAt DateTime @default(now())
  scans     Scan[]
}

model Scan {
  id              String          @id @default(cuid())
  targetId        String
  target          Target          @relation(fields: [targetId], references: [id])
  status          ScanStatus      @default(PENDING)
  startedAt       DateTime?
  finishedAt      DateTime?
  createdAt       DateTime        @default(now())
  vulnerabilities Vulnerability[]
}

enum ScanStatus {
  PENDING
  RUNNING
  COMPLETED
  FAILED
}

model Vulnerability {
  id          String   @id @default(cuid())
  scanId      String
  scan        Scan     @relation(fields: [scanId], references: [id])
  module      String
  type        String
  severity    Severity
  description String
  evidence    String?
  createdAt   DateTime @default(now())
}

enum Severity {
  LOW
  MEDIUM
  HIGH
  CRITICAL
}
```

- [ ] **Step 3: Rodar migration**

```bash
npm run db:migrate -- --name init
npm run db:generate
```

Expected: tabelas `Target`, `Scan`, `Vulnerability` criadas no PostgreSQL.

- [ ] **Step 4: Criar singleton do Prisma em `src/db/client.ts`**

```typescript
import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient };

export const prisma =
  globalForPrisma.prisma ?? new PrismaClient({ log: ["error"] });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
```

- [ ] **Step 5: Criar `src/config/env.ts`**

```typescript
import "dotenv/config";

function required(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required env var: ${key}`);
  return value;
}

export const env = {
  databaseUrl: required("DATABASE_URL"),
  redisUrl: required("REDIS_URL"),
  port: parseInt(process.env["PORT"] ?? "3000", 10),
  fuzzerConcurrency: parseInt(process.env["FUZZER_CONCURRENCY"] ?? "5", 10),
  fuzzerTimeoutMs: parseInt(process.env["FUZZER_TIMEOUT_MS"] ?? "3000", 10),
};
```

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: prisma schema — Target, Scan, Vulnerability models"
```

---

# WAVE 2 — Motor de Scanner

## Task 3: Tipos compartilhados e interface dos módulos

**Files:**
- Create: `src/scanner/types.ts`

- [ ] **Step 1: Criar `src/scanner/types.ts`**

```typescript
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Finding {
  module: string;
  type: string;
  severity: Severity;
  description: string;
  evidence?: string;
}

export interface ScanContext {
  url: string;
  scanId: string;
}

export interface IScannerModule {
  name: string;
  execute(ctx: ScanContext): Promise<Finding[]>;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/scanner/types.ts
git commit -m "feat: scanner types and IScannerModule interface"
```

---

## Task 4: Módulo 0 — Reconhecimento (Recon)

**Files:**
- Create: `src/scanner/modules/recon.module.ts`
- Create: `tests/scanner/recon.module.test.ts`

- [ ] **Step 1: Escrever o teste em `tests/scanner/recon.module.test.ts`**

```typescript
import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { ReconModule } from "../../src/scanner/modules/recon.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("ReconModule", () => {
  const module = new ReconModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("retorna vazio quando alvo está online", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ status: 200 });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("retorna finding CRITICAL quando alvo não responde", async () => {
    mockedAxios.get = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("CRITICAL");
    expect(findings[0]!.type).toBe("TARGET_UNREACHABLE");
  });
});
```

- [ ] **Step 2: Rodar para verificar falha**

```bash
npm test -- tests/scanner/recon.module.test.ts
```

Expected: FAIL — "ReconModule is not a constructor"

- [ ] **Step 3: Implementar `src/scanner/modules/recon.module.ts`**

```typescript
import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

export class ReconModule implements IScannerModule {
  name = "recon";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    try {
      await axios.get(ctx.url, { timeout: 5000 });
      return [];
    } catch {
      return [
        {
          module: this.name,
          type: "TARGET_UNREACHABLE",
          severity: "CRITICAL",
          description: `Alvo ${ctx.url} não está acessível. Scan cancelado.`,
          evidence: `GET ${ctx.url} → Connection refused/timeout`,
        },
      ];
    }
  }
}
```

- [ ] **Step 4: Rodar para verificar passagem**

```bash
npm test -- tests/scanner/recon.module.test.ts
```

Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/recon.module.ts tests/scanner/recon.module.test.ts
git commit -m "feat: recon module — target reachability check"
```

---

## Task 5: Módulo 1 — Auditor de Headers de Segurança

**Files:**
- Create: `src/scanner/modules/headers.module.ts`
- Create: `tests/scanner/headers.module.test.ts`

- [ ] **Step 1: Escrever o teste em `tests/scanner/headers.module.test.ts`**

```typescript
import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { HeadersModule } from "../../src/scanner/modules/headers.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("HeadersModule", () => {
  const module = new HeadersModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("não reporta findings quando todos os headers estão presentes", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });

  it("reporta finding MEDIUM para header HSTS ausente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ headers: {} });
    const findings = await module.execute(ctx);
    const hstsFinding = findings.find((f) => f.type === "MISSING_HSTS");
    expect(hstsFinding).toBeDefined();
    expect(hstsFinding!.severity).toBe("MEDIUM");
  });

  it("reporta finding HIGH para CSP ausente", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ headers: {} });
    const findings = await module.execute(ctx);
    const cspFinding = findings.find(
      (f) => f.type === "MISSING_CONTENT_SECURITY_POLICY"
    );
    expect(cspFinding).toBeDefined();
    expect(cspFinding!.severity).toBe("HIGH");
  });
});
```

- [ ] **Step 2: Rodar para verificar falha**

```bash
npm test -- tests/scanner/headers.module.test.ts
```

Expected: FAIL

- [ ] **Step 3: Implementar `src/scanner/modules/headers.module.ts`**

```typescript
import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

interface HeaderRule {
  header: string;
  type: string;
  severity: Finding["severity"];
  description: string;
}

const REQUIRED_HEADERS: HeaderRule[] = [
  {
    header: "strict-transport-security",
    type: "MISSING_HSTS",
    severity: "MEDIUM",
    description:
      "Header Strict-Transport-Security ausente. Permite ataques de downgrade HTTP.",
  },
  {
    header: "content-security-policy",
    type: "MISSING_CONTENT_SECURITY_POLICY",
    severity: "HIGH",
    description:
      "Header Content-Security-Policy ausente. Aumenta superfície de ataques XSS.",
  },
  {
    header: "x-frame-options",
    type: "MISSING_X_FRAME_OPTIONS",
    severity: "MEDIUM",
    description:
      "Header X-Frame-Options ausente. Permite ataques de Clickjacking.",
  },
  {
    header: "x-content-type-options",
    type: "MISSING_X_CONTENT_TYPE_OPTIONS",
    severity: "LOW",
    description:
      "Header X-Content-Type-Options ausente. Permite MIME-type sniffing.",
  },
  {
    header: "referrer-policy",
    type: "MISSING_REFERRER_POLICY",
    severity: "LOW",
    description:
      "Header Referrer-Policy ausente. Pode vazar URLs sensíveis via Referer.",
  },
];

export class HeadersModule implements IScannerModule {
  name = "headers";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    const response = await axios.get(ctx.url, { timeout: 5000 });
    const responseHeaders = response.headers as Record<string, string>;
    const findings: Finding[] = [];

    for (const rule of REQUIRED_HEADERS) {
      if (!responseHeaders[rule.header]) {
        findings.push({
          module: this.name,
          type: rule.type,
          severity: rule.severity,
          description: rule.description,
          evidence: `Header '${rule.header}' não encontrado na resposta de GET ${ctx.url}`,
        });
      }
    }

    return findings;
  }
}
```

- [ ] **Step 4: Rodar para verificar passagem**

```bash
npm test -- tests/scanner/headers.module.test.ts
```

Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/headers.module.ts tests/scanner/headers.module.test.ts
git commit -m "feat: headers module — 5 security header rules"
```

---

## Task 6: Wordlist e Módulo 2 — Directory Fuzzer

**Files:**
- Create: `src/scanner/wordlists/common.txt`
- Create: `src/scanner/modules/fuzzer.module.ts`
- Create: `tests/scanner/fuzzer.module.test.ts`

- [ ] **Step 1: Criar wordlist `src/scanner/wordlists/common.txt`**

```
admin
administrator
login
logout
dashboard
api
api/v1
api/v2
backup
config
configuration
.env
.git
.git/config
.htaccess
phpinfo.php
wp-admin
wp-login.php
wp-config.php
robots.txt
sitemap.xml
test
tests
debug
console
panel
cpanel
phpmyadmin
adminer
db
database
upload
uploads
files
static
assets
secret
secrets
private
hidden
old
bak
tmp
temp
logs
log
error.log
access.log
server-status
server-info
```

- [ ] **Step 2: Escrever teste em `tests/scanner/fuzzer.module.test.ts`**

```typescript
import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { FuzzerModule } from "../../src/scanner/modules/fuzzer.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("FuzzerModule", () => {
  const module = new FuzzerModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("reporta finding HIGH para rota /admin com status 200", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/admin")) return Promise.resolve({ status: 200 });
      return Promise.resolve({ status: 404 });
    });
    const findings = await module.execute(ctx);
    const adminFinding = findings.find((f) => f.evidence?.includes("/admin"));
    expect(adminFinding).toBeDefined();
    expect(adminFinding!.severity).toBe("HIGH");
  });

  it("reporta finding CRITICAL para /.env com status 200", async () => {
    mockedAxios.get = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith("/.env")) return Promise.resolve({ status: 200 });
      return Promise.resolve({ status: 404 });
    });
    const findings = await module.execute(ctx);
    const envFinding = findings.find((f) => f.evidence?.includes("/.env"));
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe("CRITICAL");
  });

  it("não reporta findings para status 404", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({ status: 404 });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });
});
```

- [ ] **Step 3: Rodar para verificar falha**

```bash
npm test -- tests/scanner/fuzzer.module.test.ts
```

Expected: FAIL

- [ ] **Step 4: Implementar `src/scanner/modules/fuzzer.module.ts`**

```typescript
import axios from "axios";
import { readFileSync } from "fs";
import { join } from "path";
import type { Finding, IScannerModule, ScanContext } from "../types";
import { env } from "../../config/env";

const SENSITIVE_PATHS = new Set([".env", ".git", ".git/config", ".htaccess", "wp-config.php"]);
const ADMIN_PATHS = new Set(["admin", "administrator", "dashboard", "panel", "cpanel", "phpmyadmin"]);

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
    const tasks = this.wordlist.map(
      (path) => () => checkPath(ctx.url, path)
    );

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
```

- [ ] **Step 5: Rodar para verificar passagem**

```bash
npm test -- tests/scanner/fuzzer.module.test.ts
```

Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add src/scanner/wordlists/ src/scanner/modules/fuzzer.module.ts tests/scanner/fuzzer.module.test.ts
git commit -m "feat: fuzzer module — concurrent directory/file discovery"
```

---

## Task 7: Módulo 3 — Fingerprinting de Tecnologias

**Files:**
- Create: `src/scanner/modules/fingerprint.module.ts`
- Create: `tests/scanner/fingerprint.module.test.ts`

- [ ] **Step 1: Escrever teste em `tests/scanner/fingerprint.module.test.ts`**

```typescript
import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { FingerprintModule } from "../../src/scanner/modules/fingerprint.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

describe("FingerprintModule", () => {
  const module = new FingerprintModule();
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  it("detecta PHP via header X-Powered-By", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: { "x-powered-by": "PHP/7.4.33" },
      data: "<html></html>",
    });
    const findings = await module.execute(ctx);
    const phpFinding = findings.find((f) => f.description.includes("PHP/7.4.33"));
    expect(phpFinding).toBeDefined();
    expect(phpFinding!.severity).toBe("LOW");
  });

  it("detecta WordPress via assinatura no HTML", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {},
      data: '<link rel="stylesheet" href="/wp-content/themes/twentyone/style.css">',
    });
    const findings = await module.execute(ctx);
    const wpFinding = findings.find((f) => f.description.includes("WordPress"));
    expect(wpFinding).toBeDefined();
  });

  it("não reporta findings quando sem assinaturas conhecidas", async () => {
    mockedAxios.get = vi.fn().mockResolvedValue({
      headers: {},
      data: "<html><body>Hello</body></html>",
    });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Rodar para verificar falha**

```bash
npm test -- tests/scanner/fingerprint.module.test.ts
```

Expected: FAIL

- [ ] **Step 3: Implementar `src/scanner/modules/fingerprint.module.ts`**

```typescript
import axios from "axios";
import * as cheerio from "cheerio";
import type { Finding, IScannerModule, ScanContext } from "../types";

interface HtmlSignature {
  name: string;
  pattern: RegExp;
}

const HTML_SIGNATURES: HtmlSignature[] = [
  { name: "WordPress", pattern: /wp-content|wp-includes/i },
  { name: "Joomla", pattern: /\/components\/com_/i },
  { name: "Drupal", pattern: /sites\/default\/files|drupal\.js/i },
  { name: "Laravel", pattern: /laravel_session/i },
  { name: "Django", pattern: /csrfmiddlewaretoken/i },
  { name: "React", pattern: /__REACT_DEVTOOLS_GLOBAL_HOOK__|react\.development\.js/i },
  { name: "Next.js", pattern: /__NEXT_DATA__/i },
];

export class FingerprintModule implements IScannerModule {
  name = "fingerprint";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    const response = await axios.get(ctx.url, { timeout: 5000 });
    const headers = response.headers as Record<string, string>;
    const html = response.data as string;
    const findings: Finding[] = [];

    const poweredBy = headers["x-powered-by"] ?? headers["server"];
    if (poweredBy) {
      findings.push({
        module: this.name,
        type: "TECHNOLOGY_DISCLOSURE",
        severity: "LOW",
        description: `Tecnologia exposta via header: ${poweredBy}`,
        evidence: `Header '${headers["x-powered-by"] ? "X-Powered-By" : "Server"}': ${poweredBy}`,
      });
    }

    const $ = cheerio.load(html);
    const bodyHtml = $.html();

    for (const sig of HTML_SIGNATURES) {
      if (sig.pattern.test(bodyHtml)) {
        findings.push({
          module: this.name,
          type: "TECHNOLOGY_DISCLOSURE",
          severity: "LOW",
          description: `${sig.name} detectado por assinatura no HTML`,
          evidence: `Padrão '${sig.pattern.source}' encontrado em ${ctx.url}`,
        });
      }
    }

    return findings;
  }
}
```

- [ ] **Step 4: Rodar para verificar passagem**

```bash
npm test -- tests/scanner/fingerprint.module.test.ts
```

Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/fingerprint.module.ts tests/scanner/fingerprint.module.test.ts
git commit -m "feat: fingerprint module — tech detection via headers + HTML signatures"
```

---

## Task 8: Engine — Orquestrador dos Módulos

**Files:**
- Create: `src/scanner/engine.ts`
- Create: `tests/scanner/engine.test.ts`

- [ ] **Step 1: Escrever teste em `tests/scanner/engine.test.ts`**

```typescript
import { describe, it, expect, vi } from "vitest";
import { ScanEngine } from "../../src/scanner/engine";
import type { IScannerModule, ScanContext, Finding } from "../../src/scanner/types";

function makeModule(name: string, findings: Finding[]): IScannerModule {
  return {
    name,
    execute: vi.fn().mockResolvedValue(findings),
  };
}

describe("ScanEngine", () => {
  const ctx: ScanContext = { url: "https://example.com", scanId: "scan-001" };

  it("agrega findings de todos os módulos", async () => {
    const engine = new ScanEngine([
      makeModule("mod-a", [
        { module: "mod-a", type: "T1", severity: "LOW", description: "d1" },
      ]),
      makeModule("mod-b", [
        { module: "mod-b", type: "T2", severity: "HIGH", description: "d2" },
      ]),
    ]);

    const findings = await engine.run(ctx);
    expect(findings).toHaveLength(2);
  });

  it("cancela módulos subsequentes se recon retorna TARGET_UNREACHABLE", async () => {
    const reconModule = makeModule("recon", [
      { module: "recon", type: "TARGET_UNREACHABLE", severity: "CRITICAL", description: "down" },
    ]);
    const headersModule = makeModule("headers", []);

    const engine = new ScanEngine([reconModule, headersModule]);
    const findings = await engine.run(ctx);

    expect(findings).toHaveLength(1);
    expect(headersModule.execute).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Rodar para verificar falha**

```bash
npm test -- tests/scanner/engine.test.ts
```

Expected: FAIL

- [ ] **Step 3: Implementar `src/scanner/engine.ts`**

```typescript
import type { Finding, IScannerModule, ScanContext } from "./types";

export class ScanEngine {
  constructor(private modules: IScannerModule[]) {}

  async run(ctx: ScanContext): Promise<Finding[]> {
    const allFindings: Finding[] = [];

    for (const mod of this.modules) {
      const findings = await mod.execute(ctx);
      allFindings.push(...findings);

      const isUnreachable = findings.some(
        (f) => f.type === "TARGET_UNREACHABLE"
      );
      if (isUnreachable) break;
    }

    return allFindings;
  }
}
```

- [ ] **Step 4: Rodar para verificar passagem**

```bash
npm test -- tests/scanner/engine.test.ts
```

Expected: PASS (2 tests)

- [ ] **Step 5: Rodar toda suite de testes**

```bash
npm test
```

Expected: PASS (todos os testes das waves anteriores)

- [ ] **Step 6: Commit**

```bash
git add src/scanner/engine.ts tests/scanner/engine.test.ts
git commit -m "feat: scan engine — module orchestrator with early exit on unreachable"
```

---

# WAVE 3 — Fila Assíncrona (BullMQ + Redis)

## Task 9: Producer e Worker da Fila

**Files:**
- Create: `src/queue/producer.ts`
- Create: `src/queue/worker.ts`

- [ ] **Step 1: Criar `src/queue/producer.ts`**

```typescript
import { Queue } from "bullmq";
import IORedis from "ioredis";
import { env } from "../config/env";

export interface ScanJobData {
  scanId: string;
  targetId: string;
  url: string;
}

const connection = new IORedis(env.redisUrl, { maxRetriesPerRequest: null });

export const scanQueue = new Queue<ScanJobData>("scans", { connection });

export async function enqueueScan(data: ScanJobData): Promise<void> {
  await scanQueue.add("scan", data, {
    attempts: 2,
    backoff: { type: "exponential", delay: 2000 },
  });
}
```

- [ ] **Step 2: Criar `src/queue/worker.ts`**

```typescript
import { Worker } from "bullmq";
import IORedis from "ioredis";
import { env } from "../config/env";
import { prisma } from "../db/client";
import { ScanEngine } from "../scanner/engine";
import { ReconModule } from "../scanner/modules/recon.module";
import { HeadersModule } from "../scanner/modules/headers.module";
import { FuzzerModule } from "../scanner/modules/fuzzer.module";
import { FingerprintModule } from "../scanner/modules/fingerprint.module";
import type { ScanJobData } from "./producer";

const connection = new IORedis(env.redisUrl, { maxRetriesPerRequest: null });

const engine = new ScanEngine([
  new ReconModule(),
  new HeadersModule(),
  new FuzzerModule(),
  new FingerprintModule(),
]);

const worker = new Worker<ScanJobData>(
  "scans",
  async (job) => {
    const { scanId, url } = job.data;

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "RUNNING", startedAt: new Date() },
    });

    try {
      const findings = await engine.run({ url, scanId });

      await prisma.vulnerability.createMany({
        data: findings.map((f) => ({
          scanId,
          module: f.module,
          type: f.type,
          severity: f.severity,
          description: f.description,
          evidence: f.evidence ?? null,
        })),
      });

      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "COMPLETED", finishedAt: new Date() },
      });
    } catch (err) {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "FAILED", finishedAt: new Date() },
      });
      throw err;
    }
  },
  { connection, concurrency: 3 }
);

worker.on("completed", (job) => {
  console.log(`[worker] Scan ${job.data.scanId} concluído.`);
});

worker.on("failed", (job, err) => {
  console.error(`[worker] Scan ${job?.data.scanId} falhou:`, err.message);
});

console.log("[worker] Aguardando jobs na fila 'scans'...");
```

- [ ] **Step 3: Commit**

```bash
git add src/queue/
git commit -m "feat: BullMQ producer + worker — async scan job processing"
```

---

# WAVE 4 — API REST

## Task 10: Validator e Rotas do Scan

**Files:**
- Create: `src/api/validators/scan.validator.ts`
- Create: `src/api/routes/scan.routes.ts`
- Create: `src/api/server.ts`
- Create: `tests/api/scan.routes.test.ts`

- [ ] **Step 1: Criar `src/api/validators/scan.validator.ts`**

```typescript
import { z } from "zod";

export const scanRequestSchema = z.object({
  url: z
    .string()
    .url("URL inválida")
    .refine(
      (url) => url.startsWith("http://") || url.startsWith("https://"),
      "URL deve usar protocolo HTTP ou HTTPS"
    ),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;
```

- [ ] **Step 2: Escrever teste em `tests/api/scan.routes.test.ts`**

```typescript
import { describe, it, expect, vi, beforeAll } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../../src/db/client", () => ({
  prisma: {
    target: { create: vi.fn().mockResolvedValue({ id: "t1", url: "https://example.com" }) },
    scan: { create: vi.fn().mockResolvedValue({ id: "s1", status: "PENDING" }), findUnique: vi.fn() },
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
});
```

- [ ] **Step 3: Instalar supertest**

```bash
npm install --save-dev supertest @types/supertest
```

- [ ] **Step 4: Rodar para verificar falha**

```bash
npm test -- tests/api/scan.routes.test.ts
```

Expected: FAIL

- [ ] **Step 5: Criar `src/api/routes/scan.routes.ts`**

```typescript
import { Router, Request, Response } from "express";
import { prisma } from "../../db/client";
import { enqueueScan } from "../../queue/producer";
import { scanRequestSchema } from "../validators/scan.validator";

export const scanRouter = Router();

scanRouter.post("/", async (req: Request, res: Response) => {
  const parsed = scanRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "URL inválida" });
    return;
  }

  const { url } = parsed.data;

  const target = await prisma.target.create({ data: { url } });
  const scan = await prisma.scan.create({ data: { targetId: target.id } });

  await enqueueScan({ scanId: scan.id, targetId: target.id, url });

  res.status(201).json({ scanId: scan.id, status: scan.status });
});

scanRouter.get("/:id/report", async (req: Request, res: Response) => {
  const scan = await prisma.scan.findUnique({
    where: { id: req.params["id"] },
    include: { target: true, vulnerabilities: true },
  });

  if (!scan) {
    res.status(404).json({ error: "Scan não encontrado" });
    return;
  }

  res.json({
    scanId: scan.id,
    url: scan.target.url,
    status: scan.status,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    vulnerabilities: scan.vulnerabilities,
  });
});
```

- [ ] **Step 6: Criar `src/api/server.ts`**

```typescript
import "dotenv/config";
import express from "express";
import { env } from "../config/env";
import { scanRouter } from "./routes/scan.routes";

const app = express();
app.use(express.json());
app.use("/api/scan", scanRouter);

app.listen(env.port, () => {
  console.log(`[api] TecTecCheck API rodando em http://localhost:${env.port}`);
});
```

- [ ] **Step 7: Rodar para verificar passagem**

```bash
npm test -- tests/api/scan.routes.test.ts
```

Expected: PASS (3 tests)

- [ ] **Step 8: Rodar toda a suite**

```bash
npm test
```

Expected: PASS (todos os testes)

- [ ] **Step 9: Commit**

```bash
git add src/api/ tests/api/
git commit -m "feat: REST API — POST /api/scan + GET /api/scan/:id/report"
```

---

# WAVE 5 — Interface CLI

## Task 11: CLI com Commander.js

**Files:**
- Create: `src/cli/commands/scan.command.ts`
- Create: `src/cli/commands/report.command.ts`
- Create: `src/cli/index.ts`

- [ ] **Step 1: Criar `src/cli/commands/scan.command.ts`**

```typescript
import axios from "axios";
import chalk from "chalk";
import ora from "ora";
import { env } from "../../config/env";

export async function runScanCommand(url: string): Promise<void> {
  const spinner = ora(`Iniciando scan para ${chalk.cyan(url)}...`).start();

  try {
    const response = await axios.post(`http://localhost:${env.port}/api/scan`, { url });
    const { scanId } = response.data as { scanId: string };

    spinner.succeed(`Scan criado! ID: ${chalk.green(scanId)}`);
    console.log(chalk.yellow("\nAguardando processamento pelo worker..."));
    console.log(`\nPara ver o relatório quando concluído, execute:`);
    console.log(chalk.cyan(`  tecteccheck report ${scanId}`));
  } catch (err: unknown) {
    spinner.fail("Falha ao criar scan.");
    if (axios.isAxiosError(err) && err.response?.data) {
      console.error(chalk.red("Erro:"), (err.response.data as { error: string }).error);
    } else {
      console.error(chalk.red("Erro:"), "API não está rodando. Execute: npm run dev");
    }
    process.exit(1);
  }
}
```

- [ ] **Step 2: Criar `src/cli/commands/report.command.ts`**

```typescript
import axios from "axios";
import chalk from "chalk";
import { env } from "../../config/env";
import type { Severity } from "../../scanner/types";

const SEVERITY_COLORS: Record<Severity, chalk.Chalk> = {
  LOW: chalk.blue,
  MEDIUM: chalk.yellow,
  HIGH: chalk.red,
  CRITICAL: chalk.bgRed.white,
};

interface Vulnerability {
  type: string;
  severity: Severity;
  description: string;
  evidence?: string;
  module: string;
}

interface ScanReport {
  scanId: string;
  url: string;
  status: string;
  startedAt: string | null;
  finishedAt: string | null;
  vulnerabilities: Vulnerability[];
}

export async function runReportCommand(scanId: string): Promise<void> {
  try {
    const response = await axios.get(
      `http://localhost:${env.port}/api/scan/${scanId}/report`
    );
    const report = response.data as ScanReport;

    console.log(chalk.bold("\n=== TecTecCheck Report ==="));
    console.log(`Alvo:   ${chalk.cyan(report.url)}`);
    console.log(`Status: ${chalk.green(report.status)}`);
    console.log(`ID:     ${report.scanId}`);

    if (report.vulnerabilities.length === 0) {
      console.log(chalk.green("\n✓ Nenhuma vulnerabilidade encontrada."));
      return;
    }

    console.log(chalk.bold(`\nVulnerabilidades encontradas (${report.vulnerabilities.length}):\n`));

    for (const vuln of report.vulnerabilities) {
      const color = SEVERITY_COLORS[vuln.severity];
      console.log(`${color(`[${vuln.severity}]`)} ${chalk.bold(vuln.type)}`);
      console.log(`  Módulo:  ${vuln.module}`);
      console.log(`  Detalhe: ${vuln.description}`);
      if (vuln.evidence) console.log(`  Evidência: ${chalk.gray(vuln.evidence)}`);
      console.log();
    }
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.response?.status === 404) {
      console.error(chalk.red(`Scan '${scanId}' não encontrado.`));
    } else {
      console.error(chalk.red("Erro ao buscar relatório. API está rodando?"));
    }
    process.exit(1);
  }
}
```

- [ ] **Step 3: Criar entry point `src/cli/index.ts`**

```typescript
#!/usr/bin/env node
import "dotenv/config";
import { Command } from "commander";
import chalk from "chalk";
import { runScanCommand } from "./commands/scan.command";
import { runReportCommand } from "./commands/report.command";

const program = new Command();

program
  .name("tecteccheck")
  .description(
    chalk.cyan("TecTecCheck") + " — Scanner de vulnerabilidades web público"
  )
  .version("0.1.0");

program
  .command("scan <url>")
  .description("Inicia um novo scan de vulnerabilidades para a URL informada")
  .action(async (url: string) => {
    await runScanCommand(url);
  });

program
  .command("report <scanId>")
  .description("Exibe o relatório de um scan concluído")
  .action(async (scanId: string) => {
    await runReportCommand(scanId);
  });

program.parse(process.argv);
```

- [ ] **Step 4: Adicionar script `bin` no `package.json`**

```json
{
  "bin": {
    "tecteccheck": "./src/cli/index.ts"
  }
}
```

- [ ] **Step 5: Testar o fluxo completo manualmente**

Terminal 1 — API:
```bash
npm run dev
```
Expected: `[api] TecTecCheck API rodando em http://localhost:3000`

Terminal 2 — Worker:
```bash
npm run worker
```
Expected: `[worker] Aguardando jobs na fila 'scans'...`

Terminal 3 — CLI:
```bash
npm run cli -- scan https://example.com
```
Expected: saída com scanId

```bash
npm run cli -- report <scanId-do-passo-anterior>
```
Expected: relatório formatado com vulnerabilidades

- [ ] **Step 6: Commit final da Wave 5**

```bash
git add src/cli/
git commit -m "feat: CLI — tecteccheck scan + tecteccheck report commands"
```

---

## Task 12: Publicação e Documentação Mínima

**Files:**
- Modify: `package.json` (campos npm)

- [ ] **Step 1: Atualizar `package.json` com metadados de publicação**

```json
{
  "name": "tecteccheck",
  "version": "0.1.0",
  "description": "Scanner de vulnerabilidades web público — Headers, Fuzzing, Fingerprinting",
  "keywords": ["security", "scanner", "vulnerability", "cli", "hacking", "pentest"],
  "author": "Seu Nome <seu@email.com>",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/seuusuario/tecteccheck"
  },
  "engines": {
    "node": ">=20"
  }
}
```

- [ ] **Step 2: Criar `.env` local a partir do exemplo**

```bash
cp .env.example .env
```

- [ ] **Step 3: Commit final**

```bash
git add package.json .env.example
git commit -m "chore: npm metadata + MIT license for public release"
```

---

## Resumo por Wave

| Wave | Tasks | O que entrega |
|------|-------|---------------|
| Wave 1 | 1–2 | Setup + DB schema rodando com Docker |
| Wave 2 | 3–8 | 4 módulos de scanner com testes, engine com early-exit |
| Wave 3 | 9 | Processamento assíncrono via BullMQ + Redis |
| Wave 4 | 10 | API REST testada com POST /scan e GET /scan/:id/report |
| Wave 5 | 11–12 | CLI `tecteccheck scan` e `tecteccheck report` funcionando |
