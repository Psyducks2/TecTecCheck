# Scanner Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 11 identified issues in the TecTecCheck scanner: redundant HTTP requests, sequential execution, small wordlist, SSRF risk, incomplete fuzzer logic, missing security headers, shallow fingerprinting, no scan dedup, no rate limiting, no recon retry.

**Architecture:** ReconModule fetches once and stores result in `ScanContext.initialResponse`; HeadersModule and FingerprintModule read from that shared response instead of making their own requests. Engine runs Recon first, then remaining modules in `Promise.all`. API layer gets SSRF validation and in-memory rate limiting.

**Tech Stack:** TypeScript, Express 5, Axios, Zod, Prisma, Vitest

---

## File Map

| Action | File | What changes |
|--------|------|--------------|
| Modify | `src/scanner/types.ts` | Add `InitialResponse` interface and `initialResponse?` to `ScanContext` |
| Modify | `src/scanner/engine.ts` | Run recon first, rest in `Promise.all` |
| Modify | `src/scanner/modules/recon.module.ts` | Store response in ctx, add 1-retry |
| Modify | `src/scanner/modules/headers.module.ts` | Use `ctx.initialResponse`, add 5 new header rules |
| Modify | `src/scanner/modules/fingerprint.module.ts` | Use `ctx.initialResponse`, add meta/cookie/CDN detection |
| Modify | `src/scanner/modules/fuzzer.module.ts` | Accept 401/301/302 status codes |
| Modify | `src/scanner/wordlists/common.txt` | Expand from 50 to ~300 paths |
| Modify | `src/api/validators/scan.validator.ts` | Block private IPs and loopback (SSRF) |
| Modify | `src/api/server.ts` | Add in-memory rate limiter middleware |
| Modify | `src/api/routes/scan.routes.ts` | Upsert target by URL instead of create |
| Modify | `tests/scanner/recon.module.test.ts` | Tests for retry + ctx mutation |
| Modify | `tests/scanner/headers.module.test.ts` | Tests for new headers + ctx.initialResponse path |
| Modify | `tests/scanner/fingerprint.module.test.ts` | Tests for meta/cookie/CDN |
| Modify | `tests/scanner/fuzzer.module.test.ts` | Tests for 401/301/302 |
| Modify | `tests/api/scan.routes.test.ts` | Tests for rate limit + dedup |

---

## Task 1: Shared response type in ScanContext

**Files:**
- Modify: `src/scanner/types.ts`
- Modify: `tests/scanner/recon.module.test.ts`

- [ ] **Step 1: Add `InitialResponse` and update `ScanContext`**

Replace the full content of `src/scanner/types.ts`:

```typescript
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Finding {
  module: string;
  type: string;
  severity: Severity;
  description: string;
  evidence?: string;
}

export interface InitialResponse {
  status: number;
  headers: Record<string, string>;
  data: string;
}

export interface ScanContext {
  url: string;
  scanId: string;
  initialResponse?: InitialResponse;
}

export interface IScannerModule {
  name: string;
  execute(ctx: ScanContext): Promise<Finding[]>;
}
```

- [ ] **Step 2: Run type-check to confirm no breakage**

```bash
npx tsc --noEmit
```

Expected: no errors (existing modules use `ctx.url` and `ctx.scanId` only — both still present).

- [ ] **Step 3: Commit**

```bash
git add src/scanner/types.ts
git commit -m "feat(scanner): add InitialResponse to ScanContext for shared HTTP response"
```

---

## Task 2: ReconModule — store response in ctx + 1-retry

**Files:**
- Modify: `src/scanner/modules/recon.module.ts`
- Modify: `tests/scanner/recon.module.test.ts`

- [ ] **Step 1: Write failing tests**

Read current `tests/scanner/recon.module.test.ts` to understand existing tests, then add:

```typescript
it("should store initialResponse in ctx on success", async () => {
  const mockGet = vi.fn().mockResolvedValueOnce({
    status: 200,
    headers: { server: "nginx" },
    data: "<html></html>",
  });
  vi.spyOn(axios, "get").mockImplementation(mockGet);

  const ctx: ScanContext = { url: "https://example.com", scanId: "1" };
  const mod = new ReconModule();
  const findings = await mod.execute(ctx);

  expect(findings).toHaveLength(0);
  expect(ctx.initialResponse).toBeDefined();
  expect(ctx.initialResponse?.status).toBe(200);
  expect(ctx.initialResponse?.headers["server"]).toBe("nginx");
});

it("should retry once on network error before returning TARGET_UNREACHABLE", async () => {
  const mockGet = vi.fn()
    .mockRejectedValueOnce({ message: "ECONNREFUSED", response: undefined })
    .mockRejectedValueOnce({ message: "ECONNREFUSED", response: undefined });
  vi.spyOn(axios, "get").mockImplementation(mockGet);

  const ctx: ScanContext = { url: "https://example.com", scanId: "1" };
  const mod = new ReconModule();
  const findings = await mod.execute(ctx);

  expect(mockGet).toHaveBeenCalledTimes(2);
  expect(findings[0]?.type).toBe("TARGET_UNREACHABLE");
});

it("should succeed on second attempt after transient error", async () => {
  const mockGet = vi.fn()
    .mockRejectedValueOnce({ message: "ETIMEDOUT", response: undefined })
    .mockResolvedValueOnce({ status: 200, headers: {}, data: "" });
  vi.spyOn(axios, "get").mockImplementation(mockGet);

  const ctx: ScanContext = { url: "https://example.com", scanId: "1" };
  const mod = new ReconModule();
  const findings = await mod.execute(ctx);

  expect(findings).toHaveLength(0);
  expect(ctx.initialResponse).toBeDefined();
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npx vitest run tests/scanner/recon.module.test.ts
```

Expected: new tests FAIL.

- [ ] **Step 3: Rewrite `recon.module.ts`**

```typescript
import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

async function fetchWithRetry(url: string, retries = 1) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await axios.get(url, {
        timeout: 30000,
        validateStatus: () => true,
        headers: { "User-Agent": UA },
      });
    } catch (err: any) {
      if (attempt === retries) throw err;
    }
  }
}

export class ReconModule implements IScannerModule {
  name = "recon";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    try {
      const response = await fetchWithRetry(ctx.url);
      ctx.initialResponse = {
        status: response!.status,
        headers: response!.headers as Record<string, string>,
        data: response!.data as string,
      };
      return [];
    } catch (err: any) {
      return [
        {
          module: this.name,
          type: "TARGET_UNREACHABLE",
          severity: "CRITICAL",
          description: `Alvo ${ctx.url} não está acessível. Scan cancelado.`,
          evidence: `GET ${ctx.url} → ${err.message}`,
        },
      ];
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/scanner/recon.module.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/recon.module.ts tests/scanner/recon.module.test.ts
git commit -m "feat(recon): store response in ScanContext and add 1-retry on network error"
```

---

## Task 3: Engine parallelization

**Files:**
- Modify: `src/scanner/engine.ts`
- Modify: `tests/scanner/engine.test.ts`

- [ ] **Step 1: Write failing test**

Read `tests/scanner/engine.test.ts`, then add:

```typescript
it("should run non-recon modules in parallel", async () => {
  const callOrder: string[] = [];

  const makeModule = (name: string, delayMs: number): IScannerModule => ({
    name,
    execute: async (ctx) => {
      await new Promise((r) => setTimeout(r, delayMs));
      callOrder.push(name);
      return [];
    },
  });

  const recon: IScannerModule = {
    name: "recon",
    execute: async (ctx) => {
      callOrder.push("recon");
      return [];
    },
  };

  const engine = new ScanEngine([recon, makeModule("headers", 50), makeModule("fingerprint", 50)]);
  const start = Date.now();
  await engine.run({ url: "https://example.com", scanId: "1" });
  const elapsed = Date.now() - start;

  expect(callOrder[0]).toBe("recon");
  // headers + fingerprint ran in parallel, total ~50ms not ~100ms
  expect(elapsed).toBeLessThan(90);
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
npx vitest run tests/scanner/engine.test.ts
```

Expected: new parallelism test FAIL (current impl is sequential, takes ~100ms).

- [ ] **Step 3: Rewrite `engine.ts`**

```typescript
import type { Finding, IScannerModule, ScanContext } from "./types";

export class ScanEngine {
  constructor(private modules: IScannerModule[]) {}

  async run(ctx: ScanContext): Promise<Finding[]> {
    const [first, ...rest] = this.modules;
    if (!first) return [];

    const firstFindings = await first.execute(ctx);
    if (firstFindings.some((f) => f.type === "TARGET_UNREACHABLE")) {
      return firstFindings;
    }

    const parallelFindings = await Promise.all(rest.map((m) => m.execute(ctx)));
    return [firstFindings, ...parallelFindings].flat();
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/scanner/engine.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scanner/engine.ts tests/scanner/engine.test.ts
git commit -m "feat(engine): run non-recon modules in parallel via Promise.all"
```

---

## Task 4: HeadersModule — use shared response + 5 new header rules

**Files:**
- Modify: `src/scanner/modules/headers.module.ts`
- Modify: `tests/scanner/headers.module.test.ts`

- [ ] **Step 1: Write failing tests for new headers and shared response**

Read `tests/scanner/headers.module.test.ts`, then add tests for each new header rule and verify `axios.get` is NOT called when `ctx.initialResponse` is set:

```typescript
it("should use ctx.initialResponse instead of making HTTP request", async () => {
  const axiosSpy = vi.spyOn(axios, "get");
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: { status: 200, headers: {}, data: "" },
  };
  const mod = new HeadersModule();
  await mod.execute(ctx);
  expect(axiosSpy).not.toHaveBeenCalled();
});

it("should flag missing permissions-policy", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: { status: 200, headers: {}, data: "" },
  };
  const findings = await new HeadersModule().execute(ctx);
  expect(findings.some((f) => f.type === "MISSING_PERMISSIONS_POLICY")).toBe(true);
});

it("should flag missing cross-origin-opener-policy", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: { status: 200, headers: {}, data: "" },
  };
  const findings = await new HeadersModule().execute(ctx);
  expect(findings.some((f) => f.type === "MISSING_COOP")).toBe(true);
});

it("should not flag headers that are present", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: {
      status: 200,
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin",
        "permissions-policy": "camera=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
      },
      data: "",
    },
  };
  const findings = await new HeadersModule().execute(ctx);
  expect(findings).toHaveLength(0);
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npx vitest run tests/scanner/headers.module.test.ts
```

Expected: new tests FAIL.

- [ ] **Step 3: Rewrite `headers.module.ts`**

```typescript
import axios from "axios";
import type { Finding, IScannerModule, ScanContext } from "../types";

interface HeaderRule {
  header: string;
  type: string;
  severity: Finding["severity"];
  description: string;
}

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const REQUIRED_HEADERS: HeaderRule[] = [
  {
    header: "strict-transport-security",
    type: "MISSING_HSTS",
    severity: "MEDIUM",
    description: "Header Strict-Transport-Security ausente. Permite ataques de downgrade HTTP.",
  },
  {
    header: "content-security-policy",
    type: "MISSING_CONTENT_SECURITY_POLICY",
    severity: "HIGH",
    description: "Header Content-Security-Policy ausente. Aumenta superfície de ataques XSS.",
  },
  {
    header: "x-frame-options",
    type: "MISSING_X_FRAME_OPTIONS",
    severity: "MEDIUM",
    description: "Header X-Frame-Options ausente. Permite ataques de Clickjacking.",
  },
  {
    header: "x-content-type-options",
    type: "MISSING_X_CONTENT_TYPE_OPTIONS",
    severity: "LOW",
    description: "Header X-Content-Type-Options ausente. Permite MIME-type sniffing.",
  },
  {
    header: "referrer-policy",
    type: "MISSING_REFERRER_POLICY",
    severity: "LOW",
    description: "Header Referrer-Policy ausente. Pode vazar URLs sensíveis via Referer.",
  },
  {
    header: "permissions-policy",
    type: "MISSING_PERMISSIONS_POLICY",
    severity: "LOW",
    description: "Header Permissions-Policy ausente. Não restringe acesso a features do browser (câmera, microfone, etc.).",
  },
  {
    header: "cross-origin-opener-policy",
    type: "MISSING_COOP",
    severity: "LOW",
    description: "Header Cross-Origin-Opener-Policy ausente. Permite ataques de Spectre via janelas cross-origin.",
  },
  {
    header: "cross-origin-resource-policy",
    type: "MISSING_CORP",
    severity: "LOW",
    description: "Header Cross-Origin-Resource-Policy ausente. Permite embedding de recursos cross-origin não autorizado.",
  },
  {
    header: "cross-origin-embedder-policy",
    type: "MISSING_COEP",
    severity: "LOW",
    description: "Header Cross-Origin-Embedder-Policy ausente. Necessário para isolar contexto de navegação.",
  },
];

export class HeadersModule implements IScannerModule {
  name = "headers";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    let responseHeaders: Record<string, string>;

    if (ctx.initialResponse) {
      responseHeaders = ctx.initialResponse.headers;
    } else {
      const response = await axios.get(ctx.url, {
        timeout: 30000,
        validateStatus: () => true,
        headers: { "User-Agent": UA },
      });
      responseHeaders = response.headers as Record<string, string>;
    }

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

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/scanner/headers.module.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/headers.module.ts tests/scanner/headers.module.test.ts
git commit -m "feat(headers): use shared ctx response; add COOP, CORP, COEP, Permissions-Policy checks"
```

---

## Task 5: FingerprintModule — shared response + meta/cookie/CDN detection

**Files:**
- Modify: `src/scanner/modules/fingerprint.module.ts`
- Modify: `tests/scanner/fingerprint.module.test.ts`

- [ ] **Step 1: Write failing tests**

Read `tests/scanner/fingerprint.module.test.ts`, then add:

```typescript
it("should use ctx.initialResponse instead of making HTTP request", async () => {
  const axiosSpy = vi.spyOn(axios, "get");
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: { status: 200, headers: {}, data: "<html></html>" },
  };
  await new FingerprintModule().execute(ctx);
  expect(axiosSpy).not.toHaveBeenCalled();
});

it("should detect WordPress via meta generator tag", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: {
      status: 200,
      headers: {},
      data: '<html><head><meta name="generator" content="WordPress 6.3" /></head></html>',
    },
  };
  const findings = await new FingerprintModule().execute(ctx);
  expect(findings.some((f) => f.description.includes("WordPress 6.3"))).toBe(true);
});

it("should detect PHP via PHPSESSID cookie", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: {
      status: 200,
      headers: { "set-cookie": "PHPSESSID=abc123; path=/" },
      data: "",
    },
  };
  const findings = await new FingerprintModule().execute(ctx);
  expect(findings.some((f) => f.description.toLowerCase().includes("php"))).toBe(true);
});

it("should detect Cloudflare CDN via cf-ray header", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: {
      status: 200,
      headers: { "cf-ray": "7d123abc-GRU" },
      data: "",
    },
  };
  const findings = await new FingerprintModule().execute(ctx);
  expect(findings.some((f) => f.description.includes("Cloudflare"))).toBe(true);
});

it("should detect Java via JSESSIONID cookie", async () => {
  const ctx: ScanContext = {
    url: "https://example.com",
    scanId: "1",
    initialResponse: {
      status: 200,
      headers: { "set-cookie": "JSESSIONID=xyz; path=/" },
      data: "",
    },
  };
  const findings = await new FingerprintModule().execute(ctx);
  expect(findings.some((f) => f.description.toLowerCase().includes("java"))).toBe(true);
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npx vitest run tests/scanner/fingerprint.module.test.ts
```

Expected: new tests FAIL.

- [ ] **Step 3: Rewrite `fingerprint.module.ts`**

```typescript
import axios from "axios";
import * as cheerio from "cheerio";
import type { Finding, IScannerModule, ScanContext } from "../types";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

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

interface CookieSignature {
  cookie: string;
  label: string;
}

const COOKIE_SIGNATURES: CookieSignature[] = [
  { cookie: "PHPSESSID", label: "PHP" },
  { cookie: "JSESSIONID", label: "Java (Servlet/JSP)" },
  { cookie: "_rails_session", label: "Ruby on Rails" },
  { cookie: "ASP.NET_SessionId", label: "ASP.NET" },
  { cookie: "connect.sid", label: "Node.js (Express/connect)" },
];

interface CdnSignature {
  header: string;
  label: string;
}

const CDN_SIGNATURES: CdnSignature[] = [
  { header: "cf-ray", label: "Cloudflare" },
  { header: "x-amz-cf-id", label: "Amazon CloudFront" },
  { header: "x-akamai-request-id", label: "Akamai" },
  { header: "x-fastly-request-id", label: "Fastly" },
  { header: "x-cdn", label: "CDN (genérico)" },
];

export class FingerprintModule implements IScannerModule {
  name = "fingerprint";

  async execute(ctx: ScanContext): Promise<Finding[]> {
    let headers: Record<string, string>;
    let html: string;

    if (ctx.initialResponse) {
      headers = ctx.initialResponse.headers;
      html = ctx.initialResponse.data;
    } else {
      const response = await axios.get(ctx.url, {
        timeout: 30000,
        validateStatus: () => true,
        headers: { "User-Agent": UA },
      });
      headers = response.headers as Record<string, string>;
      html = response.data as string;
    }

    const findings: Finding[] = [];

    // Server / X-Powered-By header
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

    // HTML body signatures
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

    // Meta generator tag
    const generator = $('meta[name="generator"]').attr("content");
    if (generator) {
      findings.push({
        module: this.name,
        type: "TECHNOLOGY_DISCLOSURE",
        severity: "LOW",
        description: `Tecnologia detectada via meta generator: ${generator}`,
        evidence: `<meta name="generator" content="${generator}">`,
      });
    }

    // Cookie-based detection
    const setCookie = headers["set-cookie"] ?? "";
    for (const sig of COOKIE_SIGNATURES) {
      if (setCookie.includes(sig.cookie)) {
        findings.push({
          module: this.name,
          type: "TECHNOLOGY_DISCLOSURE",
          severity: "LOW",
          description: `${sig.label} detectado via cookie de sessão (${sig.cookie})`,
          evidence: `Set-Cookie contém '${sig.cookie}'`,
        });
      }
    }

    // CDN detection
    for (const sig of CDN_SIGNATURES) {
      if (headers[sig.header]) {
        findings.push({
          module: this.name,
          type: "TECHNOLOGY_DISCLOSURE",
          severity: "LOW",
          description: `CDN detectado: ${sig.label}`,
          evidence: `Header '${sig.header}': ${headers[sig.header]}`,
        });
      }
    }

    return findings;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/scanner/fingerprint.module.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/fingerprint.module.ts tests/scanner/fingerprint.module.test.ts
git commit -m "feat(fingerprint): shared ctx response; add meta generator, cookie, CDN detection"
```

---

## Task 6: FuzzerModule — include 401/301/302 status codes

**Files:**
- Modify: `src/scanner/modules/fuzzer.module.ts`
- Modify: `tests/scanner/fuzzer.module.test.ts`

- [ ] **Step 1: Write failing tests**

Read `tests/scanner/fuzzer.module.test.ts`, then add:

```typescript
it("should report 401 paths as AUTH_REQUIRED finding", async () => {
  // mock checkPath to return 401 for 'admin'
  vi.spyOn(axios, "get").mockResolvedValue({ status: 401 });
  // ... setup wordlist with ['admin']
  const findings = await new FuzzerModule().execute({ url: "https://example.com", scanId: "1" });
  expect(findings.some((f) => f.type === "AUTH_REQUIRED" && f.evidence?.includes("401"))).toBe(true);
});

it("should report 301/302 redirects as REDIRECT finding", async () => {
  vi.spyOn(axios, "get").mockResolvedValue({ status: 301, headers: { location: "/login" } });
  const findings = await new FuzzerModule().execute({ url: "https://example.com", scanId: "1" });
  expect(findings.some((f) => f.type === "REDIRECT" && f.evidence?.includes("301"))).toBe(true);
});
```

> Note: FuzzerModule reads wordlist from disk. In existing tests, mock the `readFileSync` or the `checkPath` function as the existing test suite does. Follow the pattern already established in `tests/scanner/fuzzer.module.test.ts`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
npx vitest run tests/scanner/fuzzer.module.test.ts
```

Expected: new tests FAIL.

- [ ] **Step 3: Update `fuzzer.module.ts` — expand accepted status codes**

Change only the `checkPath` function and `execute` method. Full file replacement:

```typescript
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

function buildFinding(module: string, path: string, status: number, baseUrl: string, location?: string): Finding {
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/scanner/fuzzer.module.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scanner/modules/fuzzer.module.ts tests/scanner/fuzzer.module.test.ts
git commit -m "feat(fuzzer): detect 401 (AUTH_REQUIRED) and 301/302 (REDIRECT) paths"
```

---

## Task 7: Expand wordlist

**Files:**
- Modify: `src/scanner/wordlists/common.txt`

- [ ] **Step 1: Replace wordlist with expanded version (~300 entries)**

Replace `src/scanner/wordlists/common.txt` with the content below. Entries cover admin panels, API paths, backup files, CMS-specific, config files, common frameworks, and sensitive files:

```
admin
administrator
login
logout
signin
signup
register
dashboard
panel
cpanel
phpmyadmin
api
api/v1
api/v2
api/v3
graphql
swagger
swagger-ui
swagger-ui.html
swagger.json
openapi.json
api-docs
docs
documentation
backup
backup.zip
backup.tar.gz
backup.sql
backup.bak
db.sql
database.sql
dump.sql
data.sql
site.sql
.env
.env.local
.env.production
.env.backup
.git
.git/config
.git/HEAD
.git/COMMIT_EDITMSG
.gitignore
.htaccess
.htpasswd
.DS_Store
config
config.php
config.yml
config.yaml
config.json
configuration
settings
settings.php
settings.py
app.config
web.config
wp-config.php
wp-admin
wp-login.php
wp-json
wp-json/wp/v2
xmlrpc.php
wp-includes
wp-content/uploads
joomla
administrator/index.php
Joomla
drupal
sites/default/settings.php
user/login
robots.txt
sitemap.xml
sitemap_index.xml
crossdomain.xml
clientaccesspolicy.xml
security.txt
.well-known/security.txt
.well-known/change-password
info.php
phpinfo.php
test.php
debug.php
shell.php
upload.php
file.php
server-status
server-info
status
health
health-check
healthz
readyz
ping
version
actuator
actuator/health
actuator/env
actuator/mappings
actuator/info
actuator/beans
actuator/metrics
metrics
monitor
monitoring
trace
traces
logs
log
error
errors
404
500
console
rails/info/properties
rails/mailers
rails/routes
debug
admin/login
admin/dashboard
admin/panel
admin/users
admin/config
admin/backup
admin/upload
manage
management
manager
portal
control
controlpanel
member
members
user
users
account
accounts
profile
profiles
auth
oauth
oauth2
oauth/token
oauth/authorize
token
api/auth
api/login
api/token
api/users
api/admin
api/config
api/status
api/health
private
secret
secrets
hidden
internal
staging
stage
dev
development
test
testing
beta
old
old_site
backup_site
_old
archive
archives
temp
tmp
cache
uploads
upload
files
file
media
images
img
assets
static
resources
public
data
export
exports
import
imports
report
reports
download
downloads
print
pdf
excel
csv
xml
json
cgi-bin
cgi-bin/test.cgi
cgi-bin/printenv
cgi-bin/php.cgi
.svn
.svn/entries
.svn/wc.db
.hg
CVS
CVS/Root
CVS/Entries
node_modules
vendor
composer.json
composer.lock
package.json
package-lock.json
yarn.lock
requirements.txt
Gemfile
Gemfile.lock
Pipfile
Pipfile.lock
Makefile
Dockerfile
docker-compose.yml
docker-compose.yaml
.travis.yml
.circleci/config.yml
.github/workflows
readme.md
README.md
CHANGELOG.md
LICENSE
INSTALL.md
TODO
TODO.md
id_rsa
id_rsa.pub
id_dsa
id_ecdsa
authorized_keys
known_hosts
credentials
credentials.json
credentials.xml
secrets.yml
secrets.json
passwords.txt
password.txt
pass.txt
keys.txt
private_key
private.pem
server.key
server.crt
ssl.key
ssl.crt
certificate.pem
htdocs
www
web
html
public_html
wwwroot
webroot
home
index.bak
index.php.bak
index.html.bak
wp-config.php.bak
shell
webshell
cmd
cmd.php
exec.php
system.php
passwd
etc/passwd
proc/version
windows/win.ini
boot.ini
web.xml
WEB-INF/web.xml
META-INF/MANIFEST.MF
struts.xml
applicationContext.xml
spring.xml
```

- [ ] **Step 2: Verify count**

```bash
wc -l src/scanner/wordlists/common.txt
```

Expected: ~300 lines.

- [ ] **Step 3: Run fuzzer tests to confirm wordlist loads without error**

```bash
npx vitest run tests/scanner/fuzzer.module.test.ts
```

Expected: all PASS (wordlist loads fine).

- [ ] **Step 4: Commit**

```bash
git add src/scanner/wordlists/common.txt
git commit -m "feat(wordlist): expand from 50 to ~300 paths including backups, CMS, API, secrets"
```

---

## Task 8: SSRF protection in URL validator

**Files:**
- Modify: `src/api/validators/scan.validator.ts`
- Modify: `tests/api/scan.routes.test.ts`

- [ ] **Step 1: Write failing tests**

Read `tests/api/scan.routes.test.ts`, then add:

```typescript
it("should reject localhost URL", async () => {
  const res = await request(app).post("/api/scan").send({ url: "http://localhost/admin" });
  expect(res.status).toBe(400);
});

it("should reject 127.0.0.1 URL", async () => {
  const res = await request(app).post("/api/scan").send({ url: "http://127.0.0.1/" });
  expect(res.status).toBe(400);
});

it("should reject private IP 192.168.1.1", async () => {
  const res = await request(app).post("/api/scan").send({ url: "http://192.168.1.1/" });
  expect(res.status).toBe(400);
});

it("should reject private IP 10.0.0.1", async () => {
  const res = await request(app).post("/api/scan").send({ url: "http://10.0.0.1/" });
  expect(res.status).toBe(400);
});

it("should reject private IP 172.16.0.1", async () => {
  const res = await request(app).post("/api/scan").send({ url: "http://172.16.0.1/" });
  expect(res.status).toBe(400);
});

it("should accept valid public URL", async () => {
  const res = await request(app).post("/api/scan").send({ url: "https://example.com" });
  // 201 or 500 (DB not running in test) — either way not 400
  expect(res.status).not.toBe(400);
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npx vitest run tests/api/scan.routes.test.ts
```

Expected: SSRF tests FAIL (current validator accepts private IPs).

- [ ] **Step 3: Rewrite `scan.validator.ts`**

```typescript
import { z } from "zod";

const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^0\.0\.0\.0$/,
];

function isPrivateHost(url: string): boolean {
  try {
    const { hostname } = new URL(url);
    return PRIVATE_IP_PATTERNS.some((p) => p.test(hostname));
  } catch {
    return true;
  }
}

export const scanRequestSchema = z.object({
  url: z
    .string()
    .url("URL inválida")
    .refine(
      (url) => url.startsWith("http://") || url.startsWith("https://"),
      "URL deve usar protocolo HTTP ou HTTPS"
    )
    .refine(
      (url) => !isPrivateHost(url),
      "URL não pode apontar para endereços privados ou loopback"
    ),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/api/scan.routes.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api/validators/scan.validator.ts tests/api/scan.routes.test.ts
git commit -m "fix(validator): block private IPs and loopback to prevent SSRF"
```

---

## Task 9: Rate limiting

**Files:**
- Modify: `src/api/server.ts`
- Modify: `tests/api/scan.routes.test.ts`

- [ ] **Step 1: Write failing test**

Add to `tests/api/scan.routes.test.ts`:

```typescript
it("should return 429 after exceeding rate limit", async () => {
  // Fire 21 requests (limit is 20 per 60s window)
  const promises = Array.from({ length: 21 }, () =>
    request(app).post("/api/scan").send({ url: "https://example.com" })
  );
  const results = await Promise.all(promises);
  const tooMany = results.filter((r) => r.status === 429);
  expect(tooMany.length).toBeGreaterThan(0);
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
npx vitest run tests/api/scan.routes.test.ts
```

Expected: rate-limit test FAIL.

- [ ] **Step 3: Add rate limiter to `server.ts`**

```typescript
import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import { env } from "../config/env";
import { scanRouter } from "./routes/scan.routes";
import { healthRouter } from "./routes/health.routes";

const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;

const ipRequests = new Map<string, { count: number; resetAt: number }>();

function rateLimiter(req: Request, res: Response, next: NextFunction) {
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

const app = express();
app.use(express.json());
app.use("/api/scan", rateLimiter, scanRouter);
app.use("/api/health", healthRouter);

app.listen(env.port, () => {
  console.log(`[api] TecTecCheck API rodando em http://localhost:${env.port}`);
});

export { app };
```

> Note: `export { app }` is needed for supertest in tests. Check if existing tests already import `app` — if `server.ts` didn't export it before, update existing test imports accordingly.

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/api/scan.routes.test.ts
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api/server.ts tests/api/scan.routes.test.ts
git commit -m "feat(api): add in-memory rate limiter (20 req/min per IP) to POST /api/scan"
```

---

## Task 10: Target deduplication

**Files:**
- Modify: `src/api/routes/scan.routes.ts`
- Modify: `tests/api/scan.routes.test.ts`

- [ ] **Step 1: Write failing test**

Add to `tests/api/scan.routes.test.ts`:

```typescript
it("should reuse existing target when scanning same URL twice", async () => {
  // Mock prisma.target.upsert to verify it's called instead of create
  const upsertSpy = vi.spyOn(prisma.target, "upsert").mockResolvedValue({
    id: "target-1",
    url: "https://example.com",
    createdAt: new Date(),
  } as any);

  await request(app).post("/api/scan").send({ url: "https://example.com" });
  await request(app).post("/api/scan").send({ url: "https://example.com" });

  expect(upsertSpy).toHaveBeenCalledTimes(2);
  // Both calls should use the same target id (upsert returns same record)
  const calls = upsertSpy.mock.calls;
  expect(calls[0]![0]!.where).toEqual(calls[1]![0]!.where);
});
```

> Note: Follow the mocking pattern already used in `tests/api/scan.routes.test.ts` for prisma.

- [ ] **Step 2: Run test to verify it fails**

```bash
npx vitest run tests/api/scan.routes.test.ts
```

Expected: dedup test FAIL.

- [ ] **Step 3: Update `scan.routes.ts` — upsert target**

Change only the POST handler (replace `prisma.target.create` with `prisma.target.upsert`):

```typescript
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

  const { url } = parsed.data;

  const target = await prisma.target.upsert({
    where: { url },
    update: {},
    create: { url },
  });
  const scan = await prisma.scan.create({ data: { targetId: target.id } });

  await enqueueScan({ scanId: scan.id, targetId: target.id, url });

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

> **Important:** `prisma.target.upsert` requires a `@unique` constraint on the `url` field in the Prisma schema. Check `prisma/schema.prisma` — if `url` is not `@unique`, add it and run `npx prisma migrate dev --name add-target-url-unique`.

- [ ] **Step 4: Check Prisma schema for `url` unique constraint**

```bash
grep -A5 "model Target" prisma/schema.prisma
```

If `url` does not have `@unique`, add it:

```prisma
model Target {
  id        String   @id @default(cuid())
  url       String   @unique   // ← add this
  createdAt DateTime @default(now())
  scans     Scan[]
}
```

Then run:

```bash
npx prisma migrate dev --name add-target-url-unique
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
npx vitest run tests/api/scan.routes.test.ts
```

Expected: all PASS.

- [ ] **Step 6: Run full test suite**

```bash
npm test
```

Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/api/routes/scan.routes.ts tests/api/scan.routes.test.ts prisma/schema.prisma prisma/migrations
git commit -m "feat(routes): upsert target by URL to avoid duplicate records"
```

---

## Self-Review Checklist

- [x] Task 1 covers shared response type (analysis item #1)
- [x] Task 2 covers recon retry (analysis item #10)
- [x] Task 3 covers engine parallelization (analysis item #2)
- [x] Task 4 covers 5 new security headers: Permissions-Policy, COOP, CORP, COEP (analysis item #6)
- [x] Task 5 covers meta generator, cookie detection, CDN (analysis item #7)
- [x] Task 6 covers fuzzer 401/301/302 status codes (analysis item #5)
- [x] Task 7 covers wordlist expansion 50→300 (analysis item #3)
- [x] Task 8 covers SSRF protection (analysis item #4)
- [x] Task 9 covers rate limiting (analysis item #9)
- [x] Task 10 covers target dedup (analysis item #8)
- [x] Analysis item #11 (per-path fuzzer timeout) — not addressed. The current global timeout from `env.fuzzerTimeoutMs` is acceptable for now; per-path timeout config would require API/env changes beyond the identified scope.
- [x] All `ScanContext.initialResponse` references use `InitialResponse` type defined in Task 1
- [x] `ReconModule` sets `ctx.initialResponse` (Task 2); `HeadersModule` and `FingerprintModule` read it (Tasks 4, 5)
- [x] Engine runs modules array: index 0 = recon (first), rest = parallel (Task 3)
