# Web UI + One-Command Dev Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give TecTecCheck a web interface that shows scan targets, findings by severity, and backend health — all booted with a single `npm run dev`.

**Architecture:** Add a `web/` Vite + React workspace served on port 5173 that proxies `/api` to the existing Express API (port 3000). Add an `/api/health` endpoint so the UI can report "mau funcionamento" (DB/Redis down). The UI submits a scan, then polls `GET /api/scan/:id/report` until the scan finishes. `npm run dev` uses `concurrently` to boot Docker (Postgres + Redis), API, worker, and the web dev server together.

**Tech Stack:** React 18, Vite 5, TypeScript, Vitest + React Testing Library (frontend); Express, BullMQ, Prisma, ioredis, supertest (backend); `concurrently` for orchestration.

---

## File Structure

**Backend (new / modified):**
- Create `src/api/routes/health.routes.ts` — `GET /api/health` checks Postgres + Redis, returns `{ status, checks }`.
- Modify `src/api/server.ts` — mount `healthRouter` at `/api/health`.
- Create `tests/api/health.routes.test.ts` — supertest coverage for healthy + degraded states.

**Frontend (new `web/` workspace):**
- `web/package.json` — workspace manifest (`type: module`), React + Vite + Vitest deps.
- `web/index.html` — Vite entry HTML.
- `web/vite.config.ts` — React plugin + `/api` proxy to `http://localhost:3000`.
- `web/vitest.config.ts` — jsdom env, globals, RTL setup.
- `web/tsconfig.json` — React/DOM TS config.
- `web/src/main.tsx` — React bootstrap.
- `web/src/App.tsx` — page shell wiring form + health banner + report.
- `web/src/types.ts` — `Severity`, `Vulnerability`, `ScanReport`, `Health` types (mirror backend).
- `web/src/api.ts` — `postScan`, `getReport`, `getHealth` fetch helpers.
- `web/src/severity.ts` — `SEVERITY_ORDER`, `groupBySeverity`, `severityClass` (pure, unit-tested).
- `web/src/severity.test.ts` — unit tests for severity helpers.
- `web/src/hooks/useScanPolling.ts` — start a scan, poll the report until terminal status.
- `web/src/components/ScanForm.tsx` — URL input + submit.
- `web/src/components/ScanForm.test.tsx` — RTL test for submit behavior.
- `web/src/components/StatusBadge.tsx` — colored scan-status pill.
- `web/src/components/FindingCard.tsx` — one vulnerability row.
- `web/src/components/FindingCard.test.tsx` — RTL render test.
- `web/src/components/SeverityGroup.tsx` — findings grouped under a severity heading.
- `web/src/components/HealthBanner.tsx` — backend up/down banner.
- `web/src/styles.css` — minimal layout + severity colors.

**Root (modified):**
- Modify `package.json` — add `workspaces`, `concurrently` devDep, repurpose `dev` into orchestrator (`predev`, `dev:api`, `dev:web`, `test:web`).
- Modify `README.md` — replace 3-terminal instructions with one-command flow.

---

## Task 1: Backend health endpoint

**Files:**
- Create: `src/api/routes/health.routes.ts`
- Modify: `src/api/server.ts`
- Test: `tests/api/health.routes.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/api/health.routes.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../../src/db/client", () => ({
  prisma: {
    $queryRaw: vi.fn(),
  },
}));

vi.mock("ioredis", () => ({
  default: vi.fn().mockImplementation(() => ({
    connect: vi.fn().mockResolvedValue(undefined),
    ping: vi.fn().mockResolvedValue("PONG"),
    disconnect: vi.fn(),
  })),
}));

import { prisma } from "../../src/db/client";
import { healthRouter } from "../../src/api/routes/health.routes";

const app = express();
app.use("/api/health", healthRouter);

describe("GET /api/health", () => {
  beforeEach(() => {
    vi.mocked(prisma.$queryRaw).mockReset();
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
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/api/health.routes.test.ts`
Expected: FAIL — cannot resolve `../../src/api/routes/health.routes`.

- [ ] **Step 3: Write minimal implementation**

Create `src/api/routes/health.routes.ts`:

```ts
import { Router, Request, Response } from "express";
import IORedis from "ioredis";
import { prisma } from "../../db/client";
import { env } from "../../config/env";

export const healthRouter = Router();

healthRouter.get("/", async (_req: Request, res: Response) => {
  const checks = { db: false, redis: false };

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.db = true;
  } catch {
    checks.db = false;
  }

  const redis = new IORedis(env.redisUrl, {
    maxRetriesPerRequest: 1,
    lazyConnect: true,
  });
  try {
    await redis.connect();
    await redis.ping();
    checks.redis = true;
  } catch {
    checks.redis = false;
  } finally {
    redis.disconnect();
  }

  const ok = checks.db && checks.redis;
  res.status(ok ? 200 : 503).json({
    status: ok ? "ok" : "degraded",
    checks,
  });
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/api/health.routes.test.ts`
Expected: PASS — 2 tests.

- [ ] **Step 5: Mount the router**

Modify `src/api/server.ts` — add the import and `app.use` line:

```ts
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
```

- [ ] **Step 6: Run the full backend suite**

Run: `npm test`
Expected: PASS — all prior tests plus the 2 new health tests.

- [ ] **Step 7: Commit**

```bash
git add src/api/routes/health.routes.ts src/api/server.ts tests/api/health.routes.test.ts
git commit -m "feat(api): add /api/health endpoint for DB and Redis status"
```

---

## Task 2: Scaffold the web workspace

**Files:**
- Modify: `package.json` (root)
- Create: `web/package.json`
- Create: `web/index.html`
- Create: `web/vite.config.ts`
- Create: `web/tsconfig.json`
- Create: `web/src/main.tsx`
- Create: `web/src/App.tsx`
- Create: `web/src/styles.css`

- [ ] **Step 1: Register the workspace in root `package.json`**

Add a top-level `"workspaces"` key (place it right after `"type": "commonjs",`):

```json
  "type": "commonjs",
  "workspaces": [
    "web"
  ],
```

- [ ] **Step 2: Create `web/package.json`**

```json
{
  "name": "@tecteccheck/web",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "test": "vitest run"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.4.8",
    "@testing-library/react": "^16.0.0",
    "@testing-library/user-event": "^14.5.2",
    "@types/react": "^18.3.3",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "jsdom": "^24.1.1",
    "typescript": "^5.5.4",
    "vite": "^5.4.0",
    "vitest": "^4.1.9"
  }
}
```

- [ ] **Step 3: Create `web/index.html`**

```html
<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>TecTecCheck</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 4: Create `web/vite.config.ts`**

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:3000",
    },
  },
});
```

- [ ] **Step 5: Create `web/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "noEmit": true,
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src"]
}
```

- [ ] **Step 6: Create `web/src/styles.css`**

```css
:root {
  font-family: system-ui, -apple-system, sans-serif;
  color: #1a1a2e;
  background: #f4f5fb;
}
body { margin: 0; }
.app { max-width: 820px; margin: 0 auto; padding: 2rem 1.5rem; }
.app h1 { margin: 0 0 0.25rem; }
.subtitle { color: #555; margin: 0 0 1.5rem; }
.scan-form { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
.scan-form input { flex: 1; padding: 0.6rem 0.75rem; border: 1px solid #ccc; border-radius: 6px; font-size: 1rem; }
.scan-form button { padding: 0.6rem 1.2rem; border: 0; border-radius: 6px; background: #3a36e0; color: #fff; font-size: 1rem; cursor: pointer; }
.scan-form button:disabled { opacity: 0.5; cursor: not-allowed; }
.banner { padding: 0.6rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.9rem; }
.banner.up { background: #e6f9ed; color: #137a3b; }
.banner.down { background: #fdecea; color: #b3261e; }
.badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }
.badge.PENDING { background: #eee; color: #555; }
.badge.RUNNING { background: #fff4d6; color: #8a6d00; }
.badge.COMPLETED { background: #e6f9ed; color: #137a3b; }
.badge.FAILED { background: #fdecea; color: #b3261e; }
.sev-group { margin: 1rem 0; }
.sev-group h3 { margin: 0 0 0.5rem; }
.finding { border-left: 4px solid #ccc; background: #fff; padding: 0.75rem 1rem; border-radius: 0 6px 6px 0; margin-bottom: 0.5rem; }
.finding.LOW { border-color: #3a7bd5; }
.finding.MEDIUM { border-color: #d5a93a; }
.finding.HIGH { border-color: #d54b3a; }
.finding.CRITICAL { border-color: #8a0000; background: #fff5f5; }
.finding .meta { color: #777; font-size: 0.8rem; }
.finding .evidence { font-family: monospace; font-size: 0.8rem; color: #555; word-break: break-all; }
.error { color: #b3261e; }
```

- [ ] **Step 7: Create `web/src/App.tsx` (placeholder for now)**

```tsx
import "./styles.css";

export default function App() {
  return (
    <div className="app">
      <h1>TecTecCheck</h1>
      <p className="subtitle">Scanner de vulnerabilidades web</p>
    </div>
  );
}
```

- [ ] **Step 8: Create `web/src/main.tsx`**

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

- [ ] **Step 9: Install workspace deps and verify the dev server boots**

Run: `npm install`
Then run: `npm run dev -w web`
Expected: Vite prints `Local: http://localhost:5173/`. Open it — page shows the "TecTecCheck" heading. Stop the server with Ctrl+C.

- [ ] **Step 10: Commit**

```bash
git add package.json package-lock.json web/
git commit -m "feat(web): scaffold Vite + React workspace with API proxy"
```

---

## Task 3: Frontend types and API client

**Files:**
- Create: `web/src/types.ts`
- Create: `web/src/api.ts`

- [ ] **Step 1: Create `web/src/types.ts`**

```ts
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";

export interface Vulnerability {
  id: string;
  module: string;
  type: string;
  severity: Severity;
  description: string;
  evidence: string | null;
}

export interface ScanReport {
  scanId: string;
  url: string;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  vulnerabilities: Vulnerability[];
}

export interface Health {
  status: "ok" | "degraded";
  checks: { db: boolean; redis: boolean };
}
```

- [ ] **Step 2: Create `web/src/api.ts`**

```ts
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
```

- [ ] **Step 3: Type-check**

Run: `npx tsc -p web/tsconfig.json --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add web/src/types.ts web/src/api.ts
git commit -m "feat(web): add shared types and API client"
```

---

## Task 4: Severity helpers (pure, unit-tested)

**Files:**
- Create: `web/src/severity.ts`
- Create: `web/vitest.config.ts`
- Create: `web/src/test-setup.ts`
- Test: `web/src/severity.test.ts`

- [ ] **Step 1: Create `web/vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
```

- [ ] **Step 2: Create `web/src/test-setup.ts`**

```ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 3: Write the failing test**

Create `web/src/severity.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { groupBySeverity, SEVERITY_ORDER } from "./severity";
import type { Vulnerability } from "./types";

const vuln = (severity: Vulnerability["severity"], type: string): Vulnerability => ({
  id: type,
  module: "headers",
  type,
  severity,
  description: "d",
  evidence: null,
});

describe("groupBySeverity", () => {
  it("agrupa por severidade na ordem CRITICAL → LOW", () => {
    const result = groupBySeverity([
      vuln("LOW", "a"),
      vuln("CRITICAL", "b"),
      vuln("LOW", "c"),
    ]);
    expect(result.map((g) => g.severity)).toEqual(SEVERITY_ORDER);
    expect(result[0].items.map((v) => v.type)).toEqual(["b"]);
    expect(result[3].items.map((v) => v.type)).toEqual(["a", "c"]);
  });

  it("retorna grupos vazios quando não há findings", () => {
    const result = groupBySeverity([]);
    expect(result).toHaveLength(4);
    expect(result.every((g) => g.items.length === 0)).toBe(true);
  });
});
```

- [ ] **Step 4: Run test to verify it fails**

Run: `npm run test -w web -- severity`
Expected: FAIL — cannot resolve `./severity`.

- [ ] **Step 5: Write minimal implementation**

Create `web/src/severity.ts`:

```ts
import type { Severity, Vulnerability } from "./types";

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export interface SeverityGroupData {
  severity: Severity;
  items: Vulnerability[];
}

export function groupBySeverity(items: Vulnerability[]): SeverityGroupData[] {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    items: items.filter((v) => v.severity === severity),
  }));
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npm run test -w web -- severity`
Expected: PASS — 2 tests.

- [ ] **Step 7: Commit**

```bash
git add web/vitest.config.ts web/src/test-setup.ts web/src/severity.ts web/src/severity.test.ts
git commit -m "feat(web): add severity grouping helpers with tests"
```

---

## Task 5: FindingCard and StatusBadge components

**Files:**
- Create: `web/src/components/StatusBadge.tsx`
- Create: `web/src/components/FindingCard.tsx`
- Test: `web/src/components/FindingCard.test.tsx`

- [ ] **Step 1: Write the failing test**

Create `web/src/components/FindingCard.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingCard } from "./FindingCard";
import type { Vulnerability } from "../types";

const vuln: Vulnerability = {
  id: "v1",
  module: "headers",
  type: "MISSING_HSTS",
  severity: "HIGH",
  description: "Header HSTS ausente",
  evidence: "Strict-Transport-Security não encontrado",
};

describe("FindingCard", () => {
  it("mostra tipo, módulo, descrição e evidência", () => {
    render(<FindingCard vuln={vuln} />);
    expect(screen.getByText("MISSING_HSTS")).toBeInTheDocument();
    expect(screen.getByText(/headers/)).toBeInTheDocument();
    expect(screen.getByText("Header HSTS ausente")).toBeInTheDocument();
    expect(
      screen.getByText("Strict-Transport-Security não encontrado")
    ).toBeInTheDocument();
  });

  it("aplica a classe da severidade no container", () => {
    const { container } = render(<FindingCard vuln={vuln} />);
    expect(container.querySelector(".finding.HIGH")).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm run test -w web -- FindingCard`
Expected: FAIL — cannot resolve `./FindingCard`.

- [ ] **Step 3: Write `web/src/components/FindingCard.tsx`**

```tsx
import type { Vulnerability } from "../types";

export function FindingCard({ vuln }: { vuln: Vulnerability }) {
  return (
    <div className={`finding ${vuln.severity}`}>
      <strong>{vuln.type}</strong>
      <div className="meta">módulo: {vuln.module}</div>
      <div>{vuln.description}</div>
      {vuln.evidence && <div className="evidence">{vuln.evidence}</div>}
    </div>
  );
}
```

- [ ] **Step 4: Write `web/src/components/StatusBadge.tsx`**

```tsx
import type { ScanStatus } from "../types";

const LABELS: Record<ScanStatus, string> = {
  PENDING: "Na fila",
  RUNNING: "Analisando",
  COMPLETED: "Concluído",
  FAILED: "Falhou",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`badge ${status}`}>{LABELS[status]}</span>;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npm run test -w web -- FindingCard`
Expected: PASS — 2 tests.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/FindingCard.tsx web/src/components/StatusBadge.tsx web/src/components/FindingCard.test.tsx
git commit -m "feat(web): add FindingCard and StatusBadge components"
```

---

## Task 6: SeverityGroup and HealthBanner components

**Files:**
- Create: `web/src/components/SeverityGroup.tsx`
- Create: `web/src/components/HealthBanner.tsx`

- [ ] **Step 1: Write `web/src/components/SeverityGroup.tsx`**

```tsx
import type { SeverityGroupData } from "../severity";
import { FindingCard } from "./FindingCard";

export function SeverityGroup({ group }: { group: SeverityGroupData }) {
  if (group.items.length === 0) return null;
  return (
    <div className="sev-group">
      <h3>
        {group.severity} ({group.items.length})
      </h3>
      {group.items.map((vuln) => (
        <FindingCard key={vuln.id} vuln={vuln} />
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Write `web/src/components/HealthBanner.tsx`**

```tsx
import type { Health } from "../types";

export function HealthBanner({ health }: { health: Health | null }) {
  if (!health) return null;
  if (health.status === "ok") {
    return <div className="banner up">Backend OK — banco e fila conectados.</div>;
  }
  const down = [
    !health.checks.db && "PostgreSQL",
    !health.checks.redis && "Redis",
  ].filter(Boolean);
  return (
    <div className="banner down">
      Mau funcionamento: {down.join(" e ")} indisponível. Rode{" "}
      <code>npm run docker:up</code>.
    </div>
  );
}
```

- [ ] **Step 3: Type-check**

Run: `npx tsc -p web/tsconfig.json --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add web/src/components/SeverityGroup.tsx web/src/components/HealthBanner.tsx
git commit -m "feat(web): add SeverityGroup and HealthBanner components"
```

---

## Task 7: Scan form, polling hook, and App wiring

**Files:**
- Create: `web/src/hooks/useScanPolling.ts`
- Create: `web/src/components/ScanForm.tsx`
- Test: `web/src/components/ScanForm.test.tsx`
- Modify: `web/src/App.tsx`

- [ ] **Step 1: Write the failing test**

Create `web/src/components/ScanForm.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScanForm } from "./ScanForm";

describe("ScanForm", () => {
  it("chama onSubmit com a URL digitada", async () => {
    const onSubmit = vi.fn();
    render(<ScanForm onSubmit={onSubmit} busy={false} />);
    await userEvent.type(
      screen.getByPlaceholderText(/https:\/\//),
      "https://example.com"
    );
    await userEvent.click(screen.getByRole("button", { name: /escanear/i }));
    expect(onSubmit).toHaveBeenCalledWith("https://example.com");
  });

  it("desabilita o botão quando busy", () => {
    render(<ScanForm onSubmit={vi.fn()} busy={true} />);
    expect(screen.getByRole("button")).toBeDisabled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm run test -w web -- ScanForm`
Expected: FAIL — cannot resolve `./ScanForm`.

- [ ] **Step 3: Write `web/src/components/ScanForm.tsx`**

```tsx
import { useState, FormEvent } from "react";

interface Props {
  onSubmit: (url: string) => void;
  busy: boolean;
}

export function ScanForm({ onSubmit, busy }: Props) {
  const [url, setUrl] = useState("");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (trimmed) onSubmit(trimmed);
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://exemplo.com"
        aria-label="URL do alvo"
      />
      <button type="submit" disabled={busy}>
        {busy ? "Escaneando…" : "Escanear"}
      </button>
    </form>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm run test -w web -- ScanForm`
Expected: PASS — 2 tests.

- [ ] **Step 5: Write `web/src/hooks/useScanPolling.ts`**

```ts
import { useState, useCallback, useRef, useEffect } from "react";
import { postScan, getReport } from "../api";
import type { ScanReport } from "../types";

const TERMINAL = new Set(["COMPLETED", "FAILED"]);
const POLL_MS = 1500;

export function useScanPolling() {
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const stop = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  }, []);

  useEffect(() => stop, [stop]);

  const poll = useCallback(
    async (scanId: string) => {
      try {
        const next = await getReport(scanId);
        setReport(next);
        if (TERMINAL.has(next.status)) {
          setBusy(false);
          return;
        }
        timer.current = setTimeout(() => poll(scanId), POLL_MS);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Erro ao buscar relatório");
        setBusy(false);
      }
    },
    []
  );

  const start = useCallback(
    async (url: string) => {
      stop();
      setError(null);
      setReport(null);
      setBusy(true);
      try {
        const { scanId } = await postScan(url);
        await poll(scanId);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Erro ao iniciar scan");
        setBusy(false);
      }
    },
    [poll, stop]
  );

  return { report, error, busy, start };
}
```

- [ ] **Step 6: Rewrite `web/src/App.tsx`**

```tsx
import { useEffect, useState } from "react";
import "./styles.css";
import { ScanForm } from "./components/ScanForm";
import { StatusBadge } from "./components/StatusBadge";
import { SeverityGroup } from "./components/SeverityGroup";
import { HealthBanner } from "./components/HealthBanner";
import { useScanPolling } from "./hooks/useScanPolling";
import { groupBySeverity } from "./severity";
import { getHealth } from "./api";
import type { Health } from "./types";

export default function App() {
  const { report, error, busy, start } = useScanPolling();
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    let active = true;
    const check = () =>
      getHealth()
        .then((h) => active && setHealth(h))
        .catch(() => active && setHealth({ status: "degraded", checks: { db: false, redis: false } }));
    check();
    const id = setInterval(check, 5000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const groups = report ? groupBySeverity(report.vulnerabilities) : [];
  const hasFindings = report && report.vulnerabilities.length > 0;

  return (
    <div className="app">
      <h1>TecTecCheck</h1>
      <p className="subtitle">Scanner de vulnerabilidades web</p>

      <HealthBanner health={health} />
      <ScanForm onSubmit={start} busy={busy} />

      {error && <p className="error">{error}</p>}

      {report && (
        <section>
          <p>
            Alvo: <strong>{report.url}</strong> <StatusBadge status={report.status} />
          </p>
          {report.status === "COMPLETED" && !hasFindings && (
            <p>Nenhuma vulnerabilidade encontrada.</p>
          )}
          {groups.map((group) => (
            <SeverityGroup key={group.severity} group={group} />
          ))}
        </section>
      )}
    </div>
  );
}
```

- [ ] **Step 7: Run the full web suite and type-check**

Run: `npm run test -w web`
Expected: PASS — severity, FindingCard, ScanForm tests all green.
Run: `npx tsc -p web/tsconfig.json --noEmit`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add web/src/hooks/useScanPolling.ts web/src/components/ScanForm.tsx web/src/components/ScanForm.test.tsx web/src/App.tsx
git commit -m "feat(web): wire scan form, polling, health banner into App"
```

---

## Task 8: One-command orchestration

**Files:**
- Modify: `package.json` (root)

- [ ] **Step 1: Install `concurrently`**

Run: `npm install -D concurrently@^9.0.0`

- [ ] **Step 2: Update the root `scripts` block**

Replace the existing `scripts` block in `package.json` with:

```json
  "scripts": {
    "predev": "docker compose up -d",
    "dev": "concurrently -k -n api,worker,web -c blue,magenta,green \"npm run dev:api\" \"npm run worker\" \"npm run dev:web\"",
    "dev:api": "tsx src/api/server.ts",
    "dev:web": "npm run dev -w web",
    "worker": "tsx src/queue/worker.ts",
    "cli": "tsx src/cli/index.ts",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:web": "npm run test -w web",
    "build": "tsc",
    "db:migrate": "prisma migrate dev",
    "db:generate": "prisma generate",
    "docker:up": "docker compose up -d"
  },
```

- [ ] **Step 3: Boot everything with one command**

Run: `npm run dev`
Expected: `predev` starts Docker (Postgres + Redis), then three colored panels appear — `api` prints `TecTecCheck API rodando em http://localhost:3000`, `worker` prints `Aguardando jobs na fila 'scans'...`, `web` prints `Local: http://localhost:5173/`.

> First run only: in a second terminal run `npm run db:generate && npm run db:migrate -- --name init` once so the database schema exists.

- [ ] **Step 4: End-to-end smoke check**

Open `http://localhost:5173`. The green "Backend OK" banner shows. Enter `https://example.com`, click **Escanear**. The status badge moves PENDING → RUNNING → COMPLETED and findings render grouped by severity. Stop with Ctrl+C (the `-k` flag kills all panels together).

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json
git commit -m "feat: boot Docker, API, worker, and web UI with one npm run dev"
```

---

## Task 9: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the "Running the App (full flow)" section**

Swap the three-terminal block (README lines ~61–75) for:

```markdown
## Running the App (full flow)

One command boots PostgreSQL + Redis (Docker), the API, the worker, and the web UI:

```bash
npm run dev
```

- Web UI: **http://localhost:5173** — enter a URL and watch findings appear, grouped by severity.
- API: http://localhost:3000

**First run only**, create the database schema once (second terminal):

```bash
npm run db:generate
npm run db:migrate -- --name init
```

Prefer the terminal? The CLI still works:

```bash
npm run cli -- scan https://example.com
npm run cli -- report <scanId>
```
```

- [ ] **Step 2: Update the "Project Scripts" table**

Update the `npm run dev` row and add the new rows so the table reads:

```markdown
| Script | Action |
|--------|--------|
| `npm run dev` | Boot Docker + API + worker + web UI together |
| `npm run dev:api` | Start only the REST API |
| `npm run dev:web` | Start only the web UI |
| `npm run worker` | Start scan worker |
| `npm run cli` | Run CLI |
| `npm test` | Run backend test suite |
| `npm run test:web` | Run frontend test suite |
| `npm run build` | Compile TypeScript → `dist/` |
| `npm run db:migrate` | Run Prisma migrations |
| `npm run db:generate` | Generate Prisma client |
| `npm run docker:up` | Start Postgres + Redis |
```

- [ ] **Step 3: Mirror the changes in `README.pt-BR.md`** (same two edits, Portuguese wording).

- [ ] **Step 4: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs: document one-command dev flow and web UI"
```

---

## Self-Review Notes

- **Spec coverage:** Web interface (Tasks 2–7) ✓; one command boots front + back (Task 8) ✓; visible critical points / parts analyzed (SeverityGroup + module shown per finding) ✓; malfunction reports (`/api/health` + HealthBanner, Task 1 + 6) ✓; accessibility-of-running via README (Task 9) ✓.
- **Type consistency:** `ScanStatus`, `Severity`, `Vulnerability`, `ScanReport`, `Health` defined once in `web/src/types.ts` and reused; `SEVERITY_ORDER` / `groupBySeverity` / `SeverityGroupData` consistent across `severity.ts`, `SeverityGroup.tsx`, `App.tsx`. Backend `/api/health` response shape (`{ status, checks: { db, redis } }`) matches the frontend `Health` type and the health test.
- **Endpoints:** Frontend calls only existing routes (`POST /api/scan`, `GET /api/scan/:id/report`) plus the new `GET /api/health`. Vite proxy forwards `/api` to `:3000`, so no CORS needed.
