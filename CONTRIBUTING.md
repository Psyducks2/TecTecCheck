# Contributing to TecTecCheck

## Adding a New Scanner Module

TecTecCheck uses the **Strategy pattern** for scanner modules. Each module is an independent, pluggable unit that receives a `ScanContext` and returns an array of `Finding` objects.

### 1. Implement `IScannerModule`

Create a file at `src/scanner/modules/<name>.module.ts`:

```typescript
import type { Finding, IScannerModule, ScanContext } from "../types";

export class MyModule implements IScannerModule {
  name = "my-module"; // unique identifier, lowercase, no spaces

  async execute(ctx: ScanContext): Promise<Finding[]> {
    // ctx.url        — target URL
    // ctx.scanId     — current scan ID
    // ctx.config     — optional scan configuration (headers, excludePaths, maxRps, modules)
    // ctx.initialResponse — HTTP response from ReconModule (headers, status, body)
    const findings: Finding[] = [];

    // ... perform checks ...

    if (someVulnerabilityFound) {
      findings.push({
        module: this.name,
        type: "MY_FINDING_TYPE",       // SCREAMING_SNAKE_CASE
        severity: "MEDIUM",            // LOW | MEDIUM | HIGH | CRITICAL
        description: "Human-readable description of the vulnerability.",
        evidence: "Optional technical detail, e.g. GET https://... → 200",
      });
    }

    return findings;
  }
}
```

### 2. Severity Guidelines

| Severity | When to use |
|----------|-------------|
| `CRITICAL` | Immediate compromise possible (exposed secrets, RCE, unreachable target) |
| `HIGH` | Exposed admin panels, missing CSP, SQLi indicators |
| `MEDIUM` | Missing HSTS, X-Frame-Options, auth-required paths |
| `LOW` | Technology disclosure, non-sensitive redirects, informational headers |

### 3. Register the module in the worker

Open `src/queue/worker.ts` and add your module to `MODULE_REGISTRY`:

```typescript
import { MyModule } from "../scanner/modules/my.module";

const MODULE_REGISTRY: Record<ModuleName, IScannerModule> = {
  // ... existing modules ...
  "my-module": new MyModule(),
};
```

Also update the `ModuleName` type in `src/scanner/types.ts`:

```typescript
export type ModuleName =
  | "recon"
  | "identification"
  | "headers"
  | "fuzzer"
  | "fingerprint"
  | "my-module"; // add here
```

And add it to `DEFAULT_MODULE_ORDER` in `worker.ts` so it runs by default.

### 4. Respect scan configuration

If your module makes HTTP requests, always apply custom headers from the scan config:

```typescript
const customHeaders = ctx.config?.headers ?? {};
const response = await axios.get(ctx.url, {
  headers: { "User-Agent": UA, ...customHeaders },
});
```

If your module iterates over paths or items, check `ctx.config?.excludePaths`:

```typescript
import { matchesExclusion } from "../utils/exclusion"; // if extracted
// or inline: skip if path is in ctx.config?.excludePaths
```

### 5. Write tests

Create `tests/scanner/<name>.module.test.ts`. Mock `axios` to avoid real HTTP calls:

```typescript
import { describe, it, expect, vi } from "vitest";
import axios from "axios";
import { MyModule } from "../../src/scanner/modules/my.module";

vi.mock("axios");

describe("MyModule", () => {
  const module = new MyModule();
  const ctx = { url: "https://example.com", scanId: "test-001" };

  it("returns finding when vulnerability detected", async () => {
    vi.mocked(axios.get).mockResolvedValue({ status: 200, headers: {}, data: "" });
    const findings = await module.execute(ctx);
    expect(findings.some(f => f.type === "MY_FINDING_TYPE")).toBe(true);
  });

  it("returns empty when target is clean", async () => {
    vi.mocked(axios.get).mockResolvedValue({ status: 404, headers: {}, data: "" });
    const findings = await module.execute(ctx);
    expect(findings).toHaveLength(0);
  });
});
```

Run tests:

```bash
npm test
```

### 6. Checklist before opening a PR

- [ ] Module implements `IScannerModule` correctly
- [ ] `name` field is lowercase, unique, kebab-case
- [ ] All HTTP calls propagate `ctx.config?.headers`
- [ ] Findings use appropriate severity levels
- [ ] Unit tests cover: finding detected, no false positives, edge cases
- [ ] `ModuleName` type updated in `src/scanner/types.ts`
- [ ] Module registered in `MODULE_REGISTRY` and `DEFAULT_MODULE_ORDER`
- [ ] `npm test` passes with no new failures

## Development Setup

```bash
npm install
cp .env.example .env
npm run docker:up
npm run db:generate
npm run db:migrate -- --name init
npm run dev          # boots API + worker + web UI
```

## Code Style

- TypeScript strict mode — no `any` without justification
- Async/await over `.then()` chains
- No side effects at module load time (except module registries)
- Error messages in Portuguese (user-facing) or English (internal/logs)
