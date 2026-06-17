# TecTecCheck

> 🇧🇷 [Versão em Português](./README.pt-BR.md)

**TecTecCheck** is a public, open-source web vulnerability scanner runnable from the CLI. It detects common security issues in HTTP/HTTPS targets: missing security headers, exposed directories/files, and technology disclosure.

> ⚠️ **Authorized use only.** Scan only targets you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## Architecture

```
CLI  →  REST API (Express)  →  Async queue (BullMQ + Redis)  →  Workers (pluggable scanner modules)  →  PostgreSQL
```

Scanner modules (Strategy pattern):

| Module | Detects |
|--------|---------|
| **recon** | Target reachability (aborts scan if unreachable) |
| **headers** | Missing security headers (HSTS, CSP, X-Frame-Options, …) |
| **fuzzer** | Exposed directories/files via wordlist (`.env`, `/admin`, …) |
| **fingerprint** | Tech stack disclosure (PHP, WordPress, Laravel, React, …) |

## Tech Stack

Node.js 20+, TypeScript 5, Express, BullMQ, Redis, PostgreSQL, Prisma ORM, Commander.js, Chalk, Ora, Vitest, Axios, Cheerio.

## Requirements

- **Node.js** >= 20
- **Docker** (for local PostgreSQL + Redis) — install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Create local env file
cp .env.example .env

# 3. Start PostgreSQL + Redis
npm run docker:up

# 4. Generate Prisma client + run migrations
npm run db:generate
npm run db:migrate -- --name init
```

## Running Tests

Unit tests mock all network/DB I/O — **no Docker required**:

```bash
npm test          # run once
npm run test:watch
```

Expected: **19 backend tests passing**. The web UI has its own suite:

```bash
npm run test:web   # 9 tests (jsdom + React Testing Library)
```

## Running the App (full flow)

One command boots PostgreSQL + Redis (Docker), the API, the worker, and the web UI together:

```bash
npm run dev
```

- Web UI: **http://localhost:5173** — dark-themed security dashboard with three tabs:
  - **Scanner** — URL input, animated scan progress, error reporting
  - **Resultados** — findings grouped by severity with summary chips; auto-opens when scan completes
  - **Sistema** — live status cards for API, PostgreSQL and Redis
- API: http://localhost:3000

**First run only**, create the database schema once (in a second terminal):

```bash
npm run db:generate
npm run db:migrate -- --name init
```

Prefer the terminal? The CLI still works:

```bash
npm run cli -- scan https://example.com
npm run cli -- report <scanId>
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Body `{ "url": "https://..." }` → `201 { scanId, status }` |
| `GET`  | `/api/scan/:id/report` | Full scan report with findings |
| `GET`  | `/api/health` | Backend health → `{ status, checks: { db, redis } }` |

## Project Scripts

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

## Web UI

Dark-themed dashboard built with React + Vite + TypeScript. No UI framework — pure CSS with design tokens.

**Tabs**

| Tab | Content |
|-----|---------|
| **Scanner** | URL input field, animated scan button, live progress card |
| **Resultados** | Severity summary chips, findings grouped by severity; auto-switches when scan completes |
| **Sistema** | Status cards for API, PostgreSQL, Redis — polled every 5 s |

**Color system** (semantic tokens):

| Role | Color | Used for |
|------|-------|----------|
| Background deep | `#0F172A` | Page background |
| Surface | `#1E293B` | Cards, panels |
| Primary blue | `#2563EB` | Buttons, active tab, charts |
| Cyan accent | `#0EA5E9` | Progress, links, evidence text |
| Success green | `#10B981` | Online status, no findings, completed |
| Warning yellow | `#FBBF24` | MEDIUM severity, degraded service |
| Danger red | `#EF4444` | CRITICAL findings, errors, service down |
| Orange | `#F97316` | HIGH severity |

**Typography:** Space Grotesk (headings) · Inter (body) · JetBrains Mono (evidence, URLs)

## Severity Levels

`LOW` · `MEDIUM` · `HIGH` · `CRITICAL`

## License

MIT
