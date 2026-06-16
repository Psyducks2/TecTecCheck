# TecTecCheck

> 🇬🇧 [English version](./README.md)

**TecTecCheck** é um scanner de vulnerabilidades web público e de código aberto, executável via CLI. Detecta problemas comuns de segurança em alvos HTTP/HTTPS: headers de segurança ausentes, diretórios/arquivos expostos e exposição de tecnologias.

> ⚠️ **Uso autorizado apenas.** Faça scan somente em alvos que você possui ou tem permissão escrita explícita para testar. Scan não autorizado pode ser ilegal.

## Arquitetura

```
CLI  →  API REST (Express)  →  Fila assíncrona (BullMQ + Redis)  →  Workers (módulos de scanner plugáveis)  →  PostgreSQL
```

Módulos de scanner (padrão Strategy):

| Módulo | Detecta |
|--------|---------|
| **recon** | Acessibilidade do alvo (cancela scan se inacessível) |
| **headers** | Headers de segurança ausentes (HSTS, CSP, X-Frame-Options, …) |
| **fuzzer** | Diretórios/arquivos expostos via wordlist (`.env`, `/admin`, …) |
| **fingerprint** | Tecnologias expostas (PHP, WordPress, Laravel, React, …) |

## Stack

Node.js 20+, TypeScript 5, Express, BullMQ, Redis, PostgreSQL, Prisma ORM, Commander.js, Chalk, Ora, Vitest, Axios, Cheerio.

## Requisitos

- **Node.js** >= 20
- **Docker** (para PostgreSQL + Redis locais) — instale o [Docker Desktop](https://www.docker.com/products/docker-desktop/)

## Configuração

```bash
# 1. Instalar dependências
npm install

# 2. Criar arquivo .env local
cp .env.example .env

# 3. Subir PostgreSQL + Redis
npm run docker:up

# 4. Gerar Prisma client + rodar migrations
npm run db:generate
npm run db:migrate -- --name init
```

## Rodar os Testes

Os testes unitários mockam todo I/O de rede/banco — **não precisa de Docker**:

```bash
npm test          # roda uma vez
npm run test:watch
```

Esperado: **19 testes de backend passando**. A interface web tem a própria suíte:

```bash
npm run test:web   # 9 testes (jsdom + React Testing Library)
```

## Rodar a Aplicação (fluxo completo)

Um único comando sobe PostgreSQL + Redis (Docker), a API, o worker e a interface web juntos:

```bash
npm run dev
```

- Interface web: **http://localhost:5173** — digite uma URL e acompanhe os findings aparecerem, agrupados por severidade. Um banner reporta a saúde do backend (DB/Redis fora do ar, ou API inacessível).
- API: http://localhost:3000

**Apenas na primeira vez**, crie o schema do banco uma vez (em um segundo terminal):

```bash
npm run db:generate
npm run db:migrate -- --name init
```

Prefere o terminal? O CLI continua funcionando:

```bash
npm run cli -- scan https://example.com
npm run cli -- report <scanId>
```

## API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/api/scan` | Body `{ "url": "https://..." }` → `201 { scanId, status }` |
| `GET`  | `/api/scan/:id/report` | Relatório completo do scan com os findings |
| `GET`  | `/api/health` | Saúde do backend → `{ status, checks: { db, redis } }` |

## Scripts do Projeto

| Script | Ação |
|--------|------|
| `npm run dev` | Sobe Docker + API + worker + interface web juntos |
| `npm run dev:api` | Inicia apenas a API REST |
| `npm run dev:web` | Inicia apenas a interface web |
| `npm run worker` | Inicia o worker de scan |
| `npm run cli` | Roda o CLI |
| `npm test` | Roda a suíte de testes do backend |
| `npm run test:web` | Roda a suíte de testes do frontend |
| `npm run build` | Compila TypeScript → `dist/` |
| `npm run db:migrate` | Roda as migrations do Prisma |
| `npm run db:generate` | Gera o Prisma client |
| `npm run docker:up` | Sobe Postgres + Redis |

## Níveis de Severidade

`LOW` · `MEDIUM` · `HIGH` · `CRITICAL`

## Licença

MIT
