# Vigiles

Vulnerability-monitor POC. It matches OSV advisories against project lockfiles (read from git), enriches them with KEV/EPSS, triages them with locked-down `claude -p`, and applies a YAML decision policy (ping / digest / log). A local dashboard is used for labeling and evaluation.

- Spec: `docs/poc-spec.md` · Build plan: `docs/poc-plan.md` · Parent spec: `docs/Vulnerability Monitor — System Spec.pdf`
- Next.js 16 (App Router) dashboard + a separate Node worker (`src/worker`), SQLite through Drizzle.
- Next 16 differs from older versions; read `node_modules/next/dist/docs/` before using unfamiliar APIs (see `AGENTS.md`).

## Commands

Use Node 24 (`.nvmrc`). In non-interactive shells, run `export PATH=$HOME/.nvm/versions/node/v24.18.1/bin:$PATH` first.

| Command | What it does |
|---|---|
| `npm run dev` | Dashboard on http://127.0.0.1:3900 + worker |
| `npm run job -- <type> [--project x] [--config y] [--limit n] [--findings 1,2] [--force]` | Run a job inline (`--enqueue` hands it to the worker) |
| `npm test` | vitest |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run db:generate` | New migration after editing `src/lib/db/schema.ts` (migrations apply automatically on open) |

## Layout

- `config/vigiles.yaml` (settings, triage configs) and `config/policy.yaml` (decision rules). `projects/<id>.yaml` holds the project profiles. YAML is the source of truth and gets synced to the DB before every job.
- `prompts/triage/<version>.{system.md,user.md,schema.json}`: versioned triage prompts.
- `src/lib/*`: domain modules (git, inventory, osv, signals, triage, policy, eval, queries). `src/jobs/*` holds the job handlers; `src/app/*` holds the dashboard.
- Runtime data is in `~/.vigiles` (override with `VIGILES_DATA_DIR`). It is never in the repo.

## Conventions

- TypeScript strict, ESM. Inside `src/lib`, `src/jobs`, `src/worker` and `src/cli`, use relative imports. In `src/app` and `src/components`, use the `@/` alias.
- Shared enums and JSON shapes live in `src/lib/types.ts`; the DB schema lives in `src/lib/db/schema.ts`. Timestamps are ISO strings.
- Run subprocesses through `src/lib/proc.ts` (never a shell). Claude always gets `minimalEnv()`.
- DB tests use `openDb(':memory:')`. Tests sit next to the module as `*.test.ts`.
- Never modify the target repos. Read them only through git (`src/lib/git`), and never read their `.env*` files.
- Pages read the DB through query functions in `src/lib/queries/*`. Mutations go through server actions.
