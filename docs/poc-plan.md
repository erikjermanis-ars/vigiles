# Vigiles POC — Build Plan

2026-11-10 · Implements [poc-spec.md](poc-spec.md). Section references (§) point there.

Each milestone ends in something you can run and check. The order follows the data: you can't tune a decision before there are findings, and you can't evaluate before there are labels. Sizes are rough (S ≈ half a day, M ≈ 1 day, L ≈ 2 days of focused work with Claude Code).

| # | Milestone | Size | You can… |
|---|---|---|---|
| M0 | Spikes | S | trust the three external tools before building on them |
| M1 | Skeleton | M | start the app, trigger a job, watch it run |
| M2 | Scan pipeline | L | see how-clutch-web's findings with KEV/EPSS/CVSS and base priority |
| M3 | Dependency facts | M | see direct or transitive, dev-only, paths and import sites per finding |
| M4 | Triage | L | read Claude's verdict and evidence for each P0–P2 finding |
| M5 | Policy + Inbox | M | see what would have pinged, and change it by editing YAML |
| M6 | Labeling + Eval | L | label findings and measure agreement; run experiments |
| M7 | More projects | M | add held-api (and held-ios) and check the exit criteria |

---

## M0 — Spikes (S)

Goal: settle the unknowns in spec §17 before writing app code. Record results in `docs/spikes.md`.

- [ ] Install osv-scanner (`brew install osv-scanner`) and record the version.
- [ ] On a `git archive` snapshot of how-clutch-web `origin/main`:
  - [ ] Run with `--offline-vulnerabilities --download-offline-databases` and `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` set. Note where the DB lands, its size, the download time, and whether a second run re-downloads.
  - [ ] Save the JSON output as a test fixture. Confirm the shape of `results[].packages[].vulnerabilities` and `groups`, and whether withdrawn records are filtered out.
  - [ ] Compare against `npm audit` (40 vulnerable packages, measured 2026-11-10) and explain any differences (for example MAL- entries, or GHSA records missing from OSV).
- [ ] Run against held-ios `held.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`: is it supported, and how many findings?
- [ ] Hand-run one triage with the exact flags from §3.5 on the `next` "RCE on Windows-hosted servers" finding, with a rough prompt. Confirm:
  - [ ] `--system-prompt` works together with `--safe-mode` and `--restricted`.
  - [ ] Read, Grep and Glob work inside the snapshot, and nothing outside it is readable.
  - [ ] The no-code variant works (`--tools ""`, empty temporary directory as cwd).
  - [ ] Wall time, `num_turns` and `total_cost_usd` for Opus and Sonnet.
- [ ] Pick the CVSS library (must score v3.1 **and** v4.0 vectors) and check it against 3 known vectors.

**Done when** `docs/spikes.md` answers each item and the §3.5 flag set is confirmed or corrected in the spec.

---

## M1 — Skeleton (M)

- [ ] `git init`, add a `.gitignore` (node_modules, .next, `.env*`). Add a `CLAUDE.md` pointing to `docs/poc-spec.md` and `docs/poc-plan.md`.
- [ ] Next.js 16 + TypeScript + Tailwind 4 + shadcn/ui, `.nvmrc` = 24, oxlint + prettier (as in how-clutch-web), vitest.
- [ ] Drizzle + better-sqlite3 (WAL). Full schema from §13, migrations, and data-dir bootstrap (`~/.vigiles`, mode 700, `VIGILES_DATA_DIR` override).
- [ ] Config loading with Zod validation: `config/vigiles.yaml`, `config/policy.yaml` (placeholder), `projects/*.yaml`. Copy the how-clutch-web draft from §14, and confirm the ⚠ values with Erik.
- [ ] Worker (`src/worker/index.ts`):
  - [ ] Poll loop, one job at a time.
  - [ ] Progress and log appends.
  - [ ] Cancel support.
  - [ ] Mark interrupted jobs as failed on startup.
  - [ ] A `noop` job that sleeps and reports progress.
- [ ] CLI: `npm run job -- <name> [--project x] [--config y] [--limit n] [--force]` enqueues a job and tails it.
- [ ] Jobs page: a button per job, run history, live progress and log (polling every 2 seconds).
- [ ] `npm run dev` runs `next dev -H 127.0.0.1 -p 3900` and `tsx watch src/worker/index.ts` together.

**Done when** clicking `noop` shows live progress, cancelling it works, and killing the worker mid-run leaves the row as `failed: interrupted` after restart.

---

## M2 — Scan pipeline (L)

- [ ] `lib/git`: resolve ref → SHA and commit date, soft-fail `git fetch`, `ls-tree`, archive snapshot (cached by SHA, `.env*` and `.claude/` stripped) (§7.1).
- [ ] Lockfile discovery + `exclude` globs + coverage gaps (§7.2).
- [ ] `sync-osv` and the osv-scanner runner + parser (§7.4). Upsert `advisories`, write `feed_state`.
- [ ] `scan`: inventory rows, findings diff with every case in §7.5 (new / still present / fixed / no longer matches / reopened, plus origin), and events.
- [ ] `sync-kev`, then `enrich`:
  - [ ] EPSS batches of 100.
  - [ ] CVSS scoring.
  - [ ] Base priority + `priority_reasons` with thresholds read from `policy.yaml` (§8).
  - [ ] `escalated` events.
- [ ] `refresh-all` (sync-osv → sync-kev → scan → enrich for now).
- [ ] Pages:
  - [ ] Projects: ref → commit and date, lockfiles, coverage gaps, counts.
  - [ ] Findings table with filters.
  - [ ] Finding page: advisory rendered without raw HTML, and signals.
  - [ ] Staleness banner (§4.4).
- [ ] Tests:
  - [ ] Diff logic on fixture lockfiles (add package, upgrade past fix, remove, advisory `modified` changes, reappear after fix).
  - [ ] Base-priority rules.

**Done when** Refresh all on how-clutch-web lists the same vulnerable packages as `npm audit` (with differences explained in `docs/spikes.md`), a second Refresh all creates no duplicates and no events, and the gitignored legacy folders are not scanned.

---

## M3 — Dependency facts (M)

- [ ] package-lock v2/v3 parser: installed versions, `direct`, `dev_only`, up to 3 shortest paths (§7.3). Tests compare paths with `npm ls <pkg> --all --package-lock-only` on the how-clutch-web fixture.
- [ ] Import sites: static scan of the snapshot for the package, or for a transitive package the direct dependency it comes through. Exclude tests and stories.
- [ ] Store the facts on findings during `scan`, and show them on the Finding page and as Findings filters.

**Done when** these show up correctly for how-clutch-web:
- `proxy-addr`: path `shadcn > @modelcontextprotocol/sdk > express > proxy-addr`, zero import sites for `shadcn`.
- `storybook`: `dev_only`.
- `sharp`: path `next > sharp`.
- `dompurify`: path `posthog-js > dompurify`.

---

## M4 — Triage (L)

- [ ] `prompts/triage/v1.system.md`, `v1.user.md` (template with the §9.2 inputs) and `v1.schema.json` (§9.4).
- [ ] Seed `triage_configs` from `vigiles.yaml`: `v1-opus-high-code` (active) and `v1-opus-high-nocode`.
- [ ] Claude runner (§3.5, §9.5):
  - [ ] Spawn with prompt on stdin, minimal env, `ANTHROPIC_API_KEY` unset, timeout and kill.
  - [ ] One retry on schema failure.
  - [ ] Store everything, including `claude --version`.
- [ ] `triage` job:
  - [ ] Selection by input hash, ordering and `max_per_run` (§9.1).
  - [ ] Concurrency pool, per-finding progress, cancel.
  - [ ] Skip MAL-* findings.
- [ ] Finding page: one tab per config showing the verdict, the four sub-answers, evidence as `file:line` (clickable to open the file in the snapshot), remediation, cost and time. The run's raw JSON is collapsible.
- [ ] Add triage to `refresh-all`.

**Done when** how-clutch-web's P0–P2 findings are triaged, and the §1 examples come out sensibly:
- `next` Windows RCE → `deployment_conditions_met: no`
- `proxy-addr` → `build_or_tooling_only` or `not_used`
- `sharp` → points at the photo upload route

A second `triage` run with no changes triages nothing.

---

## M5 — Policy + Inbox (M)

- [ ] Rule engine supporting equality, any-of lists, `gte`/`lte` and `not`, with unit tests for every default rule in §10. Validate `policy.yaml` with Zod.
- [ ] `policy_versions` by content hash. The `decide` job writes `decisions` and `decision_changed` events. Add a "Re-evaluate policy" button that makes no LLM calls.
- [ ] Complete `refresh-all`: … → triage → decide.
- [ ] Inbox (§12):
  - [ ] Ping and Digest grouped as messages per (project, package).
  - [ ] Toggle between *since last refresh* and *all open*.
  - [ ] Each item shows the rule that fired.
- [ ] Finding page: decision trace (inputs → rule → action), and the LLM's `suggested_action` beside it.

**Done when** every open finding has a decision with a rule ID, and editing a threshold in `policy.yaml` then clicking Re-evaluate changes the affected decisions within a second and shows them in *since last refresh*.

---

## M6 — Labeling + Eval (L)

- [ ] Review page:
  - [ ] Blind labeling queue (§11.1), defaulting to unlabeled P0–P2 sorted by priority.
  - [ ] Keyboard shortcuts.
  - [ ] Reveal the decision after saving.
- [ ] Eval page (§11.2):
  - [ ] Ping recall and precision.
  - [ ] Confusion matrix with drill-down.
  - [ ] Verdict accuracy.
  - [ ] Three deciders side by side.
  - [ ] Cost and time stats per config.
  - [ ] Volume in messages.
  - [ ] Config and policy-version pickers.
- [ ] Consistency: `triage --config X --sample 20 --force --tag consistency` and a consistency metric.
- [ ] Prompt iteration path: copy `v1.*` → `v2.*`, add a config, triage only labeled findings with it, and compare on Eval.
- [ ] Run the first experiments (§11.3): code vs. no-code, then Opus vs. Sonnet.
- [ ] Ask a second developer to label about 30 of the same findings, and add an agreement view (you vs. them).

**Done when** all how-clutch-web P0–P2 findings are labeled, and at least one policy or prompt change is recorded with before/after metrics.

---

## M7 — More projects + exit check (M)

- [ ] `projects/held-api.yaml`: two lockfiles (`backend/`, `dashboard/`), NestJS API + React SPA, with its own exposure and hosting.
- [ ] `projects/held-ios.yaml` if M0 showed SwiftPM support.
- [ ] Optional: `draft-profile` job, where `claude -p` (same lockdown) reads a repo and proposes `projects/<id>.yaml` with inferred fields marked. This tests the parent spec's profile-generator skill.
- [ ] Optional: the project-brief and package-grouped triage experiments (§11.3), if cost is the issue on held-api's volume.
- [ ] Write `docs/poc-results.md` covering:
  - [ ] Exit criteria (§1) with numbers.
  - [ ] The chosen model and config.
  - [ ] The final policy.
  - [ ] Cost per finding and the projected monthly budget.
  - [ ] Answers to the parent spec's open questions on code access and LLM budget.

**Done when** the exit criteria are met on at least 100 labeled findings across at least 2 projects, or `poc-results.md` explains why not and what to change.

---

## Day-to-day tuning session (once M6 lands)

1. `npm run dev` → open `http://127.0.0.1:3900`.
2. If the staleness banner shows, go to Jobs → **Refresh all**. The first run downloads the OSV DB and triages up to 25 findings.
3. **Inbox**: anything that would ping now?
4. **Review**: label until the queue is empty.
5. **Eval** → disagreements. For each one, decide which of these it is:
   - **Wrong facts or verdict**: a prompt problem. Make a new prompt version, re-triage the labeled set, compare.
   - **Right facts, wrong action**: a policy problem. Edit `policy.yaml`, click Re-evaluate, compare.
6. When a new config or policy beats the active one on recall, then precision, then cost, make it active.
