# Vigiles

Local proof of concept of the vulnerability monitor. It answers one question for every advisory that matches one of our projects: **should a developer be pinged now, told this sprint (digest), or should it only be logged?**

```
git ref ─► lockfiles ─► osv-scanner (offline) ─► findings ─► KEV / EPSS / CVSS ─► base priority
                                                     │
                       code snapshot ─► claude -p (read-only) ─► verdict + evidence
                                                     │
                              config/policy.yaml ─► ping / digest / log ─► Inbox, Review, Eval
```

- [docs/poc-spec.md](docs/poc-spec.md) covers what it does and why.
- [docs/poc-plan.md](docs/poc-plan.md) covers the milestones.
- [docs/spikes.md](docs/spikes.md) records the verified tool behavior.

## Requirements

- Node 24 (`nvm use`)
- `osv-scanner` 2.7+ (`brew install osv-scanner`)
- `git`
- Claude Code CLI, logged in (`claude --version`; tested with 2.1.318). Triage runs on your subscription. `ANTHROPIC_API_KEY` is deliberately not passed through.

## Run

```bash
npm install
npm run build && npm start    # day to day
```

Open http://127.0.0.1:3900. `npm run dev` gives the same dashboard with hot reload for working on Vigiles itself. The production build is the safer default because Next's dev-only endpoints sit in front of the DNS-rebinding guard (`src/proxy.ts`).

Under **Jobs**, click **Refresh all**:

1. `sync-osv` downloads the OSV databases. The first run fetches about 210 MB for npm.
2. `sync-kev` fetches the CISA catalog.
3. `scan` reads each enabled project at its ref.
4. `enrich` adds EPSS scores and base priority.
5. `triage` runs Claude on up to 25 P0–P2 findings.
6. `decide` applies the policy.

The same jobs run from the terminal. Ctrl-C cancels the job in progress cleanly: Claude child processes are stopped and the job is recorded as `cancelled`.

```bash
npm run job -- refresh-all
npm run job -- scan --project how-clutch-web
npm run job -- triage --limit 5
npm run job -- triage --config v1-sonnet-high-code --findings 12,13 --force
npm run job -- decide
```

Runtime data (SQLite DB, OSV zips, code snapshots) lives in `~/.vigiles`; set `VIGILES_DATA_DIR` to override.

## Tuning loop

1. **Inbox**: what would have been sent to Slack, grouped into messages.
2. **Review**: blind labeling. `1/2/3` = ping/digest/log, `y/n/u` = affected, `Enter` = save, `j/k` = next/previous.
3. **Eval**: ping recall and precision, confusion matrices, and disagreements. Compares base-priority-only, the LLM's own suggestion, and the policy.
4. Fix what disagrees:
   - **Wrong facts or verdict**: add a new prompt version in `prompts/triage/`, add a config in `config/vigiles.yaml`, and re-triage the labeled findings.
   - **Right facts, wrong action**: edit `config/policy.yaml`, then go to Jobs → **Re-evaluate policy**. This makes no LLM calls.

## Projects

Projects are configured in `projects/<id>.yaml`:

- `how-clutch-web` is enabled.
- `held-api` and `held-ios` are present but have `enabled: false`. Confirm their ⚠ fields before enabling them.
