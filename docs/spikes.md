# M0 spikes — results

2026-11-10 · Answers the "verify early" items in [poc-spec.md](poc-spec.md) §17 and plan M0.

## osv-scanner

- Version **2.7.1** (osv-scalibr 0.5.3), installed with `brew install osv-scanner`.
- **Offline DB layout**: `$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scalibr/<Ecosystem>/all.zip`.
  - npm `all.zip` is 210 MB: ~223,500 `MAL-` (malicious package) records and ~8,100 `GHSA-` records.
  - SwiftURL is 112 KB.
- **Download**: `--download-offline-databases` fetched the npm DB in about 17 s. A second run with the flag did **not** refresh the existing zip (mtime unchanged). `sync-osv` therefore downloads zips itself with conditional requests (ETag / If-Modified-Since) and swaps them in atomically.
- **Scan time**: about 10 s for how-clutch-web, almost all of it loading the 210 MB zip. SwiftPM is instant.
- **Exit codes**: `1` means vulnerabilities were found (not an error), `0` means none.
- **JSON shape** (`--format json --all-packages`):
  - `results[].packages[]` has `package {name, version, ecosystem, purl}` and `dependency_groups: ["dev"]` for npm dev dependencies.
  - `groups[]` holds alias groups with `max_severity`, a **numeric score computed from the CVSS v3/v4 vector**. That removes the need for our own CVSS calculator.
  - `vulnerabilities[]` holds the full OSV records.
- **how-clutch-web `origin/main` (9bff790)**: 835 packages, **33 vulnerable package@versions, 137 advisory records** (all GHSA, no MAL today).
  - `npm audit` reports 40 "vulnerable packages" for the same lockfile. The difference is that npm audit also counts *parents* of vulnerable packages (for example `shadcn`, which is flagged only through its dependencies). OSV reports the vulnerable packages themselves.
- **held-ios** (`Package.resolved`, ecosystem `SwiftURL`): supported. 42 packages, 1 local package skipped, **0 vulnerabilities**.

## Claude CLI (2.1.318)

- This lockdown works with **subscription auth**:

  ```bash
  claude -p --model <m> --effort <e> --restricted --safe-mode --strict-mcp-config \
    --tools "Read,Grep,Glob" --permission-mode dontAsk --system-prompt <text> \
    --json-schema <schema> --output-format json --no-session-persistence --max-budget-usd <n>
  ```

  It also works with the environment reduced to `HOME, PATH, USER, LANG, TMPDIR` (`env -i …`).
- **Confinement**: a `Read` of `/etc/hosts` from the snapshot cwd was denied and listed in `permission_denials`. No CLAUDE.md content was loaded. `Grep` inside the snapshot worked.
- **Output**: one JSON object. `structured_output` holds the schema-validated object. The rest gives `total_cost_usd`, `usage`, `modelUsage` (resolved model ID, e.g. `claude-haiku-5-5`), `num_turns` and `duration_ms`.
- **Cost reference**: a 4-turn Haiku call with Grep cost $0.0012–0.0016 (list-price equivalent) and took 4–6 s.
- `--bare` is not usable on a subscription: it reads only `ANTHROPIC_API_KEY`.

## Repos

| Repo | Default branch (origin/HEAD) | Production ref used |
|---|---|---|
| how-clutch-web | `main` | `origin/main` |
| held-api | `qa` | `origin/main` (⚠ confirm) |
| held-ios | `develop` | `origin/main` (⚠ confirm) |

how-clutch-web's working tree is on the `design` branch. It also contains gitignored folders with their own lockfiles (`howclutch-main/`, `howclutch-platform-main/`, `.claude/worktrees/`) and `.env*` files. Reading from git avoids all of them.

## Dependency chains (npm ls --package-lock-only on how-clutch-web origin/main)

| Package | Chain |
|---|---|
| proxy-addr, body-parser | shadcn › @modelcontextprotocol/sdk › express › … |
| fast-uri | shadcn › @modelcontextprotocol/sdk › ajv › fast-uri |
| systeminformation | shadcn › @dotenvx/dotenvx › systeminformation |
| dompurify | posthog-js › dompurify |
| sharp | next › sharp |
