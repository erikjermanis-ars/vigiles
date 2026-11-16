# Vigiles plugin: how it works (creator guide)

The Vigiles plugin packages the POC as a Claude Code plugin that developers run on demand with
`/vigiles:audit`. It runs on each developer's own Claude subscription: no server, no central repo access,
no Slack app. The user guide is [plugin/README.md](../plugin/README.md).

## Shape

```
/vigiles:audit (plugin/skills/audit/SKILL.md)        Claude drives the steps, talks to the developer
   └─ node plugin/bin/vigiles <command>              bundled CLI (src/plugin → esbuild), all decisions here
        doctor · init · profile · scan · triage · report · audit
```

The split is deliberate. Everything that decides an outcome runs in the CLI with the same code, prompt and
policy as the POC: matching, signals, triage, policy. The session's Claude only handles the conversation:
drafting the profile, asking before spending usage, explaining the report and applying fixes. So the POC's
evaluation (99% agreement with labels, 9/9 with the owner, 20/20 consistent) still describes what users get,
and the session's context isn't flooded with hundreds of verdicts.

## Pipeline

| Step          | Command           | What happens                                                                                                                                                                                                                                                                                    | Reused from the POC                                               |
| ------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Prerequisites | `doctor`          | Node 20+, git, osv-scanner, claude and its login, cache dir, profile                                                                                                                                                                                                                            |                                                                   |
| Profile       | `init`, `profile` | `init` prints detected facts and a template; Claude fills it with the developer; `profile` validates                                                                                                                                                                                            | `ProjectProfileSchema`                                            |
| Scan          | `scan`            | Resolve the ref (default `HEAD`), snapshot the commit's tracked files, find lockfiles, refresh the offline OSV DB, run osv-scanner, compute dependency facts and import sites, add KEV and EPSS, compute base priority and each finding's triage input hash                                     | `src/lib/git`, `inventory`, `osv`, `signals`, `triage/input-hash` |
| Triage        | `triage`          | The POC's locked-down `claude -p` call (prompt v3, Opus, effort high, Read/Grep/Glob on the snapshot, $3 cap, one retry) for each finding without a current verdict, 3 in parallel; each verdict saved as it arrives. Stops on a login or usage-limit error or 3 CLI failures in a row (exit 3) | `src/lib/triage/{prompt,claude,concurrency}`                      |
| Report        | `report`          | Evaluate `config/policy.yaml` (incl. same-advisory groups), write `.vigiles/report.md`                                                                                                                                                                                                          | `src/lib/policy`                                                  |

The DB-coupled POC modules had their pure parts extracted into DB-free modules (re-exported from the
originals, so the dashboard is unchanged): `osv/zip.ts`, `signals/kev-feed.ts`, `signals/compute.ts`,
`policy/same-advisory.ts`, `inventory/scan-results.ts`, `triage/concurrency.ts`. The build fails if drizzle,
better-sqlite3, Next, React or `src/lib/db` end up in the bundle.

## State

| Where                                           | What                                                                                                                     | Committed |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | --------- |
| `<repo>/.vigiles/profile.yaml`                  | Project profile (same schema as `projects/*.yaml`; `repo_path` optional; `ref` = the production branch, shown to triage) | Yes       |
| `<repo>/.vigiles/verdicts.json`                 | One verdict per finding: triage output, input hash, model, prompt fingerprint, commit, cost. This is the cache           | Yes       |
| `<repo>/.vigiles/.gitignore`                    | Ignores `report.md`                                                                                                      | Yes       |
| `<repo>/.vigiles/report.md`                     | Latest report                                                                                                            | No        |
| `~/.cache/vigiles/osv-db`, `kev.json`           | OSV zips per ecosystem and the CISA KEV feed, refreshed at most every 24 h                                               | –         |
| `~/.cache/vigiles/snapshots/<projectKey>/<sha>` | Tracked files of audited commits (no `.env*`, `.git`, `.claude`, `.vigiles`, symlinks); last 3 kept                      | –         |
| `~/.cache/vigiles/repos/<projectKey>/`          | `scan.json` (last scan), `triage-failures.json`                                                                          | –         |

**Cache key.** A verdict is reused while the finding's input hash is unchanged. The hash is the POC's
`computeInputHash`: advisory `modified` date, installed and fixed versions, direct/dev-only, dependency paths,
the import sites shown to triage (file and line) and their total count, the triage-visible profile, the prompt
fingerprint (content hash of the prompt files), model, effort and code access. It has no commit SHA. So a new
advisory version, an upgrade or lockfile change in the package's dependency chain, a new or moved import, a
profile edit or a prompt change triggers re-triage. A profile edit or a new prompt changes every finding's
hash, so it re-triages everything; the skill therefore gets the profile confirmed before the first triage.

**Trust boundaries.** The repository is untrusted input: `.vigiles/` files are read only as regular files (a
symlink is refused) and parse errors never quote their content; `--ref` is validated before it reaches git
(`git fetch --end-of-options <remote> refs/heads/<branch>`); report text from advisories and the model is
escaped so it cannot form links or images. By design, a committed `verdicts.json` is trusted: an entry whose
input hash matches is reused as is. The skill's `allowed-tools` pre-approve only `doctor`, `init`, `profile`,
`scan` and `report`, so `triage` goes through Claude Code's permission prompt (unless the developer's own
permission mode or allow rules already permit it). Claude Code clears a skill's grant when the user sends
the next message, so after the developer answers a question the free commands prompt too. Re-invoking the
skill doesn't help: invoking it needs approval as well (tested).

## Equivalence with the dashboard

Tested on 2026-11-12 on how-clutch-web `origin/main` @ 9bff790, the commit the dashboard last scanned. The plugin
scanned it, triaged every finding again from scratch and wrote its report. `npm run compare:plugin` (plus
one-off checks of KEV, CVSS and the policy) compared the result with the dashboard database, opened read-only:

| Check                                    | Result                                                                                                                                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Findings                                 | 118 in both. 1 more in the plugin: an advisory OSV published after the dashboard's last scan                                                                                   |
| Priority, KEV, CVSS, triage input hash   | 118/118 identical                                                                                                                                                              |
| Policy on the dashboard's own verdicts   | 118/118 same action (14 Fix soon, 104 Logged)                                                                                                                                  |
| Fresh triage: verdict / suggested action | 116/118 / 117/118                                                                                                                                                              |
| Fresh triage: final action               | 116/118. A P1 `dompurify` finding went Fix soon → Logged (now judged not affected with high confidence); a P2 `sharp` finding went Logged → Fix soon (triage suggested digest) |
| Run                                      | 119 findings in 12 min 20 s, $10.37 at API list prices ($0.087 per finding), 0 failures                                                                                        |

The dashboard's own repeat triage runs agree on 18 of 20 verdicts, so differences of this size are normal
run-to-run variation. The input hashes are identical, so a verdict from one side is current on the other.

## Development

```bash
npm run vigiles -- scan --repo ../some-project     # run the CLI from source (tsx)
npm test && npm run typecheck && npm run lint
npm run build:plugin                               # bundle → plugin/bin/vigiles, copy prompt/policy assets
npm run compare:plugin -- --repo ../some-project   # plugin result vs the dashboard DB (read-only)
claude --plugin-dir ./plugin                       # try the plugin in Claude Code without installing it
claude plugin validate . && claude plugin validate ./plugin
```

`plugin/bin/vigiles` and the copied assets are build output, but they are committed: installing a plugin
copies the `plugin/` directory as it is, with no build step. Rebuild and commit them with every change to
`src/plugin`, `src/lib`, a prompt or `config/*`. `npm run check:plugin` (also run by `npm test`, in
`src/plugin/build.test.ts`) fails while `plugin/` is out of date, so a dashboard change to code the plugin
bundles fails the tests until you rebuild. That is deliberate: the plugin must not drift from the dashboard.
Don't add a `package.json` or lockfile to the plugin root (Claude Code would install packages there; the build
refuses both). `plugin/bin/package.json` only marks the bundle as CommonJS and must stay.

## Changing the prompt or policy

Tune in the dashboard first (labels, Eval page), as before. Then point `config/vigiles.yaml`
`triage.active_config` at the new config and run `npm run build:plugin`. It copies that prompt version and
`config/policy.yaml` into `plugin/`. A new prompt re-triages everything in every project on its next audit
(about $0.10 per finding). Policy edits need no re-triage: `report` re-applies the policy to stored verdicts.

## Releasing

1. Bump `version` in `plugin/.claude-plugin/plugin.json`. Installed copies stay on their version until it
   changes.
2. `npm run build:plugin`, test, commit, push.
3. Users get it with `/plugin marketplace update vigiles` in a session or `claude plugin update vigiles@vigiles`
   in a shell. Auto-update is off by default; each user can turn it on under Marketplaces in `/plugin`.

## Distribution

This repository is the marketplace: `.claude-plugin/marketplace.json` at the root lists `./plugin`. Developers
run `/plugin marketplace add erikjermanis-ars/vigiles` and `/plugin install vigiles@vigiles`. Claude Code runs git
without prompts, so a private repo works wherever `git clone` already works (an SSH key in `ssh-agent`, or
`gh auth setup-git`). To register the marketplace for a project's contributors, commit this to its
`.claude/settings.json`; each contributor still installs the plugin once with
`claude plugin install vigiles@vigiles --scope project`. An admin can install it for everyone with the same
keys in managed settings.

```json
{
  "extraKnownMarketplaces": { "vigiles": { "source": { "source": "github", "repo": "erikjermanis-ars/vigiles" } } },
  "enabledPlugins": { "vigiles@vigiles": true }
}
```

Later, move `plugin/` into a company-wide marketplace repo that holds all internal plugins. Claude Code is the
only target: claude.ai and Cowork (including claude.ai organization plugin sync) don't install a plugin that
has a top-level `bin/`.

## Known limits and next steps

- On-demand only: nothing runs unless someone runs it. Next: a weekly LLM-free check (GitHub Action or hook)
  that flags new P0/P1 findings and says "run /vigiles:audit".
- Code changes re-triage findings. how-clutch-web's `design` HEAD, one week after `origin/main`, re-triages
  26 of 119 findings (about $3): 21 because three new files import `next` (its findings and those of packages
  it pulls in), 5 because `dompurify`'s dependency paths changed. Dropping import sites from the key would make
  verdicts more reusable but could keep a verdict that missed a new import.
- Approval prompts for the free commands after the first turn (see Trust boundaries). The fix would be a
  plugin `PreToolUse` hook that approves exactly those five commands for the whole session (plugins can't ship
  permission rules). Not built: it is an auto-approval mechanism, so it needs an explicit decision.
- Disputing one verdict has no cheap path: adding the missing fact to the profile re-triages everything. Next:
  a per-finding note or override that does not change the profile hash.
- Cost reductions not done yet: one triage per advisory instead of per package, batching advisories of the
  same package, a cheaper first pass.
- Only tested on macOS. Monorepos with many lockfiles work (each lockfile is matched), but profiles are per
  repository.
