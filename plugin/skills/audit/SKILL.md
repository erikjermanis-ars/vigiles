---
name: audit
description: Audit this repository's dependencies for known vulnerabilities and report only the ones that matter for this project (Fix now / Fix soon), with the affected code and the fix. Use when the user asks for a dependency, vulnerability, CVE, npm audit or supply-chain security audit of the current project, or asks whether a published vulnerability affects it.
argument-hint: '[--ref <git-ref>] [--limit <n>]'
allowed-tools: Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles doctor), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles doctor *), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles init), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles init *), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles profile), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles profile *), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles scan), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles scan *), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles report), Bash(node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles report *)
---

# Vigiles dependency audit

You are running Vigiles on the git repository in the current working directory. Vigiles does the mechanical
work itself: it matches the lockfiles against the OSV vulnerability database (offline), adds CISA KEV and EPSS
signals, triages every finding against the code with its own locked-down Claude subprocess and an evaluated
prompt, and applies a fixed decision policy. Your job is to drive it, set up the project profile with the
developer, ask before spending their Claude usage, and explain the result.

Do not triage findings yourself and do not overrule a verdict. You may explain verdicts and their evidence.

Run the CLI exactly as `node ${CLAUDE_PLUGIN_ROOT}/bin/vigiles <command> [options]` from the repository, one
command per Bash call with nothing chained (no `;`, `&&`, pipes or `echo $?`): only the plain command is
pre-approved, and the Bash tool reports the exit code anyway.
Arguments the user passed: `$ARGUMENTS` (pass `--ref` and `--limit` on to `scan` and `triage`).
`doctor`, `init`, `profile`, `scan` and `report` are pre-approved, but only in the turn that invokes this
skill: after the developer answers a question, Claude Code asks them to approve these too. That is expected;
don't work around it. `triage` spends the developer's Claude usage, so it always asks; don't use `audit`.

## 1. Prerequisites

Run `doctor`. If it reports a missing prerequisite (exit code 3), tell the developer what to install and stop:
Node.js 20+, git, `osv-scanner` (`brew install osv-scanner`, or https://google.github.io/osv-scanner/installation/),
and the `claude` CLI logged in.

## 2. Project profile (`.vigiles/profile.yaml`)

Triage judges every finding against this profile (how the app is exposed, where it runs, what data it holds,
which mitigations exist), so it has to be right.

Verdicts are cached under a hash of the profile's values, so **any later change to a value triages every
finding again** (comments are free). Get the profile right before the first triage.

- **Present and valid** (doctor says so): continue. If `doctor` or `profile` reports placeholders (⚠, TODO,
  "Fill in" in a value), draft values for them from the code (read-only, as below) and still run the scan,
  which is free. Then, only if anything needs triage, ask in one question together with step 4: finish the
  profile first with your draft (recommended), or triage now and pay for triage again once it is finished. If
  they choose to finish it, show the draft, write it once they confirm, run `profile` and `scan` again, then
  run the triage they chose. If nothing needs triage, go on to the report and mention the draft in your summary.
- **Missing**: run `init`. It creates `.vigiles/`, prints facts it detected and a commented template. Then:
  1. Investigate the repository read-only to fill in the template: deployment and hosting (Dockerfiles, CI
     workflows, amplify.yml, vercel.json, infrastructure code), how the app is exposed, what data it handles
     (personal data, health, payments, credentials, minors), authentication, mitigations (WAF, rate limits,
     body-size limits), runtime and framework versions, and notes such as CLIs listed under `dependencies`
     that never run in production. Never open `.env*` files or other secrets.
  2. Ask the developer, in one question round, only what the code cannot tell you or what you inferred with
     low confidence: typically the production branch, exposure (internet-facing / vpn / internal),
     criticality (high / medium / low) and data classes.
  3. Write `.vigiles/profile.yaml`. Keep comments short; put "⚠" in any value that is still unconfirmed.
  4. Run `profile` to validate it and fix any error it reports.
  5. Show the developer the profile and get it confirmed before triage, with no ⚠, TODO or "Fill in" left in
     values (see above: a later edit re-triages everything). Then they commit it.

## 3. Scan

Run `scan`, adding `--ref <ref>` only if the developer asked for something other than the checked-out branch
(by default Vigiles audits the last commit of the current branch). It prints the findings by priority, how
many already have a cached verdict, how many need triage, and an estimate.

If it warns about uncommitted lockfile or manifest changes, tell the developer those changes are not audited
until they are committed.

## 4. Triage (spends the developer's Claude usage)

- **Nothing to triage**: go to step 5.
- **10 or fewer**, profile complete: run `triage`; the developer approves the command in the permission prompt.
- **More than 10**, or the profile still has placeholders: ask first, quoting the scan's estimate (findings,
  minutes, usage at list prices) and, if so, that the profile is unfinished. Options: triage all (recommended
  once the profile is complete: verdicts are cached in `.vigiles/verdicts.json`, so once committed this is
  mostly a one-time cost for the team), triage the most urgent N first (`--limit N`), or skip triage for now
  (the report then places untriaged findings by their signals alone).

Run exactly the command the developer chose (`triage`, or `triage --limit N`), nothing broader. Never add
`--force`, except for `triage --only <id> --force` when the developer asks to re-run one doubtful verdict
with nothing changed. For more than about 10 findings, run it with the Bash tool's `run_in_background: true`
(about 20 seconds per finding, 3 at a time, which can exceed the Bash timeout), tell the developer roughly
how long it will take, and wait for the completion notification instead of polling. Verdicts are saved as
they arrive, so an interrupted run loses nothing.

If triage stops early (exit code 3, "Stopped early"):

- a login error: the developer runs `claude` in a terminal and logs in, then you run `triage` again;
- a usage limit, or Claude failing for several findings in a row (an outage): tell the developer to wait
  (for a usage limit, until the reset time in the message), then run `triage` again. Don't retry right away.

## 5. Report

Run `report`. It writes `.vigiles/report.md` and prints a summary. Read the report, then tell the developer:

- **Fix now**: for each item, one or two lines: package and version, what an attacker could do in this app,
  where in the code, and the fix.
- **Fix soon**: one line each.
- How many findings were logged (no action needed) and how many are not triaged, plus any warning that changes
  how far the result can be trusted (coverage gaps, uncommitted lockfiles, missing KEV/EPSS data, failed triage).
- That the full detail is in `.vigiles/report.md`.

Do not paste the whole report. If nothing is in Fix now or Fix soon, say so plainly.

## 6. Offer to fix

If there are Fix now or Fix soon items, offer to apply the upgrades. Use the project's package manager; for a
transitive dependency, prefer upgrading the direct dependency that pulls it in, otherwise an override. Change
files only after the developer agrees. Afterwards run the project's build and tests.

Vigiles audits the last commit, so a `scan` right now would still show the old findings. Tell the developer
the fix is confirmed once it is committed: after they commit (or you do, if they ask), run `scan` again,
follow step 4, then run `report`. Findings still left in an upgraded package have new inputs and need triage
again (untriaged, a P0/P1 shows in Fix now); all other verdicts are reused. If they don't want to commit yet,
say the next audit after the commit will confirm it.

## 7. Wrap up

Remind the developer to commit the `.vigiles/` directory (`git add .vigiles/`: profile.yaml, verdicts.json and
the .gitignore that keeps report.md out): teammates then reuse the verdicts instead of paying for the same
triage again. If the repository is public, warn that `verdicts.json` describes in detail how exploitable each
finding is, and suggest adding it to `.vigiles/.gitignore`.

## Rules

- A malicious package in Fix now is an emergency: say so first. The remedy is to remove it, reinstall from a
  clean state, and rotate every secret that was on affected machines and in CI.
- Never edit `.vigiles/verdicts.json` by hand, and never triage more findings than the developer agreed to.
- If the developer disagrees with a verdict, show its evidence. If the profile is missing a fact (a mitigation,
  a note), explain that any change to a profile value makes every cached verdict out of date, so all findings
  are triaged again, not just this one. Ask before editing the profile. If they agree: edit it, run `profile`,
  run `scan` and quote its estimate, then follow step 4 and run `report`. Don't use `triage --only ... --force`
  after a profile edit: triage refuses until you scan again. If they decline, keep the verdict and mention the
  disagreement in your summary.
- Exit codes: 0 ok; 1 unexpected error (show the message); 2 fix the input it names (profile, missing scan);
  3 missing prerequisite, or triage stopped early (login, usage limit, outage).

## Commands

| Command                                         | What it does                                                          |
| ----------------------------------------------- | --------------------------------------------------------------------- |
| `doctor`                                        | Checks Node, git, osv-scanner, claude, the cache and the profile      |
| `init`                                          | Creates `.vigiles/` and prints detected facts plus a profile template |
| `profile`                                       | Validates `.vigiles/profile.yaml`                                     |
| `scan [--ref <ref>] [--fetch] [--refresh-db]`   | Matches lockfiles, adds signals, shows what needs triage              |
| `triage [--limit <n>] [--only <ids>] [--force]` | Triages findings without a current verdict                            |
| `report`                                        | Applies the policy and writes `.vigiles/report.md`                    |
