# Vigiles: dependency audit for Claude Code

Vigiles checks your project's dependencies for known vulnerabilities and tells you which ones actually matter
**for this project**. `npm audit` rates every known vulnerability only by its generic severity. Vigiles reads
your code to check whether each one can be exploited in your app, and sorts it into one of three outcomes.

| Outcome      | Meaning                                                                                                            | What to do       |
| ------------ | ------------------------------------------------------------------------------------------------------------------ | ---------------- |
| **Fix now**  | Real harm is possible quickly: data leak, server takeover, account takeover, a malicious package                   | Today            |
| **Fix soon** | Real, but not urgent: a denial of service, a risk to developer machines, a severe flaw your code doesn't reach yet | Within 1–2 weeks |
| **Logged**   | Not a real threat here (the vulnerable code isn't used, the platform doesn't match, only a CLI pulls it in)        | Nothing          |

In the proof of concept on three company projects, 460 findings came down to 3 "Fix now" and 26 "Fix soon".
The decisions matched the project owner's own calls in 9 of 9 cases.

## Install

You need Node.js 20+, git, the Claude Code CLI (logged in), and `osv-scanner`:

```bash
brew install osv-scanner
```

Then, in Claude Code:

```
/plugin marketplace add erikjermanis-ars/vigiles
/plugin install vigiles@vigiles
```

`erikjermanis-ars/vigiles` is the GitHub repository that hosts the plugin. Claude Code uses your existing git access
without prompting, so a private repository works if you can already clone it (an SSH key loaded in
`ssh-agent`, or `gh auth setup-git`).

## Use

Open Claude Code in your project and run:

```
/vigiles:audit
```

You can also just ask "check this project's dependencies for vulnerabilities".

**The first run in a project** asks a few questions. Vigiles needs a short project profile
(`.vigiles/profile.yaml`): where the app runs, whether it's reachable from the internet, what data it holds.
Claude drafts it from your code and asks you only what the code can't tell (usually the production branch,
exposure, criticality and data types). Confirm it before the first triage: verdicts are tied to the profile,
so changing it later triages every finding again.

Then Vigiles scans and shows how many findings need triage with a time and usage estimate. Claude asks before
triaging more than 10, and Claude Code asks you to approve every triage command (it spends your usage). The
other steps are free. They run without a prompt until you answer a question; after that, Claude Code asks you
to approve them as well. When it's done you get a short summary in the chat and the full report in
`.vigiles/report.md`. Claude offers to apply the fixes. A fix shows up as fixed in the audit once it is
committed (Vigiles reads the last commit).

Options: `/vigiles:audit --ref origin/main` audits another branch (the default is the last commit of the branch
you're on). `--limit 20` triages only the 20 most urgent findings.

## What to expect

**Time and usage.** Triage takes about 20 seconds per finding, three at a time, on your Claude subscription.
The first run on a Next.js app with 119 findings took 12 minutes and used about $10 of usage at API list
prices. Later runs triage only findings that are new or changed: an upgrade, a new advisory version, or a new
or moved import of the package in your code. After a week of active development that was about 1 in 5
findings. A Vigiles update with a new triage prompt triages everything again.

**Commit the `.vigiles/` directory**: `profile.yaml`, `verdicts.json` and a small `.gitignore` that keeps the
report out. The verdicts file is the cache: teammates who run the audit reuse your verdicts instead of paying
for them again. The report is regenerated on each run. In a public repository, add `verdicts.json` to
`.vigiles/.gitignore`, because it describes in detail how exploitable each finding is.

**Each item in the report** says what the vulnerability is, when it's exploitable in your app, where in your
code (file and line), the fix (usually a version upgrade), and a workaround if there is one.

**Accuracy.** Triage is done by Claude with a prompt that was evaluated against the project owner's
decisions, plus fixed safety rules: a malicious package is always Fix now, and a vulnerability exploited in the
wild is never just logged in an internet-facing or high-criticality app. It can still be wrong. Every verdict
shows its evidence so you can check it. If you disagree, tell Claude what the profile is missing (a mitigation,
a note). Claude can add it, but any profile change triages every finding again on the next audit; Claude shows
the cost and asks first.

## What it covers, and what it doesn't

- **Covered lockfiles**: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements*.txt`,
  `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`,
  `pubspec.lock`, `Package.resolved`, `gradle.lockfile`. npm `package-lock.json` gives the best results: Vigiles
  then knows the dependency chains and where your code imports each package.
- **Not covered**: vulnerabilities in your own code (use `/security-review` or a security review), manifests
  without a lockfile, `deno.lock` and `Podfile.lock` (the report lists all of these as not audited),
  uncommitted lockfile changes (commit first), and anything not yet published in an advisory.

## Privacy and safety

- Matching is offline: Vigiles downloads the whole OSV database for your ecosystem (npm is about 210 MB,
  cached in `~/.cache/vigiles` and refreshed at most daily), so no vulnerability service sees your dependency
  list. It also downloads the CISA KEV catalog and sends the CVE ids of your findings to FIRST
  (api.first.org) for EPSS scores.
- Triage runs Claude with read-only tools (Read, Grep, Glob) on a copy of your committed files, without `.env`
  files, `.git` or `.claude`. No shell, no network tools, no MCP servers. Your code is sent to Anthropic as in
  any Claude Code session.

## Troubleshooting

| Problem                                            | Fix                                                                                                                                                          |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| "osv-scanner not found"                            | `brew install osv-scanner`                                                                                                                                   |
| Triage stops with a login error                    | Run `claude` in a terminal, log in, then run `/vigiles:audit` again. An `ANTHROPIC_API_KEY` in your shell is not used: triage runs on your Claude Code login |
| Triage stops on a usage limit or repeated failures | Wait (for a limit, until the reset time shown), then run `/vigiles:audit` again; finished verdicts are kept                                                  |
| A finding seems wrong                              | Ask Claude why. If the profile is missing a fact, add it and audit again: every finding is triaged again (Claude shows the cost first)                       |
| A fix still shows up                               | Commit it first; Vigiles audits the last commit                                                                                                              |
| You want to start over                             | Delete `.vigiles/verdicts.json` (everything is triaged again)                                                                                                |

Questions and feedback: Erik Jermanis.
