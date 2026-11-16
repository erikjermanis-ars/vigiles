# Dependency audit: Demo Web

Audited `main` at `a1b2c3d` (committed 2026-11-10) · 1 lockfile · 812 packages · generated 2026-11-12 10:05 UTC

**Fix now 3 · Fix soon 2 · Logged 2** (3 of these 7 items not triaged yet; placed by their signals)

**Fix now**: real harm is possible soon; fix today. **Fix soon**: real but not urgent; fix within 1–2 weeks. **Logged**: not a real threat in this project; no action needed.

## Warnings

- 3 findings without a verdict (1 failed, 2 not triaged yet): placed by their signals alone. See Not triaged; run `/vigiles:audit` again to triage them.

## Fix now (3)

### evil-pkg@1.0.3 — Malicious code in evil-pkg (npm)

[MAL-2026-1234](https://osv.dev/vulnerability/MAL-2026-1234) · `package-lock.json`

- **Why:** This package version is known malware. Installing it can run attacker code on developer machines and in CI.
- **Signals:** P0 · malicious package. No AI triage needed: malicious packages always go to Fix now.
- **Fix:** Remove the package, reinstall from a clean state, and rotate every secret that was on the affected machines or in CI.
- **Dependency:** transitive, dev only via `eslint-plugin-foo > evil-pkg`

### next@15.1.0 — Authorization Bypass in Next.js Middleware

[GHSA-f82v-jwr5-mffw](https://osv.dev/vulnerability/GHSA-f82v-jwr5-mffw) · CVE-2025-29927 · `package-lock.json`

- **Why:** Anyone on the internet can reach /admin without logging in.
- **Verdict:** affected, high confidence · P0 · CVSS 9.1 · exploited in the wild (CISA KEV, since 2025-03-21) · EPSS 93%
- **Summary:** Middleware is the only authorization check for /admin, and the app is self-hosted with `next start`.
- **Exploitable when:** A request with an x-middleware-subrequest header skips middleware. No login needed.
- **Where in the code:**
  - `src/middleware.ts:12` — redirects unauthenticated users away from /admin
  - `src/app/admin/page.tsx` — no server-side session check of its own
- **Fix:** Upgrade next to 15.2.3 or later. Workaround: Strip the x-middleware-subrequest header at the load balancer.
- **Dependency:** direct

### braces@3.0.2 — Uncontrolled resource consumption in braces

[GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) · CVE-2024-4068 · `package-lock.json`

- **Why:** Not triaged yet, so there is no verdict. It is in Fix now because of its signals alone: P1 (EPSS 0.6 ≥ 0.5). Run `/vigiles:audit` again to triage it.
- **Signals:** P1 · EPSS 60%
- **Fix:** Fixed in 3.0.3.
- **Dependency:** transitive via `micromatch > braces`

## Fix soon (2)

### @sentry/node@8.40.0, @sentry/core@8.40.0 — Sentry SDK leaks environment variables in \<script> error pages

[GHSA-6465-jgvq-jhgp](https://osv.dev/vulnerability/GHSA-6465-jgvq-jhgp) · `package-lock.json`

- **Why:** Real but needs an error page to be triggered.
- **Verdict:** likely affected, medium confidence · P2 · CVSS 7.5
- **Summary:** The Node SDK renders error pages in production.
- **Exploitable when:** An error page must be shown to an attacker.
- **Where in the code:**
  - `sentry.server.config.ts:4` — Sentry.init with default integrations
- **Fix:** Upgrade @sentry/nextjs to the latest 8.x release. Fixed in 8.49.0.
- **Dependency:** transitive via `@sentry/nextjs > @sentry/node`
- **Same advisory, also in:** `@sentry/core@8.40.0` (not affected, high confidence; raised to match). One fix usually covers all of them.

### cookie@0.5.0 — cookie accepts cookie name, path, and domain with out of bounds characters

[GHSA-pxg6-pf52-xh8x](https://osv.dev/vulnerability/GHSA-pxg6-pf52-xh8x) · CVE-2024-47764 · `package-lock.json`

- **Why:** Triage failed (claude error_max_turns: reached max turns | 30), so there is no verdict yet. It is in Fix soon because of its signals alone: P2 (CVSS 7.3 ≥ 7). Run `/vigiles:audit` again to triage it.
- **Signals:** P2 · CVSS 7.3
- **Fix:** Fixed in 0.7.0.
- **Dependency:** direct

## Logged (2)

<details>
<summary>2 items with no action needed (1 of them not triaged yet, placed here by their signals)</summary>

| Package | Advisory | Priority | Why |
|---|---|---|---|
| lodash@4.17.20 | CVE-2021-23337 | P2 | not affected: Only `template \| trim` in a build script reads it. |
| postcss@8.4.20 | CVE-2023-44270 | P3 | not triaged yet; placed by its signals |

</details>

## Not triaged (3)

No verdict yet, so these findings are placed by their signals alone; each is also shown in its section above. Run `/vigiles:audit` again to triage them.

<details>
<summary>1 failed, 2 not triaged yet</summary>

| Package | Advisory | Priority | Placed in | Status |
|---|---|---|---|---|
| braces@3.0.2 | CVE-2024-4068 | P1 | Fix now | not triaged yet |
| cookie@0.5.0 | CVE-2024-47764 | P2 | Fix soon | failed: claude error_max_turns: reached max turns \| 30 |
| postcss@8.4.20 | CVE-2023-44270 | P3 | Logged | not triaged yet |

</details>

---

Data: OSV database 2026-11-12 · CISA KEV 2026-11-11 · EPSS 2026-11-12. Triage: v3-opus-high-code (prompt v3@1a2b3c4d). Policy 1e4ce23df0e6. Vigiles 0.1.0.

Commit the `.vigiles/` directory (this report is gitignored) so teammates reuse these verdicts.
