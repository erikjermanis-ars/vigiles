/**
 * Smoke test: renders the Findings, Finding, source viewer and Review pages to HTML against a seeded
 * in-memory DB (Next's router modules are stubbed). Catches runtime errors in the page trees and
 * checks that the blind Review page never puts the hidden answers into the HTML.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createElement, type AnchorHTMLAttributes, type FormHTMLAttributes, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { MALICIOUS_REMEDIATION } from '@/components/finding/helpers';
import { openDb, type Db } from '@/lib/db/client';
import { advisories, decisions, events, findings, jobRuns, labels, projects, scans, triageConfigs, triageRuns } from '@/lib/db/schema';
import { loadPolicy } from '@/lib/config/load';
import { formatDateTime } from '@/lib/format';
import { decideAll } from '@/lib/policy/decide';
import { LABELER_COOKIE } from '@/lib/queries/findings';
import { findingInputHash } from '@/lib/triage/state';
import type { DecisionInputs, ProjectProfile, TriageOutput } from '@/lib/types';

// The request's cookies (the labeler); tests set and clear it.
const cookieJar = vi.hoisted(() => new Map<string, string>());
vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name)! } : undefined),
    set: (name: string, value: string) => void cookieJar.set(name, value),
  }),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: () => {}, refresh: () => {} }),
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND');
  },
  redirect: (to: string) => {
    throw new Error(`NEXT_REDIRECT ${to}`);
  },
}));
vi.mock('next/link', () => ({
  default: ({ href, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) => createElement('a', { href, ...rest }),
}));
vi.mock('next/form', () => ({
  default: ({ action, ...rest }: FormHTMLAttributes<HTMLFormElement> & { action: string }) => createElement('form', { action, ...rest }),
}));
vi.mock('next/cache', () => ({ revalidatePath: () => {} }));

const SHA = 'f'.repeat(40);
const OLD_SHA = 'e'.repeat(40);
const ACTIVE = 'v1-opus-high-code';
const profile: ProjectProfile = {
  id: 'web',
  name: 'Web',
  enabled: true,
  repo_path: '/nonexistent',
  ref: 'origin/main',
  fetch_before_scan: false,
  exclude: [],
  owners: [],
  criticality: 'high',
  exposure: 'internet-facing',
  data_classes: [],
  runtime: {},
  deployments: [],
  third_party_services: [],
  mitigations: '',
  notes: '',
};
const output: TriageOutput = {
  verdict: 'likely_not_affected',
  confidence: 'medium',
  runtime_usage: 'build_or_tooling_only',
  vulnerable_code_used: 'no',
  attacker_reachable: 'no',
  deployment_conditions_met: 'unknown',
  summary: 'Pulled in by a CLI only.',
  evidence: [
    { file: 'src/app.ts', line: 2, note: 'only import' },
    { file: '(dependency facts)', line: null, note: 'transitive via shadcn' }, // real outputs cite non-files too
  ],
  exploit_conditions: 'Local access',
  remediation: 'Upgrade',
  workaround: null,
  suggested_action: 'digest',
  suggested_action_reason: 'SECRET-REASON',
};
const inputs: DecisionInputs = {
  priority: 'P1',
  malicious: false,
  in_kev: false,
  epss: 0.5,
  cvss: 9,
  exposure: 'internet-facing',
  criticality: 'high',
  direct: false,
  dev_only: false,
  fix_available: true,
  triage_status: 'ok',
  verdict: 'likely_not_affected',
  confidence: 'medium',
  runtime_usage: 'build_or_tooling_only',
  vulnerable_code_used: 'no',
  attacker_reachable: 'no',
  deployment_conditions_met: 'unknown',
  suggested_action: 'digest',
};

let tmp: string;
let db: Db;

beforeAll(() => {
  tmp = mkdtempSync(path.join(tmpdir(), 'vigiles-pages-smoke-'));
  process.env.VIGILES_DATA_DIR = tmp;
  db = openDb(':memory:');
  (globalThis as unknown as { __vigilesDb?: Db }).__vigilesDb = db;

  db.insert(projects).values({ id: 'web', name: 'Web', repoPath: '/x', ref: 'origin/main', profile, profileHash: 'h' }).run();
  db.insert(scans).values({ id: 1, projectId: 'web', ref: 'origin/main', commitSha: SHA, status: 'succeeded' }).run();
  db.insert(advisories)
    .values({
      osvId: 'GHSA-xxxx',
      cves: ['CVE-2026-9999'],
      aliases: ['CVE-2026-9999'],
      summary: 'Request smuggling',
      details: '## Impact\n\n<img src="https://tracker.test/p.gif"> **bold** [link](https://example.test) ![pic](https://img.test/a.png)\n\n<script>alert(1)</script>',
      references: ['https://example.test/ref', 'javascript:alert(1)'],
      cvssScore: 9,
      raw: {},
    })
    .run();
  db.insert(findings)
    .values([
      {
        id: 1, projectId: 'web', lockfile: 'package-lock.json', ecosystem: 'npm', packageName: 'proxy-addr', osvId: 'GHSA-xxxx',
        installedVersions: ['2.0.0'], fixedVersions: ['2.0.7'], origin: 'baseline', firstSeenScanId: 1, lastSeenScanId: 1,
        priority: 'P1', priorityReasons: ['epss 0.50 ≥ 0.5'], epss: 0.5, epssPercentile: 0.98, cvssScore: 9, direct: false,
        paths: [['shadcn', 'express', 'proxy-addr']], importSites: [{ file: 'src/app.ts', line: 1, specifier: 'shadcn', via: 'shadcn' }],
        importSiteCount: 57,
        instances: [
          { version: '2.0.0', direct: false, devOnly: false, paths: [['shadcn', 'express', 'proxy-addr']] },
          { version: '1.9.0', direct: false, devOnly: true, paths: [['storybook', 'proxy-addr']] },
        ],
        currentAction: 'digest', currentRuleId: 'RULE-SECRET', activeTriageRunId: 1,
      },
      {
        id: 2, projectId: 'web', lockfile: 'package-lock.json', ecosystem: 'npm', packageName: 'other', osvId: 'GHSA-xxxx',
        origin: 'new_advisory', firstSeenScanId: 1, lastSeenScanId: 1, priority: 'P2',
      },
    ])
    .run();
  db.insert(triageRuns)
    .values([
      { id: 1, findingId: 1, configName: ACTIVE, inputHash: 'h', status: 'ok', output, prompt: 'PROMPT', raw: { a: 1 }, costUsd: 0.5, commitSha: OLD_SHA },
      { id: 2, findingId: 1, configName: 'v1-sonnet-high-code', inputHash: 'h', status: 'ok', output, prompt: 'no commit recorded' },
    ])
    .run();
  db.insert(events).values({ findingId: 1, type: 'created', at: '2026-11-10T21:41:00.000Z' }).run();
  db.insert(decisions)
    .values({ findingId: 1, policyHash: loadPolicy().hash, configName: 'v1-opus-high-code', triageRunId: 1, action: 'digest', ruleId: 'RULE-SECRET', inputs })
    .run();

  const snap = path.join(tmp, 'snapshots', 'web', SHA, 'src');
  mkdirSync(snap, { recursive: true });
  writeFileSync(path.join(snap, 'app.ts'), 'import "shadcn";\nconst x = 1;\n');
  // The older commit triage run #1 read.
  const oldSnap = path.join(tmp, 'snapshots', 'web', OLD_SHA, 'src');
  mkdirSync(oldSnap, { recursive: true });
  writeFileSync(path.join(oldSnap, 'app.ts'), 'import "shadcn";\nconst OLD = 1;\n');
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Page = (props: { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string>> }) => Promise<ReactElement>;
async function render(load: () => Promise<{ default: unknown }>, params: Record<string, string> = {}, searchParams: Record<string, string> = {}) {
  const page = (await load()).default as Page;
  return renderToStaticMarkup(await page({ params: Promise.resolve(params), searchParams: Promise.resolve(searchParams) }));
}

describe('page smoke', () => {
  it('renders the findings list with filters', async () => {
    const html = await render(() => import('./page'));
    expect(html).toContain('proxy-addr');
    expect(html).toContain('CVE-2026-9999');
    expect(html).toContain('2 findings');
    const filtered = await render(() => import('./page'), {}, { priority: 'P0,P1', verdict: 'likely_not_affected', sort: 'epss' });
    expect(filtered).toContain('1 finding');
    expect(filtered).toContain('P0, P1'); // the multi-value option survives
  });

  it('renders the finding page with untrusted markdown neutralised', async () => {
    const html = await render(() => import('./[id]/page'), { id: '1' });
    for (const s of ['proxy-addr', 'RULE-SECRET', 'SECRET-REASON', 'shadcn › express › ', 'Triage with v1-opus-high-code', 'Raw CLI result']) {
      expect(html).toContain(s);
    }
    // (React adds its own form-replay <script> for server-action forms; the advisory's must not appear.)
    expect(html).not.toContain('<script>alert');
    expect(html).not.toContain('<img');
    expect(html).not.toContain('tracker.test');
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('/findings/1/source?file=src%2Fapp.ts&amp;line=2&amp;run=1#L2'); // evidence links carry their run
    expect(html).toContain('/findings/1/source?file=src%2Fapp.ts&amp;line=1#L1'); // import-site links do not
    expect(html).toContain('(dependency facts)');
    expect(html).not.toContain('file=%28dependency'); // a pseudo-citation is text, not a dead source link
    await expect(render(() => import('./[id]/page'), { id: '999' })).rejects.toThrow('NEXT_NOT_FOUND');
  });

  it('renders the per-version facts, the capped import-site count and local event times', async () => {
    const html = await render(() => import('./[id]/page'), { id: '1' });
    expect(html).toContain('Installed (2 versions)');
    expect(html).toContain('storybook › ');
    expect(html).toContain('dev only');
    expect(html).toContain('showing 1 of 57');
    expect(html).toContain(formatDateTime('2026-11-10T21:41:00.000Z'));
    expect(formatDateTime('2026-11-10T21:41:00.000Z')).toMatch(/^2026-11-1\d \d\d:41 \S+$/); // has a zone label
    expect(html).toContain(`Commit read`);
  });

  it('renders the source viewer and refuses traversal', async () => {
    const ok = await render(() => import('./[id]/source/page'), { id: '1' }, { file: 'src/app.ts', line: '2' });
    expect(ok).toContain('id="L2"');
    expect(ok).toContain('const x = 1;');
    expect(ok).toContain('latest scanned commit');
    const bad = await render(() => import('./[id]/source/page'), { id: '1' }, { file: '../../../etc/passwd' });
    expect(bad).toContain('Parent-directory segments');
  });

  it('opens an evidence link at the commit its triage run read', async () => {
    const html = await render(() => import('./[id]/source/page'), { id: '1' }, { file: 'src/app.ts', line: '2', run: '1' });
    expect(html).toContain('const OLD = 1;');
    expect(html).toContain('eeeeeeeeee');
    expect(html).toMatch(/Run #1 read commit eeeeeeeeee; the finding(&#x27;|')s latest scan is at ffffffffff/);
    expect(html).toContain(`href="/findings/1?config=${ACTIVE}&amp;run=1"`); // back to that run
    // A run that recorded no commit: the latest scan, with a note.
    const legacy = await render(() => import('./[id]/source/page'), { id: '1' }, { file: 'src/app.ts', run: '2' });
    expect(legacy).toContain('const x = 1;');
    expect(legacy).toContain('did not record which commit');
    const foreign = await render(() => import('./[id]/source/page'), { id: '2' }, { file: 'src/app.ts', run: '1' });
    expect(foreign).toContain('Triage run #1 is not a run of this finding.');
  });

  it('answers 404 for the source of a finding that does not exist', async () => {
    await expect(render(() => import('./[id]/source/page'), { id: '999' }, { file: 'src/app.ts' })).rejects.toThrow('NEXT_NOT_FOUND');
  });

  it('enqueues one forced triage per finding and config however often the button is clicked', async () => {
    const { enqueueTriageAction } = await import('./actions');
    const click = (config: string, findingId = '1') => {
      const fd = new FormData();
      fd.set('findingId', findingId);
      fd.set('config', config);
      return enqueueTriageAction(fd);
    };
    await click('v1-sonnet-high-code');
    await click('v1-sonnet-high-code');
    await click('v1-haiku-high-code');
    const triageJobs = db.select().from(jobRuns).all().filter((j) => j.type === 'triage');
    expect(triageJobs.map((j) => j.params)).toEqual([
      { findings: [1], config: 'v1-sonnet-high-code', force: true },
      { findings: [1], config: 'v1-haiku-high-code', force: true },
    ]);
    await expect(click('not-a-config')).rejects.toThrow(/unknown triage config/);
    await expect(click('v1-sonnet-high-code', '999')).rejects.toThrow(/not found/);
    expect(db.select().from(jobRuns).all().filter((j) => j.type === 'decide')).toHaveLength(0); // experiments never decide

    // The page shows the pending config's button as disabled; the others stay clickable.
    const html = await render(() => import('./[id]/page'), { id: '1' });
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Triage with v1-sonnet-high-code<\/button>/);
    expect(html).not.toMatch(/<button[^>]*disabled=""[^>]*>Triage with v1-opus-high-code<\/button>/);
    db.delete(jobRuns).run();
  });

  it('follows a triage under the active config with a decide job, once', async () => {
    const { enqueueTriageAction } = await import('./actions');
    const fd = new FormData();
    fd.set('findingId', '1');
    fd.set('config', ACTIVE);
    await enqueueTriageAction(fd);
    await enqueueTriageAction(fd);
    const jobs = db.select().from(jobRuns).orderBy(jobRuns.id).all();
    expect(jobs.map((j) => [j.type, j.params])).toEqual([
      ['triage', { findings: [1], config: ACTIVE, force: true }],
      ['decide', {}],
    ]);
    db.delete(jobRuns).run();
  });

  it('marks a decision stale after triage changed and re-evaluates the policy on request', async () => {
    db.insert(triageConfigs).values({ name: ACTIVE, promptVersion: 'v1', model: 'opus', effort: 'high', codeAccess: true, active: true }).run();
    const f1 = db.select().from(findings).where(eq(findings.id, 1)).get()!;
    const cfg = db.select().from(triageConfigs).where(eq(triageConfigs.name, ACTIVE)).get()!;
    db.insert(triageRuns).values({ id: 3, findingId: 1, configName: ACTIVE, inputHash: findingInputHash(db, f1, cfg), status: 'ok', output, prompt: 'p' }).run();

    const html = await render(() => import('./[id]/page'), { id: '1' });
    expect(html).toContain('run #3 is the current verdict, the decision used run #1');
    expect(html).toContain('Re-evaluate policy');
    expect(html).toContain(`href="/findings/1?config=${ACTIVE}&amp;run=3"`);

    const { enqueueDecideAction } = await import('./actions');
    const fd = new FormData();
    fd.set('findingId', '1');
    await enqueueDecideAction(fd);
    await enqueueDecideAction(fd); // still queued: no second job
    const decides = db.select().from(jobRuns).all().filter((j) => j.type === 'decide');
    expect(decides).toHaveLength(1);
    const after = await render(() => import('./[id]/page'), { id: '1' });
    expect(after).toContain(`decide job #${decides[0]!.id}</a> queued`);
    expect(after).toMatch(/<button[^>]*disabled=""[^>]*>Re-evaluate policy<\/button>/);

    db.delete(jobRuns).run();
    db.delete(triageRuns).where(eq(triageRuns.id, 3)).run();
    db.delete(triageConfigs).run();
  });

  it('clears the stale decision once the decide job that follows the triage has run', async () => {
    const before = {
      findings: db.select().from(findings).all(),
      decisions: db.select().from(decisions).all(),
      events: new Set(db.select({ id: events.id }).from(events).all().map((e) => e.id)),
    };
    try {
      db.insert(triageConfigs).values({ name: ACTIVE, promptVersion: 'v1', model: 'opus', effort: 'high', codeAccess: true, active: true }).run();
      db.update(findings).set({ enrichedAt: '2026-11-10T00:00:00.000Z' }).run();
      const f1 = db.select().from(findings).where(eq(findings.id, 1)).get()!;
      const cfg = db.select().from(triageConfigs).where(eq(triageConfigs.name, ACTIVE)).get()!;
      // What the forced "Triage with <active>" job writes: a newer ok run for the current inputs.
      db.insert(triageRuns).values({ id: 3, findingId: 1, configName: ACTIVE, inputHash: findingInputHash(db, f1, cfg), status: 'ok', output, prompt: 'p' }).run();
      const stale = await render(() => import('./[id]/page'), { id: '1' });
      expect(stale).toContain('stale decision'); // header badge
      expect(stale).toContain('run #3 is the current verdict');

      // The decide job queued behind it (same handler as the worker's): the decision now uses run #3.
      const stats = decideAll(db, { currentPolicy: loadPolicy(), minPriority: 'P2' });
      expect(stats.current).toBe(true);
      const fresh = await render(() => import('./[id]/page'), { id: '1' });
      expect(fresh).not.toContain('is the current verdict');
      expect(fresh).not.toContain('stale decision');
      expect(fresh).not.toContain('Re-evaluate policy');
      expect(fresh).toContain('from triage run #3');
    } finally {
      db.delete(triageRuns).where(eq(triageRuns.id, 3)).run();
      db.delete(triageConfigs).run();
      for (const row of before.findings) db.update(findings).set(row).where(eq(findings.id, row.id)).run();
      db.delete(decisions).run();
      db.insert(decisions).values(before.decisions).run();
      for (const e of db.select({ id: events.id }).from(events).all()) if (!before.events.has(e.id)) db.delete(events).where(eq(events.id, e.id)).run();
      db.delete(jobRuns).run();
    }
  });

  it('shows the fixed remediation for a malicious package and marks disabled projects', async () => {
    db.insert(projects).values({ id: 'old', name: 'Old', enabled: false, repoPath: '/y', ref: 'origin/main', profile: { ...profile, id: 'old', enabled: false }, profileHash: 'o' }).run();
    db.insert(advisories).values({ osvId: 'MAL-2026-1', summary: 'Malicious code in evil', malicious: true, raw: {} }).run();
    db.insert(findings)
      .values([
        { id: 3, projectId: 'web', lockfile: 'package-lock.json', ecosystem: 'npm', packageName: 'evil', osvId: 'MAL-2026-1', origin: 'new_dependency', firstSeenScanId: 1, lastSeenScanId: 1, priority: 'P0' },
        { id: 4, projectId: 'old', lockfile: 'package-lock.json', ecosystem: 'npm', packageName: 'stale-pkg', osvId: 'GHSA-xxxx', origin: 'baseline', firstSeenScanId: 1, lastSeenScanId: 1, priority: 'P0' },
      ])
      .run();
    try {
      const page = await render(() => import('./[id]/page'), { id: '3' });
      expect(page).toContain(MALICIOUS_REMEDIATION);
      expect(page).toContain('remove (malicious package)');
      expect(page).not.toContain('no fix yet');
      const review = await render(() => import('../review/page'), {}, { id: '3' });
      expect(review).toContain(MALICIOUS_REMEDIATION);
      expect(review).toContain('Malicious packages are not triaged');

      const list = await render(() => import('./page'));
      expect(list).toContain('stale-pkg');
      expect(list.match(/project disabled/g)).toHaveLength(1);
      const disabledPage = await render(() => import('./[id]/page'), { id: '4' });
      expect(disabledPage).toContain('project disabled');
      expect(disabledPage).toContain('Decide skips this finding');
      expect(disabledPage).not.toContain('Re-evaluate policy');
      // The review queue skips the disabled project's P0 (3 = enabled P0, 1 = P1, 2 = P2).
      const queue = await render(() => import('../review/page'));
      expect(queue).toContain('labeled <strong>0</strong> of 3');
      expect(queue).not.toContain('stale-pkg');
    } finally {
      db.delete(findings).where(eq(findings.id, 3)).run();
      db.delete(findings).where(eq(findings.id, 4)).run();
      db.delete(advisories).where(eq(advisories.osvId, 'MAL-2026-1')).run();
      db.delete(projects).where(eq(projects.id, 'old')).run();
    }
  });

  it('lets the finding page clear the optional affected answer', async () => {
    const { saveLabelAction } = await import('./actions');
    const save = (affected: string) => {
      const fd = new FormData();
      fd.set('findingId', '2');
      fd.set('expectedAction', 'digest');
      fd.set('affectedTruth', affected);
      fd.set('note', '');
      return saveLabelAction(fd);
    };
    await save('yes');
    expect(db.select().from(labels).all().find((l) => l.findingId === 2)?.affectedTruth).toBe('yes');
    const html = await render(() => import('./[id]/page'), { id: '2' });
    expect(html).toContain('Not set');
    await save('');
    expect(db.select().from(labels).all().find((l) => l.findingId === 2)?.affectedTruth).toBeNull();
    db.delete(labels).run();
  });

  it('keeps the review page blind until a label exists', async () => {
    const blind = await render(() => import('../review/page'));
    expect(blind).toContain('proxy-addr');
    expect(blind).toContain('Pulled in by a CLI only.');
    expect(blind).toContain('labeled <strong>0</strong> of 2');
    expect(blind).toContain('/findings/1/source?file=src%2Fapp.ts&amp;line=2&amp;run=1#L2');
    for (const hidden of ['RULE-SECRET', 'SECRET-REASON', 'likely not affected', 'undecided']) {
      expect(blind).not.toContain(hidden);
    }

    db.insert(labels).values({ findingId: 1, labeler: 'me', expectedAction: 'log', affectedTruth: 'no' }).run();
    const revealed = await render(() => import('../review/page'), {}, { id: '1' });
    expect(revealed).toContain('RULE-SECRET');
    expect(revealed).toContain('SECRET-REASON');
    expect(revealed).toContain('disagrees');
    expect(revealed).toContain('href="/review?id=2"');
    db.delete(labels).run();
  });

  it('labels as a second labeler chosen on the Review page', async () => {
    const { saveReviewLabelAction, setLabelerAction } = await import('../review/actions');
    const { saveLabelAction } = await import('./actions');
    const choose = (name: string, id = '1') => {
      const fd = new FormData();
      fd.set('labeler', name);
      fd.set('id', id);
      return setLabelerAction(fd);
    };
    try {
      await expect(choose('bad name!')).rejects.toThrow('NEXT_REDIRECT /review?labelerError=1&id=1');
      expect(cookieJar.has(LABELER_COOKIE)).toBe(false);
      const bad = await render(() => import('../review/page'), {}, { id: '1', labelerError: '1' });
      expect(bad).toContain('Invalid name');

      db.insert(labels).values({ findingId: 1, labeler: 'me', expectedAction: 'log' }).run();
      await expect(choose(' Ana ')).rejects.toThrow('NEXT_REDIRECT /review?id=1');
      expect(cookieJar.get(LABELER_COOKIE)).toBe('ana');

      // My label does not count for ana: her queue is blind and complete.
      const review = await render(() => import('../review/page'), {}, { id: '1' });
      expect(review).toContain('value="ana"');
      expect(review).toContain('labeled <strong>0</strong> of 2');
      expect(review).not.toContain('RULE-SECRET');

      const fd = new FormData();
      fd.set('findingId', '1');
      fd.set('expectedAction', 'ping');
      await expect(saveReviewLabelAction({ error: null }, fd)).rejects.toThrow('NEXT_REDIRECT /review?id=1');
      const fd2 = new FormData();
      fd2.set('findingId', '2');
      fd2.set('expectedAction', 'digest');
      await saveLabelAction(fd2);
      const rows = db.select().from(labels).all().map((l) => [l.findingId, l.labeler, l.expectedAction]);
      expect(rows.sort()).toEqual([
        [1, 'ana', 'ping'],
        [1, 'me', 'log'],
        [2, 'ana', 'digest'],
      ]);
      expect(await render(() => import('../review/page'), {}, { id: '1' })).toContain('RULE-SECRET'); // revealed for ana now

      const finding = await render(() => import('./[id]/page'), { id: '2' });
      expect(finding).toMatch(/labeling as <code[^>]*>ana<\/code>/);
      const list = await render(() => import('./page'), {}, { labeled: 'yes' });
      expect(list).toContain('Labeled by ana');
      expect(list).toContain('2 findings');
    } finally {
      cookieJar.clear();
      db.delete(labels).run();
    }
  });
});
