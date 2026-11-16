import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadPolicy, parsePolicy } from '../lib/config/load';
import { openDb } from '../lib/db/client';
import { findings, projects, triageConfigs, triageRuns } from '../lib/db/schema';
import { decideAll } from '../lib/policy/decide';
import { findingInputHash } from '../lib/triage/state';
import {
  ACTIONS,
  CONFIDENCES,
  ProjectProfileSchema,
  VERDICTS,
  type Criticality,
  type Exposure,
  type Priority,
  type TriageOutput,
} from '../lib/types';
import { decide, triageStateOf } from './decide';
import { makeAdvisory, makeFinding, makeOutput, makeScan, makeVerdict, PROFILE } from './report-fixtures';
import type { PluginProfile, ScanFinding, TriageFailures } from './types';
import { VerdictStore } from './verdicts';

const ROOT = path.join(import.meta.dirname, '../..');
const POLICY = loadPolicy(ROOT);

/** Signals that give each priority under the shipped thresholds for an internet-facing, high-criticality project. */
const SIGNALS: Record<Priority, Partial<ScanFinding>> = {
  P0: { inKev: true, kevDateAdded: '2025-03-21' },
  P1: { epss: 0.6 },
  P2: { cvssScore: 7.5 },
  P3: {},
};

function finding(osvId: string, priority: Priority, o: Partial<ScanFinding> = {}): ScanFinding {
  return makeFinding({ osvId, packageName: `pkg-${osvId.toLowerCase()}`, priority, ...SIGNALS[priority], ...o });
}

describe('triageStateOf', () => {
  const f = finding('GHSA-1', 'P1');
  const verdicts = new VerdictStore([makeVerdict(f)]);
  const failures: TriageFailures = { [f.id]: { inputHash: f.inputHash, error: 'boom', at: 't' } };

  it('malicious → skipped; a current verdict → ok (even with a failure); a failure for these inputs → failed; else pending', () => {
    expect(triageStateOf(f, true, verdicts, failures).status).toBe('skipped');
    expect(triageStateOf(f, false, verdicts, failures).status).toBe('ok');
    const changed = { ...f, inputHash: 'changed' };
    expect(triageStateOf(changed, false, verdicts, failures)).toEqual({ status: 'pending', verdict: null, failure: null });
    expect(triageStateOf(f, false, new VerdictStore(), failures)).toEqual({ status: 'failed', verdict: null, failure: 'boom' });
    expect(triageStateOf(changed, false, new VerdictStore(), { [f.id]: { inputHash: 'changed', error: 'e', at: 't' } }).status).toBe(
      'failed',
    );
  });
});

describe('decide', () => {
  it('applies the shipped policy: malicious pings, untriaged P1 pings, verdicts decide the rest', () => {
    const mal = finding('MAL-2026-1', 'P0', { malicious: true, inKev: false });
    const p1Pending = finding('GHSA-p1', 'P1');
    const p2Affected = finding('GHSA-p2', 'P2');
    const p3Log = finding('GHSA-p3', 'P3');
    const scan = makeScan(
      [mal, p1Pending, p2Affected, p3Log],
      [makeAdvisory({ osvId: mal.osvId, malicious: true }), makeAdvisory({ osvId: 'GHSA-p1' }), makeAdvisory({ osvId: 'GHSA-p2' })],
    );
    const verdicts = new VerdictStore([
      makeVerdict(p2Affected, { verdict: 'affected', suggested_action: 'digest' }),
      makeVerdict(p3Log, { verdict: 'not_affected', confidence: 'high', suggested_action: 'log' }),
    ]);
    const d = decide(scan, verdicts, {}, POLICY, PROFILE);
    const by = Object.fromEntries(d.findings.map((x) => [x.finding.osvId, x]));

    expect(by['MAL-2026-1']).toMatchObject({ triageStatus: 'skipped', action: 'ping', ruleId: 'malicious', verdict: null });
    expect(by['GHSA-p1']).toMatchObject({ triageStatus: 'pending', action: 'ping', ruleId: 'no-verdict-urgent' });
    expect(by['GHSA-p2']).toMatchObject({ triageStatus: 'ok', action: 'digest', ruleId: 'llm-digest' });
    expect(by['GHSA-p2']!.verdict?.output.verdict).toBe('affected');
    expect(by['GHSA-p3']).toMatchObject({ triageStatus: 'ok', action: 'log', ruleId: 'default' });
    expect(by['GHSA-p3']!.advisory).toBeNull();
    expect(d.counts).toEqual({ ping: 2, digest: 1, log: 1, untriaged: 1 });
    expect(d.policyHash).toBe(POLICY.hash);
    // Scan order is kept.
    expect(d.findings.map((x) => x.finding.id)).toEqual(scan.findings.map((f) => f.id));
  });

  it('counts failed triage as untriaged and keeps the failure message', () => {
    const f = finding('GHSA-f', 'P2');
    const d = decide(
      makeScan([f], []),
      new VerdictStore(),
      { [f.id]: { inputHash: f.inputHash, error: 'timed out', at: 't' } },
      POLICY,
      PROFILE,
    );
    expect(d.findings[0]).toMatchObject({ triageStatus: 'failed', failure: 'timed out', action: 'digest', ruleId: 'no-verdict-p2' });
    expect(d.counts.untriaged).toBe(1);
  });

  it('recomputes the base priority under the policy thresholds and the current profile', () => {
    const kev = finding('GHSA-kev', 'P0');
    const internal: PluginProfile = { ...PROFILE, exposure: 'internal', criticality: 'medium' };
    const d = decide(makeScan([kev], []), new VerdictStore(), {}, POLICY, internal);
    expect(d.findings[0]!.finding.priority).toBe('P1');
    expect(d.findings[0]!.finding.priorityReasons).toEqual(['in CISA KEV since 2025-03-21']);
    expect(d.findings[0]!.inputs.priority).toBe('P1');
    // Unchanged priority: the scan's finding object is used as is.
    const scan = makeScan([kev], []);
    const same = decide(scan, new VerdictStore(), {}, POLICY, PROFILE);
    expect(same.findings[0]!.finding).toBe(scan.findings[0]);
    expect(same.findings[0]!.finding.priority).toBe('P0');
  });

  it('raises every package of one advisory in one lockfile to the group maximum, unless same_advisory is off', () => {
    const a = makeFinding({ osvId: 'GHSA-grp', packageName: '@sentry/node', priority: 'P2', cvssScore: 7.5 });
    const b = makeFinding({ osvId: 'GHSA-grp', packageName: '@sentry/core', priority: 'P2', cvssScore: 7.5 });
    const other = makeFinding({
      osvId: 'GHSA-grp',
      packageName: '@sentry/core',
      lockfile: 'apps/x/package-lock.json',
      priority: 'P2',
      cvssScore: 7.5,
    });
    const verdicts = new VerdictStore([
      makeVerdict(a, { verdict: 'affected', suggested_action: 'ping' }),
      makeVerdict(b, { verdict: 'not_affected', runtime_usage: 'build_or_tooling_only', suggested_action: 'log' }),
      makeVerdict(other, { verdict: 'not_affected', runtime_usage: 'build_or_tooling_only', suggested_action: 'log' }),
    ]);
    const scan = makeScan([a, b, other], []);
    const on = decide(scan, verdicts, {}, POLICY, PROFILE);
    const rows = (d: typeof on) => d.findings.map((x) => [x.finding.packageName, x.finding.lockfile, x.action, x.ruleId]);
    expect(rows(on)).toEqual([
      ['@sentry/core', 'apps/x/package-lock.json', 'log', 'tooling-only'],
      ['@sentry/core', 'package-lock.json', 'ping', 'same-advisory'],
      ['@sentry/node', 'package-lock.json', 'ping', 'llm-ping'],
    ]);
    const offPolicy = parsePolicy(POLICY.content.replace('same_advisory: max', 'same_advisory: off'));
    expect(rows(decide(scan, verdicts, {}, offPolicy, PROFILE))[1]).toEqual(['@sentry/core', 'package-lock.json', 'log', 'tooling-only']);
  });
});

// ---------- equivalence with the POC's decideAll ----------

interface Case {
  osvId: string;
  packageName: string;
  priority: Priority;
  triage: 'pending' | 'failed' | 'ok';
  output?: TriageOutput;
  malicious?: boolean;
}

function matrix(): Case[] {
  const cases: Case[] = [];
  let i = 0;
  for (const priority of ['P0', 'P1', 'P2', 'P3'] as Priority[]) {
    cases.push({ osvId: `GHSA-pend-${priority}`, packageName: `pend-${priority}`, priority, triage: 'pending' });
    cases.push({ osvId: `GHSA-fail-${priority}`, packageName: `fail-${priority}`, priority, triage: 'failed' });
    for (const verdict of VERDICTS)
      for (const suggested_action of ACTIONS)
        for (const confidence of [CONFIDENCES[0], CONFIDENCES[2]])
          for (const runtime_usage of ['server', 'build_or_tooling_only'] as const) {
            const id = `GHSA-m${++i}`;
            cases.push({
              osvId: id,
              packageName: `pkg-${i}`,
              priority,
              triage: 'ok',
              output: makeOutput({ verdict, suggested_action, confidence, runtime_usage }),
            });
          }
  }
  cases.push({ osvId: 'MAL-2026-9', packageName: 'evil', priority: 'P0', triage: 'pending', malicious: true });
  // One advisory on two packages in one lockfile: the logged one is raised to the other's ping.
  cases.push({
    osvId: 'GHSA-group',
    packageName: 'grp-a',
    priority: 'P2',
    triage: 'ok',
    output: makeOutput({ verdict: 'affected', suggested_action: 'ping' }),
  });
  cases.push({
    osvId: 'GHSA-group',
    packageName: 'grp-b',
    priority: 'P2',
    triage: 'ok',
    output: makeOutput({ verdict: 'not_affected', suggested_action: 'log' }),
  });
  return cases;
}

function compareWithPoc(exposure: Exposure, criticality: Criticality) {
  const db = openDb(':memory:');
  const pocProfile = ProjectProfileSchema.parse({ ...PROFILE, repo_path: '/nonexistent', exposure, criticality });
  db.insert(projects)
    .values({ id: PROFILE.id, name: PROFILE.name, repoPath: '/nonexistent', ref: 'origin/main', profile: pocProfile, profileHash: 'h' })
    .run();
  const config = db
    .insert(triageConfigs)
    .values({ name: 'v3-opus-high-code', promptVersion: 'v3', model: 'opus', effort: 'high', codeAccess: true, active: true })
    .returning()
    .get();

  const cases = matrix();
  const scanFindings: ScanFinding[] = [];
  const verdicts = new VerdictStore();
  const failures: TriageFailures = {};
  const now = '2026-11-12T00:00:00.000Z';
  for (const c of cases) {
    const signals = c.malicious ? {} : SIGNALS[c.priority];
    const row = db
      .insert(findings)
      .values({
        projectId: PROFILE.id,
        lockfile: 'package-lock.json',
        ecosystem: 'npm',
        packageName: c.packageName,
        osvId: c.osvId,
        installedVersions: ['1.0.0'],
        fixedVersions: c.priority === 'P3' ? [] : ['1.0.1'],
        direct: c.priority !== 'P2',
        devOnly: c.priority === 'P3',
        status: 'open',
        origin: 'baseline',
        firstSeenScanId: 1,
        lastSeenScanId: 1,
        priority: c.priority,
        inKev: signals.inKev ?? false,
        kevDateAdded: signals.kevDateAdded ?? null,
        epss: signals.epss ?? null,
        cvssScore: signals.cvssScore ?? null,
        enrichedAt: now,
      })
      .returning()
      .get();
    const inputHash = findingInputHash(db, row, config);
    if (c.triage !== 'pending') {
      db.insert(triageRuns)
        .values({ findingId: row.id, configName: config.name, inputHash, status: c.triage, output: c.output ?? null, prompt: 'p' })
        .run();
    }
    const f = makeFinding({
      osvId: c.osvId,
      packageName: c.packageName,
      installedVersions: row.installedVersions,
      fixedVersions: row.fixedVersions,
      direct: row.direct,
      devOnly: row.devOnly,
      priority: c.priority,
      inKev: row.inKev,
      kevDateAdded: row.kevDateAdded,
      epss: row.epss,
      cvssScore: row.cvssScore,
      malicious: Boolean(c.malicious),
      inputHash,
    });
    scanFindings.push(f);
    if (c.triage === 'ok') verdicts.upsert(makeVerdict(f, c.output));
    if (c.triage === 'failed') failures[f.id] = { inputHash, error: 'boom', at: now };
  }

  decideAll(db, { currentPolicy: POLICY, minPriority: 'P3', now });
  const poc = new Map(
    db
      .select()
      .from(findings)
      .all()
      .map((r) => [`${r.osvId} ${r.packageName}`, `${r.currentAction} ${r.currentRuleId}`]),
  );

  const plugin = decide(makeScan(scanFindings, []), verdicts, failures, POLICY, { ...PROFILE, exposure, criticality });
  const mine = new Map(plugin.findings.map((d) => [`${d.finding.osvId} ${d.finding.packageName}`, `${d.action} ${d.ruleId}`]));
  expect(mine.size).toBe(cases.length);
  expect(Object.fromEntries(mine)).toEqual(Object.fromEntries(poc));
  return plugin;
}

describe('decide equals the POC decideAll', () => {
  it('for every priority × triage state × verdict shape on an internet-facing, high-criticality project', () => {
    const d = compareWithPoc('internet-facing', 'high');
    // The matrix exercises every action and the group raise.
    expect(d.counts.ping).toBeGreaterThan(0);
    expect(d.counts.digest).toBeGreaterThan(0);
    expect(d.counts.log).toBeGreaterThan(0);
    expect(d.findings.some((x) => x.ruleId === 'same-advisory')).toBe(true);
  });

  it('and on an internal, low-criticality project (priorities recomputed from the same signals)', () => {
    compareWithPoc('internal', 'low');
  });
});
