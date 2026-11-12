import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import {
  advisories,
  decisions,
  events,
  findings,
  jobRuns,
  kev,
  labels,
  projects,
  scans,
  triageConfigs,
  triageRuns,
} from '../db/schema';
import { renderCodeNote } from '../triage/prompt';
import { findingInputHash } from '../triage/state';
import type { DecisionInputs, ProjectProfile, TriageOutput } from '../types';
import { eq } from 'drizzle-orm';
import {
  findingFiltersToQuery,
  findingParamIds,
  findPendingTriageJob,
  getFindingDetail,
  getFindingSource,
  LABELER,
  listFindings,
  listTriageJobsForFinding,
  parseFindingFilters,
  parseLabelInput,
  readSnapshotFile,
  resolveSnapshotPath,
  sourceExcerpt,
  splitSnapshotPath,
  stripSnapshotPrefix,
  upsertLabel,
  commitFromPrompt,
  decisionStaleness,
  findPendingDecideJob,
  labelerOrDefault,
  parseLabeler,
  type FindingFilters,
} from './findings';

const SHA_WEB = 'a'.repeat(40);
const SHA_API = 'b'.repeat(40);

function profile(id: string, exposure: ProjectProfile['exposure']): ProjectProfile {
  return {
    id,
    name: id.toUpperCase(),
    enabled: true,
    repo_path: `/nonexistent/${id}`,
    ref: 'origin/main',
    fetch_before_scan: false,
    exclude: [],
    owners: [],
    criticality: 'high',
    exposure,
    data_classes: [],
    runtime: {},
    deployments: [],
    third_party_services: [],
    mitigations: '',
    notes: '',
  };
}

function triageOutput(over: Partial<TriageOutput> = {}): TriageOutput {
  return {
    verdict: 'affected',
    confidence: 'high',
    runtime_usage: 'server',
    vulnerable_code_used: 'yes',
    attacker_reachable: 'yes',
    deployment_conditions_met: 'yes',
    summary: 'Reachable from an API route.',
    evidence: [{ file: 'src/app/api/route.ts', line: 3, note: 'calls merge()' }],
    exploit_conditions: 'Attacker controls JSON body',
    remediation: 'Upgrade to 4.17.21',
    workaround: null,
    suggested_action: 'ping',
    suggested_action_reason: 'Reachable on an internet-facing route.',
    ...over,
  };
}

const decisionInputs: DecisionInputs = {
  priority: 'P1',
  malicious: false,
  in_kev: false,
  epss: 0.6,
  cvss: 9.8,
  exposure: 'internet-facing',
  criticality: 'high',
  direct: true,
  dev_only: false,
  fix_available: true,
  triage_status: 'ok',
  verdict: 'affected',
  confidence: 'high',
  runtime_usage: 'server',
  vulnerable_code_used: 'yes',
  attacker_reachable: 'yes',
  deployment_conditions_met: 'yes',
  suggested_action: 'ping',
};

type NewFinding = typeof findings.$inferInsert;
function finding(over: Partial<NewFinding> & Pick<NewFinding, 'id' | 'projectId' | 'packageName' | 'osvId'>): NewFinding {
  return {
    lockfile: 'package-lock.json',
    ecosystem: 'npm',
    installedVersions: ['1.0.0'],
    fixedVersions: ['1.0.1'],
    origin: 'baseline',
    firstSeenScanId: over.projectId === 'web' ? 1 : 2,
    lastSeenScanId: over.projectId === 'web' ? 1 : 2,
    ...over,
  };
}

/**
 * Findings (open unless noted):
 *  1 web lodash      P1 epss .6  cvss 9.8  direct      ping   verdict affected (run 4)
 *  2 web storybook   P2 epss .05 cvss 7.5  dev, direct log    verdict not_affected, labeled log by me
 *  3 api evil-pkg    P0 epss -   cvss -    new_dependency, ping, malicious
 *  4 api proxy-addr  P2 epss .2  cvss - (advisory 7.0) transitive, digest, new_advisory
 *  5 web minimist    P3 fixed
 *  6 web zod         P2 epss -   cvss 7.5  direct unknown, undecided, labeled by someone else
 */
function seed(db: Db) {
  db.insert(projects)
    .values([
      { id: 'web', name: 'Web', repoPath: '/nonexistent/web', ref: 'origin/main', profile: profile('web', 'internet-facing'), profileHash: 'pw' },
      { id: 'api', name: 'Api', repoPath: '/nonexistent/api', ref: 'origin/main', profile: profile('api', 'internal'), profileHash: 'pa' },
    ])
    .run();
  db.insert(scans)
    .values([
      { id: 1, projectId: 'web', ref: 'origin/main', commitSha: SHA_WEB, status: 'succeeded' },
      { id: 2, projectId: 'api', ref: 'origin/main', commitSha: SHA_API, status: 'succeeded' },
    ])
    .run();
  db.insert(advisories)
    .values([
      { osvId: 'GHSA-aaaa', aliases: ['CVE-2026-0001'], cves: ['CVE-2026-0001'], summary: 'Prototype pollution in lodash', details: '# Details\n<script>x</script>', cvssScore: 9.8, raw: { big: true } },
      { osvId: 'GHSA-bbbb', aliases: ['CVE-2026-0002'], cves: ['CVE-2026-0002'], summary: 'Dev server file read', cvssScore: 7.5, raw: {} },
      { osvId: 'MAL-2026-1', summary: 'Malicious code in evil-pkg', malicious: true, raw: {} },
      { osvId: 'GHSA-cccc', summary: 'Header injection', cvssScore: 7.0, raw: {} },
      { osvId: 'GHSA-dddd', summary: 'Memory exhaustion', cvssScore: 7.5, raw: {} },
    ])
    .run();
  db.insert(findings)
    .values([
      finding({ id: 1, projectId: 'web', packageName: 'lodash', osvId: 'GHSA-aaaa', priority: 'P1', priorityReasons: ['epss 0.60 ≥ 0.5'], epss: 0.6, cvssScore: 9.8, direct: true, currentAction: 'ping', currentRuleId: 'p1-affected', activeTriageRunId: 4, inKev: true, kevDateAdded: '2026-01-02', firstSeenAt: '2026-11-01T00:00:00.000Z', paths: [['lodash']], importSites: [{ file: 'src/app/api/route.ts', line: 1, specifier: 'lodash', via: 'lodash' }] }),
      finding({ id: 2, projectId: 'web', packageName: 'storybook', osvId: 'GHSA-bbbb', priority: 'P2', epss: 0.05, cvssScore: 7.5, direct: true, devOnly: true, currentAction: 'log', currentRuleId: 'tooling-only', activeTriageRunId: 2, firstSeenAt: '2026-11-02T00:00:00.000Z' }),
      finding({ id: 3, projectId: 'api', packageName: 'evil-pkg', osvId: 'MAL-2026-1', priority: 'P0', origin: 'new_dependency', direct: true, currentAction: 'ping', currentRuleId: 'malicious', firstSeenAt: '2026-11-05T00:00:00.000Z' }),
      finding({ id: 4, projectId: 'api', packageName: 'proxy-addr', osvId: 'GHSA-cccc', priority: 'P2', epss: 0.2, direct: false, origin: 'new_advisory', currentAction: 'digest', currentRuleId: 'p2-affected', firstSeenAt: '2026-11-03T00:00:00.000Z' }),
      finding({ id: 5, projectId: 'web', packageName: 'minimist', osvId: 'GHSA-aaaa', priority: 'P3', status: 'fixed', firstSeenAt: '2026-10-01T00:00:00.000Z' }),
      finding({ id: 6, projectId: 'web', packageName: 'zod', osvId: 'GHSA-dddd', priority: 'P2', cvssScore: 7.5, direct: null, firstSeenAt: '2026-11-04T00:00:00.000Z' }),
    ])
    .run();
  db.insert(triageConfigs)
    .values([
      { name: 'cfg-a', promptVersion: 'v1', model: 'opus', effort: 'high', codeAccess: true, active: true },
      { name: 'cfg-b', promptVersion: 'v1', model: 'sonnet', effort: 'high', codeAccess: true, active: false },
    ])
    .run();
  const f1 = db.select().from(findings).all().find((f) => f.id === 1)!;
  const cfgA = db.select().from(triageConfigs).all().find((c) => c.name === 'cfg-a')!;
  const currentHash = findingInputHash(db, f1, cfgA);
  db.insert(triageRuns)
    .values([
      { id: 1, findingId: 1, configName: 'cfg-a', inputHash: 'old', status: 'ok', output: triageOutput({ verdict: 'likely_affected' }), prompt: 'prompt 1', createdAt: '2026-11-01T00:00:00.000Z' },
      { id: 2, findingId: 2, configName: 'cfg-a', inputHash: 'x', status: 'ok', output: triageOutput({ verdict: 'not_affected', suggested_action: 'log', runtime_usage: 'build_or_tooling_only' }), prompt: 'prompt 2' },
      { id: 3, findingId: 1, configName: 'cfg-b', inputHash: 'y', status: 'timeout', error: 'timed out', prompt: 'prompt 3', createdAt: '2026-11-02T00:00:00.000Z' },
      { id: 4, findingId: 1, configName: 'cfg-a', inputHash: currentHash, status: 'ok', output: triageOutput(), prompt: 'prompt 4', raw: { total_cost_usd: 0.42 }, costUsd: 0.42, createdAt: '2026-11-03T00:00:00.000Z' },
      { id: 5, findingId: 6, configName: 'cfg-a', inputHash: 'z', status: 'invalid', output: { verdict: 'maybe' } as unknown as TriageOutput, prompt: 'prompt 5' },
    ])
    .run();
  db.insert(decisions)
    .values([
      { findingId: 1, policyHash: 'pol0', configName: 'cfg-a', triageRunId: 1, action: 'digest', ruleId: 'p1-not-affected', inputs: decisionInputs, decidedAt: '2026-11-01T00:00:00.000Z' },
      { findingId: 1, policyHash: 'pol1', configName: 'cfg-a', triageRunId: 4, action: 'ping', ruleId: 'p1-affected', inputs: decisionInputs, decidedAt: '2026-11-03T00:00:00.000Z' },
    ])
    .run();
  db.insert(labels)
    .values([
      { findingId: 2, labeler: LABELER, expectedAction: 'log', affectedTruth: 'no' },
      { findingId: 6, labeler: 'someone-else', expectedAction: 'ping' },
    ])
    .run();
  db.insert(events)
    .values([
      { findingId: 1, type: 'created', at: '2026-11-01T00:00:00.000Z' },
      { findingId: 1, type: 'escalated', data: { from: 'P2', to: 'P1' }, at: '2026-11-04T00:00:00.000Z' },
      { findingId: 2, type: 'created', at: '2026-11-02T00:00:00.000Z' },
    ])
    .run();
  db.insert(kev).values({ cve: 'CVE-2026-0001', dateAdded: '2026-01-02', ransomware: 'Known' }).run();
  db.insert(jobRuns)
    .values([
      { type: 'triage', params: { findings: [1], config: 'cfg-b', force: true }, status: 'queued' },
      { type: 'triage', params: { findings: [2], config: 'cfg-a', force: true }, status: 'failed', error: 'boom' },
      { type: 'scan', params: { findings: [1] }, status: 'queued' },
    ])
    .run();
}

const ctx = { activeConfig: 'cfg-a', policyHash: 'pol1', minPriority: 'P2' as const };

let db: Db;
beforeAll(() => {
  db = openDb(':memory:');
  seed(db);
});

const ids = (f: Partial<FindingFilters> | Record<string, string | string[]> = {}) =>
  listFindings(db, parseFindingFilters(f as Record<string, string | string[]>)).rows.map((r) => r.id);

describe('parseFindingFilters', () => {
  it('defaults to open findings sorted by priority', () => {
    const f = parseFindingFilters({});
    expect(f).toMatchObject({ status: ['open'], sort: 'priority', project: [], priority: [], devOnly: null, direct: null, labeled: null, q: '', ids: [] });
  });

  it('accepts lists, ignores unknown values and normalises flags', () => {
    const f = parseFindingFilters({
      status: 'all',
      priority: ['P0,P1', 'P9'],
      action: 'none',
      verdict: 'bogus',
      direct: 'unknown',
      labeled: 'yes',
      devOnly: 'no',
      ids: '1,abc,2,-3',
      sort: 'epss',
      q: '  lodash ',
    });
    expect(f).toMatchObject({ status: [], priority: ['P0', 'P1'], action: ['none'], verdict: [], direct: 'unknown', labeled: true, devOnly: false, ids: [1, 2], sort: 'epss', q: 'lodash' });
    expect(parseFindingFilters({ status: 'bogus' }).status).toEqual(['open']);
    expect(parseFindingFilters({ sort: 'nope' }).sort).toBe('priority');
  });

  it('keeps the free-text query whole (no comma splitting)', () => {
    expect(parseFindingFilters({ q: ' foo,bar ' }).q).toBe('foo,bar');
    expect(parseFindingFilters({ q: ['first', 'second'] }).q).toBe('first');
    const f = parseFindingFilters({ q: 'a,b' });
    expect(parseFindingFilters(Object.fromEntries(new URLSearchParams(findingFiltersToQuery(f).slice(1)))).q).toBe('a,b');
  });

  it('round-trips through findingFiltersToQuery', () => {
    const original = parseFindingFilters({ project: 'web', status: 'all', verdict: 'affected,none', labeled: 'no', q: 'x y', sort: 'cvss', ids: '4' });
    const qs = findingFiltersToQuery(original);
    const back = parseFindingFilters(Object.fromEntries(new URLSearchParams(qs.slice(1))));
    expect(back).toEqual(original);
    expect(findingFiltersToQuery(parseFindingFilters({}))).toBe('');
    expect(findingFiltersToQuery(parseFindingFilters({}), { sort: 'package' })).toBe('?sort=package');
  });

  it('defaults the project filter to the header scope, which a project parameter overrides', () => {
    const scoped = { defaultProject: ['held-api'] };
    expect(parseFindingFilters({}, scoped).project).toEqual(['held-api']);
    expect(parseFindingFilters({ project: 'held-ios' }, scoped).project).toEqual(['held-ios']);
    // "all projects" in the filter (or an empty value) overrides the scope for this list
    expect(parseFindingFilters({ project: 'all' }, scoped).project).toEqual([]);
    expect(parseFindingFilters({ project: '' }, scoped).project).toEqual([]);
    expect(parseFindingFilters({ project: 'all' }).project).toEqual([]);
    expect(parseFindingFilters({}, { defaultProject: null }).project).toEqual([]);
  });

  it('writes links that mean the same whatever scope cookie the next request carries', () => {
    const scoped = { defaultProject: ['held-api'] };
    const inScope = parseFindingFilters({ action: 'ping' }, scoped);
    expect(findingFiltersToQuery(inScope, {}, scoped)).toBe('?action=ping');
    const everything = parseFindingFilters({ project: 'all', action: 'ping' }, scoped);
    expect(findingFiltersToQuery(everything, { sort: 'epss' }, scoped)).toBe('?project=all&action=ping&sort=epss');
    const other = parseFindingFilters({ project: 'held-ios' }, scoped);
    expect(findingFiltersToQuery(other, {}, scoped)).toBe('?project=held-ios');
    for (const f of [inScope, everything, other]) {
      const back = parseFindingFilters(Object.fromEntries(new URLSearchParams(findingFiltersToQuery(f, {}, scoped).slice(1))), scoped);
      expect(back).toEqual(f);
    }
  });
});

describe('listFindings', () => {
  it('lists open findings in priority order (priority, EPSS, CVSS)', () => {
    const list = listFindings(db, parseFindingFilters({}));
    expect(list.rows.map((r) => r.id)).toEqual([3, 1, 4, 2, 6]);
    expect(list.total).toBe(5);
  });

  it('maps advisory, triage verdict and label columns', () => {
    const rows = listFindings(db, parseFindingFilters({ status: 'all' })).rows;
    const byId = new Map(rows.map((r) => [r.id, r]));
    expect(byId.get(1)).toMatchObject({ cves: ['CVE-2026-0001'], summary: 'Prototype pollution in lodash', verdict: 'affected', confidence: 'high', cvssScore: 9.8, labelAction: null, inKev: true });
    expect(byId.get(2)).toMatchObject({ verdict: 'not_affected', labelAction: 'log', devOnly: true });
    expect(byId.get(4)).toMatchObject({ cvssScore: 7.0, verdict: null, cves: [] }); // advisory CVSS fallback
    expect(byId.get(3)).toMatchObject({ malicious: true });
    expect(byId.get(6)).toMatchObject({ labelAction: null, verdict: null }); // labeled by someone else only
  });

  it('applies each filter', () => {
    expect(ids({ project: 'web' })).toEqual([1, 2, 6]);
    expect(ids({ status: 'all' })).toContain(5);
    expect(ids({ status: 'fixed' })).toEqual([5]);
    expect(ids({ priority: 'P2' })).toEqual([4, 2, 6]);
    expect(ids({ action: 'ping' })).toEqual([3, 1]);
    expect(ids({ action: 'none' })).toEqual([6]);
    expect(ids({ action: 'digest,none' })).toEqual([4, 6]);
    expect(ids({ verdict: 'affected' })).toEqual([1]);
    expect(ids({ verdict: 'none' })).toEqual([3, 4, 6]);
    expect(ids({ devOnly: 'yes' })).toEqual([2]);
    expect(ids({ direct: 'no' })).toEqual([4]);
    expect(ids({ direct: 'unknown' })).toEqual([6]);
    expect(ids({ direct: 'yes' })).toEqual([3, 1, 2]);
    expect(ids({ origin: 'new_dependency' })).toEqual([3]);
    expect(ids({ labeled: 'yes' })).toEqual([2]);
    expect(ids({ labeled: 'no' })).toEqual([3, 1, 4, 6]);
    expect(ids({ expected: 'log' })).toEqual([2]);
    expect(ids({ ids: '2,5', status: 'all' })).toEqual([2, 5]);
  });

  it('searches package, OSV id and aliases case-insensitively', () => {
    expect(ids({ q: 'LODASH' })).toEqual([1]);
    expect(ids({ q: 'cve-2026-0002' })).toEqual([2]);
    expect(ids({ q: 'MAL-' })).toEqual([3]);
    expect(ids({ q: 'nothing-matches' })).toEqual([]);
  });

  it('sorts by each key', () => {
    expect(ids({ sort: 'epss' })).toEqual([1, 4, 2, 3, 6]);
    expect(ids({ sort: 'cvss' })).toEqual([1, 2, 6, 4, 3]);
    expect(ids({ sort: 'package' })).toEqual([3, 1, 4, 2, 6]);
    expect(ids({ sort: 'firstSeen' })).toEqual([3, 6, 4, 2, 1]);
  });

  it('shows no verdict when the active run is not a successful one', () => {
    const local = openDb(':memory:');
    seed(local);
    // A failed run kept by the decision for its trace, even if it carries a verdict-looking output.
    local
      .insert(triageRuns)
      .values({ id: 9, findingId: 4, configName: 'cfg-a', inputHash: 'h', status: 'invalid', output: triageOutput({ verdict: 'affected' }), prompt: 'p' })
      .run();
    local.update(findings).set({ activeTriageRunId: 9 }).where(eq(findings.id, 4)).run();
    const row = listFindings(local, parseFindingFilters({ ids: '4' })).rows[0]!;
    expect(row).toMatchObject({ id: 4, verdict: null, confidence: null });
    expect(listFindings(local, parseFindingFilters({ verdict: 'affected' })).rows.map((r) => r.id)).toEqual([1]);
    expect(listFindings(local, parseFindingFilters({ verdict: 'none' })).rows.map((r) => r.id)).toContain(4);
  });

  it('applies the limit after counting', () => {
    const list = listFindings(db, parseFindingFilters({}), 2);
    expect(list.rows.map((r) => r.id)).toEqual([3, 1]);
    expect(list.total).toBe(5);
    expect(list.limit).toBe(2);
  });
});

describe('getFindingDetail', () => {
  it('returns null for an unknown finding', () => {
    expect(getFindingDetail(db, 999, ctx)).toBeNull();
  });

  it('loads every section for a triaged, decided finding', () => {
    const d = getFindingDetail(db, 1, ctx)!;
    expect(d.finding.packageName).toBe('lodash');
    expect(d.project).toEqual({ id: 'web', name: 'Web', enabled: true, exposure: 'internet-facing', criticality: 'high' });
    expect(d.advisory?.summary).toBe('Prototype pollution in lodash');
    expect(d.advisory).not.toHaveProperty('raw');
    expect(d.kevEntries.map((k) => k.cve)).toEqual(['CVE-2026-0001']);
    expect(d.lastScan).toMatchObject({ id: 1, commitSha: SHA_WEB });

    expect(d.triage.tabs.map((t) => [t.configName, t.active, t.runCount, t.latestStatus])).toEqual([
      ['cfg-a', true, 2, 'ok'],
      ['cfg-b', false, 1, 'timeout'],
    ]);
    expect(d.triage.selectedConfig).toBe('cfg-a');
    expect(d.triage.runs.map((r) => r.id)).toEqual([4, 1]);
    expect(d.triage.selectedRun?.id).toBe(4);
    expect(d.triage.selectedRun?.output?.verdict).toBe('affected');
    expect(d.triage.selectedRun).not.toHaveProperty('prompt');
    expect(d.triage.selectedRunRaw).toEqual({ prompt: 'prompt 4', raw: { total_cost_usd: 0.42 } });
    expect(d.triage.state).toMatchObject({ status: 'ok', runId: 4 });

    expect(d.decision?.isCurrent).toBe(true);
    expect(d.decision?.row.ruleId).toBe('p1-affected');
    expect(d.decision?.run?.id).toBe(4);
    expect(d.label).toBeNull();
    expect(d.events.map((e) => e.type)).toEqual(['escalated', 'created']);
    expect(d.triageJobs).toHaveLength(1);
    expect(d.triageJobs[0]).toMatchObject({ status: 'queued', config: 'cfg-b' });
  });

  it('switches config and run, falling back when they do not match', () => {
    const b = getFindingDetail(db, 1, ctx, { config: 'cfg-b' })!;
    expect(b.triage.selectedConfig).toBe('cfg-b');
    expect(b.triage.selectedRun).toMatchObject({ id: 3, status: 'timeout', output: null, invalidOutput: null });
    expect(b.triage.state?.status).toBe('pending'); // no run for cfg-b's current input hash

    expect(getFindingDetail(db, 1, ctx, { config: 'nope' })!.triage.selectedConfig).toBe('cfg-a');
    expect(getFindingDetail(db, 1, ctx, { runId: 1 })!.triage.selectedRun?.id).toBe(1);
    expect(getFindingDetail(db, 1, ctx, { runId: 3 })!.triage.selectedRun?.id).toBe(4); // run 3 is cfg-b's
  });

  it('falls back to the latest decision when none exists for the current policy', () => {
    const d = getFindingDetail(db, 1, { ...ctx, policyHash: 'polX' })!;
    expect(d.decision?.isCurrent).toBe(false);
    expect(d.decision?.row.policyHash).toBe('pol1');
    expect(getFindingDetail(db, 1, { ...ctx, policyHash: null })!.decision?.isCurrent).toBe(false);
    expect(getFindingDetail(db, 4, ctx)!.decision).toBeNull();
  });

  it('keeps invalid triage output out of `output`', () => {
    const d = getFindingDetail(db, 6, ctx)!;
    expect(d.triage.selectedRun).toMatchObject({ id: 5, output: null, invalidOutput: { verdict: 'maybe' } });
  });

  it('shows my label and failed triage jobs', () => {
    const d = getFindingDetail(db, 2, ctx)!;
    expect(d.label).toMatchObject({ expectedAction: 'log', affectedTruth: 'no' });
    expect(d.triageJobs[0]).toMatchObject({ status: 'failed', error: 'boom' });
    expect(getFindingDetail(db, 6, ctx)!.label).toBeNull(); // someone else's label is not mine
  });
});

describe('triage jobs for a finding', () => {
  it('reads finding ids from arrays, comma strings and single numbers', () => {
    expect(findingParamIds({ findings: [1, '2', 'x', -3] })).toEqual([1, 2]);
    expect(findingParamIds({ findings: '3,4' })).toEqual([3, 4]);
    expect(findingParamIds({ findings: 5 })).toEqual([5]);
    expect(findingParamIds({})).toEqual([]);
    expect(findingParamIds(null)).toEqual([]);
  });

  it('finds a queued or running triage job for the same finding and config only', () => {
    const local = openDb(':memory:');
    seed(local);
    // seed: job 1 queued triage {findings:[1], config:cfg-b}; job 2 failed triage for 2; job 3 queued *scan* naming 1
    expect(findPendingTriageJob(local, 1, 'cfg-b', 'cfg-a')).toBe(1);
    expect(findPendingTriageJob(local, 1, 'cfg-a', 'cfg-a')).toBeNull(); // other config; the scan job does not count
    expect(findPendingTriageJob(local, 2, 'cfg-a', 'cfg-a')).toBeNull(); // failed, not pending

    // No `config` means the active one; CLI-style comma string ids.
    // A running row without a live owner process was interrupted: it is not pending.
    const dead = local.insert(jobRuns).values({ type: 'triage', params: { findings: '4,6' }, status: 'running', pid: null }).returning().get();
    expect(findPendingTriageJob(local, 6, 'cfg-a', 'cfg-a')).toBeNull();
    local.update(jobRuns).set({ status: 'failed' }).where(eq(jobRuns.id, dead.id)).run();
    const running = local
      .insert(jobRuns)
      .values({ type: 'triage', params: { findings: '4,6' }, status: 'running', pid: process.pid })
      .returning()
      .get();
    expect(findPendingTriageJob(local, 6, 'cfg-a', 'cfg-a')).toBe(running.id);
    expect(findPendingTriageJob(local, 6, 'cfg-b', 'cfg-a')).toBeNull();
    expect(listTriageJobsForFinding(local, 6).map((j) => j.id)).toEqual([running.id, dead.id]);
    local.update(jobRuns).set({ status: 'succeeded' }).where(eq(jobRuns.id, running.id)).run();
    expect(findPendingTriageJob(local, 6, 'cfg-a', 'cfg-a')).toBeNull();
  });
});

describe('labels', () => {
  it('parses form fields', () => {
    expect(parseLabelInput({ findingId: '4', expectedAction: 'ping', affectedTruth: '', note: '   ' })).toEqual({
      ok: true,
      value: { findingId: 4, expectedAction: 'ping', affectedTruth: null, note: null },
    });
    expect(parseLabelInput({ findingId: '4', expectedAction: 'log', affectedTruth: null, note: null })).toMatchObject({ ok: true });
    expect(parseLabelInput({ findingId: '4', expectedAction: 'digest', affectedTruth: 'unsure', note: ' why ' })).toMatchObject({
      ok: true,
      value: { affectedTruth: 'unsure', note: 'why' },
    });
    const bad = parseLabelInput({ findingId: '4', expectedAction: 'urgent' });
    expect(bad.ok).toBe(false);
    expect(parseLabelInput({ findingId: 'abc', expectedAction: 'ping' }).ok).toBe(false);
    expect(parseLabelInput({ findingId: '4', expectedAction: 'ping', affectedTruth: 'maybe' }).ok).toBe(false);
  });

  it('upserts one label per finding and labeler', () => {
    const local = openDb(':memory:');
    seed(local);
    upsertLabel(local, { findingId: 4, expectedAction: 'ping', affectedTruth: 'yes', note: 'first' });
    const updated = upsertLabel(local, { findingId: 4, expectedAction: 'digest', affectedTruth: null, note: null });
    expect(updated).toMatchObject({ findingId: 4, labeler: LABELER, expectedAction: 'digest', affectedTruth: null, note: null });
    expect(local.select().from(labels).all().filter((l) => l.findingId === 4)).toHaveLength(1);
    expect(() => upsertLabel(local, { findingId: 999, expectedAction: 'log', affectedTruth: null, note: null })).toThrow(/not found/);
  });
});

describe('labelers', () => {
  it('accepts short names of letters, digits, _ and -, lower-cased', () => {
    expect(parseLabeler('ana')).toBe('ana');
    expect(parseLabeler('  Ana_2-b ')).toBe('ana_2-b');
    expect(parseLabeler('a'.repeat(32))).toBe('a'.repeat(32));
    for (const bad of ['', ' ', '-ana', '_x', 'a'.repeat(33), 'an a', 'ana;', '../me', 'é', null, undefined, 42]) {
      expect(parseLabeler(bad)).toBeNull();
    }
    expect(labelerOrDefault(undefined)).toBe(LABELER);
    expect(labelerOrDefault('bad name')).toBe(LABELER);
    expect(labelerOrDefault('Ana')).toBe('ana');
  });

  it('lists and filters by the given labeler\'s labels', () => {
    const forOther = (f: Record<string, string>) => listFindings(db, parseFindingFilters(f), undefined, 'someone-else').rows;
    expect(forOther({ labeled: 'yes' }).map((r) => r.id)).toEqual([6]);
    expect(forOther({ expected: 'ping' }).map((r) => r.id)).toEqual([6]);
    expect(forOther({ ids: '2,6' }).map((r) => [r.id, r.labelAction])).toEqual([
      [2, null],
      [6, 'ping'],
    ]);
    expect(ids({ labeled: 'yes' })).toEqual([2]); // the default labeler is unchanged
  });

  it('loads and writes the given labeler\'s label on the finding page', () => {
    const local = openDb(':memory:');
    seed(local);
    expect(getFindingDetail(local, 6, ctx, { labeler: 'someone-else' })).toMatchObject({ labeler: 'someone-else', label: { expectedAction: 'ping' } });
    expect(getFindingDetail(local, 6, ctx)).toMatchObject({ labeler: LABELER, label: null });
    upsertLabel(local, { findingId: 6, expectedAction: 'log', affectedTruth: null, note: null }, 'ana');
    expect(local.select().from(labels).all().filter((l) => l.findingId === 6).map((l) => [l.labeler, l.expectedAction]).sort()).toEqual([
      ['ana', 'log'],
      ['someone-else', 'ping'],
    ]);
  });
});

describe('disabled projects', () => {
  it('marks findings of a disabled project on the list and the finding page', () => {
    const local = openDb(':memory:');
    seed(local);
    local.update(projects).set({ enabled: false }).where(eq(projects.id, 'api')).run();
    const rows = listFindings(local, parseFindingFilters({})).rows;
    expect(rows.filter((r) => !r.projectEnabled).map((r) => r.id)).toEqual([3, 4]);
    expect(getFindingDetail(local, 4, ctx)!.project).toMatchObject({ id: 'api', enabled: false });
    expect(getFindingDetail(local, 1, ctx)!.project).toMatchObject({ enabled: true });
  });
});

describe('stale decisions', () => {
  it('is not stale while the decision used the current ok run', () => {
    expect(getFindingDetail(db, 1, ctx)!.decision?.stale).toBeNull();
  });

  it('flags a newer ok run of the active config (e.g. after "Triage with …")', () => {
    const local = openDb(':memory:');
    seed(local);
    const run4 = local.select().from(triageRuns).where(eq(triageRuns.id, 4)).get()!;
    local.insert(triageRuns).values({ id: 30, findingId: 1, configName: 'cfg-a', inputHash: run4.inputHash, status: 'ok', output: triageOutput(), prompt: 'p' }).run();
    const d = getFindingDetail(local, 1, ctx)!;
    expect(d.decision?.stale).toMatchObject({ currentRunId: 30 });
    expect(d.decision?.stale?.reason).toMatch(/run #30 is the current verdict, the decision used run #4/);
    // An older, non-current decision is compared too, but only for the active config.
    expect(decisionStaleness(local, d.finding, { configName: 'cfg-b', triageRunId: 3, inputs: decisionInputs }, ctx)).toBeNull();
    expect(decisionStaleness(local, d.finding, { configName: 'cfg-a', triageRunId: null, inputs: { ...decisionInputs, triage_status: 'pending' } }, ctx)?.reason).toMatch(
      /run #30 succeeded, the decision had no verdict/,
    );
  });

  it('flags a decision whose verdict no longer matches the inputs', () => {
    const local = openDb(':memory:');
    seed(local);
    local.update(findings).set({ installedVersions: ['2.0.0'] }).where(eq(findings.id, 1)).run();
    const stale = getFindingDetail(local, 1, ctx)!.decision?.stale;
    expect(stale).toMatchObject({ currentRunId: null });
    expect(stale?.reason).toMatch(/inputs changed since this decision \(now pending\)/);
  });

  it('finds the newest queued or running decide job', () => {
    const local = openDb(':memory:');
    seed(local);
    expect(findPendingDecideJob(local)).toBeNull();
    const queued = local.insert(jobRuns).values({ type: 'decide', status: 'queued' }).returning().get();
    expect(findPendingDecideJob(local)).toEqual({ id: queued.id, status: 'queued' });
    local.update(jobRuns).set({ status: 'running', pid: 2147483646 }).where(eq(jobRuns.id, queued.id)).run();
    expect(findPendingDecideJob(local)).toBeNull(); // owner process gone → interrupted, not pending
    local.update(jobRuns).set({ status: 'running', pid: process.pid }).where(eq(jobRuns.id, queued.id)).run();
    expect(findPendingDecideJob(local)).toEqual({ id: queued.id, status: 'running' });
    local.update(jobRuns).set({ status: 'succeeded' }).where(eq(jobRuns.id, queued.id)).run();
    expect(findPendingDecideJob(local)).toBeNull();
    expect(getFindingDetail(local, 1, ctx)!.pendingDecide).toBeNull();
  });
});

describe('snapshot path guard', () => {
  const root = '/data/snapshots/web/abc';

  it('accepts relative paths inside the snapshot', () => {
    expect(resolveSnapshotPath(root, 'src/app/page.tsx')).toEqual({ ok: true, relPath: 'src/app/page.tsx', absPath: '/data/snapshots/web/abc/src/app/page.tsx' });
    expect(resolveSnapshotPath(root, './src//lib/./a.ts')).toMatchObject({ ok: true, relPath: 'src/lib/a.ts' });
  });

  it.each([
    ['', 'empty'],
    ['.', 'only dot'],
    ['/etc/passwd', 'absolute'],
    ['C:\\Windows\\win.ini', 'drive letter'],
    ['\\\\server\\share', 'UNC'],
    ['..', 'parent'],
    ['../web/abc2/x', 'parent prefix'],
    ['src/../../x', 'parent inside'],
    ['src\\..\\..\\x', 'backslash parent'],
    ['a\0b', 'NUL byte'],
    ['.env', 'env file'],
    ['config/.env.local', 'nested env file'],
    ['.git/config', 'git dir'],
    ['.claude/settings.json', 'claude dir'],
    // case-insensitive volumes (macOS) open .env for .ENV
    ['.ENV', 'upper-case env file'],
    ['Config/.Env.local', 'mixed-case nested env file'],
    ['.GIT/config', 'upper-case git dir'],
    ['.Claude/settings.json', 'mixed-case claude dir'],
  ])('rejects %j (%s)', (input) => {
    expect(resolveSnapshotPath(root, input).ok).toBe(false);
  });

  it('strips absolute snapshot prefixes the model may cite, only for the resolved commit', () => {
    expect(stripSnapshotPrefix('/data/snapshots/web/abc123/src/a.ts', '/data/snapshots', 'web', 'abc123')).toBe('src/a.ts');
    // Another commit's snapshot: left absolute (the guard refuses it) rather than read at the wrong commit.
    expect(stripSnapshotPrefix('/data/snapshots/web/abc123/src/a.ts', '/data/snapshots', 'web', 'def456')).toBe('/data/snapshots/web/abc123/src/a.ts');
    expect(stripSnapshotPrefix('/data/snapshots/api/abc123/src/a.ts', '/data/snapshots', 'web', 'abc123')).toBe('/data/snapshots/api/abc123/src/a.ts');
    expect(stripSnapshotPrefix('src/a.ts', '/data/snapshots', 'web', 'abc123')).toBe('src/a.ts');
    expect(splitSnapshotPath('/data/snapshots/web/abc123/src/a.ts', '/data/snapshots', 'web')).toEqual({ commitSha: 'abc123', rest: 'src/a.ts' });
    expect(splitSnapshotPath('/data/snapshots/web/abc123', '/data/snapshots', 'web')).toBeNull();
    expect(splitSnapshotPath('src/a.ts', '/data/snapshots', 'web')).toBeNull();
    // whatever remains still goes through the guard
    const stripped = stripSnapshotPrefix('/data/snapshots/web/abc/../../etc/passwd', '/data/snapshots', 'web', 'abc');
    expect(resolveSnapshotPath(root, stripped).ok).toBe(false);
  });
});

describe('sourceExcerpt', () => {
  const text = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`).join('\n') + '\n';

  it('shows ±40 lines around the target', () => {
    const e = sourceExcerpt(text, 50);
    expect(e).toMatchObject({ startLine: 10, totalLines: 100, line: 50 });
    expect(e.lines).toHaveLength(81);
    expect(e.lines[0]).toBe('line 10');
    expect(e.lines.at(-1)).toBe('line 90');
  });

  it('clamps at both ends and handles no target line', () => {
    expect(sourceExcerpt(text, 1)).toMatchObject({ startLine: 1, line: 1 });
    expect(sourceExcerpt(text, 1).lines).toHaveLength(41);
    expect(sourceExcerpt(text, 999)).toMatchObject({ startLine: 60, line: 100 });
    const top = sourceExcerpt(text, null);
    expect(top).toMatchObject({ startLine: 1, line: null });
    expect(top.lines).toHaveLength(81);
    expect(sourceExcerpt('', 3)).toMatchObject({ totalLines: 1, line: 1 });
  });
});

describe('snapshot files on disk', () => {
  let tmp: string;
  let snapshotsRoot: string;
  let webDir: string;

  beforeAll(() => {
    tmp = mkdtempSync(path.join(tmpdir(), 'vigiles-findings-test-'));
    snapshotsRoot = path.join(tmp, 'snapshots');
    webDir = path.join(snapshotsRoot, 'web', SHA_WEB);
    mkdirSync(path.join(webDir, 'src'), { recursive: true });
    writeFileSync(path.join(webDir, 'src', 'app.ts'), 'import x from "lodash";\nconst a = 1;\nx.merge(a);\n');
    writeFileSync(path.join(webDir, 'bin.dat'), Buffer.from([1, 2, 0, 3]));
    writeFileSync(path.join(tmp, 'secret.txt'), 'outside the snapshot');
    symlinkSync(path.join(tmp, 'secret.txt'), path.join(webDir, 'escape.txt'));
    symlinkSync(path.join(webDir, 'src', 'app.ts'), path.join(webDir, 'inside.ts'));
    // A secret the scrub missed (e.g. a mixed-case name) reached through an innocent-looking symlink.
    writeFileSync(path.join(webDir, '.Envrc'), 'TOKEN=secret');
    symlinkSync(path.join(webDir, '.Envrc'), path.join(webDir, 'notes.txt'));
  });
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  const read = (rel: string) => {
    const p = resolveSnapshotPath(webDir, rel);
    if (!p.ok) throw new Error(p.reason);
    return readSnapshotFile(webDir, p.absPath);
  };

  it('reads regular files and in-snapshot symlinks', () => {
    expect(read('src/app.ts')).toMatchObject({ ok: true });
    expect(read('inside.ts')).toMatchObject({ ok: true });
  });

  it('rejects symlinks escaping the snapshot, binaries, directories and missing files', () => {
    expect(read('escape.txt')).toEqual({ ok: false, reason: 'Path escapes the snapshot (symlink).' });
    expect(read('bin.dat')).toEqual({ ok: false, reason: 'Binary file.' });
    expect(read('src')).toEqual({ ok: false, reason: 'Not a regular file.' });
    expect(read('missing.ts')).toEqual({ ok: false, reason: 'File not found in the snapshot.' });
  });

  it('rejects an in-snapshot symlink whose target is a hidden secret file', () => {
    const r = read('notes.txt');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/never shown/);
    expect(JSON.stringify(r)).not.toContain('TOKEN');
  });

  it('strips the real-path form of the snapshots root too', () => {
    const linkRoot = path.join(tmp, 'snapshots-link');
    symlinkSync(snapshotsRoot, linkRoot);
    const cited = path.join(realpathSync(snapshotsRoot), 'web', SHA_WEB, 'src', 'app.ts');
    expect(stripSnapshotPrefix(cited, linkRoot, 'web', SHA_WEB)).toBe('src/app.ts');
    expect(getFindingSource(db, 1, cited, 2, linkRoot)).toMatchObject({ ok: true, file: 'src/app.ts' });
  });

  it('loads an excerpt for a finding through its last scan', () => {
    const src = getFindingSource(db, 1, 'src/app.ts', 3, snapshotsRoot);
    expect(src).toMatchObject({ ok: true, projectId: 'web', commitSha: SHA_WEB, file: 'src/app.ts' });
    if (src.ok) {
      expect(src.excerpt).toMatchObject({ startLine: 1, line: 3, totalLines: 3 });
      expect(src.commit).toMatchObject({ via: 'last-scan', runId: null, latestCommitSha: SHA_WEB, notes: [] });
    }
    const absolute = getFindingSource(db, 1, path.join(snapshotsRoot, 'web', SHA_WEB, 'src', 'app.ts'), null, snapshotsRoot);
    expect(absolute).toMatchObject({ ok: true, file: 'src/app.ts' });
    // An absolute path into another commit's snapshot is not read as this commit's file.
    const other = getFindingSource(db, 1, path.join(snapshotsRoot, 'web', 'deadbeef', 'src', 'app.ts'), null, snapshotsRoot);
    expect(other).toMatchObject({ ok: false, commitSha: SHA_WEB });
    if (!other.ok) expect(other.message).toMatch(/snapshot of commit deadbeef, not aaaaaaaaaa/);
  });

  it('explains every failure instead of throwing', () => {
    expect(getFindingSource(db, 999, 'src/app.ts', 1, snapshotsRoot)).toMatchObject({ ok: false, message: 'Finding not found.', missingFinding: true });
    expect(getFindingSource(db, 1, '../../api/x', 1, snapshotsRoot)).toMatchObject({ ok: false });
    expect(getFindingSource(db, 1, '/etc/passwd', 1, snapshotsRoot)).toMatchObject({ ok: false, message: 'Absolute paths are not allowed.' });
    expect(getFindingSource(db, 1, 'escape.txt', 1, snapshotsRoot)).toMatchObject({ ok: false });
    const gone = getFindingSource(db, 4, 'src/app.ts', 1, snapshotsRoot);
    expect(gone.ok).toBe(false);
    if (!gone.ok) {
      expect(gone.message).toMatch(/snapshot of api at bbbbbbbbbb is not on disk/);
      expect(gone.missingFinding).toBeUndefined();
    }
  });

  describe('evidence links of a triage run', () => {
    const OLD_SHA = 'c'.repeat(40);
    let local: Db;
    beforeAll(() => {
      local = openDb(':memory:');
      seed(local);
      // An older commit of web: run 20 read it (commit_sha recorded), the finding was rescanned at SHA_WEB since.
      local.insert(scans).values({ id: 3, projectId: 'web', ref: 'origin/main', commitSha: OLD_SHA, status: 'succeeded' }).run();
      local
        .insert(triageRuns)
        .values([
          { id: 20, findingId: 1, configName: 'cfg-a', inputHash: 'h', status: 'ok', output: triageOutput(), prompt: 'p', commitSha: OLD_SHA, scanId: 3 },
          { id: 21, findingId: 1, configName: 'cfg-a', inputHash: 'h', status: 'ok', output: triageOutput(), prompt: 'p', scanId: 3 },
          { id: 22, findingId: 1, configName: 'cfg-a', inputHash: 'h', status: 'ok', output: triageOutput(), prompt: `Your working directory is \`/x\`: a read-only snapshot of this project at commit ${OLD_SHA} (ref origin/main).` },
          { id: 23, findingId: 1, configName: 'cfg-b', inputHash: 'h', status: 'ok', output: triageOutput(), prompt: 'no code access' },
          { id: 24, findingId: 1, configName: 'cfg-a', inputHash: 'h', status: 'ok', output: triageOutput(), prompt: 'p', commitSha: SHA_WEB },
        ])
        .run();
      const oldDir = path.join(snapshotsRoot, 'web', OLD_SHA, 'src');
      mkdirSync(oldDir, { recursive: true });
      writeFileSync(path.join(oldDir, 'app.ts'), 'old line 1\nold line 2\nold line 3\n');
    });

    it('opens the commit the run read, with a note that it is not the latest scan', () => {
      const src = getFindingSource(local, 1, 'src/app.ts', 2, snapshotsRoot, { runId: 20 });
      expect(src).toMatchObject({ ok: true, commitSha: OLD_SHA, commit: { via: 'run', runId: 20, runConfig: 'cfg-a', latestCommitSha: SHA_WEB } });
      if (src.ok) {
        expect(src.excerpt.lines).toEqual(['old line 1', 'old line 2', 'old line 3']);
        expect(src.commit.notes.join(' ')).toMatch(/Run #20 read commit cccccccccc; the finding's latest scan is at aaaaaaaaaa/);
      }
      // The model's absolute path into its own snapshot resolves; the latest commit's path does not.
      const cited = getFindingSource(local, 1, path.join(snapshotsRoot, 'web', OLD_SHA, 'src', 'app.ts'), 1, snapshotsRoot, { runId: 20 });
      expect(cited).toMatchObject({ ok: true, commitSha: OLD_SHA });
      const latest = getFindingSource(local, 1, path.join(snapshotsRoot, 'web', SHA_WEB, 'src', 'app.ts'), 1, snapshotsRoot, { runId: 20 });
      expect(latest).toMatchObject({ ok: false, commitSha: OLD_SHA });
    });

    it('falls back to the run\'s scan, then the commit named in a legacy prompt', () => {
      expect(getFindingSource(local, 1, 'src/app.ts', 1, snapshotsRoot, { runId: 21 })).toMatchObject({ ok: true, commitSha: OLD_SHA, commit: { via: 'run-scan' } });
      expect(getFindingSource(local, 1, 'src/app.ts', 1, snapshotsRoot, { runId: 22 })).toMatchObject({ ok: true, commitSha: OLD_SHA, commit: { via: 'run-prompt' } });
      const codeLine = (sha: string) => `Your working directory is \`/x\`: a read-only snapshot of this project at commit ${sha} (ref origin/main).`;
      expect(commitFromPrompt(codeLine(OLD_SHA))).toBe(OLD_SHA);
      expect(commitFromPrompt(codeLine('abc'))).toBeNull();
      expect(commitFromPrompt(null)).toBeNull();
      // The untrusted advisory comes before the code section and may name other commits: only the
      // code section's own sentence counts, and the last one wins.
      const advisory = `<advisory>\nFixed at commit ${'b'.repeat(40)}. Also: a read-only snapshot of this project at commit ${'9'.repeat(40)}\n</advisory>`;
      expect(commitFromPrompt(`${advisory}\n## Code\n${codeLine(OLD_SHA)}`)).toBe(OLD_SHA);
      expect(commitFromPrompt(`at commit ${OLD_SHA} (ref x)`)).toBeNull();
      // Contract with the prompt renderer: the code note it writes is what legacy runs are parsed from.
      expect(commitFromPrompt(renderCodeNote({ access: true, workdir: '/x', commitSha: OLD_SHA, ref: 'origin/main', commitDate: '2026-11-10T22:41:00+01:00' }))).toBe(OLD_SHA);
      expect(commitFromPrompt(renderCodeNote({ access: false }))).toBeNull();
    });

    it('uses the latest scan, with a note, for a run that recorded no commit', () => {
      const src = getFindingSource(local, 1, 'src/app.ts', 1, snapshotsRoot, { runId: 23 });
      expect(src).toMatchObject({ ok: true, commitSha: SHA_WEB, commit: { via: 'last-scan', runId: 23 } });
      if (src.ok) expect(src.commit.notes.join(' ')).toMatch(/did not record which commit/);
    });

    it('adds no note when the run read the latest scanned commit', () => {
      const src = getFindingSource(local, 1, 'src/app.ts', 1, snapshotsRoot, { runId: 24 });
      expect(src).toMatchObject({ ok: true, commitSha: SHA_WEB, commit: { via: 'run', notes: [] } });
    });

    it('refuses a run of another finding or an unknown run', () => {
      expect(getFindingSource(local, 2, 'src/app.ts', 1, snapshotsRoot, { runId: 20 })).toMatchObject({ ok: false, message: 'Triage run #20 is not a run of this finding.' });
      expect(getFindingSource(local, 1, 'src/app.ts', 1, snapshotsRoot, { runId: 999 })).toMatchObject({ ok: false });
    });

    it('says the run\'s snapshot is gone instead of showing another commit', () => {
      local.insert(triageRuns).values({ id: 25, findingId: 1, configName: 'cfg-a', inputHash: 'h', status: 'ok', prompt: 'p', commitSha: 'd'.repeat(40) }).run();
      const src = getFindingSource(local, 1, 'src/app.ts', 1, snapshotsRoot, { runId: 25 });
      expect(src).toMatchObject({ ok: false, commitSha: 'd'.repeat(40) });
      if (!src.ok) expect(src.message).toMatch(/at dddddddddd is not on disk/);
    });
  });
});
