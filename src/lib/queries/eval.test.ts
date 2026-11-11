import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { eq } from 'drizzle-orm';
import { parsePolicy } from '../config/load';
import { findings, labels, policyVersions, triageConfigs } from '../db/schema';
import { decideAll } from '../policy/decide';
import {
  insertConfig,
  insertDecision,
  insertEvent,
  insertFinding,
  insertJob,
  insertLabel,
  insertProject,
  insertTriageRun,
  triageOutput,
} from '../eval/test-fixtures';
import {
  cellKey,
  getEvalOptions,
  getEvalReport,
  loadSelectedPolicy,
  parseCellKey,
  refreshVolumes,
  resolveSelection,
  rowsForCell,
} from './eval';

// P1: affected/likely_affected → ping, any other verdict → digest; everything else → log.
const POLICY_YAML = `
thresholds: { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9.0, cvss_high: 7.0 }
rules:
  - id: p1-affected
    when: { priority: P1, verdict: [affected, likely_affected] }
    then: ping
  - id: p1-other
    when: { priority: P1 }
    then: digest
  - id: default
    when: {}
    then: log
`;

describe('eval report on synthetic data', () => {
  let db: Db;
  let ids: Record<string, number>;

  beforeEach(() => {
    db = openDb(':memory:');
    const { scanId } = insertProject(db, 'web');
    const cfgA = insertConfig(db, 'cfg-a', true);
    const cfgB = insertConfig(db, 'cfg-b', false);
    db.insert(policyVersions)
      .values([
        { hash: 'pol1', content: 'rules: []', firstSeenAt: '2026-11-01T00:00:00.000Z' },
        { hash: 'pol2', content: 'rules: [x]', firstSeenAt: '2026-11-02T00:00:00.000Z' },
      ])
      .run();

    const f1 = insertFinding(db, scanId, { packageName: 'next', priority: 'P0', action: 'ping', cves: ['CVE-2026-0001'] });
    const f2 = insertFinding(db, scanId, { packageName: 'next', priority: 'P1', action: 'ping' });
    const f3 = insertFinding(db, scanId, { packageName: 'zod', priority: 'P2', action: 'digest' });
    const f4 = insertFinding(db, scanId, { packageName: 'old', priority: 'P3', action: null, status: 'fixed' });
    const f5 = insertFinding(db, scanId, { packageName: 'sharp', priority: 'P2', action: 'digest', origin: 'new_advisory' });
    const f6 = insertFinding(db, scanId, { packageName: 'lodash', priority: 'P3', action: 'log' });
    ids = { f1: f1.id, f2: f2.id, f3: f3.id, f4: f4.id, f5: f5.id, f6: f6.id };

    // f1: two identical ok runs (consistent); decision made from the latest
    insertTriageRun(db, f1.id, cfgA, { output: triageOutput({ verdict: 'affected', suggested_action: 'ping' }) });
    const f1r2 = insertTriageRun(db, f1.id, cfgA, { output: triageOutput({ verdict: 'affected', suggested_action: 'ping' }) });
    // f2: same verdict, different action between runs; the latest says log
    insertTriageRun(db, f2.id, cfgA, { output: triageOutput({ verdict: 'not_affected', suggested_action: 'digest' }), costUsd: 1.5 });
    const f2r2 = insertTriageRun(db, f2.id, cfgA, { output: triageOutput({ verdict: 'not_affected', suggested_action: 'log' }) });
    // f4: only a run at an outdated input hash → not usable
    insertTriageRun(db, f4.id, cfgA, { inputHash: 'outdated' });
    // f5: ok run, but its decision was made from an older run
    insertTriageRun(db, f5.id, cfgA, { output: triageOutput({ verdict: 'likely_not_affected', suggested_action: 'digest' }) });
    // cfg-b: one failed run
    insertTriageRun(db, f1.id, cfgB, { status: 'failed', output: null, costUsd: 2, durationMs: 1000, numTurns: 1 });

    insertDecision(db, f1.id, 'pol1', 'cfg-a', 'ping', f1r2.id);
    insertDecision(db, f2.id, 'pol1', 'cfg-a', 'ping', f2r2.id);
    insertDecision(db, f3.id, 'pol1', 'cfg-a', 'digest', null);
    insertDecision(db, f5.id, 'pol1', 'cfg-a', 'digest', 999);
    insertDecision(db, f1.id, 'pol2', 'cfg-a', 'log', f1r2.id);

    insertLabel(db, f1.id, 'ping', { truth: 'yes' });
    insertLabel(db, f2.id, 'log', { truth: 'no' });
    insertLabel(db, f3.id, 'ping', { truth: 'unsure' });
    insertLabel(db, f4.id, 'log');
    insertLabel(db, f5.id, 'digest', { truth: 'yes' });
    insertLabel(db, f1.id, 'ping', { labeler: 'bob', truth: 'yes' });
    insertLabel(db, f2.id, 'digest', { labeler: 'bob', truth: 'no' });
    insertLabel(db, f6.id, 'log', { labeler: 'bob' });
  });

  const report = (o: { config?: string; policy?: string; labeler?: string } = {}) =>
    getEvalReport(
      db,
      { configName: o.config ?? 'cfg-a', policyHash: o.policy ?? 'pol1', labeler: o.labeler ?? 'me' },
      { minPriority: 'P2' },
    );

  it('lists pickers with sensible defaults', () => {
    const opts = getEvalOptions(db, 'pol1');
    expect(opts.configs.map((c) => c.name)).toEqual(['cfg-a', 'cfg-b']);
    expect(opts.policies.map((p) => [p.hash, p.current])).toEqual([
      ['pol2', false],
      ['pol1', true],
    ]);
    expect(opts.labelers).toEqual(['bob', 'me']);
    expect(opts.labelerCount).toBe(2);
    expect(opts.defaults).toEqual({ configName: 'cfg-a', policyHash: 'pol1', labeler: 'me' });
    expect(getEvalOptions(db, null).defaults.policyHash).toBe('pol2');
    expect(resolveSelection(opts.defaults, { config: 'cfg-b', policy: '', labeler: ['bob'] })).toEqual({
      configName: 'cfg-b',
      policyHash: 'pol1',
      labeler: 'bob',
    });
  });

  it('scores the base-priority decider on every labeled finding', () => {
    const base = report().deciders.find((d) => d.name === 'base')!;
    expect(base.metrics.n).toBe(5);
    expect(base.excluded).toBe(0);
    expect(base.metrics.pingRecall).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(base.metrics.pingPrecision).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(base.metrics.accuracy).toEqual({ num: 3, den: 5, value: 0.6 });
  });

  it('scores the LLM decider only where an ok run exists at the current input hash', () => {
    const r = report();
    const llm = r.deciders.find((d) => d.name === 'llm')!;
    expect(llm.metrics.n).toBe(3);
    expect(llm.excluded).toBe(2);
    expect(llm.excludedNote).toContain('1 pending');
    expect(llm.excludedNote).toContain('1 skipped');
    expect(llm.metrics.accuracy).toEqual({ num: 3, den: 3, value: 1 });
    expect(r.rows.find((x) => x.findingId === ids.f2)!.llm).toBe('log'); // the latest ok run wins
  });

  it('scores the policy decider from the decisions of the selected policy × config', () => {
    const r = report();
    const policy = r.deciders.find((d) => d.name === 'policy')!;
    expect(policy.metrics.n).toBe(4);
    expect(policy.excluded).toBe(1);
    expect(policy.metrics.pingRecall).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(policy.metrics.pingPrecision).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(policy.metrics.matrix.ping).toEqual({ ping: 1, digest: 1, log: 0 });
    expect(r.missingDecisions).toEqual({ open: 0, closed: 1, disabled: 0 });
    expect(r.staleDecisions).toBe(1);

    expect(r.disagreements.map((d) => d.findingId)).toEqual([ids.f3, ids.f2]); // missed ping first
    expect(r.cells[cellKey({ decider: 'policy', label: 'ping', decided: 'digest' })]).toEqual([ids.f3]);
    const cell = parseCellKey('policy:log:ping')!;
    expect(rowsForCell(r, cell).map((x) => x.findingId)).toEqual([ids.f2]);
    expect(parseCellKey('policy:ping:bogus')).toBeNull();

    const other = report({ policy: 'pol2' });
    expect(other.deciders.find((d) => d.name === 'policy')!.metrics.n).toBe(1);
    expect(other.missingDecisions).toEqual({ open: 3, closed: 1, disabled: 0 });
  });

  it('flags a decision as stale when the verdict it used is no longer the one that counts', () => {
    const config = db.select().from(triageConfigs).where(eq(triageConfigs.name, 'cfg-a')).get()!;
    const scanId = db.select().from(findings).where(eq(findings.id, ids.f1!)).get()!.lastSeenScanId;
    const f7 = insertFinding(db, scanId, { packageName: 'axios', priority: 'P1', action: 'ping' });
    const run = insertTriageRun(db, f7.id, config);
    insertDecision(db, f7.id, 'pol1', 'cfg-a', 'ping', run.id);
    insertLabel(db, f7.id, 'ping');
    // A failed triage that is still the latest: the decision used no verdict, and none counts now either.
    const f8 = insertFinding(db, scanId, { packageName: 'qs', priority: 'P1', action: 'ping' });
    const failed = insertTriageRun(db, f8.id, config, { status: 'failed' });
    insertDecision(db, f8.id, 'pol1', 'cfg-a', 'ping', failed.id, { triage_status: 'failed', verdict: null });
    insertLabel(db, f8.id, 'ping');

    const before = report();
    expect(before.staleDecisions).toBe(1); // f5 only
    expect(before.rows.find((r) => r.findingId === f8.id)).toMatchObject({ triageStatus: 'failed', decisionStale: false });

    // The finding's inputs change (new installed version): its ok run no longer matches the input hash.
    db.update(findings)
      .set({ installedVersions: ['2.0.0'] })
      .where(eq(findings.id, f7.id))
      .run();
    const after = report();
    expect(after.rows.find((r) => r.findingId === f7.id)).toMatchObject({ triageStatus: 'pending', llm: null, decisionStale: true });
    expect(after.staleDecisions).toBe(2);
  });

  it('counts only labelers that have labels', () => {
    db.delete(labels).where(eq(labels.labeler, 'me')).run();
    const opts = getEvalOptions(db, 'pol1');
    expect(opts.labelers).toEqual(['me', 'bob']);
    expect(opts.labelerCount).toBe(1);
  });

  it('computes verdict accuracy against affected_truth', () => {
    expect(report().verdict).toMatchObject({ num: 2, den: 3, excludedNoTruth: 2, excludedNoVerdict: 0 });
  });

  it('computes cost and consistency per config', () => {
    const r = report();
    const a = r.cost.find((c) => c.configName === 'cfg-a')!;
    expect(a.runs).toBe(6);
    expect(a.okRate.value).toBe(1);
    expect(a.costUsd.total).toBeCloseTo(4);
    const b = r.cost.find((c) => c.configName === 'cfg-b')!;
    expect(b).toMatchObject({ runs: 1, okRate: { num: 0, den: 1 }, costUsd: { total: 2 } });

    expect(r.consistency).toHaveLength(1);
    expect(r.consistency[0]).toMatchObject({
      configName: 'cfg-a',
      groups: 2,
      identicalVerdict: { num: 2, den: 2 },
      identicalAction: { num: 1, den: 2 },
      // pol1's stored content is not a valid policy, so no policy action can be computed
      identicalPolicyAction: { num: 0, den: 0, value: null },
    });
    expect(r.consistencyPolicy.hash).toBe('pol1');
    expect(r.consistencyPolicy.error).toContain('pol1');
  });

  it('counts message volume per project', () => {
    const v = report().volume;
    expect(v.current).toEqual([
      { projectId: 'web', pingMessages: 1, pingFindings: 2, digestMessages: 2, digestFindings: 2, logFindings: 1 },
    ]);
    expect(v.afterBaseline[0]).toMatchObject({ digestMessages: 1, pingMessages: 0 });
    expect(v.selected[0]).toMatchObject({ pingMessages: 1, digestMessages: 2, logFindings: 0 });
    expect(v.perRefresh).toEqual([]);
  });

  it('leaves disabled projects out of the volume tables', () => {
    const { scanId } = insertProject(db, 'legacy', { enabled: false });
    const f = insertFinding(db, scanId, { projectId: 'legacy', packageName: 'next', action: 'ping' });
    insertDecision(db, f.id, 'pol1', 'cfg-a', 'ping');
    const v = report().volume;
    expect(v.current.map((r) => r.projectId)).toEqual(['web']);
    expect(v.selected.map((r) => r.projectId)).toEqual(['web']);
    // A labeled finding of a disabled project has no decision for another policy; it is not counted as fixable.
    insertLabel(db, f.id, 'ping');
    expect(report({ policy: 'pol2' }).missingDecisions).toEqual({ open: 3, closed: 1, disabled: 1 });
  });

  it('compares labelers on shared findings', () => {
    const r = report();
    expect(r.agreement).toHaveLength(1);
    expect(r.agreement[0]!.other).toBe('bob');
    expect(r.agreement[0]!.action.n).toBe(2);
    expect(r.agreement[0]!.action.agree.value).toBe(0.5);
    expect(r.agreement[0]!.affected).toEqual({ num: 2, den: 2, value: 1 });
    expect(report({ labeler: 'bob' }).rows).toHaveLength(3);
  });

  it('excludes everything from the LLM decider when the config is unknown', () => {
    const r = report({ config: 'nope' });
    expect(r.configFound).toBe(false);
    const llm = r.deciders.find((d) => d.name === 'llm')!;
    expect(llm.metrics.n).toBe(0);
    expect(llm.metrics.pingRecall.value).toBeNull();
    expect(llm.excludedNote).toContain('config not found');
  });
});

describe('consistency of the policy action', () => {
  let db: Db;
  let scanId: number;

  beforeEach(() => {
    db = openDb(':memory:');
    scanId = insertProject(db, 'web').scanId;
    insertConfig(db, 'cfg-a', true);
  });

  const cfg = () => db.select().from(triageConfigs).where(eq(triageConfigs.name, 'cfg-a')).get()!;

  it('puts each repeated run through the selected policy and scores identical policy actions', () => {
    const loaded = parsePolicy(POLICY_YAML);
    db.insert(policyVersions).values({ hash: loaded.hash, content: loaded.content }).run();
    // Different verdicts and suggested actions, but both lead to ping under the policy.
    const same = insertFinding(db, scanId, { priority: 'P1' });
    insertTriageRun(db, same.id, cfg(), { output: triageOutput({ verdict: 'affected', suggested_action: 'ping' }) });
    insertTriageRun(db, same.id, cfg(), { output: triageOutput({ verdict: 'likely_affected', suggested_action: 'digest' }) });
    // Same suggested action, but the verdict flips the policy action.
    const flips = insertFinding(db, scanId, { priority: 'P1' });
    insertTriageRun(db, flips.id, cfg(), { output: triageOutput({ verdict: 'affected', suggested_action: 'ping' }) });
    insertTriageRun(db, flips.id, cfg(), { output: triageOutput({ verdict: 'not_affected', suggested_action: 'ping' }) });
    // A single run is no repetition.
    const single = insertFinding(db, scanId, { priority: 'P1' });
    insertTriageRun(db, single.id, cfg());
    // Runs at another input hash are another group.
    insertTriageRun(db, single.id, cfg(), { inputHash: 'old', output: triageOutput({ verdict: 'not_affected' }) });

    const r = getEvalReport(db, { configName: 'cfg-a', policyHash: loaded.hash, labeler: 'me' }, { minPriority: 'P2' });
    expect(r.consistencyPolicy).toEqual({ hash: loaded.hash, error: null });
    expect(r.consistency).toEqual([
      expect.objectContaining({
        configName: 'cfg-a',
        groups: 2,
        runs: 4,
        identicalPolicyAction: { num: 1, den: 2, value: 0.5 },
        identicalVerdict: { num: 0, den: 2, value: 0 },
        identicalAction: { num: 1, den: 2, value: 0.5 },
      }),
    ]);
  });

  it('uses the policy file on disk when the selected hash is not stored yet', () => {
    const loaded = parsePolicy(POLICY_YAML);
    const f = insertFinding(db, scanId, { priority: 'P1' });
    insertTriageRun(db, f.id, cfg(), { output: triageOutput({ verdict: 'not_affected' }) });
    insertTriageRun(db, f.id, cfg(), { output: triageOutput({ verdict: 'likely_not_affected' }) });
    expect(loadSelectedPolicy(db, loaded.hash, null).error).toContain('not stored');
    const r = getEvalReport(
      db,
      { configName: 'cfg-a', policyHash: loaded.hash, labeler: 'me' },
      { minPriority: 'P2', currentPolicy: loaded },
    );
    expect(r.consistency[0]!.identicalPolicyAction).toEqual({ num: 1, den: 1, value: 1 });
    expect(loadSelectedPolicy(db, '', loaded).error).toBe('no policy version selected');
  });

  it('evaluates the selected stored version, not the file on disk, with its own thresholds', () => {
    const selected = parsePolicy(POLICY_YAML);
    db.insert(policyVersions).values({ hash: selected.hash, content: selected.content }).run();
    // The file on disk logs everything, so under it every group would be identical.
    const onDisk = parsePolicy(`
thresholds: { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9.0, cvss_high: 7.0 }
rules:
  - { id: default, when: {}, then: log }
`);
    // enrich stored P3, but its EPSS of 0.6 is P1 under the selected policy's thresholds (as decide computes it).
    const f = insertFinding(db, scanId, { priority: 'P3' });
    db.update(findings).set({ epss: 0.6, enrichedAt: '2026-11-01T00:00:00.000Z' }).where(eq(findings.id, f.id)).run();
    insertTriageRun(db, f.id, cfg(), { output: triageOutput({ verdict: 'affected', suggested_action: 'digest' }) });
    insertTriageRun(db, f.id, cfg(), { output: triageOutput({ verdict: 'not_affected', suggested_action: 'digest' }) });

    const report = (policyHash: string) =>
      getEvalReport(db, { configName: 'cfg-a', policyHash, labeler: 'me' }, { minPriority: 'P2', currentPolicy: onDisk });
    // P1: affected → ping, not_affected → digest. With the stored P3 both would fall through to log.
    expect(report(selected.hash).consistency[0]).toMatchObject({
      identicalPolicyAction: { num: 0, den: 1 },
      identicalAction: { num: 1, den: 1 },
    });
    expect(report(onDisk.hash).consistency[0]!.identicalPolicyAction).toEqual({ num: 1, den: 1, value: 1 });
  });
});

describe('volume per refresh', () => {
  let db: Db;
  let scanId: number;

  beforeEach(() => {
    db = openDb(':memory:');
    scanId = insertProject(db, 'web').scanId;
  });

  const changed = (findingId: number, jobRunId: number, from: string | null, to: string) =>
    insertEvent(db, findingId, 'decision_changed', '2026-11-01T00:00:00.000Z', { jobRunId, data: { from, to, ruleId: 'r' } });

  it('counts the findings each succeeded refresh decided or re-decided, as Inbox-style messages', () => {
    const next1 = insertFinding(db, scanId, { packageName: 'next', action: 'ping' });
    const next2 = insertFinding(db, scanId, { packageName: 'next', action: 'ping' });
    const zod = insertFinding(db, scanId, { packageName: 'zod', action: 'digest' });
    const lodash = insertFinding(db, scanId, { packageName: 'lodash', action: 'log' });
    const undecided = insertFinding(db, scanId, { packageName: 'qs', action: null });
    const legacyScan = insertProject(db, 'legacy', { enabled: false }).scanId;
    const legacy = insertFinding(db, legacyScan, { projectId: 'legacy', packageName: 'next', action: 'ping' });

    const a = insertJob(db, { type: 'refresh-all', status: 'succeeded', finishedAt: '2026-11-01T00:10:00.000Z' });
    const aScan = insertJob(db, { type: 'scan', parentId: a });
    const aDecide = insertJob(db, { type: 'decide', parentId: a });
    insertEvent(db, next1.id, 'created', '2026-11-01T00:01:00.000Z', { jobRunId: aScan });
    insertEvent(db, undecided.id, 'created', '2026-11-01T00:01:00.000Z', { jobRunId: aScan });
    changed(next1.id, aDecide, null, 'ping'); // a first decision
    changed(next2.id, aDecide, 'digest', 'ping');
    changed(zod.id, aDecide, 'log', 'digest');
    changed(lodash.id, aDecide, 'digest', 'log');
    changed(legacy.id, aDecide, null, 'ping'); // disabled project: left out

    // A failed refresh and a standalone decide never count.
    const failed = insertJob(db, { type: 'refresh-all', status: 'failed' });
    changed(zod.id, insertJob(db, { type: 'decide', parentId: failed }), 'digest', 'ping');
    changed(zod.id, insertJob(db, { type: 'decide' }), 'ping', 'digest');

    // A later refresh whose decide runs one level deeper.
    const c = insertJob(db, { type: 'refresh-all', status: 'succeeded', finishedAt: '2026-11-08T00:10:00.000Z' });
    const cStep = insertJob(db, { type: 'pipeline-step', parentId: c });
    changed(zod.id, insertJob(db, { type: 'decide', parentId: cStep }), 'digest', 'ping');

    const volumes = refreshVolumes(db);
    expect(volumes.map((v) => v.refresh.id)).toEqual([c, a]);
    const [later, first] = volumes;
    expect(later!.total).toEqual({ pingMessages: 1, pingFindings: 1, digestMessages: 0, digestFindings: 0, logFindings: 0 });
    expect(later!.newWithoutDecision).toBe(0);
    expect(first!.projects).toEqual([
      { projectId: 'web', pingMessages: 1, pingFindings: 2, digestMessages: 1, digestFindings: 1, logFindings: 1 },
    ]);
    expect(first!.total).toMatchObject({ pingMessages: 1, digestMessages: 1, logFindings: 1 });
    expect(first!.newWithoutDecision).toBe(1);

    expect(refreshVolumes(db, 1).map((v) => v.refresh.id)).toEqual([c]);
  });

  it('counts the first decisions and changes the decide job records under a refresh', () => {
    const policy = parsePolicy(POLICY_YAML);
    const config = insertConfig(db, 'cfg-a', true);
    const legacyScan = insertProject(db, 'legacy', { enabled: false }).scanId;
    const enrich = (id: number) =>
      db.update(findings).set({ epss: 0.6, enrichedAt: '2026-11-01T00:02:00.000Z' }).where(eq(findings.id, id)).run();
    const next1 = insertFinding(db, scanId, { packageName: 'next' });
    const next2 = insertFinding(db, scanId, { packageName: 'next' });
    const zod = insertFinding(db, scanId, { packageName: 'zod' });
    const legacy = insertFinding(db, legacyScan, { projectId: 'legacy', packageName: 'next' });
    const unenriched = insertFinding(db, scanId, { packageName: 'qs' });
    for (const f of [next1, next2, zod, legacy]) enrich(f.id);

    const first = insertJob(db, { type: 'refresh-all', status: 'succeeded', finishedAt: '2026-11-01T00:10:00.000Z' });
    const scan = insertJob(db, { type: 'scan', parentId: first });
    for (const f of [next1, next2, zod, legacy, unenriched])
      insertEvent(db, f.id, 'created', '2026-11-01T00:01:00.000Z', { jobRunId: scan });
    const stats = decideAll(db, { currentPolicy: policy, minPriority: 'P2', jobRunId: insertJob(db, { type: 'decide', parentId: first }) });
    expect(stats).toMatchObject({ firstDecisions: 3, digest: 3, unenriched: 1, disabledSkipped: 1 });

    // The next refresh: a triage says next1 is affected, so it now pings; the others are unchanged.
    insertTriageRun(db, next1.id, config, { output: triageOutput({ verdict: 'affected' }) });
    const second = insertJob(db, { type: 'refresh-all', status: 'succeeded', finishedAt: '2026-11-05T00:10:00.000Z' });
    decideAll(db, { currentPolicy: policy, minPriority: 'P2', jobRunId: insertJob(db, { type: 'decide', parentId: second }) });

    const [later, earlier] = refreshVolumes(db);
    expect(earlier!.refresh.id).toBe(first);
    // next (2 findings) and zod: two digest messages; the disabled project and the undecided finding send nothing.
    expect(earlier!.total).toEqual({ pingMessages: 0, pingFindings: 0, digestMessages: 2, digestFindings: 3, logFindings: 0 });
    expect(earlier!.projects.map((p) => p.projectId)).toEqual(['web']);
    expect(earlier!.newWithoutDecision).toBe(1);
    expect(later!.refresh.id).toBe(second);
    expect(later!.total).toEqual({ pingMessages: 1, pingFindings: 1, digestMessages: 0, digestFindings: 0, logFindings: 0 });
  });
});
