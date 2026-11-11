import { asc, eq } from 'drizzle-orm';
import { beforeEach, describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { sha256, type LoadedPolicy } from '../config/load';
import { PolicySchema } from '../config/schema';
import { openDb, type Db } from '../db/client';
import { advisories, decisions, events, findings, policyVersions, projects, triageConfigs, triageRuns } from '../db/schema';
import { findingInputHash } from '../triage/state';
import { ProjectProfileSchema, type Priority, type TriageOutput, type Verdict } from '../types';
import { decideAll } from './decide';

const THRESHOLDS = 'thresholds: { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9, cvss_high: 7 }';

/** Schema-parsed only (no load-time validatePolicyFields), so decideAll's own guard can be tested. */
function policy(rules: string, thresholds = THRESHOLDS): LoadedPolicy {
  const content = `${thresholds}\nrules:\n${rules}`;
  return { policy: PolicySchema.parse(parseYaml(content)), content, hash: sha256(content).slice(0, 12) };
}

const RULES_A = `
  - { id: malicious, when: { malicious: true }, then: ping }
  - { id: no-verdict-urgent, when: { priority: [P0, P1], triage_status: [pending, failed] }, then: ping }
  - { id: affected, when: { verdict: [affected, likely_affected] }, then: digest }
  - { id: default, when: {}, then: log }`;
const POLICY_A = policy(RULES_A);
// Same rules as A with a much lower EPSS bar: an EPSS of 0.05 is P1 here, P3 under A.
const POLICY_A_LOW_EPSS = policy(RULES_A, 'thresholds: { epss_high: 0.04, epss_medium: 0.01, cvss_critical: 9, cvss_high: 7 }');

// Same as A, except affected findings now ping.
const POLICY_B = policy(`
  - { id: malicious, when: { malicious: true }, then: ping }
  - { id: no-verdict-urgent, when: { priority: [P0, P1], triage_status: [pending, failed] }, then: ping }
  - { id: affected-ping, when: { verdict: [affected, likely_affected] }, then: ping }
  - { id: default, when: {}, then: log }`);

const ACTIVE = 'cfg-active';
const OTHER = 'cfg-other';
const NOW = '2026-11-10T12:00:00.000Z';
const LATER = '2026-11-10T13:00:00.000Z';

function triageOutput(verdict: Verdict): TriageOutput {
  return {
    verdict,
    confidence: 'high',
    runtime_usage: 'server',
    vulnerable_code_used: 'yes',
    attacker_reachable: 'unknown',
    deployment_conditions_met: 'unknown',
    summary: 'synthetic',
    evidence: [],
    exploit_conditions: '',
    remediation: '',
    workaround: null,
    suggested_action: 'digest',
    suggested_action_reason: '',
  };
}

let db: Db;
const scanId = 1;

/** Stored signals that give each priority under THRESHOLDS for the internet-facing, high-criticality project. */
const SIGNALS: Record<Priority, { inKev?: boolean; epss?: number; cvssScore?: number }> = {
  P0: { inKev: true },
  P1: { epss: 0.6 },
  P2: { cvssScore: 7.5 },
  P3: {},
};

/** A finding as `enrich` left it (signals and enrichedAt), or un-enriched when `priority` is null. */
function addFinding(osvId: string, priority: Priority | null, status: 'open' | 'fixed' = 'open', projectId = 'web'): number {
  return db
    .insert(findings)
    .values({
      projectId,
      lockfile: 'package-lock.json',
      ecosystem: 'npm',
      packageName: `pkg-${osvId}`,
      osvId,
      installedVersions: ['1.0.0'],
      fixedVersions: ['1.0.1'],
      direct: true,
      status,
      origin: 'baseline',
      firstSeenScanId: scanId,
      lastSeenScanId: scanId,
      priority,
      ...(priority ? { ...SIGNALS[priority], enrichedAt: NOW } : {}),
    })
    .returning({ id: findings.id })
    .get().id;
}

function addRun(findingId: number, configName: string, status: 'ok' | 'failed', verdict?: Verdict): number {
  const finding = db.select().from(findings).where(eq(findings.id, findingId)).get()!;
  const config = db.select().from(triageConfigs).where(eq(triageConfigs.name, configName)).get()!;
  return db
    .insert(triageRuns)
    .values({
      findingId,
      configName,
      inputHash: findingInputHash(db, finding, config),
      status,
      output: verdict ? triageOutput(verdict) : null,
      prompt: 'synthetic prompt',
    })
    .returning({ id: triageRuns.id })
    .get().id;
}

/** What `enrich` writes: signals, priority and enrichedAt. */
function enrich(id: number, signals: { priority: Priority; epss?: number | null; cvssScore?: number | null; inKev?: boolean }) {
  db.update(findings)
    .set({ epss: null, cvssScore: null, inKev: false, ...signals, enrichedAt: NOW })
    .where(eq(findings.id, id))
    .run();
}

function findingRow(id: number) {
  return db.select().from(findings).where(eq(findings.id, id)).get()!;
}

function decisionRows(policyHash: string, configName = ACTIVE) {
  return db
    .select()
    .from(decisions)
    .where(eq(decisions.policyHash, policyHash))
    .orderBy(asc(decisions.findingId))
    .all()
    .filter((d) => d.configName === configName);
}

function changeEvents() {
  return db.select().from(events).where(eq(events.type, 'decision_changed')).orderBy(asc(events.id)).all();
}

/** decision_changed events for a change of an existing current action (not a first decision). */
function realChanges() {
  return changeEvents().filter((e) => e.data?.from !== null);
}

const base = { currentPolicy: POLICY_A, minPriority: 'P2' as Priority, jobRunId: 42, now: NOW };

let ids: { affected: number; pending: number; malicious: number; p3: number; failed: number; fixed: number };
let okRunId: number;
let failedRunId: number;

beforeEach(() => {
  db = openDb(':memory:');
  const profile = ProjectProfileSchema.parse({
    id: 'web',
    name: 'Web',
    repo_path: '/nonexistent',
    criticality: 'high',
    exposure: 'internet-facing',
  });
  db.insert(projects).values({ id: 'web', name: 'Web', repoPath: '/nonexistent', ref: 'origin/main', profile, profileHash: 'h1' }).run();
  db.insert(triageConfigs)
    .values([
      { name: ACTIVE, promptVersion: 'v1', model: 'opus', effort: 'high', codeAccess: true, active: true },
      { name: OTHER, promptVersion: 'v1', model: 'haiku', effort: 'high', codeAccess: true, active: false },
    ])
    .run();
  db.insert(advisories)
    .values([
      { osvId: 'GHSA-1', modified: '2026-01-01T00:00:00Z', raw: {} },
      { osvId: 'MAL-2026-1', modified: '2026-01-01T00:00:00Z', malicious: true, raw: {} },
    ])
    .run();
  db.insert(policyVersions).values({ hash: POLICY_A.hash, content: POLICY_A.content }).run();

  ids = {
    affected: addFinding('GHSA-1', 'P1'),
    pending: addFinding('GHSA-2', 'P1'),
    malicious: addFinding('MAL-2026-1', 'P0'),
    p3: addFinding('GHSA-3', 'P3'),
    failed: addFinding('GHSA-4', 'P0'),
    fixed: addFinding('GHSA-5', 'P1', 'fixed'),
  };
  okRunId = addRun(ids.affected, ACTIVE, 'ok', 'affected');
  failedRunId = addRun(ids.failed, ACTIVE, 'failed');
});

describe('decideAll', () => {
  it('decides every open finding and sets its current decision', () => {
    const stats = decideAll(db, base);

    expect(stats).toEqual({
      policyHash: POLICY_A.hash,
      config: ACTIVE,
      current: true,
      evaluated: 5,
      ping: 3,
      digest: 1,
      log: 1,
      changed: 0,
      firstDecisions: 5,
      unenriched: 0,
      disabledSkipped: 0,
      reprioritized: 0,
      rules: { affected: 1, 'no-verdict-urgent': 2, malicious: 1, default: 1 },
    });

    const expected: Record<number, [string, string, number | null]> = {
      [ids.affected]: ['digest', 'affected', okRunId],
      [ids.pending]: ['ping', 'no-verdict-urgent', null],
      [ids.malicious]: ['ping', 'malicious', null],
      [ids.p3]: ['log', 'default', null],
      [ids.failed]: ['ping', 'no-verdict-urgent', failedRunId],
    };
    const rows = decisionRows(POLICY_A.hash);
    expect(rows).toHaveLength(5);
    for (const row of rows) {
      const [action, ruleId, runId] = expected[row.findingId]!;
      expect({ action: row.action, ruleId: row.ruleId, triageRunId: row.triageRunId, decidedAt: row.decidedAt }).toEqual({
        action,
        ruleId,
        triageRunId: runId,
        decidedAt: NOW,
      });
      const f = findingRow(row.findingId);
      expect({ a: f.currentAction, r: f.currentRuleId, t: f.activeTriageRunId, d: f.decidedAt }).toEqual({
        a: action,
        r: ruleId,
        t: runId,
        d: NOW,
      });
    }

    expect(rows.find((r) => r.findingId === ids.affected)!.inputs).toMatchObject({
      priority: 'P1',
      triage_status: 'ok',
      verdict: 'affected',
      exposure: 'internet-facing',
      fix_available: true,
    });
    expect(rows.find((r) => r.findingId === ids.p3)!.inputs.triage_status).toBe('skipped');

    // Closed findings are left alone. A first decision is an event (from: null), so new findings reach the
    // Inbox's 'since last refresh' view.
    expect(findingRow(ids.fixed).currentAction).toBeNull();
    expect(changeEvents().map((e) => [e.findingId, e.jobRunId, e.at, e.data])).toEqual(
      rows.map((r) => [r.findingId, 42, NOW, { from: null, to: r.action, ruleId: r.ruleId, policyHash: POLICY_A.hash }]),
    );
    expect(realChanges()).toHaveLength(0);
  });

  it('upserts on re-run: one decision per finding/policy/config, no events when nothing changed', () => {
    decideAll(db, base);
    const stats = decideAll(db, { ...base, now: LATER });

    expect(stats).toMatchObject({ changed: 0, firstDecisions: 0 });
    const rows = decisionRows(POLICY_A.hash);
    expect(rows).toHaveLength(5);
    expect(rows.every((r) => r.decidedAt === LATER)).toBe(true);
    // Only the first run's first-decision events.
    expect(changeEvents()).toHaveLength(5);
    expect(changeEvents().every((e) => e.at === NOW)).toBe(true);
  });

  it('writes decision_changed only for findings whose action actually changed', () => {
    decideAll(db, base);
    // Triage arrives for the pending P1: not affected → falls through to the default rule.
    const runId = addRun(ids.pending, ACTIVE, 'ok', 'not_affected');
    const stats = decideAll(db, { ...base, now: LATER, jobRunId: 43 });

    expect(stats).toMatchObject({ changed: 1, firstDecisions: 0 });
    const evs = realChanges();
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({
      findingId: ids.pending,
      jobRunId: 43,
      at: LATER,
      data: { from: 'ping', to: 'log', ruleId: 'default', fromRuleId: 'no-verdict-urgent', policyHash: POLICY_A.hash },
    });
    expect(findingRow(ids.pending)).toMatchObject({ currentAction: 'log', currentRuleId: 'default', activeTriageRunId: runId });
    expect(decisionRows(POLICY_A.hash).find((r) => r.findingId === ids.pending)).toMatchObject({ action: 'log', triageRunId: runId });
  });

  it('clears the triage run reference when that run no longer applies', () => {
    decideAll(db, base);
    expect(findingRow(ids.affected).activeTriageRunId).toBe(okRunId);
    // An upgrade changes the input hash, so the ok run is stale and the P1 is pending again.
    db.update(findings)
      .set({ installedVersions: ['1.0.2'] })
      .where(eq(findings.id, ids.affected))
      .run();
    const stats = decideAll(db, { ...base, now: LATER });

    expect(stats.changed).toBe(1);
    expect(findingRow(ids.affected)).toMatchObject({ currentAction: 'ping', currentRuleId: 'no-verdict-urgent', activeTriageRunId: null });
    expect(decisionRows(POLICY_A.hash).find((r) => r.findingId === ids.affected)).toMatchObject({
      action: 'ping',
      triageRunId: null,
      decidedAt: LATER,
    });
    expect(realChanges()[0]!.data).toMatchObject({ from: 'digest', to: 'ping', ruleId: 'no-verdict-urgent' });
  });

  it("re-prioritizes from stored signals with the policy's thresholds when a threshold is edited", () => {
    const id = addFinding('GHSA-6', null);
    enrich(id, { priority: 'P3', epss: 0.05 });
    decideAll(db, base);
    expect(findingRow(id)).toMatchObject({ currentAction: 'log', currentRuleId: 'default' });
    expect(decisionRows(POLICY_A.hash).find((r) => r.findingId === id)!.inputs).toMatchObject({ priority: 'P3', triage_status: 'skipped' });

    // policy.yaml edited (lower EPSS bar), then Re-evaluate: no enrich in between.
    const stats = decideAll(db, { ...base, currentPolicy: POLICY_A_LOW_EPSS, now: LATER });

    expect(stats).toMatchObject({ current: true, changed: 1, reprioritized: 1 });
    // Now P1, so it is due for triage (pending, not skipped) and fails loud.
    expect(decisionRows(POLICY_A_LOW_EPSS.hash).find((r) => r.findingId === id)).toMatchObject({
      action: 'ping',
      ruleId: 'no-verdict-urgent',
      inputs: expect.objectContaining({ priority: 'P1', triage_status: 'pending', epss: 0.05 }),
    });
    expect(findingRow(id)).toMatchObject({ currentAction: 'ping', currentRuleId: 'no-verdict-urgent' });
    expect(realChanges().map((e) => [e.findingId, e.data])).toEqual([
      [id, { from: 'log', to: 'ping', ruleId: 'no-verdict-urgent', fromRuleId: 'default', policyHash: POLICY_A_LOW_EPSS.hash }],
    ]);
    // findings.priority stays enrich's to write.
    expect(findingRow(id).priority).toBe('P3');
  });

  it('evaluates a stored policy version with its own thresholds, leaving findings alone', () => {
    const id = addFinding('GHSA-6', null);
    enrich(id, { priority: 'P3', epss: 0.05 });
    decideAll(db, base);
    db.insert(policyVersions).values({ hash: POLICY_A_LOW_EPSS.hash, content: POLICY_A_LOW_EPSS.content }).run();

    const stats = decideAll(db, { ...base, policyHash: POLICY_A_LOW_EPSS.hash, now: LATER });

    expect(stats).toMatchObject({ current: false, changed: 0, reprioritized: 1 });
    expect(decisionRows(POLICY_A_LOW_EPSS.hash).find((r) => r.findingId === id)).toMatchObject({ action: 'ping' });
    expect(decisionRows(POLICY_A.hash).find((r) => r.findingId === id)).toMatchObject({ action: 'log' });
    expect(findingRow(id)).toMatchObject({ priority: 'P3', currentAction: 'log', decidedAt: NOW });
  });

  it('ignores a triage run made for stale inputs', () => {
    // The ok run was made for version 1.0.0; after an upgrade to 1.0.2 its input hash no longer matches.
    db.update(findings)
      .set({ installedVersions: ['1.0.2'] })
      .where(eq(findings.id, ids.affected))
      .run();
    decideAll(db, base);
    expect(findingRow(ids.affected)).toMatchObject({ currentAction: 'ping', currentRuleId: 'no-verdict-urgent', activeTriageRunId: null });
  });

  it('a new current policy re-decides findings and records the change', () => {
    decideAll(db, base);
    const stats = decideAll(db, { ...base, currentPolicy: POLICY_B, now: LATER });

    expect(stats).toMatchObject({ policyHash: POLICY_B.hash, current: true, changed: 1 });
    expect(findingRow(ids.affected)).toMatchObject({ currentAction: 'ping', currentRuleId: 'affected-ping' });
    expect(realChanges()[0]!.data).toMatchObject({ from: 'digest', to: 'ping', ruleId: 'affected-ping', policyHash: POLICY_B.hash });
    // The old version's decisions stay for comparison on the Eval page.
    expect(decisionRows(POLICY_A.hash)).toHaveLength(5);
    expect(decisionRows(POLICY_B.hash)).toHaveLength(5);
    // B was never synced; decide stores it so its decisions resolve to content.
    expect(db.select().from(policyVersions).where(eq(policyVersions.hash, POLICY_B.hash)).get()?.content).toBe(POLICY_B.content);
  });

  it('evaluating a stored, non-current policy version writes decisions but leaves findings alone', () => {
    decideAll(db, base);
    db.insert(policyVersions).values({ hash: POLICY_B.hash, content: POLICY_B.content }).run();
    const before = findingRow(ids.affected);

    const stats = decideAll(db, { ...base, policyHash: POLICY_B.hash, now: LATER });

    expect(stats).toMatchObject({ policyHash: POLICY_B.hash, config: ACTIVE, current: false, evaluated: 5, changed: 0, firstDecisions: 0 });
    expect(decisionRows(POLICY_B.hash).find((r) => r.findingId === ids.affected)).toMatchObject({
      action: 'ping',
      ruleId: 'affected-ping',
    });
    expect(findingRow(ids.affected)).toEqual(before);
    expect(realChanges()).toHaveLength(0);
    expect(changeEvents().filter((e) => e.at === LATER)).toHaveLength(0);
  });

  it('passing the current hash explicitly is the same as the current file', () => {
    const stats = decideAll(db, { ...base, policyHash: POLICY_A.hash });
    expect(stats.current).toBe(true);
    expect(findingRow(ids.affected).currentAction).toBe('digest');
  });

  it('evaluating a non-active triage config uses its own runs and leaves findings alone', () => {
    decideAll(db, base);
    addRun(ids.pending, OTHER, 'ok', 'affected');

    const stats = decideAll(db, { ...base, configName: OTHER, now: LATER });

    expect(stats).toMatchObject({ config: OTHER, current: false, changed: 0 });
    const rows = decisionRows(POLICY_A.hash, OTHER);
    expect(rows).toHaveLength(5);
    // No run under OTHER for `affected` → pending P1 → ping; the OTHER run for `pending` → digest.
    expect(rows.find((r) => r.findingId === ids.affected)).toMatchObject({ action: 'ping', ruleId: 'no-verdict-urgent' });
    expect(rows.find((r) => r.findingId === ids.pending)).toMatchObject({ action: 'digest', ruleId: 'affected' });
    expect(findingRow(ids.pending)).toMatchObject({ currentAction: 'ping', decidedAt: NOW });
  });

  it('fails clearly on an unknown policy version or triage config', () => {
    expect(() => decideAll(db, { ...base, policyHash: 'deadbeef0000' })).toThrow(/policy version "deadbeef0000" not found/);
    expect(() => decideAll(db, { ...base, configName: 'nope' })).toThrow(/triage config "nope" not found/);
  });

  it('refuses to evaluate a policy with a typo, before writing anything', () => {
    const typo = policy(`
  - { id: a, when: { verdict: afected }, then: ping }
  - { id: default, when: {}, then: log }`);
    expect(() => decideAll(db, { ...base, currentPolicy: typo })).toThrow(/afected/);
    expect(db.select().from(decisions).all()).toHaveLength(0);
  });

  it('leaves un-enriched findings undecided (no decision row, no event) and decides them once enriched', () => {
    const fresh = addFinding('GHSA-new', null); // the scan created it; enrich has not run since
    const freshMal = addFinding('MAL-2026-2', null); // malicious (MAL- prefix, no advisory row yet) needs no signals

    const stats = decideAll(db, base);

    expect(stats).toMatchObject({ evaluated: 6, unenriched: 1, firstDecisions: 6 });
    expect(findingRow(fresh)).toMatchObject({ currentAction: null, currentRuleId: null, decidedAt: null });
    expect(decisionRows(POLICY_A.hash).some((r) => r.findingId === fresh)).toBe(false);
    expect(changeEvents().some((e) => e.findingId === fresh)).toBe(false);
    expect(findingRow(freshMal)).toMatchObject({ currentAction: 'ping', currentRuleId: 'malicious' });

    enrich(fresh, { priority: 'P1', epss: 0.6 });
    const again = decideAll(db, { ...base, now: LATER, jobRunId: 43 });

    expect(again).toMatchObject({ unenriched: 0, firstDecisions: 1, changed: 0 });
    expect(findingRow(fresh)).toMatchObject({ currentAction: 'ping', currentRuleId: 'no-verdict-urgent' });
    expect(changeEvents().filter((e) => e.findingId === fresh)).toEqual([
      expect.objectContaining({
        jobRunId: 43,
        at: LATER,
        data: { from: null, to: 'ping', ruleId: 'no-verdict-urgent', policyHash: POLICY_A.hash },
      }),
    ]);
  });

  it('does not evaluate findings of disabled projects and clears their current decision without an event', () => {
    const profile = ProjectProfileSchema.parse({
      id: 'off',
      name: 'Off',
      repo_path: '/nonexistent',
      criticality: 'high',
      exposure: 'internet-facing',
    });
    db.insert(projects).values({ id: 'off', name: 'Off', repoPath: '/nonexistent', ref: 'origin/main', profile, profileHash: 'h2' }).run();
    const off = addFinding('GHSA-off', 'P0', 'open', 'off');
    decideAll(db, base);
    expect(findingRow(off)).toMatchObject({ currentAction: 'ping', currentRuleId: 'no-verdict-urgent' });
    const eventsBefore = changeEvents().length;

    db.update(projects).set({ enabled: false }).where(eq(projects.id, 'off')).run();
    const stats = decideAll(db, { ...base, now: LATER });

    expect(stats).toMatchObject({ evaluated: 5, disabledSkipped: 1, changed: 0, firstDecisions: 0 });
    expect(findingRow(off)).toMatchObject({ currentAction: null, currentRuleId: null, activeTriageRunId: null, decidedAt: null });
    expect(changeEvents()).toHaveLength(eventsBefore);
    // The decision made while the project was enabled is not refreshed.
    expect(decisionRows(POLICY_A.hash).find((r) => r.findingId === off)!.decidedAt).toBe(NOW);

    // Enabled again: decided afresh, as a first decision.
    db.update(projects).set({ enabled: true }).where(eq(projects.id, 'off')).run();
    const back = decideAll(db, { ...base, now: LATER });
    expect(back).toMatchObject({ disabledSkipped: 0, firstDecisions: 1 });
    expect(changeEvents().at(-1)).toMatchObject({ findingId: off, data: { from: null, to: 'ping' } });
  });

  it('an evaluation (not current) skips disabled and un-enriched findings without touching any finding', () => {
    const fresh = addFinding('GHSA-new', null);
    decideAll(db, base);
    db.insert(policyVersions).values({ hash: POLICY_B.hash, content: POLICY_B.content }).run();
    db.update(projects).set({ enabled: false }).where(eq(projects.id, 'web')).run();
    const before = db.select().from(findings).orderBy(asc(findings.id)).all();

    const stats = decideAll(db, { ...base, policyHash: POLICY_B.hash, now: LATER });

    expect(stats).toMatchObject({ current: false, evaluated: 0, disabledSkipped: 6, unenriched: 0 });
    expect(decisionRows(POLICY_B.hash)).toHaveLength(0);
    expect(db.select().from(findings).orderBy(asc(findings.id)).all()).toEqual(before);
    expect(findingRow(fresh).currentAction).toBeNull();
  });

  it('decides a large batch quickly', () => {
    const priorities: Priority[] = ['P0', 'P1', 'P2', 'P3'];
    for (let i = 0; i < 1500; i++) addFinding(`GHSA-bulk-${i}`, priorities[i % 4]!);
    const t0 = performance.now();
    const stats = decideAll(db, base);
    const ms = performance.now() - t0;
    expect(stats.evaluated).toBe(1505);
    expect(ms).toBeLessThan(5000);
  });
});
