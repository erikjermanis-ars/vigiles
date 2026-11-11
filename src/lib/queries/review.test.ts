import { eq } from 'drizzle-orm';
import { beforeAll, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { advisories, findings, labels, projects, scans, triageRuns } from '../db/schema';
import type { ProjectProfile, TriageOutput } from '../types';
import { LABELER } from './findings';
import { compareLabel, getReviewItem, getReviewQueue, pickReviewTarget, reviewNeighbors, toBlindEvidence, type ReviewQueue } from './review';

const profile: ProjectProfile = {
  id: 'web',
  name: 'Web',
  enabled: true,
  repo_path: '/nonexistent/web',
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
  mitigations: 'Behind login',
  notes: 'shadcn is a CLI',
};

const output = (over: Partial<TriageOutput> = {}): TriageOutput => ({
  verdict: 'likely_not_affected',
  confidence: 'medium',
  runtime_usage: 'build_or_tooling_only',
  vulnerable_code_used: 'no',
  attacker_reachable: 'no',
  deployment_conditions_met: 'unknown',
  summary: 'Only the CLI pulls this in.',
  evidence: [{ file: 'package.json', line: 12, note: 'shadcn in dependencies' }],
  exploit_conditions: 'Local attacker',
  remediation: 'Upgrade shadcn',
  workaround: 'Remove shadcn from dependencies',
  suggested_action: 'log',
  suggested_action_reason: 'CLI only.',
  ...over,
});

type NewFinding = typeof findings.$inferInsert;
const f = (over: Partial<NewFinding> & Pick<NewFinding, 'id' | 'packageName'>): NewFinding => ({
  projectId: 'web',
  lockfile: 'package-lock.json',
  ecosystem: 'npm',
  osvId: `GHSA-${over.id}`,
  origin: 'baseline',
  firstSeenScanId: 1,
  lastSeenScanId: 1,
  ...over,
});

/**
 * Review order of open P0–P2: 10 (P0), 11 (P1), 12 (P2 epss .3), 13 (P2 epss .1, labeled by me),
 * 14 (P2 no epss, cvss 9 via advisory), 15 (P2 no epss, cvss 5). Excluded: 16 (P3), 17 (fixed), 18 (no priority).
 */
function seed(db: Db) {
  db.insert(projects).values({ id: 'web', name: 'Web', repoPath: '/x', ref: 'origin/main', profile, profileHash: 'h' }).run();
  db.insert(scans).values({ id: 1, projectId: 'web', ref: 'origin/main', commitSha: 'c'.repeat(40), status: 'succeeded' }).run();
  db.insert(advisories)
    .values([
      { osvId: 'GHSA-11', cves: ['CVE-2026-1111'], aliases: ['CVE-2026-1111'], summary: 'Bad thing', details: 'Details **here**', raw: {} },
      { osvId: 'GHSA-14', cvssScore: 9, raw: {} },
    ])
    .run();
  db.insert(findings)
    .values([
      f({ id: 15, packageName: 'e', priority: 'P2', cvssScore: 5 }),
      f({ id: 14, packageName: 'd', priority: 'P2' }),
      f({ id: 13, packageName: 'c', priority: 'P2', epss: 0.1 }),
      f({ id: 12, packageName: 'b', priority: 'P2', epss: 0.3, activeTriageRunId: null }),
      f({ id: 11, packageName: 'a', priority: 'P1', epss: 0.01, currentAction: 'digest', currentRuleId: 'p1-not-affected', activeTriageRunId: 2, priorityReasons: ['kev'] }),
      f({ id: 10, packageName: 'mal', priority: 'P0', currentAction: 'ping', currentRuleId: 'malicious' }),
      f({ id: 16, packageName: 'p3', priority: 'P3' }),
      f({ id: 17, packageName: 'gone', priority: 'P0', status: 'fixed' }),
      f({ id: 18, packageName: 'new', priority: null }),
    ])
    .run();
  db.insert(triageRuns)
    .values([
      { id: 1, findingId: 11, configName: 'active', inputHash: 'old', status: 'ok', output: output({ summary: 'older run' }), prompt: 'p' },
      { id: 2, findingId: 11, configName: 'active', inputHash: 'cur', status: 'ok', output: output(), prompt: 'p' },
      { id: 3, findingId: 12, configName: 'other', inputHash: 'x', status: 'ok', output: output({ summary: 'other config' }), prompt: 'p' },
      { id: 4, findingId: 12, configName: 'active', inputHash: 'x', status: 'ok', output: output({ summary: 'fallback run', verdict: 'affected', suggested_action: 'digest' }), prompt: 'p' },
      { id: 5, findingId: 12, configName: 'active', inputHash: 'y', status: 'failed', prompt: 'p' },
    ])
    .run();
  db.insert(labels)
    .values([
      { findingId: 13, labeler: LABELER, expectedAction: 'digest', affectedTruth: 'yes' },
      { findingId: 14, labeler: 'other', expectedAction: 'ping' },
    ])
    .run();
}

let db: Db;
let queue: ReviewQueue;
beforeAll(() => {
  db = openDb(':memory:');
  seed(db);
  queue = getReviewQueue(db);
});

describe('getReviewQueue', () => {
  it('orders open P0–P2 findings by priority, then EPSS, then CVSS', () => {
    expect(queue.order).toEqual([10, 11, 12, 13, 14, 15]);
  });

  it('excludes findings labeled by me, but not by other labelers', () => {
    expect(queue.unlabeled).toEqual([10, 11, 12, 14, 15]);
    expect(queue).toMatchObject({ total: 6, labeled: 1 });
    expect(getReviewQueue(db, 'other').unlabeled).toEqual([10, 11, 12, 13, 15]);
    expect(getReviewQueue(db, 'other')).toMatchObject({ total: 6, labeled: 1 });
  });

  it('leaves out findings of disabled projects', () => {
    const local = openDb(':memory:');
    seed(local);
    local.insert(projects).values({ id: 'old', name: 'Old', enabled: false, repoPath: '/y', ref: 'origin/main', profile: { ...profile, id: 'old', enabled: false }, profileHash: 'o' }).run();
    local.insert(findings).values(f({ id: 19, projectId: 'old', packageName: 'stale', priority: 'P0' })).run();
    expect(getReviewQueue(local).order).toEqual([10, 11, 12, 13, 14, 15]);
    // Still reachable by id (e.g. from the Finding page), marked as disabled.
    expect(getReviewItem(local, 19, { activeConfig: 'active' })!.project).toMatchObject({ name: 'Old', enabled: false });
    local.update(projects).set({ enabled: true }).where(eq(projects.id, 'old')).run();
    expect(getReviewQueue(local).order).toEqual([10, 19, 11, 12, 13, 14, 15]);
  });
});

describe('navigation', () => {
  it('picks the requested finding, else the first unlabeled one', () => {
    expect(pickReviewTarget(queue, null)).toBe(10);
    expect(pickReviewTarget(queue, 13)).toBe(13);
    expect(pickReviewTarget({ order: [1], unlabeled: [], total: 1, labeled: 1 }, null)).toBeNull();
  });

  it('moves to the next unlabeled finding (wrapping) and the previous one in order', () => {
    expect(reviewNeighbors(queue, 10)).toEqual({ next: 11, prev: null });
    expect(reviewNeighbors(queue, 12)).toEqual({ next: 14, prev: 11 }); // skips labeled 13
    expect(reviewNeighbors(queue, 13)).toEqual({ next: 14, prev: 12 }); // after labeling 13
    expect(reviewNeighbors(queue, 15)).toEqual({ next: 10, prev: 14 }); // wraps to skipped ones
    expect(reviewNeighbors(queue, 16)).toEqual({ next: 10, prev: null }); // outside the queue
  });

  it('has no next when the current finding is the only unlabeled one', () => {
    const q: ReviewQueue = { order: [1, 2], unlabeled: [2], total: 2, labeled: 1 };
    expect(reviewNeighbors(q, 2)).toEqual({ next: null, prev: 1 });
    expect(reviewNeighbors(q, 1)).toEqual({ next: 2, prev: null });
  });
});

describe('getReviewItem', () => {
  it('returns null for an unknown finding', () => {
    expect(getReviewItem(db, 999, { activeConfig: 'active' })).toBeNull();
  });

  it('carries the per-version facts and the uncapped import-site count', () => {
    const local = openDb(':memory:');
    seed(local);
    const instances = [
      { version: '1.0.0', direct: true, devOnly: false, paths: [['a']] },
      { version: '0.9.0', direct: false, devOnly: true, paths: [['storybook', 'a']] },
    ];
    local.update(findings).set({ instances, importSiteCount: 57, installedVersions: ['0.9.0', '1.0.0'] }).where(eq(findings.id, 11)).run();
    const item = getReviewItem(local, 11, { activeConfig: 'active' })!;
    expect(item.finding).toMatchObject({ instances, importSiteCount: 57 });
    expect(item.project).toMatchObject({ enabled: true });
  });

  it('reads the given labeler\'s label for the reveal', () => {
    expect(getReviewItem(db, 14, { activeConfig: 'active' })!.label).toBeNull();
    const other = getReviewItem(db, 14, { activeConfig: 'active', labeler: 'other' })!;
    expect(other.label).toMatchObject({ labeler: 'other', expectedAction: 'ping' });
    expect(other.reveal).not.toBeNull();
  });

  it('shows facts and evidence but hides the verdict, suggestion and decision before labeling', () => {
    const item = getReviewItem(db, 11, { activeConfig: 'active' })!;
    expect(item.label).toBeNull();
    expect(item.reveal).toBeNull();
    expect(item.finding).toMatchObject({ packageName: 'a', priority: 'P1', priorityReasons: ['kev'] });
    expect(item.advisory).toMatchObject({ summary: 'Bad thing', cves: ['CVE-2026-1111'] });
    expect(item.project).toMatchObject({ exposure: 'internet-facing', notes: 'shadcn is a CLI' });
    expect(item.evidence).toMatchObject({ runId: 2, summary: 'Only the CLI pulls this in.', runtime_usage: 'build_or_tooling_only', workaround: 'Remove shadcn from dependencies' });

    const payload = JSON.stringify(item);
    for (const hidden of ['"verdict"', '"confidence"', 'suggested_action', 'currentAction', 'currentRuleId', 'p1-not-affected', 'likely_not_affected', 'CLI only.']) {
      expect(payload).not.toContain(hidden);
    }
  });

  it('copies only blind fields from a triage output', () => {
    expect(Object.keys(toBlindEvidence({ id: 1, configName: 'c', createdAt: 't' }, output())).sort()).toEqual(
      [
        'attacker_reachable',
        'configName',
        'createdAt',
        'deployment_conditions_met',
        'evidence',
        'exploit_conditions',
        'isDecisionRun',
        'remediation',
        'runId',
        'runtime_usage',
        'summary',
        'vulnerable_code_used',
        'workaround',
      ].sort(),
    );
  });

  it('falls back to the newest ok run of the active config when no decision run is set', () => {
    const item = getReviewItem(db, 12, { activeConfig: 'active' })!;
    expect(item.evidence).toMatchObject({ runId: 4, configName: 'active', summary: 'fallback run', isDecisionRun: false });
    expect(getReviewItem(db, 11, { activeConfig: 'active' })!.evidence).toMatchObject({ runId: 2, isDecisionRun: true });
    expect(getReviewItem(db, 15, { activeConfig: 'active' })!.evidence).toBeNull();
  });

  it('falls back too when the decision kept a failed run (the policy saw no verdict)', () => {
    const local = openDb(':memory:');
    seed(local);
    local.update(findings).set({ activeTriageRunId: 5 }).where(eq(findings.id, 12)).run(); // run 5 failed
    const blind = getReviewItem(local, 12, { activeConfig: 'active' })!;
    expect(blind.evidence).toMatchObject({ runId: 4, summary: 'fallback run', isDecisionRun: false });
    expect(JSON.stringify(blind)).not.toContain('"verdict"');

    local.insert(labels).values({ findingId: 12, labeler: LABELER, expectedAction: 'digest' }).run();
    expect(getReviewItem(local, 12, { activeConfig: 'active' })!.reveal).toMatchObject({ verdict: 'affected', suggestedAction: 'digest' });
  });

  it('reveals the decision once labeled', () => {
    upsert(11, 'ping', 'no');
    const item = getReviewItem(db, 11, { activeConfig: 'active' })!;
    expect(item.label).toMatchObject({ expectedAction: 'ping', affectedTruth: 'no' });
    expect(item.reveal).toEqual({
      policyAction: 'digest',
      ruleId: 'p1-not-affected',
      verdict: 'likely_not_affected',
      confidence: 'medium',
      suggestedAction: 'log',
      suggestedActionReason: 'CLI only.',
    });
    expect(getReviewQueue(db).unlabeled).not.toContain(11);
  });
});

function upsert(findingId: number, expectedAction: 'ping' | 'digest' | 'log', affectedTruth: 'yes' | 'no' | 'unsure' | null) {
  db.insert(labels).values({ findingId, labeler: LABELER, expectedAction, affectedTruth }).run();
}

describe('compareLabel', () => {
  const reveal = { policyAction: 'ping' as const, ruleId: 'r', verdict: 'affected' as const, confidence: 'high' as const, suggestedAction: 'digest' as const, suggestedActionReason: null };

  it('compares the label with the policy, the LLM suggestion and the verdict', () => {
    expect(compareLabel({ expectedAction: 'ping', affectedTruth: 'yes' }, reveal)).toEqual({ policy: 'agree', llm: 'disagree', verdict: 'agree' });
    expect(compareLabel({ expectedAction: 'digest', affectedTruth: 'no' }, reveal)).toEqual({ policy: 'disagree', llm: 'agree', verdict: 'disagree' });
    expect(compareLabel({ expectedAction: 'log', affectedTruth: 'no' }, { ...reveal, verdict: 'likely_not_affected' })).toMatchObject({ verdict: 'agree' });
  });

  it('reports n/a when either side is missing or unsure', () => {
    const none = { ...reveal, policyAction: null, suggestedAction: null, verdict: null };
    expect(compareLabel({ expectedAction: 'log', affectedTruth: 'yes' }, none)).toEqual({ policy: 'n/a', llm: 'n/a', verdict: 'n/a' });
    expect(compareLabel({ expectedAction: 'log', affectedTruth: 'unsure' }, reveal).verdict).toBe('n/a');
    expect(compareLabel({ expectedAction: 'log', affectedTruth: null }, reveal).verdict).toBe('n/a');
  });
});
