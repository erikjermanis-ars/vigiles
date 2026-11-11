/** Synthetic rows for DB tests of the eval, inbox, jobs and projects queries (never real client data). */
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, decisions, events, findings, jobRuns, labels, projects, scans, triageConfigs, triageRuns } from '../db/schema';
import { findingInputHash } from '../triage/state';
import type { Action, DecisionInputs, EventType, ProjectProfile, TriageOutput, TriageRunStatus } from '../types';

export function insertProject(db: Db, id = 'web', overrides: Partial<ProjectProfile> = {}) {
  const profile: ProjectProfile = {
    id,
    name: `Project ${id}`,
    enabled: true,
    repo_path: `/nonexistent/${id}`,
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
    ...overrides,
  };
  db.insert(projects)
    .values({
      id,
      name: profile.name,
      enabled: profile.enabled,
      repoPath: profile.repo_path,
      ref: profile.ref,
      profile,
      profileHash: `hash-${id}`,
    })
    .run();
  const scanId = db
    .insert(scans)
    .values({
      projectId: id,
      ref: profile.ref,
      commitSha: 'abcdef1234567890',
      commitDate: '2026-11-01T10:00:00.000Z',
      status: 'succeeded',
      lockfiles: ['package-lock.json'],
    })
    .returning({ id: scans.id })
    .get().id;
  db.update(projects).set({ lastScanId: scanId }).where(eq(projects.id, id)).run();
  return { profile, scanId };
}

export function insertAdvisory(db: Db, osvId: string, opts: { cves?: string[]; summary?: string; malicious?: boolean } = {}) {
  db.insert(advisories)
    .values({
      osvId,
      cves: opts.cves ?? [],
      summary: opts.summary ?? `Summary of ${osvId}. More text.`,
      modified: '2026-01-01T00:00:00Z',
      malicious: opts.malicious ?? false,
      raw: {},
    })
    .run();
}

export interface FindingOpts {
  projectId?: string;
  packageName?: string;
  osvId?: string;
  cves?: string[];
  priority?: 'P0' | 'P1' | 'P2' | 'P3' | null;
  status?: 'open' | 'fixed' | 'no_longer_matches';
  action?: Action | null;
  ruleId?: string | null;
  fixedVersions?: string[];
  origin?: 'baseline' | 'new_advisory' | 'new_dependency';
  advisorySummary?: string;
  /** advisories.malicious */
  malicious?: boolean;
}

let osvCounter = 0;

export function insertFinding(db: Db, scanId: number, o: FindingOpts = {}) {
  const osvId = o.osvId ?? `GHSA-test-${++osvCounter}`;
  insertAdvisory(db, osvId, { cves: o.cves, summary: o.advisorySummary, malicious: o.malicious });
  return db
    .insert(findings)
    .values({
      projectId: o.projectId ?? 'web',
      lockfile: 'package-lock.json',
      ecosystem: 'npm',
      packageName: o.packageName ?? 'next',
      osvId,
      installedVersions: ['1.0.0'],
      fixedVersions: o.fixedVersions ?? [],
      origin: o.origin ?? 'baseline',
      status: o.status ?? 'open',
      firstSeenScanId: scanId,
      lastSeenScanId: scanId,
      advisoryModified: '2026-01-01T00:00:00Z',
      priority: o.priority === undefined ? 'P1' : o.priority,
      currentAction: o.action ?? null,
      currentRuleId: o.ruleId ?? null,
    })
    .returning()
    .get();
}

export function insertConfig(db: Db, name = 'cfg-a', active = true) {
  return db
    .insert(triageConfigs)
    .values({ name, promptVersion: 'v1', model: 'opus', effort: 'high', codeAccess: true, active })
    .returning()
    .get();
}

export function triageOutput(o: Partial<TriageOutput> = {}): TriageOutput {
  return {
    verdict: 'affected',
    confidence: 'high',
    runtime_usage: 'server',
    vulnerable_code_used: 'yes',
    attacker_reachable: 'yes',
    deployment_conditions_met: 'yes',
    summary: 'The upload route passes user files to the vulnerable function. Second sentence.',
    evidence: [{ file: 'src/app/api/upload/route.ts', line: 12, note: 'calls it' }],
    exploit_conditions: 'An authenticated user uploads a crafted file.',
    remediation: 'Upgrade.',
    workaround: null,
    suggested_action: 'ping',
    suggested_action_reason: 'Reachable.',
    ...o,
  };
}

/** Inserts a triage run at the finding's current input hash for `config` (or at `inputHash` when given). */
export function insertTriageRun(
  db: Db,
  findingId: number,
  config: typeof triageConfigs.$inferSelect,
  o: {
    status?: TriageRunStatus;
    output?: TriageOutput | null;
    inputHash?: string;
    costUsd?: number;
    durationMs?: number;
    numTurns?: number;
  } = {},
) {
  const finding = db.select().from(findings).where(eq(findings.id, findingId)).get()!;
  const status = o.status ?? 'ok';
  return db
    .insert(triageRuns)
    .values({
      findingId,
      configName: config.name,
      inputHash: o.inputHash ?? findingInputHash(db, finding, config),
      status,
      output: o.output === undefined ? (status === 'ok' ? triageOutput() : null) : o.output,
      prompt: 'prompt',
      costUsd: o.costUsd ?? 0.5,
      durationMs: o.durationMs ?? 60_000,
      numTurns: o.numTurns ?? 5,
    })
    .returning()
    .get();
}

const decisionInputs: DecisionInputs = {
  priority: 'P1',
  malicious: false,
  in_kev: false,
  epss: null,
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

export function insertDecision(
  db: Db,
  findingId: number,
  policyHash: string,
  configName: string,
  action: Action,
  triageRunId: number | null = null,
  inputs: Partial<DecisionInputs> = {},
) {
  db.insert(decisions)
    .values({ findingId, policyHash, configName, action, ruleId: `rule-${action}`, inputs: { ...decisionInputs, ...inputs }, triageRunId })
    .run();
}

export function insertLabel(
  db: Db,
  findingId: number,
  expectedAction: Action,
  o: { labeler?: string; truth?: 'yes' | 'no' | 'unsure' | null } = {},
) {
  db.insert(labels)
    .values({ findingId, labeler: o.labeler ?? 'me', expectedAction, affectedTruth: o.truth ?? null })
    .run();
}

export function insertEvent(
  db: Db,
  findingId: number,
  type: EventType,
  at: string,
  o: { jobRunId?: number | null; data?: Record<string, unknown> | null } = {},
) {
  db.insert(events)
    .values({ findingId, type, at, jobRunId: o.jobRunId ?? null, data: o.data ?? null })
    .run();
}

export function insertJob(
  db: Db,
  o: {
    type?: string;
    status?: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
    parentId?: number | null;
    createdAt?: string;
    startedAt?: string | null;
    finishedAt?: string | null;
    stats?: Record<string, unknown>;
  } = {},
) {
  return db
    .insert(jobRuns)
    .values({
      type: o.type ?? 'noop',
      status: o.status ?? 'succeeded',
      parentId: o.parentId ?? null,
      ...(o.createdAt ? { createdAt: o.createdAt } : {}),
      startedAt: o.startedAt ?? null,
      finishedAt: o.finishedAt ?? null,
      stats: o.stats ?? null,
    })
    .returning({ id: jobRuns.id })
    .get().id;
}
