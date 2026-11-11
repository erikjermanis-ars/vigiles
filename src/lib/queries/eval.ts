/**
 * Eval page queries (spec §11.2): compares three deciders (base priority only, the LLM's
 * suggested_action, and the policy) against one labeler's labels, plus verdict accuracy,
 * triage cost/time, consistency, message volume and inter-labeler agreement.
 */
import { and, asc, desc, eq, getTableColumns, inArray, isNull, or } from 'drizzle-orm';
import { loadPolicy, parsePolicy, type LoadedPolicy } from '../config/load';
import type { Policy } from '../config/schema';
import type { Db } from '../db/client';
import {
  advisories,
  decisions,
  events,
  findings,
  jobRuns,
  labels,
  policyVersions,
  projects,
  triageConfigs,
  triageRuns,
} from '../db/schema';
import {
  basePriorityAction,
  consistency,
  deciderMetrics,
  labelerAgreement,
  messageVolume,
  ratio,
  triageRunStats,
  verdictAccuracy,
  type ActionPair,
  type Agreement,
  type Consistency,
  type DeciderMetrics,
  type Ratio,
  type RunStats,
  type VerdictAccuracy,
  type VolumeRow,
} from '../eval/metrics';
import { displayVulnId } from '../format';
import { evaluatePolicy } from '../policy/engine';
import { buildDecisionInputs, isMalicious, priorityUnderPolicy } from '../policy/inputs';
import { resolveTriageState } from '../triage/state';
import {
  ACTIONS,
  PRIORITIES,
  TriageOutputSchema,
  type Action,
  type AffectedTruth,
  type Confidence,
  type FindingStatus,
  type Priority,
  type ProjectProfile,
  type TriageOutput,
  type TriageStatus,
  type Verdict,
} from '../types';
import { succeededRefreshAlls, type LastRefresh } from './inbox';

export type DeciderName = 'base' | 'llm' | 'policy';
export const DECIDERS: readonly { name: DeciderName; title: string }[] = [
  { name: 'base', title: 'Base priority only' },
  { name: 'llm', title: 'LLM suggested_action' },
  { name: 'policy', title: 'Policy' },
];

export interface EvalSelection {
  configName: string;
  policyHash: string;
  labeler: string;
}

export const DEFAULT_LABELER = 'me';

// ---------- pickers ----------

/** config/policy.yaml as it is on disk now; the error text when the file is unreadable or invalid. */
export function loadCurrentPolicy(): { loaded: LoadedPolicy | null; hash: string | null; error: string | null } {
  try {
    const loaded = loadPolicy();
    return { loaded, hash: loaded.hash, error: null };
  } catch (err) {
    return { loaded: null, hash: null, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Hash of config/policy.yaml as it is on disk now; the error text when the file is unreadable or invalid. */
export function currentPolicyHash(): { hash: string | null; error: string | null } {
  const { hash, error } = loadCurrentPolicy();
  return { hash, error };
}

export interface SelectedPolicy {
  hash: string;
  policy: Policy | null;
  /** Why the policy could not be loaded (unknown hash, invalid stored content) */
  error: string | null;
}

/** The selected policy version: the file on disk when its hash matches, else the stored policy_versions row. */
export function loadSelectedPolicy(db: Db, hash: string, current: LoadedPolicy | null | undefined): SelectedPolicy {
  if (!hash) return { hash, policy: null, error: 'no policy version selected' };
  if (current && current.hash === hash) return { hash, policy: current.policy, error: null };
  const row = db.select({ content: policyVersions.content }).from(policyVersions).where(eq(policyVersions.hash, hash)).get();
  if (!row) return { hash, policy: null, error: `policy version ${hash} is not stored (run any job to sync config)` };
  try {
    return { hash, policy: parsePolicy(row.content, `policy_versions[${hash}]`).policy, error: null };
  } catch (err) {
    return { hash, policy: null, error: (err instanceof Error ? err.message : String(err)).split('\n')[0]! };
  }
}

export interface EvalOptions {
  configs: { name: string; active: boolean; model: string; effort: string; codeAccess: boolean; promptVersion: string }[];
  policies: { hash: string; firstSeenAt: string; current: boolean }[];
  /** Picker choices: everyone who labeled, plus the default labeler */
  labelers: string[];
  /** Distinct labelers that actually have labels (inter-labeler agreement needs at least two) */
  labelerCount: number;
  defaults: EvalSelection;
}

export function getEvalOptions(db: Db, currentHash: string | null): EvalOptions {
  const configs = db
    .select({
      name: triageConfigs.name,
      active: triageConfigs.active,
      model: triageConfigs.model,
      effort: triageConfigs.effort,
      codeAccess: triageConfigs.codeAccess,
      promptVersion: triageConfigs.promptVersion,
    })
    .from(triageConfigs)
    .orderBy(desc(triageConfigs.active), asc(triageConfigs.name))
    .all();
  const policies = db
    .select({ hash: policyVersions.hash, firstSeenAt: policyVersions.firstSeenAt })
    .from(policyVersions)
    .orderBy(desc(policyVersions.firstSeenAt))
    .all()
    .map((p) => ({ ...p, current: p.hash === currentHash }));
  const labelers = db
    .selectDistinct({ labeler: labels.labeler })
    .from(labels)
    .orderBy(asc(labels.labeler))
    .all()
    .map((r) => r.labeler);
  return {
    configs,
    policies,
    labelers: labelers.includes(DEFAULT_LABELER) ? labelers : [DEFAULT_LABELER, ...labelers],
    labelerCount: labelers.length,
    defaults: {
      configName: configs.find((c) => c.active)?.name ?? configs[0]?.name ?? '',
      policyHash: currentHash ?? policies[0]?.hash ?? '',
      labeler: DEFAULT_LABELER,
    },
  };
}

const firstParam = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;

export function resolveSelection(
  defaults: EvalSelection,
  query: { config?: string | string[]; policy?: string | string[]; labeler?: string | string[] },
): EvalSelection {
  return {
    configName: firstParam(query.config) ?? defaults.configName,
    policyHash: firstParam(query.policy) ?? defaults.policyHash,
    labeler: firstParam(query.labeler) ?? defaults.labeler,
  };
}

// ---------- report ----------

export interface LabeledRow {
  findingId: number;
  projectId: string;
  packageName: string;
  osvId: string;
  vulnId: string;
  status: FindingStatus;
  priority: Priority | null;
  label: Action;
  affectedTruth: AffectedTruth | null;
  note: string | null;
  base: Action;
  triageStatus: TriageStatus | null;
  /** suggested_action of the ok run at the current input hash */
  llm: Action | null;
  verdict: Verdict | null;
  confidence: Confidence | null;
  policy: Action | null;
  policyRuleId: string | null;
  /** The decision was made from a different triage run than the one that is current now */
  decisionStale: boolean;
}

export interface DeciderResult {
  name: DeciderName;
  title: string;
  metrics: DeciderMetrics;
  excluded: number;
  excludedNote: string | null;
}

export interface CellKey {
  decider: DeciderName;
  label: Action;
  decided: Action;
}

export const cellKey = (c: CellKey) => `${c.decider}:${c.label}:${c.decided}`;

export function parseCellKey(v: string | string[] | undefined): CellKey | null {
  const s = Array.isArray(v) ? v[0] : v;
  const m = /^(base|llm|policy):(ping|digest|log):(ping|digest|log)$/.exec(s ?? '');
  return m ? { decider: m[1] as DeciderName, label: m[2] as Action, decided: m[3] as Action } : null;
}

export interface LabelerComparison {
  other: string;
  action: Agreement;
  /** Agreement on affected_truth where both said yes or no */
  affected: Ratio;
}

export interface EvalReport {
  selection: EvalSelection;
  configFound: boolean;
  rows: LabeledRow[];
  deciders: DeciderResult[];
  /** cellKey → finding ids */
  cells: Record<string, number[]>;
  verdict: VerdictAccuracy;
  /** Policy action ≠ label; missed pings first, then false pings */
  disagreements: LabeledRow[];
  /** Labeled findings without a decision for the selected policy × config; `disabled` (open findings of disabled projects, which decide skips) is not in `open` */
  missingDecisions: { open: number; closed: number; disabled: number };
  staleDecisions: number;
  cost: (RunStats & { configName: string })[];
  consistency: (Consistency & { configName: string })[];
  /** The policy version whose action the consistency table compares (the selected one) */
  consistencyPolicy: { hash: string; error: string | null };
  volume: {
    /** Current decisions (findings.current_action) of open findings */
    current: VolumeRow[];
    /** Current decisions of open findings that the first scan found (origin baseline) */
    baseline: VolumeRow[];
    /** Current decisions of open findings found after the first scan */
    afterBaseline: VolumeRow[];
    /** Open findings under the selected policy × config (decisions table) */
    selected: VolumeRow[];
    /** What each recent succeeded Refresh all would have sent, newest first */
    perRefresh: RefreshVolume[];
  };
  agreement: LabelerComparison[];
}

/** Messages one Refresh all would have sent: the findings whose decision it set or changed, by the new action. */
export interface RefreshVolume {
  refresh: LastRefresh;
  /** Per project, counted like the Inbox (one message per project, package and action) */
  projects: VolumeRow[];
  total: Omit<VolumeRow, 'projectId'>;
  /** Findings created in this refresh without a decision event in it (decided before first decisions were recorded, or not decided) */
  newWithoutDecision: number;
}

/** How many succeeded Refresh all runs the per-refresh volume table covers. */
export const PER_REFRESH_LIMIT = 10;

type FindingRow = typeof findings.$inferSelect;
type TriageRunRow = typeof triageRuns.$inferSelect;

const priorityRank = (p: Priority | null) => (p ? PRIORITIES.indexOf(p) : PRIORITIES.length);

// Map.groupBy is ES2024; the project targets ES2023 typings.
function groupBy<T, K>(items: Iterable<T>, key: (item: T) => K): Map<K, T[]> {
  const out = new Map<K, T[]>();
  for (const item of items) {
    const k = key(item);
    const list = out.get(k);
    if (list) list.push(item);
    else out.set(k, [item]);
  }
  return out;
}

function disagreementRank(r: LabeledRow): number {
  if (r.label === 'ping' && r.policy !== 'ping') return 0; // missed ping: breaks the 100% recall target
  if (r.policy === 'ping' && r.label !== 'ping') return 1; // false ping: costs precision
  return 2;
}

/** The ok triage run whose verdict a decision used, or null when it was made without one (pending, failed, skipped). */
function decidedFromOkRun(d: Pick<typeof decisions.$inferSelect, 'triageRunId' | 'inputs'>): number | null {
  return d.inputs.triage_status === 'ok' ? d.triageRunId : null;
}

/**
 * A decision is stale when the verdict it used is not the one that counts now: a newer ok run exists, or the
 * finding's inputs changed so its old run no longer matches the current input hash (or the reverse).
 * Comparing only ok runs keeps pending ↔ skipped (which can differ by min_priority) from counting.
 */
function labeledRows(db: Db, sel: EvalSelection, minPriority: Priority): { rows: LabeledRow[]; configFound: boolean } {
  const config = sel.configName ? db.select().from(triageConfigs).where(eq(triageConfigs.name, sel.configName)).get() : undefined;
  const decisionByFinding = new Map(
    db
      .select()
      .from(decisions)
      .where(and(eq(decisions.policyHash, sel.policyHash), eq(decisions.configName, sel.configName)))
      .all()
      .map((d) => [d.findingId, d]),
  );
  const joined = db
    .select({ label: labels, finding: findings, cves: advisories.cves })
    .from(labels)
    .innerJoin(findings, eq(findings.id, labels.findingId))
    .leftJoin(advisories, eq(advisories.osvId, findings.osvId))
    .where(eq(labels.labeler, sel.labeler))
    .orderBy(asc(findings.id))
    .all();

  const rows = joined.map(({ label, finding, cves }): LabeledRow => {
    const state = config ? resolveTriageState(db, finding, config, minPriority) : null;
    const parsed = state?.status === 'ok' && state.run?.output ? TriageOutputSchema.safeParse(state.run.output) : null;
    const output = parsed?.success ? parsed.data : null;
    const decision = decisionByFinding.get(finding.id);
    return {
      findingId: finding.id,
      projectId: finding.projectId,
      packageName: finding.packageName,
      osvId: finding.osvId,
      vulnId: displayVulnId(finding.osvId, cves),
      status: finding.status,
      priority: finding.priority,
      label: label.expectedAction,
      affectedTruth: label.affectedTruth,
      note: label.note,
      base: basePriorityAction(finding.priority),
      triageStatus: state?.status ?? null,
      llm: output?.suggested_action ?? null,
      verdict: output?.verdict ?? null,
      confidence: output?.confidence ?? null,
      policy: decision?.action ?? null,
      policyRuleId: decision?.ruleId ?? null,
      decisionStale: Boolean(decision && state && decidedFromOkRun(decision) !== (state.status === 'ok' ? state.run!.id : null)),
    };
  });
  return { rows, configFound: Boolean(config) };
}

function llmExcludedNote(rows: readonly LabeledRow[], configFound: boolean): string | null {
  const missing = rows.filter((r) => r.llm === null);
  if (!missing.length) return null;
  if (!configFound) return `${missing.length} excluded: triage config not found (run any job to sync config).`;
  const by = new Map<string, number>();
  for (const r of missing) {
    const k = r.triageStatus === 'ok' ? 'invalid output' : (r.triageStatus ?? 'unknown');
    by.set(k, (by.get(k) ?? 0) + 1);
  }
  const parts = [...by.entries()].map(([k, n]) => `${n} ${k}`).join(', ');
  return `${missing.length} excluded: no ok triage run for this config at the current input hash (${parts}).`;
}

function deciderResults(rows: readonly LabeledRow[], configFound: boolean): { deciders: DeciderResult[]; cells: Record<string, number[]> } {
  const cells: Record<string, number[]> = {};
  const deciders = DECIDERS.map(({ name, title }): DeciderResult => {
    const pairs: ActionPair[] = [];
    for (const r of rows) {
      const decided = r[name];
      if (!decided) continue;
      pairs.push({ label: r.label, decided });
      (cells[cellKey({ decider: name, label: r.label, decided })] ??= []).push(r.findingId);
    }
    const excluded = rows.length - pairs.length;
    const excludedNote =
      excluded === 0
        ? null
        : name === 'llm'
          ? llmExcludedNote(rows, configFound)
          : `${excluded} excluded: no decision for this policy × config.`;
    return { name, title, metrics: deciderMetrics(pairs), excluded, excludedNote };
  });
  return { deciders, cells };
}

function costByConfig(db: Db): (RunStats & { configName: string })[] {
  const runs = db
    .select({
      configName: triageRuns.configName,
      status: triageRuns.status,
      durationMs: triageRuns.durationMs,
      costUsd: triageRuns.costUsd,
      numTurns: triageRuns.numTurns,
    })
    .from(triageRuns)
    .all();
  const byConfig = groupBy(runs, (r) => r.configName);
  return [...byConfig.entries()]
    .map(([configName, rs]) => ({ configName, ...triageRunStats(rs) }))
    .sort((a, b) => a.configName.localeCompare(b.configName));
}

// Disabled projects are left out of the volume tables, as they are out of the Inbox; a finding whose project
// row is missing still counts (it cannot be "disabled").
const enabledProject = or(isNull(projects.id), eq(projects.enabled, true));

// Keeps `IN (...)` lists well under SQLite's bound-parameter limit.
function chunks<T>(items: readonly T[], size = 500): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

// Everything but the large prompt and raw columns; buildDecisionInputs only reads the run's output.
const { prompt: _prompt, raw: _raw, ...runColumns } = getTableColumns(triageRuns);

/**
 * Consistency per config (spec §11.2, exit criterion "same triage config run twice gives the same action").
 * Runs are grouped by finding, config and input hash. Each ok run is put through the selected policy as if it
 * were the finding's verdict, so the primary metric is the share of groups whose runs all lead to the same
 * policy action; identical verdict and identical suggested_action are secondary.
 */
function consistencyByConfig(db: Db, policy: Policy | null): (Consistency & { configName: string })[] {
  const runs = db.select(runColumns).from(triageRuns).where(eq(triageRuns.status, 'ok')).orderBy(asc(triageRuns.id)).all();
  type Run = (typeof runs)[number] & { parsed: TriageOutput };
  const groups = new Map<string, { configName: string; findingId: number; runs: Run[] }>();
  for (const r of runs) {
    const parsed = TriageOutputSchema.safeParse(r.output);
    if (!parsed.success) continue;
    const key = `${r.configName}\u0000${r.findingId}\u0000${r.inputHash}`;
    const g = groups.get(key) ?? { configName: r.configName, findingId: r.findingId, runs: [] };
    g.runs.push({ ...r, parsed: parsed.data });
    groups.set(key, g);
  }
  const repeated = [...groups.values()].filter((g) => g.runs.length >= 2);
  const policyAction = policy ? policyActionFor(db, policy, repeated) : () => null;

  const byConfig = groupBy(repeated, (g) => g.configName);
  return [...byConfig.entries()]
    .map(([configName, gs]) => ({
      configName,
      ...consistency(
        gs.map((g) =>
          g.runs.map((r) => ({ verdict: r.parsed.verdict, action: r.parsed.suggested_action, policyAction: policyAction(g.findingId, r) })),
        ),
      ),
    }))
    .filter((c) => c.groups > 0)
    .sort((a, b) => a.configName.localeCompare(b.configName));
}

/** The policy action for a finding with the given ok run as its verdict, or null (finding or project gone, policy error). */
function policyActionFor(
  db: Db,
  policy: Policy,
  groups: readonly { findingId: number }[],
): (findingId: number, run: Omit<TriageRunRow, 'prompt' | 'raw'> & { parsed: TriageOutput }) => Action | null {
  const ids = [...new Set(groups.map((g) => g.findingId))];
  const findingById = new Map<number, FindingRow>();
  const maliciousByOsvId = new Map<string, boolean>();
  for (const chunk of chunks(ids)) {
    const rows = db
      .select({ finding: findings, malicious: advisories.malicious })
      .from(findings)
      .leftJoin(advisories, eq(advisories.osvId, findings.osvId))
      .where(inArray(findings.id, chunk))
      .all();
    for (const r of rows) {
      findingById.set(r.finding.id, r.finding);
      if (r.malicious !== null) maliciousByOsvId.set(r.finding.osvId, r.malicious);
    }
  }
  const profiles = new Map<string, ProjectProfile>(
    db
      .select({ id: projects.id, profile: projects.profile })
      .from(projects)
      .all()
      .map((p) => [p.id, p.profile]),
  );
  return (findingId, run) => {
    const stored = findingById.get(findingId);
    const profile = stored ? profiles.get(stored.projectId) : undefined;
    if (!stored || !profile) return null;
    const flag = maliciousByOsvId.get(stored.osvId);
    const advisory = flag === undefined ? null : { malicious: flag };
    // As the decide job does: the base priority under the evaluated policy's own thresholds.
    const priority = priorityUnderPolicy(stored, profile, isMalicious(stored, advisory), policy.thresholds);
    const inputs = buildDecisionInputs({ ...stored, priority }, profile, advisory, {
      status: 'ok',
      run: { ...run, output: run.parsed, prompt: '', raw: null },
    });
    try {
      return evaluatePolicy(policy, inputs).action;
    } catch {
      return null;
    }
  };
}

function volumes(db: Db, sel: EvalSelection): EvalReport['volume'] {
  const open = db
    .select({ projectId: findings.projectId, packageName: findings.packageName, action: findings.currentAction, origin: findings.origin })
    .from(findings)
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .where(and(eq(findings.status, 'open'), enabledProject))
    .all();
  const selected = db
    .select({ projectId: findings.projectId, packageName: findings.packageName, action: decisions.action })
    .from(decisions)
    .innerJoin(findings, eq(findings.id, decisions.findingId))
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .where(
      and(eq(findings.status, 'open'), enabledProject, eq(decisions.policyHash, sel.policyHash), eq(decisions.configName, sel.configName)),
    )
    .all();
  return {
    current: messageVolume(open),
    baseline: messageVolume(open.filter((r) => r.origin === 'baseline')),
    afterBaseline: messageVolume(open.filter((r) => r.origin !== 'baseline')),
    selected: messageVolume(selected),
    perRefresh: refreshVolumes(db),
  };
}

const isAction = (v: unknown): v is Action => typeof v === 'string' && (ACTIONS as readonly string[]).includes(v);

/**
 * Per succeeded Refresh all (newest first): the findings whose current decision it set or changed, counted as
 * messages by the action they changed to. A refresh's events are the ones its child jobs wrote (events.job_run_id).
 */
export function refreshVolumes(db: Db, limit = PER_REFRESH_LIMIT): RefreshVolume[] {
  const refreshes = succeededRefreshAlls(db, limit);
  if (!refreshes.length) return [];
  // Every job of each refresh (children, and their children if any) → that refresh's id.
  const owner = new Map<number, number>(refreshes.map((r) => [r.id, r.id]));
  let frontier = refreshes.map((r) => r.id);
  while (frontier.length) {
    const next: number[] = [];
    for (const chunk of chunks(frontier)) {
      for (const c of db
        .select({ id: jobRuns.id, parentId: jobRuns.parentId })
        .from(jobRuns)
        .where(inArray(jobRuns.parentId, chunk))
        .all()) {
        if (owner.has(c.id)) continue;
        owner.set(c.id, owner.get(c.parentId!)!);
        next.push(c.id);
      }
    }
    frontier = next;
  }

  const perRefresh = new Map(
    refreshes.map((r) => [
      r.id,
      { decided: new Map<number, { projectId: string; packageName: string; action: Action }>(), created: new Set<number>() },
    ]),
  );
  for (const chunk of chunks([...owner.keys()])) {
    const rows = db
      .select({
        findingId: events.findingId,
        type: events.type,
        jobRunId: events.jobRunId,
        data: events.data,
        projectId: findings.projectId,
        packageName: findings.packageName,
      })
      .from(events)
      .innerJoin(findings, eq(findings.id, events.findingId))
      .leftJoin(projects, eq(projects.id, findings.projectId))
      .where(and(inArray(events.type, ['decision_changed', 'created']), inArray(events.jobRunId, chunk), enabledProject))
      .orderBy(asc(events.id))
      .all();
    for (const e of rows) {
      const acc = perRefresh.get(owner.get(e.jobRunId!)!)!;
      if (e.type === 'created') {
        acc.created.add(e.findingId);
        continue;
      }
      const to = e.data?.to;
      // The last change in the refresh wins (one decide runs per refresh, so normally there is one).
      if (isAction(to)) acc.decided.set(e.findingId, { projectId: e.projectId, packageName: e.packageName, action: to });
    }
  }

  return refreshes.map((refresh) => {
    const acc = perRefresh.get(refresh.id)!;
    const rows = messageVolume([...acc.decided.values()]);
    const sum = (k: keyof Omit<VolumeRow, 'projectId'>) => rows.reduce((n, r) => n + r[k], 0);
    return {
      refresh,
      projects: rows,
      total: {
        pingMessages: sum('pingMessages'),
        pingFindings: sum('pingFindings'),
        digestMessages: sum('digestMessages'),
        digestFindings: sum('digestFindings'),
        logFindings: sum('logFindings'),
      },
      newWithoutDecision: [...acc.created].filter((id) => !acc.decided.has(id)).length,
    };
  });
}

function agreementWithOthers(db: Db, labeler: string): LabelerComparison[] {
  const all = db
    .select({ findingId: labels.findingId, labeler: labels.labeler, action: labels.expectedAction, truth: labels.affectedTruth })
    .from(labels)
    .all();
  const mine = new Map(all.filter((l) => l.labeler === labeler).map((l) => [l.findingId, l]));
  const others = [...new Set(all.map((l) => l.labeler))].filter((l) => l !== labeler).sort();
  return others.map((other) => {
    const pairs = all.filter((l) => l.labeler === other && mine.has(l.findingId)).map((l) => ({ a: mine.get(l.findingId)!, b: l }));
    const decisive = (t: AffectedTruth | null) => t === 'yes' || t === 'no';
    const truthPairs = pairs.filter((p) => decisive(p.a.truth) && decisive(p.b.truth));
    return {
      other,
      action: labelerAgreement(pairs.map((p) => ({ a: p.a.action, b: p.b.action }))),
      affected: ratio(truthPairs.filter((p) => p.a.truth === p.b.truth).length, truthPairs.length),
    };
  });
}

export function getEvalReport(
  db: Db,
  sel: EvalSelection,
  opts: {
    minPriority: Priority;
    /** config/policy.yaml as loaded now; used when the selected hash is the file's (it may not be stored yet) */
    currentPolicy?: LoadedPolicy | null;
  },
): EvalReport {
  const { rows, configFound } = labeledRows(db, sel, opts.minPriority);
  const selectedPolicy = loadSelectedPolicy(db, sel.policyHash, opts.currentPolicy);
  const { deciders, cells } = deciderResults(rows, configFound);
  const withoutDecision = rows.filter((r) => r.policy === null);
  const disabledProjects = new Set(
    db
      .select({ id: projects.id })
      .from(projects)
      .where(eq(projects.enabled, false))
      .all()
      .map((p) => p.id),
  );
  const openWithout = withoutDecision.filter((r) => r.status === 'open');
  return {
    selection: sel,
    configFound,
    rows,
    deciders,
    cells,
    verdict: verdictAccuracy(rows.map((r) => ({ truth: r.affectedTruth, verdict: r.verdict }))),
    disagreements: rows
      .filter((r) => r.policy !== null && r.policy !== r.label)
      .sort(
        (a, b) =>
          disagreementRank(a) - disagreementRank(b) || priorityRank(a.priority) - priorityRank(b.priority) || a.findingId - b.findingId,
      ),
    missingDecisions: {
      open: openWithout.filter((r) => !disabledProjects.has(r.projectId)).length,
      closed: withoutDecision.filter((r) => r.status !== 'open').length,
      disabled: openWithout.filter((r) => disabledProjects.has(r.projectId)).length,
    },
    staleDecisions: rows.filter((r) => r.decisionStale).length,
    cost: costByConfig(db),
    consistency: consistencyByConfig(db, selectedPolicy.policy),
    consistencyPolicy: { hash: selectedPolicy.hash, error: selectedPolicy.error },
    volume: volumes(db, sel),
    agreement: agreementWithOthers(db, sel.labeler),
  };
}

/** The labeled rows behind one confusion-matrix cell. */
export function rowsForCell(report: EvalReport, cell: CellKey): LabeledRow[] {
  const ids = new Set(report.cells[cellKey(cell)] ?? []);
  return report.rows.filter((r) => ids.has(r.findingId));
}
