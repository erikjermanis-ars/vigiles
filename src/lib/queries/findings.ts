/**
 * Read models for the Findings list, the Finding page and its source viewer (spec §12), plus the
 * label upsert shared by the Finding and Review pages. Pages call these; they never query tables directly.
 */
import { isProcessAlive } from '../jobs/queue';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { and, desc, eq, getTableColumns, inArray, isNotNull, isNull, or, type SQL } from 'drizzle-orm';
import type { SQLiteColumn } from 'drizzle-orm/sqlite-core';
import { z } from 'zod';
import { loadPolicy, loadVigilesConfig, repoRoot } from '../config/load';
import type { Db } from '../db/client';
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
import { snapshotDir } from '../git';
import { resolveTriageState } from '../triage/state';
import {
  ACTIONS,
  AFFECTED_TRUTHS,
  CONFIDENCES,
  FINDING_ORIGINS,
  FINDING_STATUSES,
  PRIORITIES,
  TriageOutputSchema,
  VERDICTS,
  type Action,
  type AffectedTruth,
  type Confidence,
  type Criticality,
  type Exposure,
  type FindingOrigin,
  type FindingStatus,
  type Priority,
  type TriageOutput,
  type TriageRunStatus,
  type TriageStatus,
  type Verdict,
} from '../types';

/** The default labeler. A second person picks another name on the Review page (cookie, see below). */
export const LABELER = 'me';
/** Cookie holding the dashboard's current labeler (spec §17: a second developer labels too). */
export const LABELER_COOKIE = 'vigiles_labeler';
const LABELER_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/i;
export const FINDINGS_LIST_LIMIT = 500;

/**
 * A valid labeler name, trimmed and lower-cased (so 'Ana' and 'ana' are one person), else null.
 * Names are 1–32 characters: letters, digits, '_' and '-', starting with a letter or digit.
 */
export function parseLabeler(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  return LABELER_RE.test(v) ? v.toLowerCase() : null;
}

/** The labeler a stored cookie value names; an absent or invalid value means the default. */
export function labelerOrDefault(value: unknown): string {
  return parseLabeler(value) ?? LABELER;
}

export type FindingRow = typeof findings.$inferSelect;
export type AdvisoryRow = typeof advisories.$inferSelect;
export type DecisionRow = typeof decisions.$inferSelect;
export type LabelRow = typeof labels.$inferSelect;
export type EventRow = typeof events.$inferSelect;
export type KevRow = typeof kev.$inferSelect;
export type SearchParams = Record<string, string | string[] | undefined>;

// ---------- config context ----------

/** What the UI needs from the YAML config to pick the "current" decision and triage config. */
export interface DecisionContext {
  activeConfig: string;
  /** Every triage config in vigiles.yaml, in file order */
  configNames: string[];
  minPriority: Priority;
  /** Hash of config/policy.yaml as it is now; null when the file does not parse */
  policyHash: string | null;
  policyError: string | null;
}

export function loadDecisionContext(root = repoRoot()): DecisionContext {
  const config = loadVigilesConfig(root);
  let policyHash: string | null = null;
  let policyError: string | null = null;
  try {
    policyHash = loadPolicy(root).hash;
  } catch (err) {
    policyError = err instanceof Error ? err.message : String(err);
  }
  return {
    activeConfig: config.triage.active_config,
    configNames: config.triage.configs.map((c) => c.name),
    minPriority: config.triage.min_priority,
    policyHash,
    policyError,
  };
}

// ---------- small shared helpers ----------

function isOneOf<T extends string>(allowed: readonly T[], v: unknown): v is T {
  return typeof v === 'string' && (allowed as readonly string[]).includes(v);
}

/** Validates a stored triage output (JSON from the DB is checked at the edge, spec §13). */
export function parseTriageOutput(value: unknown): TriageOutput | null {
  if (value === null || value === undefined) return null;
  const parsed = TriageOutputSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** Verdict + confidence only, tolerant of outputs that fail the full schema. */
function readVerdict(output: unknown): { verdict: Verdict | null; confidence: Confidence | null } {
  if (!output || typeof output !== 'object') return { verdict: null, confidence: null };
  const o = output as Record<string, unknown>;
  return {
    verdict: isOneOf(VERDICTS, o.verdict) ? o.verdict : null,
    confidence: isOneOf(CONFIDENCES, o.confidence) ? o.confidence : null,
  };
}

const rankPriority = (p: Priority | null): number => (p ? PRIORITIES.indexOf(p) : PRIORITIES.length);
/** Descending with nulls last. */
const descNullsLast = (a: number | null, b: number | null): number => (b ?? -Infinity) - (a ?? -Infinity) || 0;

export interface PriorityOrderFields {
  id: number;
  priority: Priority | null;
  epss: number | null;
  cvssScore: number | null;
}

/** The triage/review order (spec §9.1): base priority, then EPSS, then CVSS, then id. */
export function comparePriorityOrder(a: PriorityOrderFields, b: PriorityOrderFields): number {
  return (
    rankPriority(a.priority) - rankPriority(b.priority) ||
    descNullsLast(a.epss, b.epss) ||
    descNullsLast(a.cvssScore, b.cvssScore) ||
    a.id - b.id
  );
}

// ---------- findings list ----------

export const FINDING_SORTS = ['priority', 'epss', 'cvss', 'firstSeen', 'package'] as const;
export type FindingSort = (typeof FINDING_SORTS)[number];

export interface FindingFilters {
  project: string[];
  /** Empty = any status */
  status: FindingStatus[];
  priority: (Priority | 'none')[];
  /** Current policy action; 'none' = not decided yet */
  action: (Action | 'none')[];
  /** Verdict of the active triage run; 'none' = no active run */
  verdict: (Verdict | 'none')[];
  /** Your label's expected action */
  expected: Action[];
  origin: FindingOrigin[];
  devOnly: boolean | null;
  direct: 'yes' | 'no' | 'unknown' | null;
  labeled: boolean | null;
  /** Case-insensitive substring of the package name, OSV id or an alias */
  q: string;
  /** Explicit finding ids (lets other pages link to an arbitrary set) */
  ids: number[];
  sort: FindingSort;
}

function paramValues(sp: SearchParams, key: string): string[] {
  const raw = sp[key];
  const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  return list
    .flatMap((v) => v.split(','))
    .map((v) => v.trim())
    .filter(Boolean);
}

function enumValues<T extends string>(sp: SearchParams, key: string, allowed: readonly T[]): T[] {
  return [...new Set(paramValues(sp, key).filter((v): v is T => isOneOf(allowed, v)))];
}

function yesNo(sp: SearchParams, key: string): boolean | null {
  const v = paramValues(sp, key)[0];
  return v === 'yes' ? true : v === 'no' ? false : null;
}

/** Free text is taken as typed: unlike list filters it is not split on commas. */
function textParam(sp: SearchParams, key: string): string {
  const raw = sp[key];
  const first = Array.isArray(raw) ? raw[0] : raw;
  return (first ?? '').trim();
}

/** Options for the Findings query string: the dashboard's project scope is the project filter's default. */
export interface FindingQueryOptions {
  /**
   * The project filter when the query has no `project` parameter (the header's scope cookie). A `project`
   * parameter always wins: `project=all` (or an empty value) means every project.
   */
  defaultProject?: readonly string[] | null;
}

/** The `project` filter: the parameter when present ('all' = every project), else the default. */
function projectFilter(sp: SearchParams, opts: FindingQueryOptions): string[] {
  if (sp.project === undefined) return [...new Set(opts.defaultProject ?? [])];
  const values = [...new Set(paramValues(sp, 'project'))];
  return values.includes('all') ? [] : values;
}

/** Parses the Findings page query string. Unknown values are ignored; status defaults to open. */
export function parseFindingFilters(sp: SearchParams, opts: FindingQueryOptions = {}): FindingFilters {
  const statusRaw = paramValues(sp, 'status');
  const status = enumValues(sp, 'status', FINDING_STATUSES);
  const direct = paramValues(sp, 'direct')[0];
  const sort = paramValues(sp, 'sort')[0];
  return {
    project: projectFilter(sp, opts),
    status: statusRaw.includes('all') ? [] : status.length ? status : ['open'],
    priority: enumValues(sp, 'priority', [...PRIORITIES, 'none'] as const),
    action: enumValues(sp, 'action', [...ACTIONS, 'none'] as const),
    verdict: enumValues(sp, 'verdict', [...VERDICTS, 'none'] as const),
    expected: enumValues(sp, 'expected', ACTIONS),
    origin: enumValues(sp, 'origin', FINDING_ORIGINS),
    devOnly: yesNo(sp, 'devOnly'),
    direct: direct === 'yes' || direct === 'no' || direct === 'unknown' ? direct : null,
    labeled: yesNo(sp, 'labeled'),
    q: textParam(sp, 'q').slice(0, 200),
    ids: [
      ...new Set(
        paramValues(sp, 'ids')
          .map(Number)
          .filter((n) => Number.isInteger(n) && n > 0),
      ),
    ],
    sort: isOneOf(FINDING_SORTS, sort) ? sort : 'priority',
  };
}

/**
 * Inverse of parseFindingFilters (defaults omitted), for links that keep the current filters. With a
 * `defaultProject`, a project filter equal to it is omitted and an empty one is written as `project=all`, so the
 * link means the same whatever scope cookie the next request carries.
 */
export function findingFiltersToQuery(f: FindingFilters, overrides: Partial<FindingFilters> = {}, opts: FindingQueryOptions = {}): string {
  const m = { ...f, ...overrides };
  const qs = new URLSearchParams();
  const list = (key: string, v: readonly (string | number)[]) => {
    if (v.length) qs.set(key, v.join(','));
  };
  const def = [...new Set(opts.defaultProject ?? [])];
  const sameAsDefault = m.project.length === def.length && m.project.every((p) => def.includes(p));
  if (!sameAsDefault) {
    if (m.project.length) list('project', m.project);
    else qs.set('project', 'all');
  }
  if (m.status.length === 0) qs.set('status', 'all');
  else if (!(m.status.length === 1 && m.status[0] === 'open')) list('status', m.status);
  list('priority', m.priority);
  list('action', m.action);
  list('verdict', m.verdict);
  list('expected', m.expected);
  list('origin', m.origin);
  if (m.devOnly !== null) qs.set('devOnly', m.devOnly ? 'yes' : 'no');
  if (m.direct !== null) qs.set('direct', m.direct);
  if (m.labeled !== null) qs.set('labeled', m.labeled ? 'yes' : 'no');
  if (m.q) qs.set('q', m.q);
  list('ids', m.ids);
  if (m.sort !== 'priority') qs.set('sort', m.sort);
  const s = qs.toString();
  return s ? `?${s}` : '';
}

/** `col IN (values)`, plus `OR col IS NULL` when the filter includes 'none'. */
function inOrNull<T extends string>(col: SQLiteColumn, values: (T | 'none')[]): SQL | undefined {
  if (!values.length) return undefined;
  const concrete = values.filter((v) => v !== 'none');
  const parts: SQL[] = [];
  if (concrete.length) parts.push(inArray(col, concrete));
  if (values.includes('none')) parts.push(isNull(col));
  return or(...parts);
}

export interface FindingListRow {
  id: number;
  projectId: string;
  /** False when projects/<id>.yaml says enabled: false (scan and triage skip it) */
  projectEnabled: boolean;
  lockfile: string;
  ecosystem: string;
  packageName: string;
  installedVersions: string[];
  fixedVersions: string[];
  osvId: string;
  cves: string[];
  aliases: string[];
  summary: string | null;
  status: FindingStatus;
  origin: FindingOrigin;
  priority: Priority | null;
  currentAction: Action | null;
  currentRuleId: string | null;
  direct: boolean | null;
  devOnly: boolean;
  inKev: boolean;
  malicious: boolean;
  epss: number | null;
  epssPercentile: number | null;
  cvssScore: number | null;
  verdict: Verdict | null;
  confidence: Confidence | null;
  /** The current labeler's label (see LABELER_COOKIE) */
  labelAction: Action | null;
  firstSeenAt: string;
}

export interface FindingList {
  rows: FindingListRow[];
  /** Matches before the limit was applied */
  total: number;
  limit: number;
}

export function compareFindingRows(sort: FindingSort): (a: FindingListRow, b: FindingListRow) => number {
  switch (sort) {
    case 'priority':
      return comparePriorityOrder;
    case 'epss':
      return (a, b) => descNullsLast(a.epss, b.epss) || comparePriorityOrder(a, b);
    case 'cvss':
      return (a, b) => descNullsLast(a.cvssScore, b.cvssScore) || comparePriorityOrder(a, b);
    case 'firstSeen':
      return (a, b) => b.firstSeenAt.localeCompare(a.firstSeenAt) || b.id - a.id;
    case 'package':
      return (a, b) =>
        a.packageName.localeCompare(b.packageName) ||
        a.projectId.localeCompare(b.projectId) ||
        a.osvId.localeCompare(b.osvId) ||
        a.id - b.id;
  }
}

function matchesQuery(row: FindingListRow, q: string): boolean {
  const needle = q.toLowerCase();
  return [row.packageName, row.osvId, ...row.aliases, ...row.cves].some((s) => s.toLowerCase().includes(needle));
}

/**
 * Simple column filters run in SQL; verdict (inside the triage JSON) and the free-text query run
 * in JS so the query stays portable to Postgres. The POC has hundreds of findings, not millions.
 * `labeled`, `expected` and `labelAction` refer to `labeler`'s labels.
 */
export function listFindings(db: Db, filters: FindingFilters, limit = FINDINGS_LIST_LIMIT, labeler = LABELER): FindingList {
  const conds: (SQL | undefined)[] = [
    filters.project.length ? inArray(findings.projectId, filters.project) : undefined,
    filters.status.length ? inArray(findings.status, filters.status) : undefined,
    inOrNull(findings.priority, filters.priority),
    inOrNull(findings.currentAction, filters.action),
    filters.origin.length ? inArray(findings.origin, filters.origin) : undefined,
    filters.expected.length ? inArray(labels.expectedAction, filters.expected) : undefined,
    filters.ids.length ? inArray(findings.id, filters.ids) : undefined,
    filters.devOnly === null ? undefined : eq(findings.devOnly, filters.devOnly),
    filters.direct === null
      ? undefined
      : filters.direct === 'unknown'
        ? isNull(findings.direct)
        : eq(findings.direct, filters.direct === 'yes'),
    filters.labeled === null ? undefined : filters.labeled ? isNotNull(labels.findingId) : isNull(labels.findingId),
  ];

  const raw = db
    .select({
      id: findings.id,
      projectId: findings.projectId,
      projectEnabled: projects.enabled,
      lockfile: findings.lockfile,
      ecosystem: findings.ecosystem,
      packageName: findings.packageName,
      installedVersions: findings.installedVersions,
      fixedVersions: findings.fixedVersions,
      osvId: findings.osvId,
      cves: advisories.cves,
      aliases: advisories.aliases,
      summary: advisories.summary,
      status: findings.status,
      origin: findings.origin,
      priority: findings.priority,
      currentAction: findings.currentAction,
      currentRuleId: findings.currentRuleId,
      direct: findings.direct,
      devOnly: findings.devOnly,
      inKev: findings.inKev,
      malicious: advisories.malicious,
      epss: findings.epss,
      epssPercentile: findings.epssPercentile,
      findingCvss: findings.cvssScore,
      advisoryCvss: advisories.cvssScore,
      output: triageRuns.output,
      runStatus: triageRuns.status,
      labelAction: labels.expectedAction,
      firstSeenAt: findings.firstSeenAt,
    })
    .from(findings)
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .leftJoin(advisories, eq(advisories.osvId, findings.osvId))
    .leftJoin(triageRuns, eq(triageRuns.id, findings.activeTriageRunId))
    .leftJoin(labels, and(eq(labels.findingId, findings.id), eq(labels.labeler, labeler)))
    .where(and(...conds))
    .all();

  let rows: FindingListRow[] = raw.map(({ findingCvss, advisoryCvss, output, runStatus, ...r }) => ({
    ...r,
    // A finding whose project row is gone (removed from projects/) counts as enabled: nothing disabled it.
    projectEnabled: r.projectEnabled ?? true,
    cves: r.cves ?? [],
    aliases: r.aliases ?? [],
    malicious: r.malicious ?? false,
    cvssScore: findingCvss ?? advisoryCvss,
    // The active run can be a failed one (the decision keeps it for the trace); the policy treats that
    // as no verdict (spec §9.5), so the list must too.
    ...readVerdict(runStatus === 'ok' ? output : null),
  }));

  if (filters.verdict.length) {
    rows = rows.filter((r) => filters.verdict.includes(r.verdict ?? 'none'));
  }
  if (filters.q) rows = rows.filter((r) => matchesQuery(r, filters.q));
  rows.sort(compareFindingRows(filters.sort));
  return { rows: rows.slice(0, limit), total: rows.length, limit };
}

export interface ProjectOption {
  id: string;
  name: string;
  enabled: boolean;
}

export function listProjectOptions(db: Db): ProjectOption[] {
  return db
    .select({ id: projects.id, name: projects.name, enabled: projects.enabled })
    .from(projects)
    .orderBy(projects.id)
    .all();
}

// ---------- finding detail ----------

/** Every triage_runs column except the large prompt and raw CLI result. */
const { prompt: _prompt, raw: _runRaw, ...runSummaryColumns } = getTableColumns(triageRuns);
type RunSummaryRow = Omit<typeof triageRuns.$inferSelect, 'prompt' | 'raw'>;

/** Every advisories column except the raw OSV record. */
const { raw: _advisoryRaw, ...advisoryColumns } = getTableColumns(advisories);

/** A triage run without its large prompt/raw columns, with the output validated. */
export type TriageRunView = Omit<RunSummaryRow, 'output'> & {
  /** Schema-valid output, else null */
  output: TriageOutput | null;
  /** The stored output when it does not match the schema (shown raw) */
  invalidOutput: unknown;
};

function toRunView(row: RunSummaryRow): TriageRunView {
  const { output: stored, ...rest } = row;
  const output = parseTriageOutput(stored);
  return { ...rest, output, invalidOutput: output === null && stored !== null ? stored : null };
}

export function getTriageRun(db: Db, runId: number): TriageRunView | null {
  const row = db.select(runSummaryColumns).from(triageRuns).where(eq(triageRuns.id, runId)).get();
  return row ? toRunView(row) : null;
}

export interface TriageTab {
  configName: string;
  active: boolean;
  runCount: number;
  latestStatus: TriageRunStatus;
  latestAt: string;
}

export interface TriageSection {
  /** Configs that have runs for this finding; the active config first */
  tabs: TriageTab[];
  selectedConfig: string | null;
  /** Runs of the selected config, newest first */
  runs: TriageRunView[];
  /** The run shown in full: ?run= when it belongs to the selected config, else the newest */
  selectedRun: TriageRunView | null;
  selectedRunRaw: { prompt: string; raw: Record<string, unknown> | null } | null;
  /** Triage state of the selected config for the finding's current inputs (spec §9.1) */
  state: { status: TriageStatus; inputHash: string; runId: number | null; reason?: string } | null;
}

export interface DecisionView {
  row: DecisionRow;
  /** True when the row is for the current policy hash and active triage config */
  isCurrent: boolean;
  /** The triage run the decision used */
  run: TriageRunView | null;
  /**
   * Set when triage changed after this decision (e.g. a standalone "Triage with …" run): the active
   * config's current state for the finding is not the one the decision used, so Decide would differ.
   */
  stale: DecisionStaleness | null;
}

export interface DecisionStaleness {
  /** The active config's ok run for the finding's current inputs, when that is what changed */
  currentRunId: number | null;
  reason: string;
}

export interface DecideJobView {
  id: number;
  status: 'queued' | 'running';
}

export interface TriageJobView {
  id: number;
  status: string;
  config: string | null;
  error: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface FindingDetail {
  finding: FindingRow;
  project: { id: string; name: string; enabled: boolean; exposure: Exposure; criticality: Criticality } | null;
  advisory: Omit<AdvisoryRow, 'raw'> | null;
  kevEntries: KevRow[];
  lastScan: { id: number; ref: string; commitSha: string | null; commitDate: string | null; startedAt: string } | null;
  triage: TriageSection;
  decision: DecisionView | null;
  label: LabelRow | null;
  /** Newest first */
  events: EventRow[];
  /** Recent triage jobs whose params name this finding, newest first */
  triageJobs: TriageJobView[];
  /** The newest queued or running decide job (top-level or a refresh-all step), if any */
  pendingDecide: DecideJobView | null;
  /** The labeler whose label `label` is */
  labeler: string;
}

function sortTabs(tabs: TriageTab[]): TriageTab[] {
  return [...tabs].sort((a, b) => Number(b.active) - Number(a.active) || a.configName.localeCompare(b.configName));
}

function buildTriageSection(
  db: Db,
  finding: FindingRow,
  ctx: Pick<DecisionContext, 'activeConfig' | 'minPriority'>,
  opts: { config?: string | null; runId?: number | null },
): TriageSection {
  const all = db
    .select(runSummaryColumns)
    .from(triageRuns)
    .where(eq(triageRuns.findingId, finding.id))
    .orderBy(desc(triageRuns.id))
    .all()
    .map(toRunView);

  const byConfig = new Map<string, TriageRunView[]>();
  for (const run of all) {
    const list = byConfig.get(run.configName) ?? [];
    list.push(run);
    byConfig.set(run.configName, list);
  }
  const tabs = sortTabs(
    [...byConfig.entries()].map(([configName, runs]) => ({
      configName,
      active: configName === ctx.activeConfig,
      runCount: runs.length,
      latestStatus: runs[0]!.status,
      latestAt: runs[0]!.createdAt,
    })),
  );

  const selectedConfig =
    (opts.config && byConfig.has(opts.config) ? opts.config : null) ??
    (byConfig.has(ctx.activeConfig) ? ctx.activeConfig : null) ??
    tabs[0]?.configName ??
    null;
  const runs = selectedConfig ? (byConfig.get(selectedConfig) ?? []) : [];
  const selectedRun = runs.find((r) => r.id === opts.runId) ?? runs[0] ?? null;
  const rawRow = selectedRun
    ? db.select({ prompt: triageRuns.prompt, raw: triageRuns.raw }).from(triageRuns).where(eq(triageRuns.id, selectedRun.id)).get()
    : undefined;

  // The current-inputs state needs the config's DB row (synced from YAML by the worker).
  const stateConfigName = selectedConfig ?? ctx.activeConfig;
  const configRow = db.select().from(triageConfigs).where(eq(triageConfigs.name, stateConfigName)).get();
  const state = configRow ? resolveTriageState(db, finding, configRow, ctx.minPriority) : null;

  return {
    tabs,
    selectedConfig,
    runs,
    selectedRun,
    selectedRunRaw: rawRow ? { prompt: rawRow.prompt, raw: rawRow.raw ?? null } : null,
    state: state ? { status: state.status, inputHash: state.inputHash, runId: state.run?.id ?? null, reason: state.reason } : null,
  };
}

/**
 * Compares a decision with what Decide would use now (spec §10 inputs): a newer ok run of the active
 * config for the current inputs, or no ok run any more although the decision used one (the inputs
 * changed). Only the ok-run check is priority-independent, so failed/pending differences that depend
 * on the policy's own priority thresholds are not flagged here.
 */
export function decisionStaleness(
  db: Db,
  finding: FindingRow,
  row: Pick<DecisionRow, 'configName' | 'triageRunId' | 'inputs'>,
  ctx: Pick<DecisionContext, 'activeConfig' | 'minPriority'>,
): DecisionStaleness | null {
  if (row.configName !== ctx.activeConfig) return null;
  const configRow = db.select().from(triageConfigs).where(eq(triageConfigs.name, ctx.activeConfig)).get();
  if (!configRow) return null;
  const state = resolveTriageState(db, finding, configRow, ctx.minPriority);
  if (state.status === 'ok' && state.run && state.run.id !== row.triageRunId) {
    return {
      currentRunId: state.run.id,
      reason:
        row.triageRunId !== null
          ? `Triage changed since this decision: run #${state.run.id} is the current verdict, the decision used run #${row.triageRunId}.`
          : `Triage changed since this decision: run #${state.run.id} succeeded, the decision had no verdict.`,
    };
  }
  if (row.inputs.triage_status === 'ok' && state.status !== 'ok') {
    return {
      currentRunId: null,
      reason: `The triage inputs changed since this decision (now ${state.status}); the verdict it used is out of date.`,
    };
  }
  return null;
}

function loadDecision(
  db: Db,
  finding: FindingRow,
  ctx: Pick<DecisionContext, 'activeConfig' | 'policyHash' | 'minPriority'>,
): DecisionView | null {
  const findingId = finding.id;
  const current = ctx.policyHash
    ? db
        .select()
        .from(decisions)
        .where(
          and(
            eq(decisions.findingId, findingId),
            eq(decisions.policyHash, ctx.policyHash),
            eq(decisions.configName, ctx.activeConfig),
          ),
        )
        .get()
    : undefined;
  const row =
    current ??
    db.select().from(decisions).where(eq(decisions.findingId, findingId)).orderBy(desc(decisions.decidedAt), desc(decisions.id)).limit(1).get();
  if (!row) return null;
  return {
    row,
    isCurrent: row === current,
    run: row.triageRunId ? getTriageRun(db, row.triageRunId) : null,
    stale: decisionStaleness(db, finding, row, ctx),
  };
}

/** The newest queued or running `decide` job, so the Finding page can show that a re-evaluation is on its way. */
/** A queued row, or a running row whose owner process is alive (a dead pid means the run was interrupted). */
function isLivePendingRow(row: { status: string; pid: number | null }): boolean {
  return row.status === 'queued' || (row.status === 'running' && row.pid !== null && isProcessAlive(row.pid));
}

export function findPendingDecideJob(db: Db): DecideJobView | null {
  const row = db
    .select({ id: jobRuns.id, status: jobRuns.status, pid: jobRuns.pid })
    .from(jobRuns)
    .where(and(eq(jobRuns.type, 'decide'), inArray(jobRuns.status, ['queued', 'running'])))
    .orderBy(desc(jobRuns.id))
    .all()
    .find(isLivePendingRow);
  return row && (row.status === 'queued' || row.status === 'running') ? { id: row.id, status: row.status } : null;
}

export function getLabel(db: Db, findingId: number, labeler = LABELER): LabelRow | null {
  return db.select().from(labels).where(and(eq(labels.findingId, findingId), eq(labels.labeler, labeler))).get() ?? null;
}

/** `params.findings` as the triage job accepts it: an id array, or a comma string from the CLI. */
export function findingParamIds(params: Record<string, unknown> | null): number[] {
  const list = params?.findings;
  const values = Array.isArray(list) ? list : typeof list === 'string' ? list.split(',') : typeof list === 'number' ? [list] : [];
  return values.map(Number).filter((n) => Number.isInteger(n) && n > 0);
}

/** Triage jobs that explicitly name this finding (e.g. from the "Triage with …" buttons). */
export function listTriageJobsForFinding(db: Db, findingId: number, limit = 5): TriageJobView[] {
  return (
    db
      // Not select(): job logs can be large and are not shown here.
      .select({
        id: jobRuns.id,
        status: jobRuns.status,
        params: jobRuns.params,
        error: jobRuns.error,
        createdAt: jobRuns.createdAt,
        finishedAt: jobRuns.finishedAt,
      })
      .from(jobRuns)
      .where(eq(jobRuns.type, 'triage'))
      .orderBy(desc(jobRuns.id))
      .limit(200)
      .all()
      .filter((j) => findingParamIds(j.params).includes(findingId))
      .slice(0, limit)
      .map((j) => ({
        id: j.id,
        status: j.status,
        config: typeof j.params.config === 'string' ? j.params.config : null,
        error: j.error,
        createdAt: j.createdAt,
        finishedAt: j.finishedAt,
      }))
  );
}

/**
 * A queued or running triage job that already covers this finding under this config (a job without
 * `config` runs the active one). The "Triage with …" button checks it so a double click does not pay
 * for the same forced triage twice.
 */
export function findPendingTriageJob(db: Db, findingId: number, config: string, activeConfig: string): number | null {
  const pending = db
    .select({ id: jobRuns.id, params: jobRuns.params, status: jobRuns.status, pid: jobRuns.pid })
    .from(jobRuns)
    .where(and(eq(jobRuns.type, 'triage'), inArray(jobRuns.status, ['queued', 'running'])))
    .orderBy(desc(jobRuns.id))
    .all()
    .filter(isLivePendingRow);
  const match = pending.find((j) => {
    const jobConfig = typeof j.params.config === 'string' ? j.params.config : activeConfig;
    return jobConfig === config && findingParamIds(j.params).includes(findingId);
  });
  return match?.id ?? null;
}

export function findingExists(db: Db, id: number): boolean {
  return db.select({ id: findings.id }).from(findings).where(eq(findings.id, id)).get() !== undefined;
}

export function getFindingDetail(
  db: Db,
  id: number,
  ctx: Pick<DecisionContext, 'activeConfig' | 'policyHash' | 'minPriority'>,
  opts: { config?: string | null; runId?: number | null; labeler?: string } = {},
): FindingDetail | null {
  const finding = db.select().from(findings).where(eq(findings.id, id)).get();
  if (!finding) return null;

  const projectRow = db.select().from(projects).where(eq(projects.id, finding.projectId)).get();
  const advisory = db.select(advisoryColumns).from(advisories).where(eq(advisories.osvId, finding.osvId)).get() ?? null;
  const cves = advisory?.cves ?? [];
  const kevEntries = cves.length ? db.select().from(kev).where(inArray(kev.cve, cves)).all() : [];
  const scan = db.select().from(scans).where(eq(scans.id, finding.lastSeenScanId)).get();
  const labeler = opts.labeler ?? LABELER;

  return {
    finding,
    project: projectRow
      ? {
          id: projectRow.id,
          name: projectRow.name,
          enabled: projectRow.enabled,
          exposure: projectRow.profile.exposure,
          criticality: projectRow.profile.criticality,
        }
      : null,
    advisory,
    kevEntries,
    lastScan: scan
      ? { id: scan.id, ref: scan.ref, commitSha: scan.commitSha, commitDate: scan.commitDate, startedAt: scan.startedAt }
      : null,
    triage: buildTriageSection(db, finding, ctx, opts),
    decision: loadDecision(db, finding, ctx),
    label: getLabel(db, id, labeler),
    events: db.select().from(events).where(eq(events.findingId, id)).orderBy(desc(events.at), desc(events.id)).all(),
    triageJobs: listTriageJobsForFinding(db, id),
    pendingDecide: findPendingDecideJob(db),
    labeler,
  };
}

// ---------- labels ----------

const optionalText = z
  .string()
  .optional()
  .transform((v) => (v && v.trim() ? v.trim() : null));

export const LabelInputSchema = z.object({
  findingId: z.coerce.number().int().positive(),
  expectedAction: z.enum(ACTIONS, { error: 'Choose an expected action (ping, digest or log)' }),
  affectedTruth: z
    .union([z.enum(AFFECTED_TRUTHS), z.literal('')])
    .optional()
    .transform((v): AffectedTruth | null => (v ? v : null)),
  note: optionalText.pipe(z.string().max(5000).nullable()),
});
export type LabelInput = z.output<typeof LabelInputSchema>;

const LABEL_FIELDS = ['findingId', 'expectedAction', 'affectedTruth', 'note'] as const;

/** Validates label form fields; returns an error message instead of throwing. */
export function parseLabelInput(
  fields: FormData | Record<string, unknown>,
): { ok: true; value: LabelInput } | { ok: false; error: string } {
  const get = (k: string): unknown => (fields instanceof FormData ? fields.get(k) : fields[k]);
  // FormData.get returns null for a missing field (e.g. no radio chosen); treat it as absent.
  const normalized = Object.fromEntries(LABEL_FIELDS.map((k) => [k, get(k) ?? undefined]));
  const parsed = LabelInputSchema.safeParse(normalized);
  if (parsed.success) return { ok: true, value: parsed.data };
  return { ok: false, error: parsed.error.issues.map((i) => i.message).join('; ') };
}

/** Insert or replace the label for (finding, labeler). Throws when the finding does not exist. */
export function upsertLabel(db: Db, input: LabelInput, labeler = LABELER): LabelRow {
  if (!findingExists(db, input.findingId)) throw new Error(`finding ${input.findingId} not found`);
  const values = {
    findingId: input.findingId,
    labeler,
    expectedAction: input.expectedAction,
    affectedTruth: input.affectedTruth,
    note: input.note,
    labeledAt: new Date().toISOString(),
  };
  return db
    .insert(labels)
    .values(values)
    .onConflictDoUpdate({
      target: [labels.findingId, labels.labeler],
      set: { expectedAction: values.expectedAction, affectedTruth: values.affectedTruth, note: values.note, labeledAt: values.labeledAt },
    })
    .returning()
    .get();
}

// ---------- source viewer ----------

export const SOURCE_CONTEXT_LINES = 40;
const MAX_SOURCE_BYTES = 2_000_000;

export type SnapshotPath = { ok: true; relPath: string; absPath: string } | { ok: false; reason: string };

/**
 * Case-insensitive because macOS volumes usually are: `.ENV` opens `.env` there, and a tracked `.Env`
 * file is not removed by the (case-sensitive) snapshot scrub.
 */
function isHiddenSegment(segment: string): boolean {
  const s = segment.toLowerCase();
  return s === '.git' || s === '.claude' || s.startsWith('.env');
}

/**
 * Lexical guard for a user-supplied snapshot path: rejects absolute paths, `..` segments, NUL bytes
 * and secrets that the snapshot scrub removes anyway, and requires the result to stay inside `root`.
 * Symlinks are checked separately by readSnapshotFile, which needs the filesystem.
 */
export function resolveSnapshotPath(root: string, requested: string): SnapshotPath {
  const fail = (reason: string): SnapshotPath => ({ ok: false, reason });
  const trimmed = requested.trim();
  if (!trimmed) return fail('No file given.');
  if (trimmed.includes('\0')) return fail('Invalid file path.');
  if (path.isAbsolute(trimmed) || /^[a-zA-Z]:/.test(trimmed) || trimmed.startsWith('\\')) {
    return fail('Absolute paths are not allowed.');
  }
  // Backslashes count as separators so `..\x` cannot slip past the `..` check.
  const segments = trimmed.split(/[\\/]+/).filter((s) => s !== '' && s !== '.');
  if (!segments.length) return fail('No file given.');
  if (segments.includes('..')) return fail('Parent-directory segments (..) are not allowed.');
  if (segments.some(isHiddenSegment)) {
    return fail('This path is never shown (secrets and tool config are removed from snapshots).');
  }
  const rootAbs = path.resolve(root);
  const absPath = path.resolve(rootAbs, ...segments);
  if (!absPath.startsWith(rootAbs + path.sep)) return fail('Path escapes the snapshot.');
  return { ok: true, relPath: segments.join('/'), absPath };
}

/**
 * Splits an absolute path inside one of the project's snapshots, `<snapshots>/<project>/<sha>/<rest>`,
 * into the commit and the snapshot-relative rest. Null for anything else.
 */
export function splitSnapshotPath(requested: string, snapshotsRoot: string, projectId: string): { commitSha: string; rest: string } | null {
  // The model reports paths from its cwd, which can be the real path (macOS: /tmp → /private/tmp).
  const roots = new Set([path.resolve(snapshotsRoot)]);
  try {
    roots.add(realpathSync(snapshotsRoot));
  } catch {
    // the snapshots root does not exist (yet); the lexical form is enough
  }
  for (const root of roots) {
    const prefix = path.join(root, projectId) + path.sep;
    if (!requested.startsWith(prefix)) continue;
    const rest = requested.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash <= 0) return null;
    return { commitSha: rest.slice(0, slash), rest: rest.slice(slash + 1) };
  }
  return null;
}

/**
 * Triage evidence may cite absolute paths inside a snapshot (the model's cwd). Strip a leading
 * `<snapshots>/<project>/<commitSha>/` so they resolve against that snapshot. A prefix naming another
 * commit is left in place (the file there may differ from this commit's), and so is anything else;
 * the result always goes through resolveSnapshotPath, which refuses absolute paths.
 */
export function stripSnapshotPrefix(requested: string, snapshotsRoot: string, projectId: string, commitSha: string): string {
  const split = splitSnapshotPath(requested, snapshotsRoot, projectId);
  return split && split.commitSha === commitSha ? split.rest : requested;
}

/** Reads a file that resolveSnapshotPath accepted, re-checking the real path so symlinks cannot escape. */
export function readSnapshotFile(root: string, absPath: string): { ok: true; text: string } | { ok: false; reason: string } {
  let realRoot: string;
  let realFile: string;
  try {
    realRoot = realpathSync(root);
  } catch {
    return { ok: false, reason: 'The snapshot directory does not exist.' };
  }
  try {
    realFile = realpathSync(absPath);
  } catch {
    return { ok: false, reason: 'File not found in the snapshot.' };
  }
  if (!realFile.startsWith(realRoot + path.sep)) return { ok: false, reason: 'Path escapes the snapshot (symlink).' };
  // A symlink inside the snapshot may point at a file the lexical check would have refused.
  if (path.relative(realRoot, realFile).split(path.sep).some(isHiddenSegment)) {
    return { ok: false, reason: 'This path is never shown (secrets and tool config are removed from snapshots).' };
  }
  const st = statSync(realFile);
  if (!st.isFile()) return { ok: false, reason: 'Not a regular file.' };
  if (st.size > MAX_SOURCE_BYTES) return { ok: false, reason: 'File is too large to display.' };
  const buf = readFileSync(realFile);
  if (buf.subarray(0, 8000).includes(0)) return { ok: false, reason: 'Binary file.' };
  return { ok: true, text: buf.toString('utf8') };
}

export interface SourceExcerpt {
  /** 1-based number of lines[0] */
  startLine: number;
  lines: string[];
  totalLines: number;
  /** Target line clamped to the file, or null when none was requested */
  line: number | null;
}

export function sourceExcerpt(text: string, line: number | null, context = SOURCE_CONTEXT_LINES): SourceExcerpt {
  const all = text.split(/\r?\n/);
  if (all.length > 1 && all[all.length - 1] === '') all.pop();
  const total = all.length;
  const target = line === null ? null : Math.min(Math.max(1, line), total);
  const start = target === null ? 1 : Math.max(1, target - context);
  const end = target === null ? Math.min(total, 2 * context + 1) : Math.min(total, target + context);
  return { startLine: start, lines: all.slice(start - 1, end), totalLines: total, line: target };
}

/** How the source viewer chose the commit whose snapshot it shows. */
export type SourceCommitVia =
  /** triage_runs.commit_sha */
  | 'run'
  /** the run's scan_id → scans.commit_sha */
  | 'run-scan'
  /** legacy run: 'at commit <sha>' in its rendered prompt */
  | 'run-prompt'
  /** the finding's latest scan (import-site links, and runs that recorded no commit) */
  | 'last-scan';

export interface SourceCommit {
  commitSha: string;
  via: SourceCommitVia;
  /** The triage run whose evidence linked here, when the link came from one */
  runId: number | null;
  runConfig: string | null;
  /** The finding's latest scanned commit */
  latestCommitSha: string | null;
  /** Shown above the file: e.g. that the run read an older commit than the latest scan */
  notes: string[];
}

export type FindingSource =
  | { ok: true; projectId: string; commitSha: string; file: string; excerpt: SourceExcerpt; commit: SourceCommit }
  | {
      ok: false;
      message: string;
      /** The finding does not exist (the page answers 404) */
      missingFinding?: boolean;
      projectId?: string;
      commitSha?: string | null;
      commit?: SourceCommit;
    };

/**
 * The sentence the code section of the prompt opens with (src/lib/triage/prompt.ts). Anchored on the
 * whole phrase, not just 'at commit <sha>': the advisory text earlier in the prompt is untrusted and can
 * mention commits ('fixed at commit …'). The last match wins, since the code section comes last.
 */
const PROMPT_COMMIT_RE = /a read-only snapshot of this project at commit ([0-9a-f]{40})\b/g;

/** Runs from before triage_runs.commit_sha existed name their commit only in the rendered prompt. */
export function commitFromPrompt(prompt: string | null | undefined): string | null {
  if (!prompt) return null;
  let sha: string | null = null;
  for (const m of prompt.matchAll(PROMPT_COMMIT_RE)) sha = m[1] ?? sha;
  return sha;
}

const short = (sha: string) => sha.slice(0, 10);

/**
 * The commit to open for a finding's source link. Evidence links carry their triage run (`runId`): the
 * run's snapshot is what the model read, and a finding keeps one run across later scans of new commits.
 * Links without a run (import sites, which each scan recomputes) use the finding's latest scan.
 */
export function resolveSourceCommit(
  db: Db,
  finding: { id: number; lastSeenScanId: number },
  runId: number | null,
): { ok: true; commit: SourceCommit } | { ok: false; message: string } {
  const scanCommit = (scanId: number | null) =>
    scanId === null ? null : (db.select({ commitSha: scans.commitSha }).from(scans).where(eq(scans.id, scanId)).get()?.commitSha ?? null);
  const latestCommitSha = scanCommit(finding.lastSeenScanId);
  const notes: string[] = [];

  if (runId !== null) {
    const run = db
      .select({ id: triageRuns.id, findingId: triageRuns.findingId, configName: triageRuns.configName, commitSha: triageRuns.commitSha, scanId: triageRuns.scanId })
      .from(triageRuns)
      .where(eq(triageRuns.id, runId))
      .get();
    if (!run || run.findingId !== finding.id) return { ok: false, message: `Triage run #${runId} is not a run of this finding.` };

    let commitSha: string | null = run.commitSha;
    let via: SourceCommitVia = 'run';
    if (!commitSha && run.scanId !== null) {
      commitSha = scanCommit(run.scanId);
      via = 'run-scan';
    }
    if (!commitSha) {
      const prompt = db.select({ prompt: triageRuns.prompt }).from(triageRuns).where(eq(triageRuns.id, run.id)).get()?.prompt;
      commitSha = commitFromPrompt(prompt);
      via = 'run-prompt';
    }
    if (commitSha) {
      if (latestCommitSha && commitSha !== latestCommitSha) {
        notes.push(
          `Run #${run.id} read commit ${short(commitSha)}; the finding's latest scan is at ${short(latestCommitSha)}. ` +
            'This is the file as the model saw it, which may differ from the code today.',
        );
      }
      return { ok: true, commit: { commitSha, via, runId: run.id, runConfig: run.configName, latestCommitSha, notes } };
    }
    if (!latestCommitSha) return { ok: false, message: `Run #${run.id} recorded no commit, and the finding's last scan has none either.` };
    notes.push(`Run #${run.id} did not record which commit it read; showing the finding's latest scanned commit, which may differ.`);
    return { ok: true, commit: { commitSha: latestCommitSha, via: 'last-scan', runId: run.id, runConfig: run.configName, latestCommitSha, notes } };
  }

  if (!latestCommitSha) return { ok: false, message: 'The finding’s last scan has no commit, so there is no snapshot.' };
  return { ok: true, commit: { commitSha: latestCommitSha, via: 'last-scan', runId: null, runConfig: null, latestCommitSha, notes } };
}

/**
 * Loads ±40 lines of a snapshot file: the snapshot the given triage run read (evidence links), else
 * the finding's latest scanned commit (import-site links). See resolveSourceCommit.
 */
export function getFindingSource(
  db: Db,
  findingId: number,
  requestedFile: string,
  line: number | null,
  snapshotsRoot: string,
  opts: { runId?: number | null } = {},
): FindingSource {
  const finding = db
    .select({ id: findings.id, projectId: findings.projectId, lastSeenScanId: findings.lastSeenScanId })
    .from(findings)
    .where(eq(findings.id, findingId))
    .get();
  if (!finding) return { ok: false, message: 'Finding not found.', missingFinding: true };
  const { projectId } = finding;
  const resolved = resolveSourceCommit(db, finding, opts.runId ?? null);
  if (!resolved.ok) return { ok: false, message: resolved.message, projectId };
  const { commit } = resolved;
  const { commitSha } = commit;
  const fail = (message: string): FindingSource => ({ ok: false, message, projectId, commitSha, commit });

  const dir = snapshotDir(snapshotsRoot, projectId, commitSha);
  const cited = splitSnapshotPath(requestedFile, snapshotsRoot, projectId);
  if (cited && cited.commitSha !== commitSha) {
    return fail(
      `This path is inside the snapshot of commit ${short(cited.commitSha)}, not ${short(commitSha)}, which this link resolves to. ` +
        'The file there may differ, so it is not shown as this commit’s.',
    );
  }
  const checked = resolveSnapshotPath(dir, stripSnapshotPrefix(requestedFile, snapshotsRoot, projectId, commitSha));
  if (!checked.ok) return fail(checked.reason);

  let dirExists = false;
  try {
    dirExists = statSync(dir).isDirectory();
  } catch {
    dirExists = false;
  }
  if (!dirExists) {
    return fail(
      `The snapshot of ${projectId} at ${short(commitSha)} is not on disk (it lives under the data directory's snapshots/ and may have been deleted). ` +
        'A scan only recreates the snapshot of the ref’s current commit.',
    );
  }
  const read = readSnapshotFile(dir, checked.absPath);
  if (!read.ok) return fail(read.reason);
  return { ok: true, projectId, commitSha, file: checked.relPath, excerpt: sourceExcerpt(read.text, line), commit };
}
