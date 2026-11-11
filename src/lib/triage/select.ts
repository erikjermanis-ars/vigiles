/**
 * Chooses which findings a triage job runs (spec §9.1):
 *   pending → yes; failed → only while fewer than MAX_ATTEMPTS_PER_HASH runs that say something about the
 *   finding exist for the current input hash (infrastructure failures do not count); ok → only with force;
 *   skipped (malicious, below min priority) → never.
 * Open-ended runs skip disabled projects; an explicit request (findingIds or projectId) does not, as with
 * scan --project. Explicitly requested findings that are filtered out are reported with the reason.
 * Ordered by priority (P0 first, unprioritised last), EPSS desc, CVSS desc, id; capped by `limit`.
 */
import { and, eq, inArray } from 'drizzle-orm';
import { sha256 } from '../config/load';
import type { Db } from '../db/client';
import { findings, labels, projects, triageConfigs, triageRuns } from '../db/schema';
import { PRIORITIES, type Priority, type TriageRunStatus } from '../types';
import { priorityAtLeast, resolveTriageState, type TriageState } from './state';

type FindingRow = typeof findings.$inferSelect;
type TriageConfigRow = typeof triageConfigs.$inferSelect;

/**
 * Runs per input hash before a failing finding stops being retried automatically (force overrides). Only runs
 * for which countsTowardRetryCap holds count.
 */
export const MAX_ATTEMPTS_PER_HASH = 2;

export interface SelectOptions {
  minPriority: Priority;
  limit: number;
  findingIds?: number[];
  projectId?: string;
  force?: boolean;
  /** Deterministic sample of n labeled open findings (consistency runs, usually with force) */
  sample?: number;
}

export interface TriageCandidate {
  finding: FindingRow;
  state: TriageState;
}

export interface TriageExclusion {
  findingId: number;
  reason: string;
}

export interface TriageSelection {
  candidates: TriageCandidate[];
  /** Eligible findings left over because of `limit` */
  remaining: number;
  /** Those left-over findings in order (the job refills slots freed by setup failures from here) */
  backlog: TriageCandidate[];
  /** Explicitly requested findings (findingIds) that are not triaged, in request order; empty for other runs */
  excluded: TriageExclusion[];
}

function priorityRank(p: Priority | null): number {
  return p ? PRIORITIES.indexOf(p) : PRIORITIES.length;
}

/** Nulls sort last; larger numbers first. */
function descNullsLast(a: number | null, b: number | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return b - a;
}

export function compareCandidates(a: FindingRow, b: FindingRow): number {
  return (
    priorityRank(a.priority) - priorityRank(b.priority) ||
    descNullsLast(a.epss, b.epss) ||
    descNullsLast(a.cvssScore, b.cvssScore) ||
    a.id - b.id
  );
}

/** Stable pseudo-random order for sampling: the same finding ids always sample the same way. */
export function sampleOrderKey(findingId: number): string {
  return sha256(`triage-sample:${findingId}`);
}

/**
 * Errors that say claude (or the account) was unavailable rather than anything about the finding: API errors,
 * overload, rate and usage limits, auth and network problems.
 */
const AVAILABILITY_ERROR =
  /api error|overloaded|rate[ _-]?limit|usage limit|limit (reached|exceeded)|hit your (usage )?limit|quota|credit balance|billing|\b(401|403|429|5\d\d)\b|unauthori[sz]ed|forbidden|authenticat|oauth|\/login|log ?in again|api key|token (has )?expired|unavailable|timed? ?out|\btimeout\b|econn\w*|enotfound|etimedout|socket hang up|network|connection (error|refused|reset)|fetch failed/i;

/** CLI result subtypes for a run that hit its own budget, turn or schema-retry limit. */
const LIMIT_SUBTYPES = new Set(['error_max_budget_usd', 'error_max_turns', 'error_max_structured_output_retries']);

/** The errors parseAttempt and runClaudeTriage record for an attempt that printed no JSON result. */
const NO_RESULT_ERROR = /^(claude exited |claude stdout is not a JSON object|could not start )/;

export interface RetryCapRun {
  status: TriageRunStatus;
  attempts: number;
  error: string | null;
  /** The CLI's JSON result (triage_runs.raw); null when claude never produced one */
  raw: Record<string, unknown> | null;
}

/**
 * Whether a stored run uses up one of the finding's automatic retries (MAX_ATTEMPTS_PER_HASH). Invalid output
 * and timeouts do, and so does a CLI failure with a parsed result that is not an availability problem (e.g. a
 * budget or turn limit). Infrastructure failures do not: a setup failure (claude never ran), a CLI that could
 * not start or printed no JSON result, and an is_error result about the API, limits or auth. Otherwise an
 * outage or usage limit would use up the retries of the highest-priority findings for good.
 */
export function countsTowardRetryCap(run: RetryCapRun): boolean {
  if (run.status === 'invalid' || run.status === 'timeout') return true;
  if (run.status !== 'failed') return false;
  if (run.attempts === 0 || !run.raw) return false;
  // The last attempt printed no result (raw is then an earlier attempt's): the CLI crashed or could not run.
  if (NO_RESULT_ERROR.test(run.error ?? '')) return false;
  // The run's own limits were hit: retrying spends the same again.
  if (typeof run.raw.subtype === 'string' && LIMIT_SUBTYPES.has(run.raw.subtype)) return true;
  // The CLI's own message: an is_error result, or (without a result) the stderr line `error` quotes. A result
  // of a run that is not is_error is the model's answer, whose words (network, timeout, ...) say nothing here.
  const hasResult = typeof run.raw.result === 'string';
  const message = run.raw.is_error === true && hasResult ? String(run.raw.result) : hasResult ? '' : (run.error ?? '');
  return !AVAILABILITY_ERROR.test(message);
}

function countRunsForHash(db: Db, findingId: number, configName: string, inputHash: string): number {
  return db
    .select({ status: triageRuns.status, attempts: triageRuns.attempts, error: triageRuns.error, raw: triageRuns.raw })
    .from(triageRuns)
    .where(
      and(
        eq(triageRuns.findingId, findingId),
        eq(triageRuns.configName, configName),
        eq(triageRuns.inputHash, inputHash),
        inArray(triageRuns.status, ['failed', 'invalid', 'timeout']),
      ),
    )
    .all()
    .filter(countsTowardRetryCap).length;
}

type Exclude = (findingId: number, reason: string) => void;

/** The requested findings that exist, are open, and match the other explicit filters; the rest are excluded. */
function requestedFindings(db: Db, ids: number[], opts: SelectOptions, exclude: Exclude): FindingRow[] {
  if (!ids.length) return [];
  const rows = new Map(
    db
      .select()
      .from(findings)
      .where(inArray(findings.id, ids))
      .all()
      .map((f) => [f.id, f]),
  );
  const projectIds = new Set(
    db
      .select({ id: projects.id })
      .from(projects)
      .all()
      .map((p) => p.id),
  );
  const labeled =
    opts.sample === undefined
      ? null
      : new Set(
          db
            .select({ id: labels.findingId })
            .from(labels)
            .where(inArray(labels.findingId, ids))
            .all()
            .map((l) => l.id),
        );
  const out: FindingRow[] = [];
  for (const id of ids) {
    const f = rows.get(id);
    if (!f) exclude(id, 'no such finding');
    else if (f.status !== 'open') exclude(id, `the finding is ${f.status}, not open`);
    else if (!projectIds.has(f.projectId)) exclude(id, `its project "${f.projectId}" is not configured`);
    else if (opts.projectId !== undefined && f.projectId !== opts.projectId)
      exclude(id, `it belongs to project "${f.projectId}", not "${opts.projectId}"`);
    else if (labeled && !labeled.has(id)) exclude(id, 'it is not labeled (a sample is drawn from labeled findings)');
    else out.push(f);
  }
  return out;
}

function openFindings(db: Db, opts: SelectOptions, exclude: Exclude): FindingRow[] {
  if (opts.findingIds !== undefined) return requestedFindings(db, [...new Set(opts.findingIds)], opts, exclude);
  const conditions = [eq(findings.status, 'open')];
  // Open-ended runs skip disabled projects; naming the project triages it anyway (as scan --project does).
  if (opts.projectId !== undefined) conditions.push(eq(findings.projectId, opts.projectId));
  else conditions.push(eq(projects.enabled, true));
  if (opts.sample !== undefined) {
    conditions.push(inArray(findings.id, db.select({ id: labels.findingId }).from(labels)));
  }
  return db
    .select({ finding: findings })
    .from(findings)
    .innerJoin(projects, eq(projects.id, findings.projectId))
    .where(and(...conditions))
    .all()
    .map((r) => r.finding);
}

export function selectTriageCandidates(db: Db, config: TriageConfigRow, opts: SelectOptions): TriageSelection {
  // Explicitly requested findings are triaged even below min priority (malicious stays skipped).
  const ignoreMinPriority = opts.findingIds !== undefined;
  const excluded: TriageExclusion[] = [];
  const exclude: Exclude = (findingId, reason) => {
    if (opts.findingIds !== undefined) excluded.push({ findingId, reason });
  };

  let triageable: TriageCandidate[] = [];
  for (const finding of openFindings(db, opts, exclude)) {
    const state = resolveTriageState(db, finding, config, opts.minPriority, { ignoreMinPriority });
    if (state.status === 'skipped') {
      exclude(finding.id, state.reason ?? 'skipped');
      continue;
    }
    // resolveTriageState reports an existing ok run before it checks min priority, so a P3 finding that was
    // once triaged on request would otherwise come back on every forced or sampled run.
    if (!ignoreMinPriority && !priorityAtLeast(finding.priority, opts.minPriority)) continue;
    triageable.push({ finding, state });
  }

  // The sample is drawn before the ok/failed filters so the same findings are picked with or without force.
  if (opts.sample !== undefined) {
    const sample = opts.sample;
    const ordered = triageable
      .map((c) => ({ c, key: sampleOrderKey(c.finding.id) }))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      .map(({ c }) => c);
    for (const c of ordered.slice(sample)) exclude(c.finding.id, `it was not drawn in the sample of ${sample}`);
    triageable = ordered.slice(0, sample);
  }

  const eligible: TriageCandidate[] = [];
  for (const c of triageable) {
    if (opts.force) {
      eligible.push(c);
      continue;
    }
    if (c.state.status === 'ok') {
      exclude(c.finding.id, `it already has an ok run under ${config.name} for its current inputs (force re-runs it)`);
      continue;
    }
    const runs = countRunsForHash(db, c.finding.id, config.name, c.state.inputHash);
    if (runs >= MAX_ATTEMPTS_PER_HASH) {
      exclude(
        c.finding.id,
        `${runs} runs under ${config.name} already failed for its current inputs (automatic retries stop at ` +
          `${MAX_ATTEMPTS_PER_HASH}; force re-runs it)`,
      );
      continue;
    }
    eligible.push(c);
  }
  eligible.sort((a, b) => compareCandidates(a.finding, b.finding));

  const cut = Math.max(0, opts.limit);
  const candidates = eligible.slice(0, cut);
  const backlog = eligible.slice(cut);
  const order = new Map((opts.findingIds ?? []).map((id, i) => [id, i]));
  excluded.sort((a, b) => (order.get(a.findingId) ?? 0) - (order.get(b.findingId) ?? 0));
  return { candidates, remaining: backlog.length, backlog, excluded };
}
