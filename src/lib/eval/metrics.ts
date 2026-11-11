/**
 * Evaluation metrics (spec §11.2). Pure functions over plain rows so they can be unit-tested
 * without a database; src/lib/queries/eval.ts gathers the rows.
 */
import { ACTIONS, type Action, type AffectedTruth, type Priority, type TriageRunStatus, type Verdict } from '../types';

// ---------- ratios ----------

/** A fraction that keeps its parts, so the UI can show "7/9" and a zero denominator stays visible as "—". */
export interface Ratio {
  num: number;
  den: number;
  value: number | null;
}

export function ratio(num: number, den: number): Ratio {
  return { num, den, value: den === 0 ? null : num / den };
}

/**
 * Percentage rounded down, so a ratio below a target never displays as meeting it
 * (199/200 ping recall reads "99%", not "100%"). The epsilon absorbs float noise such as 0.29 * 100 = 28.999….
 */
export function floorPct(value: number, digits = 0): string {
  const f = 10 ** digits;
  return `${(Math.floor(value * 100 * f + 1e-9) / f).toFixed(digits)}%`;
}

// ---------- deciders ----------

/** The "base priority only" decider: P0/P1 → ping, P2 → digest, P3 or no priority → log. */
export function basePriorityAction(priority: Priority | null | undefined): Action {
  if (priority === 'P0' || priority === 'P1') return 'ping';
  if (priority === 'P2') return 'digest';
  return 'log';
}

/** One labeled finding as seen by one decider. */
export interface ActionPair {
  label: Action;
  decided: Action;
}

/** counts[label][decided]: rows are your label, columns the decider's action. */
export type ConfusionMatrix = Record<Action, Record<Action, number>>;

export function emptyMatrix(): ConfusionMatrix {
  const row = () => Object.fromEntries(ACTIONS.map((a) => [a, 0])) as Record<Action, number>;
  return { ping: row(), digest: row(), log: row() };
}

export function confusionMatrix(pairs: readonly ActionPair[]): ConfusionMatrix {
  const m = emptyMatrix();
  for (const p of pairs) m[p.label][p.decided]++;
  return m;
}

/** Of the findings you labeled ping, the share the decider also pinged (target 100%). */
export function pingRecall(pairs: readonly ActionPair[]): Ratio {
  const labeledPing = pairs.filter((p) => p.label === 'ping');
  return ratio(labeledPing.filter((p) => p.decided === 'ping').length, labeledPing.length);
}

/** Of the decider's pings, the share you labeled ping (target ≥ 80%). */
export function pingPrecision(pairs: readonly ActionPair[]): Ratio {
  const decidedPing = pairs.filter((p) => p.decided === 'ping');
  return ratio(decidedPing.filter((p) => p.label === 'ping').length, decidedPing.length);
}

export function exactAccuracy(pairs: readonly ActionPair[]): Ratio {
  return ratio(pairs.filter((p) => p.label === p.decided).length, pairs.length);
}

export interface DeciderMetrics {
  n: number;
  pingRecall: Ratio;
  pingPrecision: Ratio;
  accuracy: Ratio;
  matrix: ConfusionMatrix;
}

export function deciderMetrics(pairs: readonly ActionPair[]): DeciderMetrics {
  return {
    n: pairs.length,
    pingRecall: pingRecall(pairs),
    pingPrecision: pingPrecision(pairs),
    accuracy: exactAccuracy(pairs),
    matrix: confusionMatrix(pairs),
  };
}

export const TARGETS = {
  pingRecall: 1,
  pingPrecision: 0.8,
  consistency: 0.9,
} as const;

// ---------- verdict accuracy ----------

/** yes ↔ affected / likely_affected; no ↔ not_affected / likely_not_affected; unsure or missing → not scorable (null). */
export function verdictMatchesTruth(verdict: Verdict | null | undefined, truth: AffectedTruth | null | undefined): boolean | null {
  if (!verdict || !truth || truth === 'unsure') return null;
  const saysAffected = verdict === 'affected' || verdict === 'likely_affected';
  return truth === 'yes' ? saysAffected : !saysAffected;
}

export interface VerdictAccuracy extends Ratio {
  /** affected_truth missing or 'unsure' */
  excludedNoTruth: number;
  /** truth given but no ok triage verdict */
  excludedNoVerdict: number;
}

export function verdictAccuracy(rows: readonly { truth: AffectedTruth | null; verdict: Verdict | null }[]): VerdictAccuracy {
  let correct = 0;
  let scored = 0;
  let excludedNoTruth = 0;
  let excludedNoVerdict = 0;
  for (const r of rows) {
    if (!r.truth || r.truth === 'unsure') {
      excludedNoTruth++;
      continue;
    }
    if (!r.verdict) {
      excludedNoVerdict++;
      continue;
    }
    scored++;
    if (verdictMatchesTruth(r.verdict, r.truth)) correct++;
  }
  return { ...ratio(correct, scored), excludedNoTruth, excludedNoVerdict };
}

// ---------- consistency ----------

export interface RunOutcome {
  verdict: Verdict;
  /** The run's own suggested_action */
  action: Action;
  /** The action the evaluated policy takes with this run as the finding's verdict; null when it could not be computed */
  policyAction?: Action | null;
}

export interface Consistency {
  /** Findings (per config and input hash) with at least two ok runs */
  groups: number;
  runs: number;
  /**
   * Groups whose runs all lead to the same policy action: the "same triage config run twice gives the same action"
   * exit criterion (≥ 90%). Only groups where every run has a policy action are scored.
   */
  identicalPolicyAction: Ratio;
  identicalVerdict: Ratio;
  /** Same suggested_action (the LLM's own opinion, which the policy only partly uses) */
  identicalAction: Ratio;
}

/** Each inner array is the ok runs of one finding under one config and input hash. Groups with < 2 runs are ignored. */
export function consistency(groups: readonly (readonly RunOutcome[])[]): Consistency {
  const repeated = groups.filter((g) => g.length >= 2);
  const allSame = <T>(xs: readonly T[]) => xs.every((x) => x === xs[0]);
  const withPolicy = repeated.filter((g) => g.every((r) => r.policyAction != null));
  return {
    groups: repeated.length,
    runs: repeated.reduce((n, g) => n + g.length, 0),
    identicalPolicyAction: ratio(withPolicy.filter((g) => allSame(g.map((r) => r.policyAction))).length, withPolicy.length),
    identicalVerdict: ratio(repeated.filter((g) => allSame(g.map((r) => r.verdict))).length, repeated.length),
    identicalAction: ratio(repeated.filter((g) => allSame(g.map((r) => r.action))).length, repeated.length),
  };
}

// ---------- cost and time ----------

/** Linear-interpolated quantile (q in [0, 1]); null for an empty list. */
export function quantile(values: readonly number[], q: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * Math.min(1, Math.max(0, q));
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (pos - lo);
}

export const median = (values: readonly number[]) => quantile(values, 0.5);

export interface TriageRunSample {
  status: TriageRunStatus;
  durationMs: number | null;
  costUsd: number | null;
  numTurns: number | null;
}

export interface RunStats {
  runs: number;
  /** Runs the user cancelled; they count in `runs` and in the total cost, but not in the ok rate or the time quantiles */
  cancelled: number;
  okRate: Ratio;
  durationMs: { median: number | null; p90: number | null };
  costUsd: { median: number | null; p90: number | null; total: number };
  medianTurns: number | null;
}

/**
 * Cost and time per run. Failed attempts count (they cost money and time too); runs the user cancelled are
 * no verdict on the model, and their truncated durations would pull the time quantiles down. Values that were
 * never recorded are skipped.
 */
export function triageRunStats(runs: readonly TriageRunSample[]): RunStats {
  const present = (xs: (number | null)[]) => xs.filter((x): x is number => x !== null && Number.isFinite(x));
  const finished = runs.filter((r) => r.status !== 'cancelled');
  const durations = present(finished.map((r) => r.durationMs));
  const costs = present(finished.map((r) => r.costUsd));
  const cancelledCost = present(runs.filter((r) => r.status === 'cancelled').map((r) => r.costUsd));
  return {
    runs: runs.length,
    cancelled: runs.length - finished.length,
    okRate: ratio(finished.filter((r) => r.status === 'ok').length, finished.length),
    durationMs: { median: median(durations), p90: quantile(durations, 0.9) },
    costUsd: { median: median(costs), p90: quantile(costs, 0.9), total: [...costs, ...cancelledCost].reduce((a, b) => a + b, 0) },
    medianTurns: median(present(finished.map((r) => r.numTurns))),
  };
}

// ---------- inter-labeler agreement ----------

export interface Agreement {
  n: number;
  agree: Ratio;
  /** Cohen's kappa: agreement corrected for chance; null when undefined (no pairs, or both always pick one class). */
  kappa: number | null;
}

export function labelerAgreement(pairs: readonly { a: Action; b: Action }[]): Agreement {
  const n = pairs.length;
  const agreeCount = pairs.filter((p) => p.a === p.b).length;
  if (n === 0) return { n, agree: ratio(0, 0), kappa: null };
  const po = agreeCount / n;
  let pe = 0;
  for (const k of ACTIONS) {
    pe += (pairs.filter((p) => p.a === k).length / n) * (pairs.filter((p) => p.b === k).length / n);
  }
  return { n, agree: ratio(agreeCount, n), kappa: pe === 1 ? null : (po - pe) / (1 - pe) };
}

// ---------- message volume ----------

export interface VolumeRow {
  projectId: string;
  pingMessages: number;
  pingFindings: number;
  digestMessages: number;
  digestFindings: number;
  logFindings: number;
}

/** Counts Slack-style messages per project: one message per (project, package) per action, as the Inbox groups them (§12). */
export function messageVolume(rows: readonly { projectId: string; packageName: string; action: Action | null }[]): VolumeRow[] {
  const byProject = new Map<string, { row: VolumeRow; ping: Set<string>; digest: Set<string> }>();
  for (const r of rows) {
    let acc = byProject.get(r.projectId);
    if (!acc) {
      acc = {
        row: { projectId: r.projectId, pingMessages: 0, pingFindings: 0, digestMessages: 0, digestFindings: 0, logFindings: 0 },
        ping: new Set(),
        digest: new Set(),
      };
      byProject.set(r.projectId, acc);
    }
    if (r.action === 'ping') {
      acc.row.pingFindings++;
      acc.ping.add(r.packageName);
    } else if (r.action === 'digest') {
      acc.row.digestFindings++;
      acc.digest.add(r.packageName);
    } else if (r.action === 'log') {
      acc.row.logFindings++;
    }
  }
  return [...byProject.values()]
    .map(({ row, ping, digest }) => ({ ...row, pingMessages: ping.size, digestMessages: digest.size }))
    .sort((a, b) => a.projectId.localeCompare(b.projectId));
}
