/**
 * Evaluates the decision policy for every open finding (spec §6 `decide`, §10). No LLM, no network:
 * decisions are recomputed from stored signals and triage runs inside one transaction. The base priority
 * is recomputed with the evaluated policy's thresholds (findings.priority stays enrich's to write).
 *
 * Each (finding, policy version, triage config) gets one `decisions` row. Only the current policy file
 * together with the active triage config drives findings.current_* and emits `decision_changed` events
 * (also for a first decision, from: null, so a new finding shows up in the Inbox's 'since last refresh');
 * any other combination is an evaluation (Eval page) and leaves the findings untouched.
 *
 * Two kinds of open findings are not evaluated (no decisions row) and have no current decision:
 * - findings of disabled projects (inactive until the project is enabled again);
 * - findings enrich has not scored yet (no base priority; the rules would quietly log them).
 */
import { eq, inArray } from 'drizzle-orm';
import { parsePolicy, type LoadedPolicy } from '../config/load';
import type { Db } from '../db/client';
import { advisories, decisions, events, findings, policyVersions, projects, triageConfigs } from '../db/schema';
import { resolveTriageState } from '../triage/state';
import type { Action, DecisionInputs, Priority, ProjectProfile } from '../types';
import { evaluatePolicy, validatePolicyFields } from './engine';
import { awaitingEnrichment, buildDecisionInputs, isMalicious, priorityUnderPolicy } from './inputs';
import { raiseToSameAdvisoryMax } from './same-advisory';

// The DB-free same-advisory step lives in ./same-advisory; re-exported so existing imports keep working.
export { ACTION_RANK, raiseToSameAdvisoryMax, SAME_ADVISORY_RULE, type SameAdvisoryRow } from './same-advisory';

type TriageConfigRow = typeof triageConfigs.$inferSelect;
type FindingRow = typeof findings.$inferSelect;

export interface DecideOptions {
  /** The policy file as it is now (loadPolicy). */
  currentPolicy: LoadedPolicy;
  /** Evaluate this stored version (policy_versions.hash) instead of the current file. */
  policyHash?: string;
  /** Triage config whose verdicts are used; defaults to the active one. */
  configName?: string;
  /** config.triage.min_priority: findings below it count as `skipped` rather than `pending`. */
  minPriority: Priority;
  jobRunId?: number | null;
  now?: string;
}

// A type alias (not an interface) so it is assignable to a job's Record<string, unknown> stats.
export type DecideStats = Record<Action, number> & {
  policyHash: string;
  config: string;
  /** True when this run drove findings.current_* (current policy file + active config). */
  current: boolean;
  evaluated: number;
  /** Findings whose current action changed (one decision_changed event each). Always 0 when not current. */
  changed: number;
  /** Findings that got their first current action (one decision_changed event each, from: null). Always 0 when not current. */
  firstDecisions: number;
  /** Open findings not evaluated because enrich has not scored them yet (left undecided). */
  unenriched: number;
  /** Open findings of disabled projects, not evaluated (their current decision is cleared). */
  disabledSkipped: number;
  /** Findings whose base priority under this policy's thresholds differs from findings.priority (last enrich). */
  reprioritized: number;
  /** How many findings each rule decided. */
  rules: Record<string, number>;
};

/** Loads a stored policy version, or the current file when no hash (or the current hash) is given. */
export function resolvePolicy(db: Db, current: LoadedPolicy, hash?: string): LoadedPolicy {
  if (!hash || hash === current.hash) return current;
  const row = db.select().from(policyVersions).where(eq(policyVersions.hash, hash)).get();
  if (!row) throw new Error(`policy version "${hash}" not found in policy_versions`);
  const loaded = parsePolicy(row.content, `policy_versions[${hash}]`);
  if (loaded.hash !== hash) throw new Error(`policy version "${hash}" content hashes to "${loaded.hash}"`);
  return loaded;
}

export function resolveTriageConfig(db: Db, name?: string): TriageConfigRow {
  const row = name
    ? db.select().from(triageConfigs).where(eq(triageConfigs.name, name)).get()
    : db.select().from(triageConfigs).where(eq(triageConfigs.active, true)).get();
  if (!row) throw new Error(name ? `triage config "${name}" not found` : 'no active triage config (is config synced?)');
  return row;
}

// Keeps `IN (...)` lists well under SQLite's bound-parameter limit.
function chunks<T>(items: T[], size = 500): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function maliciousByOsvId(db: Db, osvIds: string[]): Map<string, { malicious: boolean }> {
  const map = new Map<string, { malicious: boolean }>();
  for (const ids of chunks([...new Set(osvIds)])) {
    const rows = db
      .select({ osvId: advisories.osvId, malicious: advisories.malicious })
      .from(advisories)
      .where(inArray(advisories.osvId, ids))
      .all();
    for (const r of rows) map.set(r.osvId, { malicious: r.malicious });
  }
  return map;
}

export function decideAll(db: Db, opts: DecideOptions): DecideStats {
  const target = resolvePolicy(db, opts.currentPolicy, opts.policyHash);
  validatePolicyFields(target.policy);
  const config = resolveTriageConfig(db, opts.configName);
  const current = target.hash === opts.currentPolicy.hash && config.active;
  const now = opts.now ?? new Date().toISOString();
  const jobRunId = opts.jobRunId ?? null;

  const stats: DecideStats = {
    policyHash: target.hash,
    config: config.name,
    current,
    evaluated: 0,
    ping: 0,
    digest: 0,
    log: 0,
    changed: 0,
    firstDecisions: 0,
    unenriched: 0,
    disabledSkipped: 0,
    reprioritized: 0,
    rules: {},
  };

  // better-sqlite3 runs everything on one connection, so the reads inside resolveTriageState (which takes
  // `db`) are part of this transaction too. IMMEDIATE takes the write lock before the first read, so another
  // connection (CLI, dashboard) cannot commit between what we read and what we write.
  db.transaction(
    () => {
      // Normally already stored by the config sync; guarantees every decisions.policy_hash resolves to its content.
      db.insert(policyVersions).values({ hash: target.hash, content: target.content }).onConflictDoNothing().run();

      const open = db.select().from(findings).where(eq(findings.status, 'open')).orderBy(findings.id).all();
      const projectRows = new Map(
        db
          .select({ id: projects.id, profile: projects.profile, enabled: projects.enabled })
          .from(projects)
          .all()
          .map((p) => [p.id, p]),
      );
      const advisoryFlags = maliciousByOsvId(
        db,
        open.map((f) => f.osvId),
      );

      /** Clears the current decision of a finding that is not evaluated. No event: nothing was decided. */
      const clearCurrent = (stored: FindingRow) => {
        if (!current || (stored.currentAction === null && stored.currentRuleId === null && stored.activeTriageRunId === null)) return;
        db.update(findings)
          .set({ currentAction: null, currentRuleId: null, activeTriageRunId: null, decidedAt: null })
          .where(eq(findings.id, stored.id))
          .run();
      };

      const evaluated: {
        finding: FindingRow;
        action: Action;
        ruleId: string;
        inputs: DecisionInputs;
        triageRunId: number | null;
      }[] = [];

      for (const stored of open) {
        const project = projectRows.get(stored.projectId);
        if (!project) throw new Error(`finding #${stored.id}: project "${stored.projectId}" not found`);
        if (!project.enabled) {
          stats.disabledSkipped++;
          clearCurrent(stored);
          continue;
        }
        const profile: ProjectProfile = project.profile;
        const advisory = advisoryFlags.get(stored.osvId);
        if (awaitingEnrichment(stored, advisory)) {
          stats.unenriched++;
          clearCurrent(stored);
          continue;
        }
        const priority = priorityUnderPolicy(stored, profile, isMalicious(stored, advisory), target.policy.thresholds);
        if (priority !== stored.priority) stats.reprioritized++;
        // The triage state's min_priority check must see the same priority as the rules do.
        const finding = { ...stored, priority };
        const triage = resolveTriageState(db, finding, config, opts.minPriority);
        const inputs = buildDecisionInputs(finding, profile, advisory, triage);
        const { action, ruleId } = evaluatePolicy(target.policy, inputs);
        // The ok run whose verdict was used, or the failed run (so the trace can show the error).
        evaluated.push({ finding, action, ruleId, inputs, triageRunId: triage.run?.id ?? null });
      }

      if (target.policy.same_advisory === 'max') raiseToSameAdvisoryMax(evaluated);

      for (const { finding, action, ruleId, inputs, triageRunId } of evaluated) {
        db.insert(decisions)
          .values({
            findingId: finding.id,
            policyHash: target.hash,
            configName: config.name,
            triageRunId,
            action,
            ruleId,
            inputs,
            decidedAt: now,
          })
          .onConflictDoUpdate({
            target: [decisions.findingId, decisions.policyHash, decisions.configName],
            set: { action, ruleId, inputs, triageRunId, decidedAt: now },
          })
          .run();

        stats.evaluated++;
        stats[action]++;
        stats.rules[ruleId] = (stats.rules[ruleId] ?? 0) + 1;

        if (!current) continue;
        db.update(findings)
          .set({ currentAction: action, currentRuleId: ruleId, activeTriageRunId: triageRunId, decidedAt: now })
          .where(eq(findings.id, finding.id))
          .run();
        const previous = finding.currentAction;
        if (previous === action) continue;
        // A first decision is an event too: it is what puts a new (or re-enabled, or newly enriched) finding
        // into the Inbox's 'since last refresh' view.
        const data =
          previous === null
            ? { from: null, to: action, ruleId, policyHash: target.hash }
            : { from: previous, to: action, ruleId, fromRuleId: finding.currentRuleId, policyHash: target.hash };
        db.insert(events).values({ findingId: finding.id, type: 'decision_changed', jobRunId, data, at: now }).run();
        if (previous === null) stats.firstDecisions++;
        else stats.changed++;
      }
    },
    { behavior: 'immediate' },
  );

  return stats;
}
