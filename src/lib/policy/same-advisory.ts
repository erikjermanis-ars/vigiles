/** The policy's `same_advisory: max` step (spec §10), without the DB. policy/decide.ts re-exports it. */
import type { Action } from '../types';

/** Actions from least to most urgent. */
export const ACTION_RANK: Record<Action, number> = { log: 0, digest: 1, ping: 2 };

/** Rule id recorded when a finding was raised to match another finding of the same advisory. */
export const SAME_ADVISORY_RULE = 'same-advisory';

/** What raiseToSameAdvisoryMax reads and updates on a decided finding. */
export interface SameAdvisoryRow {
  finding: { projectId: string; lockfile: string; osvId: string };
  action: Action;
  ruleId: string;
}

/**
 * One advisory in one lockfile is one problem, even when it matches several packages: raise every finding in such a
 * group to the most urgent action of the group (rule id 'same-advisory'). Pure; mutates and returns `rows`.
 */
export function raiseToSameAdvisoryMax<T extends SameAdvisoryRow>(rows: T[]): T[] {
  const best = new Map<string, Action>();
  const key = (r: T) => `${r.finding.projectId}\0${r.finding.lockfile}\0${r.finding.osvId}`;
  for (const r of rows) {
    const k = key(r);
    const b = best.get(k);
    if (!b || ACTION_RANK[r.action] > ACTION_RANK[b]) best.set(k, r.action);
  }
  for (const r of rows) {
    const b = best.get(key(r))!;
    if (ACTION_RANK[b] > ACTION_RANK[r.action]) {
      r.action = b;
      r.ruleId = SAME_ADVISORY_RULE;
    }
  }
  return rows;
}
