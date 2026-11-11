import { loadPolicy } from '../lib/config/load';
import type { JobHandler } from '../lib/jobs/types';
import { decideAll, type DecideStats } from '../lib/policy/decide';

/** Policy hashes are the first 12 hex chars of a sha256 (see parsePolicy). */
const POLICY_HASH_LENGTH = 12;

/**
 * CLI flags arrive as numbers when they look numeric, and as `true` when bare. An all-digit policy hash
 * therefore loses its leading zeros on the way in; padding back to the hash length restores it.
 */
function optionalName(params: Record<string, unknown>, key: string, padTo = 0): string | undefined {
  const v = params[key];
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v === 'string') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return String(v).padStart(padTo, '0');
  throw new Error(`decide: --${key} needs a name, got ${JSON.stringify(v)}`);
}

/**
 * Params: `policy?` (a policy_versions hash to evaluate instead of the current file),
 * `config?` (triage config name; default the active one). Spec §6, §10.
 */
export function decideParams(params: Record<string, unknown>): { policyHash?: string; configName?: string } {
  return { policyHash: optionalName(params, 'policy', POLICY_HASH_LENGTH), configName: optionalName(params, 'config') };
}

export const run: JobHandler = async (ctx) => {
  ctx.throwIfCancelled();
  const stats = decideAll(ctx.db, {
    currentPolicy: loadPolicy(ctx.root),
    ...decideParams(ctx.params),
    minPriority: ctx.config.triage.min_priority,
    jobRunId: ctx.jobId,
  });
  for (const line of decideSummary(stats)) ctx.log(line);
  return stats;
};

/** The job log lines for a decide run: the totals, then a warning per kind of finding left undecided. */
export function decideSummary(stats: DecideStats): string[] {
  const lines = [
    `policy ${stats.policyHash} × ${stats.config}${stats.current ? ' (current)' : ''}: ` +
      `${stats.evaluated} evaluated, ${stats.ping} ping, ${stats.digest} digest, ${stats.log} log, ` +
      `${stats.changed} changed, ${stats.firstDecisions} first decision(s)`,
  ];
  if (stats.unenriched) {
    lines.push(
      `warning: ${stats.unenriched} open finding(s) have no signals yet (enrich has not scored them) and were left ` +
        'undecided; run enrich (or Refresh all), then decide',
    );
  }
  if (stats.disabledSkipped) {
    lines.push(`${stats.disabledSkipped} open finding(s) of disabled projects were not evaluated (no current decision)`);
  }
  if (stats.reprioritized) {
    lines.push(
      `${stats.reprioritized} finding(s) have a different base priority under this policy's thresholds than the ` +
        'last enrich stored; decisions use the policy priority (run enrich to update the findings themselves)',
    );
  }
  return lines;
}
