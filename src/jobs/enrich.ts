import { loadPolicy } from '../lib/config/load';
import type { JobContext, JobHandler } from '../lib/jobs/types';
import { enrichOpenFindings } from '../lib/signals/enrich';
import type { FetchFn } from '../lib/signals/http';

/** EPSS, KEV join, CVSS score and base priority for every open finding (spec §6, §8). */
export const run: JobHandler = (ctx) => runEnrich(ctx);

export async function runEnrich(ctx: JobContext, deps: { fetchFn?: FetchFn } = {}) {
  const { policy, hash } = loadPolicy(ctx.root);
  ctx.log(`thresholds from policy ${hash}: ${JSON.stringify(policy.thresholds)}`);
  return enrichOpenFindings(ctx.db, {
    thresholds: policy.thresholds,
    fetchFn: deps.fetchFn,
    signal: ctx.signal,
    jobRunId: ctx.jobId,
    log: (m) => ctx.log(m),
    progress: (t) => ctx.progress(t),
    throwIfCancelled: () => ctx.throwIfCancelled(),
  });
}
