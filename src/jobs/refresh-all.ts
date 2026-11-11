import type { VigilesConfig } from '../lib/config/schema';
import { CancelledError, JobFailedError, type JobContext, type JobHandler } from '../lib/jobs/types';
import type { JobType } from '../lib/types';

export interface PipelineStep {
  type: JobType;
  params?: Record<string, unknown>;
  /**
   * What a failed child does to the pipeline:
   * - `continue`: logged as a warning; the pipeline goes on and can still succeed.
   * - `fail-at-end`: logged; the pipeline goes on (the later steps work on what is stored) but fails once every
   *   step ran, so the refresh is not recorded as a success.
   * - `abort`: the failure fails the pipeline at once.
   */
  onFailure: 'continue' | 'fail-at-end' | 'abort';
  /** Why continuing is acceptable (shown in the warning). */
  softReason?: string;
}

export type StepResult = { status: 'succeeded'; stats: Record<string, unknown> } | { status: 'failed'; error: string };

export interface PipelineStats extends Record<string, unknown> {
  steps: Partial<Record<JobType, StepResult>>;
  warnings: string[];
  /** `fail-at-end` steps that failed: the pipeline ran to the end but fails. */
  failedSteps: JobType[];
}

export type PipelineDeps = Pick<JobContext, 'runChild' | 'log' | 'progress'>;

/**
 * Spec §6: sync-osv → sync-kev → scan → enrich → triage(limit) → decide.
 * A scan that failed for some project still lets enrich, triage and decide handle the findings the other
 * projects produced (they only read stored data), but the refresh fails at the end: its 'since last refresh'
 * anchor must not move past a scan that did not happen.
 */
export function refreshAllSteps(config: VigilesConfig): PipelineStep[] {
  return [
    { type: 'sync-osv', onFailure: 'continue', softReason: 'scanning with the existing OSV DB' },
    { type: 'sync-kev', onFailure: 'continue', softReason: 'using the existing KEV catalog' },
    {
      type: 'scan',
      onFailure: 'fail-at-end',
      softReason: 'enriching, triaging and deciding the findings that were scanned; the refresh fails at the end',
    },
    { type: 'enrich', onFailure: 'abort' },
    {
      type: 'triage',
      params: { limit: config.triage.max_per_run },
      onFailure: 'continue',
      softReason: 'deciding with the triage results already stored',
    },
    { type: 'decide', onFailure: 'abort' },
  ];
}

/**
 * Runs the steps in order as child jobs. Only a child job failure (JobFailedError) on a `continue` or
 * `fail-at-end` step is tolerated; cancellation and any other error always propagate at once.
 */
export async function runPipeline(steps: PipelineStep[], deps: PipelineDeps): Promise<PipelineStats> {
  const result: PipelineStats = { steps: {}, warnings: [], failedSteps: [] };
  for (const [i, step] of steps.entries()) {
    deps.progress(`step ${i + 1}/${steps.length}: ${step.type}`);
    try {
      const stats = await deps.runChild(step.type, step.params ?? {});
      result.steps[step.type] = { status: 'succeeded', stats };
    } catch (err) {
      if (err instanceof CancelledError || !(err instanceof JobFailedError) || step.onFailure === 'abort') throw err;
      result.steps[step.type] = { status: 'failed', error: err.message };
      if (step.onFailure === 'fail-at-end') result.failedSteps.push(step.type);
      const warning = `${err.message}; continuing${step.softReason ? ` (${step.softReason})` : ''}`;
      result.warnings.push(warning);
      deps.log(`warning: ${warning}`);
    }
  }
  return result;
}

/** Thrown after a pipeline that ran to the end with a `fail-at-end` failure; carries its stats to the job row. */
export class PipelineFailedError extends Error {
  constructor(public stats: PipelineStats) {
    const details = stats.failedSteps.map((t) => {
      const r = stats.steps[t];
      return r?.status === 'failed' ? r.error : t;
    });
    super(`refresh completed with failures: ${stats.failedSteps.join(', ')}\n${details.join('\n')}`);
    // The stack would only point here; the message already says what failed.
    this.stack = this.message;
  }
}

export const run: JobHandler = async (ctx) => {
  const stats = await runPipeline(refreshAllSteps(ctx.config), ctx);
  if (stats.failedSteps.length) {
    ctx.log(`done; failed: ${stats.failedSteps.join(', ')} (${stats.warnings.length} warning(s))`);
    throw new PipelineFailedError(stats);
  }
  ctx.log(stats.warnings.length ? `done with ${stats.warnings.length} warning(s)` : 'done');
  return stats;
};
