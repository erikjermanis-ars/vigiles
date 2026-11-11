/**
 * `triage` job (spec §6, §9): runs Claude on the findings that need it under one triage config.
 *
 *   npm run job -- triage [--config v1-sonnet-high-code] [--project x] [--findings 1,2] [--limit n]
 *                         [--force] [--tag consistency] [--sample 20]
 *
 * Only one triage job runs at a time (another process's running triage makes this one fail at once), so two
 * jobs never select and pay for the same findings. An explicit --findings request fails, before claude runs,
 * when any requested finding cannot be triaged; each reason is logged.
 */
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { jobRuns, projects, triageConfigs } from '../lib/db/schema';
import { describeLiveJob, liveRunningJobs } from '../lib/jobs/queue';
import type { JobContext, JobHandler } from '../lib/jobs/types';
import { getClaudeVersion, type ClaudeTriageResult } from '../lib/triage/claude';
import { loadTriagePrompt } from '../lib/triage/prompt';
import { forEachConcurrent, memoizedSnapshots, triageFinding } from '../lib/triage/runner';
import { selectTriageCandidates, type TriageCandidate } from '../lib/triage/select';
import type { TriageRunStatus } from '../lib/types';

// Strict: a mistyped flag (`--finding 3`) must fail rather than silently widen the run to max_per_run paid triages.
const ParamsSchema = z
  .object({
    config: z.coerce.string().optional(),
    project: z.coerce.string().optional(),
    // The CLI passes `--findings 1,2` as [1, 2]; a lone id or a comma string also works.
    findings: z
      .union([z.array(z.coerce.number()), z.coerce.string().transform((s) => s.split(',').filter(Boolean).map(Number))])
      .pipe(z.array(z.number().int().positive()))
      .optional(),
    limit: z.coerce.number().int().positive().optional(),
    force: z.union([z.boolean(), z.enum(['true', 'false']).transform((v) => v === 'true')]).optional(),
    tag: z.coerce.string().optional(),
    sample: z.coerce.number().int().positive().optional(),
  })
  .strict();

/**
 * Findings in a row whose every claude attempt failed at the CLI level (is_error, bad exit, no JSON).
 * That pattern means claude itself is unavailable (usage limit, auth, outage), not that the findings are
 * hard; carrying on would only spend time (and, for the failures that do count, each remaining finding's
 * MAX_ATTEMPTS_PER_HASH retries).
 */
export const MAX_CONSECUTIVE_CLI_FAILURES = 3;

type Counts = Record<TriageRunStatus, number>;

function describe(c: TriageCandidate, r: ClaudeTriageResult): string {
  const f = c.finding;
  const verdict = r.output ? ` ${r.output.verdict}/${r.output.confidence} → ${r.output.suggested_action}` : '';
  const cost = r.costUsd === null ? '' : ` · $${r.costUsd.toFixed(4)}`;
  const time = r.durationMs === null ? '' : ` · ${(r.durationMs / 1000).toFixed(1)}s`;
  const turns = r.numTurns === null ? '' : ` · ${r.numTurns} turns`;
  const retry = r.attempts > 1 ? ` · ${r.attempts} attempts` : '';
  const error = r.status === 'ok' ? '' : ` · ${r.error ?? ''}`;
  return `#${f.id} ${f.osvId} ${f.packageName} (${f.priority ?? 'no priority'}): ${r.status}${verdict}${cost}${time}${turns}${retry}${error}`;
}

/**
 * Fails when a live process is running another triage job (top-level, or the step of a Refresh all) that
 * started before this one. Of two jobs that start at the same moment and see each other, the later one (by
 * started_at, then id) gives way, so exactly one runs. A process runs one triage at a time, so another row
 * with this process's pid was left by an earlier process that had the same pid.
 */
function assertNoOtherTriage(ctx: JobContext): void {
  const own = ctx.db.select({ startedAt: jobRuns.startedAt }).from(jobRuns).where(eq(jobRuns.id, ctx.jobId)).get();
  const startedBefore = (j: { id: number; startedAt: string | null }) =>
    !own?.startedAt || !j.startedAt || j.startedAt < own.startedAt || (j.startedAt === own.startedAt && j.id < ctx.jobId);
  const other = liveRunningJobs(ctx.db, { type: 'triage' }).find((j) => j.id !== ctx.jobId && j.pid !== process.pid && startedBefore(j));
  if (other) {
    throw new Error(
      `another triage job is running: ${describeLiveJob(other)}. Two triage jobs would select and pay for the ` +
        'same findings; wait for it to finish (or cancel it), then run this one again',
    );
  }
}

/** claude never ran (no snapshot, missing advisory, …): the run does not count toward the finding's retries. */
const isSetupFailure = (r: ClaudeTriageResult) => r.status === 'failed' && r.attempts === 0;

export const run: JobHandler = async (ctx) => {
  const params = ParamsSchema.parse(ctx.params);
  assertNoOtherTriage(ctx);
  const configName = params.config ?? ctx.config.triage.active_config;
  const triageConfig = ctx.db.select().from(triageConfigs).where(eq(triageConfigs.name, configName)).get();
  if (!triageConfig) throw new Error(`unknown triage config "${configName}" (see triage.configs in config/vigiles.yaml)`);
  if (params.project !== undefined && !ctx.db.select({ id: projects.id }).from(projects).where(eq(projects.id, params.project)).get()) {
    throw new Error(`unknown project "${params.project}" (no projects/${params.project}.yaml)`);
  }

  // An explicit request (--findings, --sample) is already bounded by what was asked for; max_per_run only
  // caps open-ended runs. A truncated --sample would also skew the consistency experiment.
  const limit = params.limit ?? Math.max(ctx.config.triage.max_per_run, params.findings?.length ?? 0, params.sample ?? 0);
  const selection = selectTriageCandidates(ctx.db, triageConfig, {
    minPriority: ctx.config.triage.min_priority,
    limit,
    findingIds: params.findings,
    projectId: params.project,
    force: params.force,
    sample: params.sample,
  });
  if (selection.excluded.length) {
    for (const e of selection.excluded) ctx.log(`#${e.findingId} cannot be triaged under ${configName}: ${e.reason}`);
    const requested = new Set(params.findings).size;
    const list = selection.excluded.map((e) => `#${e.findingId}: ${e.reason}`);
    const shown = list.slice(0, 5).join('; ') + (list.length > 5 ? `; and ${list.length - 5} more (see the log)` : '');
    throw new Error(
      `${selection.excluded.length} of ${requested} requested finding(s) cannot be triaged under ${configName}, ` +
        `so nothing was run. ${shown}`,
    );
  }

  const backlog = [...selection.backlog];
  let total = selection.candidates.length;
  const counts: Counts = { ok: 0, failed: 0, invalid: 0, timeout: 0, cancelled: 0 };
  let costUsd = 0;
  const stats = () => ({ config: configName, selected: total, ...counts, costUsd: Number(costUsd.toFixed(4)), remaining: backlog.length });

  ctx.log(`config ${configName}: ${total} selected, ${backlog.length} left for later runs (limit ${limit})`);
  if (!total) return stats();

  const prompt = loadTriagePrompt(ctx.root, triageConfig.promptVersion);
  const claudeVersion = await getClaudeVersion(ctx.config.bin.claude, ctx.signal);
  ctx.log(`claude ${claudeVersion}; model ${triageConfig.model}, effort ${triageConfig.effort}, code access ${triageConfig.codeAccess}`);

  const env = {
    db: ctx.db,
    config: ctx.config,
    paths: ctx.paths,
    triageConfig,
    prompt,
    claudeVersion,
    jobRunId: ctx.jobId,
    tag: params.tag ?? null,
    signal: ctx.signal,
    snapshots: memoizedSnapshots(ctx.config.bin.git, ctx.paths.snapshots),
  };

  let done = 0;
  let started = 0;
  let cliFailuresInARow = 0;
  let lastCliError = '';
  // Stops starting new findings without killing the runs in flight (those use ctx.signal).
  const breaker = new AbortController();
  const running = AbortSignal.any([ctx.signal, breaker.signal]);
  ctx.progress(`triage 0/${total}`);

  // A setup failure does not count toward the finding's retries, so the same findings would take the first
  // slots of every run; each one frees its slot for the next eligible finding instead.
  let wave = selection.candidates;
  while (wave.length) {
    let freed = 0;
    started += await forEachConcurrent(wave, ctx.config.triage.concurrency, running, async (candidate) => {
      const { result } = await triageFinding(env, candidate);
      counts[result.status]++;
      costUsd += result.costUsd ?? 0;
      done++;
      if (isSetupFailure(result)) freed++;
      ctx.progress(`triage ${done}/${total}`);
      for (const e of result.retriedErrors) ctx.log(`#${candidate.finding.id} retried after ${e}`);
      if (result.permissionDenials) ctx.log(`#${candidate.finding.id} ${result.permissionDenials} tool call(s) were denied by the CLI`);
      ctx.log(describe(candidate, result));

      // Setup failures (attempts 0) and cancels say nothing about claude's health.
      if (result.status === 'failed' && result.attempts > 0) {
        cliFailuresInARow++;
        lastCliError = result.error ?? '';
        if (cliFailuresInARow >= MAX_CONSECUTIVE_CLI_FAILURES) breaker.abort();
      } else if (result.status !== 'cancelled' && result.attempts > 0) {
        cliFailuresInARow = 0;
      }
    });
    if (running.aborted || started < total || !freed || !backlog.length) break;
    wave = backlog.splice(0, freed);
    total += wave.length;
    ctx.log(`${freed} setup failure(s) did not run claude; taking ${wave.length} more finding(s) from the backlog`);
  }

  ctx.throwIfCancelled();
  ctx.log(`done: ${counts.ok} ok, ${done - counts.ok} not ok, $${costUsd.toFixed(4)}`);
  if (breaker.signal.aborted && started < total) {
    throw new Error(
      `stopped: claude failed for ${cliFailuresInARow} findings in a row, ${total - started} not started ` +
        `(usage limit or outage?). Last error: ${lastCliError}`,
    );
  }
  return stats();
};
