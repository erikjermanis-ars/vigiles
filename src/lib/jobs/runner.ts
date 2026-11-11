/** Executes job_runs rows. Used by the worker loop and the inline CLI; children run inline via ctx.runChild. */
import { and, eq, inArray, isNull, notInArray, or, sql } from 'drizzle-orm';
import { handlers } from '../../jobs';
import { dataPaths, loadVigilesConfig, repoRoot } from '../config/load';
import { syncConfigToDb } from '../config/sync';
import type { Db } from '../db/client';
import { jobRuns, scans } from '../db/schema';
import type { JobType } from '../types';
import { isProcessAlive, nextQueuedJob } from './queue';
import { CancelledError, JobFailedError, type JobContext } from './types';

const nowIso = () => new Date().toISOString();

function errorText(err: unknown): string {
  if (err instanceof Error) return err.stack ?? err.message;
  return String(err);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * A handler may attach the stats it gathered to the error it throws (`Object.assign(err, { stats })`), e.g. a
 * scan that failed for one project but scanned the others. They are stored on the failed row.
 */
function statsOf(err: unknown): Record<string, unknown> | undefined {
  const stats = isRecord(err) ? err.stats : undefined;
  return isRecord(stats) ? stats : undefined;
}

/** "cancelled", plus the reason a top-level signal was aborted with (e.g. "worker received SIGTERM"). */
function cancelText(signal: AbortSignal): string {
  return typeof signal.reason === 'string' && signal.reason ? `cancelled (${signal.reason})` : 'cancelled';
}

export interface RunJobOptions {
  /** Shared with children so cancelling the parent aborts them. Only runChild passes it. */
  controller?: AbortController;
  /**
   * Top-level jobs: an external stop request (worker or CLI shutdown). Aborting it cancels the job as a Cancel
   * click would: children are killed through ctx.signal and the row is recorded `cancelled` before runJob
   * resolves. The cancel_requested poll keeps running alongside it. Abort with a string reason to record it.
   */
  signal?: AbortSignal;
  echo?: (line: string) => void;
}

/**
 * Runs the job row `id` to completion and returns its final status.
 * Never throws for job failures (they are recorded on the row); `runChild` turns them into JobFailedError.
 * The row records this process's pid while it runs, so a restarting worker can tell it is still owned.
 */
export async function runJob(db: Db, id: number, opts: RunJobOptions = {}): Promise<'succeeded' | 'failed' | 'cancelled'> {
  const row = db.select().from(jobRuns).where(eq(jobRuns.id, id)).get();
  if (!row) throw new Error(`job ${id} not found`);
  const controller = opts.controller ?? new AbortController();
  const echo = opts.echo ?? ((l: string) => console.log(l));
  const root = repoRoot();

  // A queued job cancelled from the dashboard between being picked and being started stays cancelled.
  const started = db
    .update(jobRuns)
    .set({ status: 'running', startedAt: nowIso(), pid: process.pid })
    .where(and(eq(jobRuns.id, id), inArray(jobRuns.status, ['queued', 'running'])))
    .run();
  if (started.changes === 0) {
    const status = db.select({ s: jobRuns.status }).from(jobRuns).where(eq(jobRuns.id, id)).get()?.s;
    return status === 'succeeded' || status === 'failed' ? status : 'cancelled';
  }

  const external = opts.signal;
  const forward = () => controller.abort(external?.reason);
  if (external) {
    if (external.aborted) forward();
    else external.addEventListener('abort', forward, { once: true });
  }

  // Poll cancel_requested for top-level jobs (children share the parent's controller).
  let cancelPoll: NodeJS.Timeout | undefined;
  if (!opts.controller) {
    cancelPoll = setInterval(() => {
      const r = db.select({ c: jobRuns.cancelRequested }).from(jobRuns).where(eq(jobRuns.id, id)).get();
      if (r?.c) controller.abort();
    }, 1000);
  }

  const ctx: JobContext = {
    db,
    jobId: id,
    type: row.type as JobType,
    params: row.params ?? {},
    config: loadVigilesConfig(root),
    paths: dataPaths(loadVigilesConfig(root)),
    root,
    signal: controller.signal,
    log(message) {
      const line = `${nowIso().slice(11, 19)} ${message}`;
      db.update(jobRuns)
        .set({ log: sql`${jobRuns.log} || ${line + '\n'}` })
        .where(eq(jobRuns.id, id))
        .run();
      echo(`[${row.type}#${id}] ${message}`);
    },
    progress(text) {
      db.update(jobRuns).set({ progress: text }).where(eq(jobRuns.id, id)).run();
    },
    throwIfCancelled() {
      if (controller.signal.aborted) throw new CancelledError();
    },
    async runChild(type, params = {}) {
      if (controller.signal.aborted) throw new CancelledError();
      const child = db.insert(jobRuns).values({ type, params, status: 'queued', parentId: id }).returning({ id: jobRuns.id }).get();
      const status = await runJob(db, child.id, { controller, echo });
      const done = db.select().from(jobRuns).where(eq(jobRuns.id, child.id)).get();
      if (status === 'cancelled') throw new CancelledError();
      if (status === 'failed') throw new JobFailedError(type, child.id, (done?.error ?? '').split('\n')[0] ?? '');
      return (done?.stats ?? {}) as Record<string, unknown>;
    },
  };

  try {
    syncConfigToDb(db, root);
    const handler = handlers[ctx.type];
    if (!handler) throw new Error(`unknown job type ${row.type}`);
    const stats = (await handler(ctx)) ?? {};
    // `error` is cleared: a row reclaimed by mistake (or retried) must not keep an old error next to `succeeded`.
    db.update(jobRuns)
      .set({ status: 'succeeded', stats, error: null, finishedAt: nowIso(), progress: null })
      .where(eq(jobRuns.id, id))
      .run();
    return 'succeeded';
  } catch (err) {
    const cancelled = err instanceof CancelledError || controller.signal.aborted;
    const stats = statsOf(err);
    db.update(jobRuns)
      .set({
        status: cancelled ? 'cancelled' : 'failed',
        error: cancelled ? cancelText(controller.signal) : errorText(err),
        finishedAt: nowIso(),
        ...(stats ? { stats } : {}),
      })
      .where(eq(jobRuns.id, id))
      .run();
    if (!cancelled) echo(`[${row.type}#${id}] FAILED: ${errorText(err)}`);
    return cancelled ? 'cancelled' : 'failed';
  } finally {
    if (cancelPoll) clearInterval(cancelPoll);
    external?.removeEventListener('abort', forward);
  }
}

/**
 * Marks job rows left `running` by a process that is gone (crashed or restarted worker, killed CLI) as failed,
 * and the scans they left running. Rows whose pid is still alive belong to another live process (an inline
 * CLI job next to the worker) and are left alone, together with their scans. Rows without a pid predate pid
 * tracking and are reclaimed.
 *
 * Call it before this process runs any job (worker startup): a row that names this process's own pid was left
 * by an earlier process that had the same pid (pids are reused), so it is reclaimed too.
 */
export function failInterruptedJobs(db: Db, alive: (pid: number) => boolean = isProcessAlive): number {
  const running = db.select({ id: jobRuns.id, pid: jobRuns.pid }).from(jobRuns).where(eq(jobRuns.status, 'running')).all();
  const dead = running.filter((r) => r.pid === null || r.pid === process.pid || !alive(r.pid));
  const live = running.filter((r) => !dead.includes(r)).map((r) => r.id);
  const now = nowIso();
  for (const r of dead) {
    db.update(jobRuns)
      .set({
        status: 'failed',
        error: r.pid === null ? 'interrupted (worker restarted)' : `interrupted (process ${r.pid} is gone)`,
        finishedAt: now,
      })
      .where(and(eq(jobRuns.id, r.id), eq(jobRuns.status, 'running')))
      .run();
  }
  db.update(scans)
    .set({ status: 'failed', error: 'interrupted', finishedAt: now })
    .where(and(eq(scans.status, 'running'), live.length ? or(isNull(scans.jobRunId), notInArray(scans.jobRunId, live)) : undefined))
    .run();
  return dead.length;
}

/** Repeats of a stop signal this soon after the first are echoes of the same Ctrl-C (see onStopSignals). */
export const SIGNAL_ECHO_MS = 3000;

const STOP_SIGNALS = ['SIGINT', 'SIGTERM'] as const;

export interface StopSignalHandlers {
  /** The first SIGINT/SIGTERM: cancel the job in progress and let its row be recorded. */
  stop(signal: NodeJS.Signals): void;
  /** A signal more than SIGNAL_ECHO_MS after the first: the user insists, exit at once. */
  force(signal: NodeJS.Signals): void;
}

export interface StopSignalOptions {
  echoMs?: number;
  now?: () => number;
  /** Defaults to `process`. */
  target?: Pick<NodeJS.EventEmitter, 'on' | 'off'>;
}

/**
 * SIGINT/SIGTERM handling for the worker and the inline CLI: the first signal calls `stop`; one that comes
 * later than `echoMs` after it calls `force`. Repeats in between are ignored, because one Ctrl-C reaches a
 * job process several times: the terminal signals the whole process group, npm (`npm run`) and tsx forward
 * the signal to their child once more, `concurrently` sends it down the process tree again, and with `-k`
 * also sends SIGTERM once the dashboard has exited. Taking those echoes for a second Ctrl-C would exit
 * before the cancelled job is recorded, leaving its row `running`. Returns a function that removes the handlers.
 */
export function onStopSignals(handlers: StopSignalHandlers, opts: StopSignalOptions = {}): () => void {
  const target = opts.target ?? process;
  const now = opts.now ?? Date.now;
  const echoMs = opts.echoMs ?? SIGNAL_ECHO_MS;
  let first: number | null = null;
  const listener = (signal: NodeJS.Signals) => {
    const t = now();
    if (first === null) {
      first = t;
      handlers.stop(signal);
    } else if (t - first > echoMs) {
      handlers.force(signal);
    }
  };
  for (const s of STOP_SIGNALS) target.on(s, listener);
  return () => {
    for (const s of STOP_SIGNALS) target.off(s, listener);
  };
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  });
}

export interface WorkerLoopOptions {
  /** Stop request. Aborting it also cancels the job in progress; the loop resolves once that row is recorded. */
  signal: AbortSignal;
  pollMs?: number;
  log?: (line: string) => void;
  echo?: (line: string) => void;
}

/** The worker: runs queued top-level jobs one at a time (spec §6) until `signal` aborts. */
export async function runWorkerLoop(db: Db, opts: WorkerLoopOptions): Promise<void> {
  const log = opts.log ?? ((l: string) => console.log(l));
  while (!opts.signal.aborted) {
    const job = nextQueuedJob(db);
    if (job) {
      log(`[worker] start ${job.type}#${job.id}`);
      const status = await runJob(db, job.id, { signal: opts.signal, echo: opts.echo });
      log(`[worker] ${job.type}#${job.id} ${status}`);
      continue;
    }
    await sleep(opts.pollMs ?? 1000, opts.signal);
  }
}
