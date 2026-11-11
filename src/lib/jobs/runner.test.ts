import { execFileSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDb, type Db } from '../db/client';
import { jobRuns, scans } from '../db/schema';
import type { JobType } from '../types';
import type { JobContext, JobHandler } from './types';

const mocks = vi.hoisted(() => ({ handlers: {} as Partial<Record<string, (ctx: JobContext) => ReturnType<JobHandler>>> }));
vi.mock('../../jobs', () => ({ handlers: mocks.handlers }));
vi.mock('../config/sync', () => ({ syncConfigToDb: () => ({}) }));

const { failInterruptedJobs, onStopSignals, runJob, runWorkerLoop, SIGNAL_ECHO_MS } = await import('./runner');

const dataDir = mkdtempSync(path.join(tmpdir(), 'vigiles-runner-'));
vi.stubEnv('VIGILES_DATA_DIR', dataDir);
afterAll(() => {
  vi.unstubAllEnvs();
  rmSync(dataDir, { recursive: true, force: true });
});

/** A pid that belonged to a process that has exited. */
const DEAD_PID = Number(execFileSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' }));

let db: Db;
beforeEach(() => {
  db = openDb(':memory:');
  for (const k of Object.keys(mocks.handlers)) delete mocks.handlers[k];
});

const row = (id: number) => db.select().from(jobRuns).where(eq(jobRuns.id, id)).get()!;
const insertJob = (type: JobType, values: Partial<typeof jobRuns.$inferInsert> = {}) =>
  db
    .insert(jobRuns)
    .values({ type, ...values })
    .returning({ id: jobRuns.id })
    .get().id;
const quiet = { echo: () => {} };

/** A job that runs until it is cancelled, then stops the way real jobs do (throwIfCancelled). */
const untilAborted = async (ctx: JobContext) => {
  await new Promise<void>((resolve) =>
    ctx.signal.aborted ? resolve() : ctx.signal.addEventListener('abort', () => resolve(), { once: true }),
  );
  ctx.throwIfCancelled();
  return {};
};

describe('runJob', () => {
  it('records the owner pid while running and clears a previous error on success', async () => {
    let pidWhileRunning: number | null = null;
    mocks.handlers.noop = async (ctx) => {
      pidWhileRunning = row(ctx.jobId).pid;
      return { ok: true };
    };
    const id = insertJob('noop', { status: 'queued', error: 'interrupted (worker restarted)' });

    expect(await runJob(db, id, quiet)).toBe('succeeded');

    expect(pidWhileRunning).toBe(process.pid);
    expect(row(id)).toMatchObject({ status: 'succeeded', error: null, pid: process.pid, stats: { ok: true } });
  });

  it('keeps stats a handler attached to its error on the failed row', async () => {
    mocks.handlers.scan = async () => {
      throw Object.assign(new Error('scan failed for web: boom'), { stats: { projects: { web: { error: 'boom' } } } });
    };
    const id = insertJob('scan', { status: 'queued' });

    expect(await runJob(db, id, quiet)).toBe('failed');
    expect(row(id)).toMatchObject({ status: 'failed', stats: { projects: { web: { error: 'boom' } } } });
    expect(row(id).error).toMatch(/^Error: scan failed for web: boom/);
  });

  it('an external signal cancels a top-level job and its children, recording the reason', async () => {
    mocks.handlers['refresh-all'] = async (ctx) => {
      await ctx.runChild('noop');
      return {};
    };
    mocks.handlers.noop = untilAborted;
    const stop = new AbortController();
    const id = insertJob('refresh-all', { status: 'queued' });

    const done = runJob(db, id, { ...quiet, signal: stop.signal });
    await vi.waitFor(() => expect(db.select().from(jobRuns).all()).toHaveLength(2));
    stop.abort('worker received SIGTERM');

    expect(await done).toBe('cancelled');
    expect(row(id)).toMatchObject({ status: 'cancelled', error: 'cancelled (worker received SIGTERM)' });
    const child = db.select().from(jobRuns).where(eq(jobRuns.parentId, id)).get()!;
    expect(child).toMatchObject({ type: 'noop', status: 'cancelled', pid: process.pid });
  });

  it('still honours cancel_requested when an external signal is given', async () => {
    mocks.handlers.noop = untilAborted;
    const id = insertJob('noop', { status: 'queued' });
    const done = runJob(db, id, { ...quiet, signal: new AbortController().signal });
    await vi.waitFor(() => expect(row(id).status).toBe('running'));
    db.update(jobRuns).set({ cancelRequested: true }).where(eq(jobRuns.id, id)).run();

    expect(await done).toBe('cancelled');
    expect(row(id).error).toBe('cancelled');
  });

  it('does not start a job that was cancelled after it was picked', async () => {
    const handler = vi.fn(async () => ({}));
    mocks.handlers.noop = handler;
    const id = insertJob('noop', { status: 'cancelled', error: 'cancelled before start' });

    expect(await runJob(db, id, quiet)).toBe('cancelled');
    expect(handler).not.toHaveBeenCalled();
    expect(row(id)).toMatchObject({ status: 'cancelled', pid: null, startedAt: null });
  });
});

describe('failInterruptedJobs', () => {
  it('reclaims only rows (and their scans) whose process is gone or unknown', () => {
    // The parent of this test process stands in for another live process (an inline CLI next to the worker).
    const live = insertJob('triage', { status: 'running', pid: process.ppid });
    const liveChild = insertJob('scan', { status: 'running', pid: process.ppid, parentId: live });
    const dead = insertJob('refresh-all', { status: 'running', pid: DEAD_PID });
    const legacy = insertJob('scan', { status: 'running', pid: null });
    // Left by an earlier process that had our pid: the caller (worker startup) runs nothing yet.
    const reused = insertJob('noop', { status: 'running', pid: process.pid });
    const finished = insertJob('scan', { status: 'succeeded', pid: DEAD_PID });
    const scan = (jobRunId: number | null) =>
      db.insert(scans).values({ projectId: 'p', jobRunId, ref: 'main', status: 'running' }).returning({ id: scans.id }).get().id;
    const scanIds = { liveChild: scan(liveChild), dead: scan(dead), legacy: scan(legacy), reused: scan(reused), none: scan(null) };

    expect(failInterruptedJobs(db)).toBe(3);

    expect(row(live).status).toBe('running');
    expect(row(liveChild).status).toBe('running');
    expect(row(dead)).toMatchObject({ status: 'failed', error: `interrupted (process ${DEAD_PID} is gone)` });
    expect(row(legacy)).toMatchObject({ status: 'failed', error: 'interrupted (worker restarted)' });
    expect(row(reused)).toMatchObject({ status: 'failed', error: `interrupted (process ${process.pid} is gone)` });
    expect(row(finished).status).toBe('succeeded');
    const scanStatus = Object.fromEntries(
      Object.entries(scanIds).map(([k, id]) => [k, db.select().from(scans).where(eq(scans.id, id)).get()!.status]),
    );
    expect(scanStatus).toEqual({ liveChild: 'running', dead: 'failed', legacy: 'failed', reused: 'failed', none: 'failed' });
  });

  it('reclaims every running scan when no job is alive', () => {
    insertJob('scan', { status: 'running', pid: DEAD_PID });
    db.insert(scans).values({ projectId: 'p', jobRunId: 77, ref: 'main', status: 'running' }).run();
    expect(failInterruptedJobs(db)).toBe(1);
    expect(db.select().from(scans).get()!.status).toBe('failed');
  });
});

describe('runWorkerLoop', () => {
  it('runs queued top-level jobs in order, one at a time', async () => {
    const order: number[] = [];
    let concurrent = 0;
    mocks.handlers.noop = async (ctx) => {
      concurrent++;
      expect(concurrent).toBe(1);
      order.push(ctx.jobId);
      await new Promise((r) => setTimeout(r, 5));
      concurrent--;
      return {};
    };
    const a = insertJob('noop', { status: 'queued' });
    const b = insertJob('noop', { status: 'queued' });
    insertJob('noop', { status: 'queued', parentId: a }); // children are run by their parent, not the worker
    const stop = new AbortController();
    const loop = runWorkerLoop(db, { signal: stop.signal, pollMs: 5, log: () => {}, echo: () => {} });

    await vi.waitFor(() => expect(row(b).status).toBe('succeeded'));
    stop.abort('test');
    await loop;
    expect(order).toEqual([a, b]);
  });

  it('on stop, cancels the job in progress, waits for its row, and starts nothing else', async () => {
    mocks.handlers.noop = untilAborted;
    const current = insertJob('noop', { status: 'queued' });
    const stop = new AbortController();
    const logs: string[] = [];
    const loop = runWorkerLoop(db, { signal: stop.signal, pollMs: 5, log: (l) => logs.push(l), echo: () => {} });
    await vi.waitFor(() => expect(row(current).status).toBe('running'));
    const next = insertJob('noop', { status: 'queued' });

    stop.abort('worker received SIGINT');
    await loop;

    expect(row(current)).toMatchObject({ status: 'cancelled', error: 'cancelled (worker received SIGINT)' });
    expect(row(next).status).toBe('queued');
    expect(logs).toEqual([`[worker] start noop#${current}`, `[worker] noop#${current} cancelled`]);
  });

  it('returns promptly when stopped while idle', async () => {
    const stop = new AbortController();
    const loop = runWorkerLoop(db, { signal: stop.signal, pollMs: 60_000, log: () => {} });
    const t0 = Date.now();
    setTimeout(() => stop.abort(), 10);
    await loop;
    expect(Date.now() - t0).toBeLessThan(1000);
  });
});

describe('onStopSignals', () => {
  it('stops on the first signal, ignores the echoes of the same Ctrl-C, and forces on a later one', () => {
    const target = new EventEmitter();
    let t = 1_000;
    const calls: string[] = [];
    const dispose = onStopSignals(
      { stop: (s) => calls.push(`stop ${s}`), force: (s) => calls.push(`force ${s}`) },
      { target, now: () => t },
    );

    target.emit('SIGINT', 'SIGINT'); // the terminal's Ctrl-C
    t += 30;
    target.emit('SIGINT', 'SIGINT'); // npm / tsx / concurrently forwarding it again
    t += 800;
    target.emit('SIGTERM', 'SIGTERM'); // concurrently -k, once the dashboard exited
    expect(calls).toEqual(['stop SIGINT']);

    t = 1_000 + SIGNAL_ECHO_MS + 1;
    target.emit('SIGINT', 'SIGINT'); // the user insists
    expect(calls).toEqual(['stop SIGINT', 'force SIGINT']);

    dispose();
    expect(target.listenerCount('SIGINT') + target.listenerCount('SIGTERM')).toBe(0);
  });

  it('installs on process by default and removes its handlers', () => {
    const before = process.listenerCount('SIGINT');
    const dispose = onStopSignals({ stop: () => {}, force: () => {} });
    expect(process.listenerCount('SIGINT')).toBe(before + 1);
    expect(process.listenerCount('SIGTERM')).toBeGreaterThan(0);
    dispose();
    expect(process.listenerCount('SIGINT')).toBe(before);
  });
});
