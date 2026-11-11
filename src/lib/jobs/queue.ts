/** Job queue operations shared by the dashboard (server actions), the CLI and the worker. */
import { and, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { jobRuns } from '../db/schema';
import { JOB_TYPES, type JobType } from '../types';

export function isJobType(t: string): t is JobType {
  return (JOB_TYPES as readonly string[]).includes(t);
}

export function enqueueJob(db: Db, type: JobType, params: Record<string, unknown> = {}): number {
  const row = db.insert(jobRuns).values({ type, params, status: 'queued' }).returning({ id: jobRuns.id }).get();
  return row.id;
}

/** Queued → cancelled immediately; running → cancel_requested (the worker aborts it). */
export function requestCancel(db: Db, id: number): void {
  const now = new Date().toISOString();
  db.update(jobRuns)
    .set({ status: 'cancelled', finishedAt: now, error: 'cancelled before start' })
    .where(and(eq(jobRuns.id, id), eq(jobRuns.status, 'queued')))
    .run();
  db.update(jobRuns)
    .set({ cancelRequested: true })
    .where(and(eq(jobRuns.id, id), eq(jobRuns.status, 'running')))
    .run();
}

export function nextQueuedJob(db: Db) {
  return db
    .select()
    .from(jobRuns)
    .where(and(eq(jobRuns.status, 'queued'), isNull(jobRuns.parentId)))
    .orderBy(jobRuns.id)
    .limit(1)
    .get();
}

export function getJob(db: Db, id: number) {
  return db.select().from(jobRuns).where(eq(jobRuns.id, id)).get();
}

/**
 * Whether a process with this pid exists. `kill(pid, 0)` sends nothing; ESRCH means no such process,
 * EPERM means it exists but belongs to another user (still alive).
 */
export function isProcessAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

export interface LiveJob {
  id: number;
  type: string;
  pid: number;
  parentId: number | null;
  startedAt: string | null;
}

/**
 * `running` rows whose owner process (job_runs.pid: the worker or an inline CLI) is still alive.
 * A running row without a pid predates pid tracking, and one whose process is gone was interrupted;
 * neither is running any more.
 */
export function liveRunningJobs(
  db: Db,
  opts: { type?: JobType; topLevelOnly?: boolean } = {},
  alive: (pid: number) => boolean = isProcessAlive,
): LiveJob[] {
  const conditions = [eq(jobRuns.status, 'running')];
  if (opts.type) conditions.push(eq(jobRuns.type, opts.type));
  if (opts.topLevelOnly) conditions.push(isNull(jobRuns.parentId));
  return db
    .select({ id: jobRuns.id, type: jobRuns.type, pid: jobRuns.pid, parentId: jobRuns.parentId, startedAt: jobRuns.startedAt })
    .from(jobRuns)
    .where(and(...conditions))
    .orderBy(jobRuns.id)
    .all()
    .filter((r): r is LiveJob => r.pid !== null && alive(r.pid));
}

/** The message for a job that cannot start because `other` is still running. */
export function describeLiveJob(other: LiveJob): string {
  return `${other.type}#${other.id} (pid ${other.pid}${other.startedAt ? `, started ${other.startedAt}` : ''})`;
}

export function isActive(db: Db): boolean {
  const r = db
    .select({ n: sql<number>`count(*)` })
    .from(jobRuns)
    .where(inArray(jobRuns.status, ['queued', 'running']))
    .get();
  return (r?.n ?? 0) > 0;
}

export function recentJobs(db: Db, limit = 50) {
  return db.select().from(jobRuns).where(isNull(jobRuns.parentId)).orderBy(desc(jobRuns.id)).limit(limit).all();
}

export function childJobs(db: Db, parentId: number) {
  return db.select().from(jobRuns).where(eq(jobRuns.parentId, parentId)).orderBy(jobRuns.id).all();
}

/** Latest successful run of a job type (top-level or child). */
export function lastSuccess(db: Db, type: JobType) {
  return db
    .select()
    .from(jobRuns)
    .where(and(eq(jobRuns.type, type), eq(jobRuns.status, 'succeeded')))
    .orderBy(desc(jobRuns.id))
    .limit(1)
    .get();
}
