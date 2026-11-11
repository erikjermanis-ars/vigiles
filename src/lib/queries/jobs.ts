/**
 * Jobs page queries (spec §6, §12) and the staleness check behind the banner (§4.4).
 */
import { asc, desc, eq, inArray, isNull, max } from 'drizzle-orm';
import type { VigilesConfig } from '../config/schema';
import type { Db } from '../db/client';
import { feedState, jobRuns, projects, triageConfigs } from '../db/schema';
import { relativeTime } from '../format';
import type { JobStatus } from '../types';
import { lastSucceededRefreshAll } from './inbox';

export type JobRunRow = typeof jobRuns.$inferSelect;
/** A job without its (possibly large) log. */
export type JobSummary = Omit<JobRunRow, 'log'>;
export interface JobNode extends JobSummary {
  children: JobNode[];
}

const summaryColumns = {
  id: jobRuns.id,
  type: jobRuns.type,
  params: jobRuns.params,
  status: jobRuns.status,
  parentId: jobRuns.parentId,
  progress: jobRuns.progress,
  stats: jobRuns.stats,
  error: jobRuns.error,
  cancelRequested: jobRuns.cancelRequested,
  pid: jobRuns.pid,
  createdAt: jobRuns.createdAt,
  startedAt: jobRuns.startedAt,
  finishedAt: jobRuns.finishedAt,
};

/** Attaches every descendant (children, grandchildren, …) of the given jobs, oldest first. */
function attachDescendants(db: Db, roots: JobNode[]): void {
  let level = roots;
  while (level.length) {
    const byId = new Map(level.map((j) => [j.id, j]));
    const kids = db
      .select(summaryColumns)
      .from(jobRuns)
      .where(inArray(jobRuns.parentId, [...byId.keys()]))
      .orderBy(asc(jobRuns.id))
      .all()
      .map((k): JobNode => ({ ...k, children: [] }));
    for (const k of kids) byId.get(k.parentId!)?.children.push(k);
    level = kids;
  }
}

/** Latest top-level jobs (newest first) with their child jobs nested. */
export function listJobHistory(db: Db, limit = 50): JobNode[] {
  const top = db
    .select(summaryColumns)
    .from(jobRuns)
    .where(isNull(jobRuns.parentId))
    .orderBy(desc(jobRuns.id))
    .limit(limit)
    .all()
    .map((j): JobNode => ({ ...j, children: [] }));
  attachDescendants(db, top);
  return top;
}

export interface JobDetail {
  job: JobRunRow;
  parent: JobSummary | null;
  children: JobNode[];
}

export function getJobDetail(db: Db, id: number): JobDetail | null {
  const job = db.select().from(jobRuns).where(eq(jobRuns.id, id)).get();
  if (!job) return null;
  const parent = job.parentId ? (db.select(summaryColumns).from(jobRuns).where(eq(jobRuns.id, job.parentId)).get() ?? null) : null;
  const self: JobNode = { ...job, children: [] };
  attachDescendants(db, [self]);
  return { job, parent, children: self.children };
}

export interface ActiveJob {
  id: number;
  type: string;
  status: JobStatus;
  createdAt: string;
  parentId: number | null;
}

export function listActiveJobs(db: Db): ActiveJob[] {
  return db
    .select({ id: jobRuns.id, type: jobRuns.type, status: jobRuns.status, createdAt: jobRuns.createdAt, parentId: jobRuns.parentId })
    .from(jobRuns)
    .where(inArray(jobRuns.status, ['queued', 'running']))
    .all();
}

/** True when a top-level job has waited more than `thresholdMs` and nothing is running: the worker is probably not started. */
export function workerSeemsDown(active: readonly ActiveJob[], now = new Date(), thresholdMs = 10_000): boolean {
  if (active.some((j) => j.status === 'running')) return false;
  return active.some((j) => j.status === 'queued' && j.parentId === null && now.getTime() - Date.parse(j.createdAt) > thresholdMs);
}

/** Wall time of a job; running jobs count up to `now`. */
export function jobDurationMs(job: Pick<JobSummary, 'status' | 'startedAt' | 'finishedAt'>, now = new Date()): number | null {
  if (!job.startedAt) return null;
  const end = job.finishedAt ? Date.parse(job.finishedAt) : job.status === 'running' ? now.getTime() : null;
  if (end === null) return null;
  return Math.max(0, end - Date.parse(job.startedAt));
}

/** "findings: 12 · new: 3 · …" from the scalar entries of a stats object. */
export function summarizeStats(stats: Record<string, unknown> | null | undefined, maxEntries = 4): string {
  if (!stats) return '';
  const parts: string[] = [];
  let skipped = 0;
  for (const [k, v] of Object.entries(stats)) {
    const scalar = typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean';
    const text = scalar ? String(v) : Array.isArray(v) ? `${v.length} items` : null;
    if (text === null || text.length > 40) continue;
    if (parts.length < maxEntries) parts.push(`${k}: ${text}`);
    else skipped++;
  }
  return parts.join(' · ') + (skipped ? ` · +${skipped} more` : '');
}

/** "{project: x}" style, compact, for history rows. */
export function formatParams(params: Record<string, unknown> | null | undefined): string {
  if (!params || Object.keys(params).length === 0) return '';
  return Object.entries(params)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(' ');
}

/** The newest run (any status, top-level or child) of each job type. */
export function latestRunByType(db: Db): Map<string, JobSummary> {
  const newestIds = db
    .select({ id: max(jobRuns.id) })
    .from(jobRuns)
    .groupBy(jobRuns.type);
  const rows = db.select(summaryColumns).from(jobRuns).where(inArray(jobRuns.id, newestIds)).all();
  return new Map(rows.map((r) => [r.type, r]));
}

export interface JobFormOptions {
  projects: { id: string; name: string; enabled: boolean }[];
  configs: { name: string; active: boolean }[];
}

export function getJobFormOptions(db: Db): JobFormOptions {
  return {
    projects: db
      .select({ id: projects.id, name: projects.name, enabled: projects.enabled })
      .from(projects)
      .orderBy(desc(projects.enabled), asc(projects.name))
      .all(),
    configs: db
      .select({ name: triageConfigs.name, active: triageConfigs.active })
      .from(triageConfigs)
      .orderBy(desc(triageConfigs.active), asc(triageConfigs.name))
      .all(),
  };
}

export type FeedRow = typeof feedState.$inferSelect;

export function listFeeds(db: Db): FeedRow[] {
  return db.select().from(feedState).orderBy(asc(feedState.feed)).all();
}

// ---------- staleness (§4.4) ----------

export interface StalenessInput {
  feeds: readonly Pick<FeedRow, 'feed' | 'lastSuccessAt'>[];
  /** When the latest succeeded Refresh all finished (or started) */
  lastRefreshAt: string | null;
  osvMaxAgeHours: number;
  refreshMaxAgeDays: number;
  now: Date;
}

export function stalenessWarnings(i: StalenessInput): string[] {
  const warnings: string[] = [];
  const ageMs = (iso: string) => i.now.getTime() - Date.parse(iso);
  const osv = i.feeds.filter((f) => f.feed.startsWith('osv:'));
  if (osv.length === 0) {
    warnings.push('The OSV database has never been synced.');
  } else {
    const stale = osv
      .filter((f) => !f.lastSuccessAt || ageMs(f.lastSuccessAt) > i.osvMaxAgeHours * 3_600_000)
      .map((f) => `${f.feed} (${f.lastSuccessAt ? `synced ${relativeTime(f.lastSuccessAt, i.now)}` : 'never synced'})`);
    if (stale.length) warnings.push(`OSV data is older than ${i.osvMaxAgeHours} h: ${stale.join(', ')}.`);
  }
  if (!i.lastRefreshAt) {
    warnings.push('No Refresh all has succeeded yet.');
  } else if (ageMs(i.lastRefreshAt) > i.refreshMaxAgeDays * 86_400_000) {
    warnings.push(`The last successful Refresh all was ${relativeTime(i.lastRefreshAt, i.now)} (limit ${i.refreshMaxAgeDays} days).`);
  }
  return warnings;
}

export function getStalenessWarnings(db: Db, config: Pick<VigilesConfig, 'staleness'>, now = new Date()): string[] {
  const refresh = lastSucceededRefreshAll(db);
  return stalenessWarnings({
    feeds: db.select({ feed: feedState.feed, lastSuccessAt: feedState.lastSuccessAt }).from(feedState).all(),
    lastRefreshAt: refresh ? (refresh.finishedAt ?? refresh.startedAt) : null,
    osvMaxAgeHours: config.staleness.osv_max_age_hours,
    refreshMaxAgeDays: config.staleness.refresh_max_age_days,
    now,
  });
}
