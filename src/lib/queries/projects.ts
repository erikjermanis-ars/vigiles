/**
 * Projects page queries (spec §4.4, §7.2, §12): profile, ref → scanned commit, lockfiles,
 * coverage gaps and open-finding counts per project.
 */
import { and, asc, count, desc, eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { findings, projects, scans } from '../db/schema';
import { ACTIONS, PRIORITIES, type Action, type FindingStatus, type Priority } from '../types';

export type ProjectRow = typeof projects.$inferSelect;
export type ScanRow = typeof scans.$inferSelect;

export interface FindingCounts {
  total: number;
  open: number;
  /** Open findings by base priority ('none' = not enriched yet) */
  byPriority: Record<Priority | 'none', number>;
  /** Open findings by current action ('undecided' = no decision yet) */
  byAction: Record<Action | 'undecided', number>;
}

export function emptyCounts(): FindingCounts {
  return {
    total: 0,
    open: 0,
    byPriority: { P0: 0, P1: 0, P2: 0, P3: 0, none: 0 },
    byAction: { ping: 0, digest: 0, log: 0, undecided: 0 },
  };
}

export interface CountRow {
  status: FindingStatus;
  priority: Priority | null;
  action: Action | null;
  n: number;
}

export function foldCounts(rows: readonly CountRow[]): FindingCounts {
  const c = emptyCounts();
  for (const r of rows) {
    c.total += r.n;
    if (r.status !== 'open') continue;
    c.open += r.n;
    c.byPriority[r.priority && PRIORITIES.includes(r.priority) ? r.priority : 'none'] += r.n;
    c.byAction[r.action && ACTIONS.includes(r.action) ? r.action : 'undecided'] += r.n;
  }
  return c;
}

function countRowsByProject(db: Db, projectId?: string) {
  return db
    .select({
      projectId: findings.projectId,
      status: findings.status,
      priority: findings.priority,
      action: findings.currentAction,
      n: count(),
    })
    .from(findings)
    .where(projectId ? eq(findings.projectId, projectId) : undefined)
    .groupBy(findings.projectId, findings.status, findings.priority, findings.currentAction)
    .all();
}

export interface ProjectScanState {
  /** The scan the project's findings reflect (projects.last_scan_id, else the latest succeeded scan) */
  lastScan: ScanRow | null;
  /** A newer scan attempt that did not succeed (running or failed), if any */
  newerAttempt: ScanRow | null;
}

function scanState(db: Db, project: ProjectRow): ProjectScanState {
  const byId = project.lastScanId ? db.select().from(scans).where(eq(scans.id, project.lastScanId)).get() : undefined;
  const lastScan =
    byId ??
    db
      .select()
      .from(scans)
      .where(and(eq(scans.projectId, project.id), eq(scans.status, 'succeeded')))
      .orderBy(desc(scans.id))
      .limit(1)
      .get() ??
    null;
  const latest = db.select().from(scans).where(eq(scans.projectId, project.id)).orderBy(desc(scans.id)).limit(1).get() ?? null;
  return { lastScan, newerAttempt: latest && latest.id !== lastScan?.id && latest.status !== 'succeeded' ? latest : null };
}

export interface ProjectOverview extends ProjectScanState {
  project: ProjectRow;
  counts: FindingCounts;
}

/** Every project, enabled ones first. */
export function listProjectsOverview(db: Db): ProjectOverview[] {
  const rows = db.select().from(projects).orderBy(desc(projects.enabled), asc(projects.name)).all();
  const countRows = countRowsByProject(db);
  return rows.map((project) => ({
    project,
    ...scanState(db, project),
    counts: foldCounts(countRows.filter((r) => r.projectId === project.id)),
  }));
}

export interface ProjectDetail extends ProjectOverview {
  scans: ScanRow[];
}

export function getProjectDetail(db: Db, id: string, scanLimit = 20): ProjectDetail | null {
  const project = db.select().from(projects).where(eq(projects.id, id)).get();
  if (!project) return null;
  return {
    project,
    ...scanState(db, project),
    counts: foldCounts(countRowsByProject(db, id)),
    scans: db.select().from(scans).where(eq(scans.projectId, id)).orderBy(desc(scans.id)).limit(scanLimit).all(),
  };
}
