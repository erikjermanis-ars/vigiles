/**
 * Projects page queries (spec §4.4, §7.2, §12): profile, ref → scanned commit, lockfiles,
 * coverage gaps and open-finding counts per project, plus the project list behind the header's scope switcher.
 */
import { and, asc, count, desc, eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { findings, ownerCases, projects, scans } from '../db/schema';
import type { ScopeProject } from '../project-scope';
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

/** The scan state of one project (also used by the Inbox's project cards). */
export function projectScanState(db: Db, project: Pick<ProjectRow, 'id' | 'lastScanId'>): ProjectScanState {
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
  /** Open owner cases (the /decide page) about this project's findings */
  openOwnerCases: number;
}

/** Open owner cases per project id (cases whose finding is gone are not counted). */
export function openOwnerCasesByProject(db: Db): Map<string, number> {
  const rows = db
    .select({ projectId: findings.projectId, n: count() })
    .from(ownerCases)
    .innerJoin(findings, eq(findings.id, ownerCases.findingId))
    .where(eq(ownerCases.status, 'open'))
    .groupBy(findings.projectId)
    .all();
  return new Map(rows.map((r) => [r.projectId, r.n]));
}

/** Every project, enabled ones first. */
export function listProjectsOverview(db: Db): ProjectOverview[] {
  const rows = db.select().from(projects).orderBy(desc(projects.enabled), asc(projects.name)).all();
  const countRows = countRowsByProject(db);
  const cases = openOwnerCasesByProject(db);
  return rows.map((project) => ({
    project,
    ...projectScanState(db, project),
    counts: foldCounts(countRows.filter((r) => r.projectId === project.id)),
    openOwnerCases: cases.get(project.id) ?? 0,
  }));
}

/** The header switcher's choices: every project, enabled ones first, then by name. */
export function listScopeProjects(db: Db): ScopeProject[] {
  return db
    .select({ id: projects.id, name: projects.name, enabled: projects.enabled })
    .from(projects)
    .orderBy(desc(projects.enabled), asc(projects.name))
    .all();
}

export type ProjectHealthTone = 'ok' | 'warn' | 'bad' | 'off';

export interface ProjectHealth {
  tone: ProjectHealthTone;
  /** Two or three words, e.g. "Monitored", "Last scan failed" */
  label: string;
  /** One plain sentence: what it means and what to do */
  detail: string;
}

/**
 * The one-glance state of a project for the Projects page: disabled, never scanned, its latest scan attempt
 * failed (findings are from an older scan), a scan running, coverage gaps, or monitored and fine.
 */
export function projectHealth(o: Pick<ProjectOverview, 'project' | 'lastScan' | 'newerAttempt'>): ProjectHealth {
  if (!o.project.enabled) {
    return {
      tone: 'off',
      label: 'Not monitored',
      detail: `Disabled in projects/${o.project.id}.yaml: scans, triage and the Inbox skip it.`,
    };
  }
  if (o.newerAttempt?.status === 'failed') {
    return {
      tone: 'bad',
      label: 'Last scan failed',
      detail: o.lastScan
        ? 'The newest scan failed; findings below are from the previous successful scan.'
        : 'Every scan so far failed, so nothing is matched yet.',
    };
  }
  if (!o.lastScan) {
    return o.newerAttempt?.status === 'running'
      ? { tone: 'warn', label: 'First scan running', detail: 'Findings appear when it finishes.' }
      : { tone: 'warn', label: 'Never scanned', detail: 'Run Refresh all on the Jobs page to scan it.' };
  }
  if (o.newerAttempt?.status === 'running') {
    return { tone: 'ok', label: 'Scanning', detail: 'A new scan is running; findings below are from the previous one.' };
  }
  if (o.lastScan.coverageGaps.length) {
    return {
      tone: 'warn',
      label: 'Monitored, with gaps',
      detail: 'Some manifests have no lockfile, so their dependencies are not checked.',
    };
  }
  return { tone: 'ok', label: 'Monitored', detail: 'Scanned successfully; every lockfile found is checked.' };
}

export interface ProjectDetail extends ProjectOverview {
  scans: ScanRow[];
}

export function getProjectDetail(db: Db, id: string, scanLimit = 20): ProjectDetail | null {
  const project = db.select().from(projects).where(eq(projects.id, id)).get();
  if (!project) return null;
  return {
    project,
    ...projectScanState(db, project),
    counts: foldCounts(countRowsByProject(db, id)),
    openOwnerCases: openOwnerCasesByProject(db).get(id) ?? 0,
    scans: db.select().from(scans).where(eq(scans.projectId, id)).orderBy(desc(scans.id)).limit(scanLimit).all(),
  };
}
