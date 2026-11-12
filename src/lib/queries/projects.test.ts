import { eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { openDb } from '../db/client';
import { ownerCases, projects, scans } from '../db/schema';
import { insertFinding, insertProject } from '../eval/test-fixtures';
import { foldCounts, getProjectDetail, listProjectsOverview, listScopeProjects, projectHealth, type ProjectOverview } from './projects';

describe('foldCounts', () => {
  it('counts open findings by priority and action, and everything in total', () => {
    const c = foldCounts([
      { status: 'open', priority: 'P0', action: 'ping', n: 2 },
      { status: 'open', priority: null, action: null, n: 1 },
      { status: 'fixed', priority: 'P1', action: 'ping', n: 5 },
    ]);
    expect(c.total).toBe(8);
    expect(c.open).toBe(3);
    expect(c.byPriority).toEqual({ P0: 2, P1: 0, P2: 0, P3: 0, none: 1 });
    expect(c.byAction).toEqual({ ping: 2, digest: 0, log: 0, undecided: 1 });
  });
});

describe('project queries', () => {
  it('lists enabled projects first with their last scan, a newer failed attempt, and counts', () => {
    const db = openDb(':memory:');
    const { scanId } = insertProject(db, 'web');
    insertProject(db, 'api');
    insertProject(db, 'zzz');
    db.update(projects).set({ enabled: false }).where(eq(projects.id, 'api')).run();
    insertFinding(db, scanId, { projectId: 'web', priority: 'P0', action: 'ping' });
    insertFinding(db, scanId, { projectId: 'web', priority: 'P2', action: 'digest' });
    insertFinding(db, scanId, { projectId: 'web', priority: 'P2', action: 'digest', status: 'fixed' });
    db.insert(scans).values({ projectId: 'web', ref: 'origin/main', status: 'failed', error: 'boom' }).run();

    const list = listProjectsOverview(db);
    expect(list.map((p) => p.project.id)).toEqual(['web', 'zzz', 'api']);
    const web = list[0]!;
    expect(web.lastScan?.id).toBe(scanId);
    expect(web.newerAttempt?.error).toBe('boom');
    expect(web.counts).toMatchObject({ total: 3, open: 2, byAction: { ping: 1, digest: 1, log: 0, undecided: 0 } });
    expect(list[1]!.newerAttempt).toBeNull();

    const detail = getProjectDetail(db, 'web')!;
    expect(detail.scans.map((s) => s.status)).toEqual(['failed', 'succeeded']);
    expect(detail.counts.byPriority.P0).toBe(1);
    expect(getProjectDetail(db, 'missing')).toBeNull();
  });
});

describe('scope projects, owner cases and health', () => {
  const brief = {
    title: 't',
    whatItIs: 'w',
    attackerCouldDo: 'a',
    whatItTakes: 'w',
    yourApp: 'y',
    exploitableToday: 'unclear' as const,
    fix: 'f',
    similarTo: null,
  };

  it('lists the switcher’s projects, enabled ones first, then by name', () => {
    const db = openDb(':memory:');
    insertProject(db, 'zeta', { name: 'Zeta' });
    insertProject(db, 'old', { name: 'Alpha (old)', enabled: false });
    insertProject(db, 'beta', { name: 'Beta' });
    db.update(projects).set({ enabled: false }).where(eq(projects.id, 'old')).run();
    expect(listScopeProjects(db)).toEqual([
      { id: 'beta', name: 'Beta', enabled: true },
      { id: 'zeta', name: 'Zeta', enabled: true },
      { id: 'old', name: 'Alpha (old)', enabled: false },
    ]);
  });

  it('counts open owner cases per project', () => {
    const db = openDb(':memory:');
    const { scanId } = insertProject(db, 'web');
    insertProject(db, 'api');
    const f = insertFinding(db, scanId, { projectId: 'web' });
    db.insert(ownerCases).values([
      { findingId: f.id, brief, reason: 'r' },
      { findingId: f.id, brief, reason: 'r' },
      { findingId: f.id, brief, reason: 'r', status: 'answered' },
      { findingId: 9999, brief, reason: 'finding gone' },
    ]).run();
    const byId = new Map(listProjectsOverview(db).map((o) => [o.project.id, o.openOwnerCases]));
    expect(byId).toEqual(new Map([['api', 0], ['web', 2]]));
    expect(getProjectDetail(db, 'web')!.openOwnerCases).toBe(2);
  });

  it('says in two words what state a project is in', () => {
    const db = openDb(':memory:');
    insertProject(db, 'web');
    const base = listProjectsOverview(db)[0]!;
    const scan = base.lastScan!;
    const at = (o: Partial<ProjectOverview>) => projectHealth({ ...base, ...o });
    expect(at({}).label).toBe('Monitored');
    expect(at({ lastScan: { ...scan, coverageGaps: ['supabase/functions/x/deno.json'] } })).toMatchObject({ tone: 'warn', label: 'Monitored, with gaps' });
    expect(at({ newerAttempt: { ...scan, id: 99, status: 'failed' } })).toMatchObject({ tone: 'bad', label: 'Last scan failed' });
    expect(at({ newerAttempt: { ...scan, id: 99, status: 'running' } })).toMatchObject({ tone: 'ok', label: 'Scanning' });
    expect(at({ lastScan: null })).toMatchObject({ tone: 'warn', label: 'Never scanned' });
    expect(at({ lastScan: null, newerAttempt: { ...scan, status: 'running' } }).label).toBe('First scan running');
    expect(at({ lastScan: null, newerAttempt: { ...scan, status: 'failed' } }).detail).toContain('Every scan so far failed');
    expect(at({ project: { ...base.project, enabled: false } })).toMatchObject({ tone: 'off', label: 'Not monitored' });
  });
});
