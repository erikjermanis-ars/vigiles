import { eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { openDb } from '../db/client';
import { projects, scans } from '../db/schema';
import { insertFinding, insertProject } from '../eval/test-fixtures';
import { foldCounts, getProjectDetail, listProjectsOverview } from './projects';

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
