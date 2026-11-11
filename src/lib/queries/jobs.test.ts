import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { feedState } from '../db/schema';
import { insertJob } from '../eval/test-fixtures';
import {
  formatParams,
  getJobDetail,
  getStalenessWarnings,
  jobDurationMs,
  listActiveJobs,
  listJobHistory,
  stalenessWarnings,
  summarizeStats,
  workerSeemsDown,
} from './jobs';

const now = new Date('2026-11-10T12:00:00.000Z');

describe('job history', () => {
  let db: Db;
  beforeEach(() => {
    db = openDb(':memory:');
  });

  it('nests children (and grandchildren) under their top-level job', () => {
    const parent = insertJob(db, { type: 'refresh-all', status: 'running' });
    const scan = insertJob(db, { type: 'scan', parentId: parent });
    const nested = insertJob(db, { type: 'noop', parentId: scan });
    insertJob(db, { type: 'enrich', parentId: parent, status: 'running' });
    const other = insertJob(db, { type: 'noop' });

    const history = listJobHistory(db);
    expect(history.map((j) => j.id)).toEqual([other, parent]);
    const p = history[1]!;
    expect(p.children.map((c) => c.type)).toEqual(['scan', 'enrich']);
    expect(p.children[0]!.children.map((c) => c.id)).toEqual([nested]);
    expect('log' in p).toBe(false);

    const detail = getJobDetail(db, scan)!;
    expect(detail.parent?.id).toBe(parent);
    expect(detail.children.map((c) => c.id)).toEqual([nested]);
    expect(getJobDetail(db, 9999)).toBeNull();
  });

  it('detects a worker that is not running', () => {
    insertJob(db, { status: 'queued', createdAt: '2026-11-10T11:59:55.000Z' });
    expect(workerSeemsDown(listActiveJobs(db), now)).toBe(false); // 5 s: give it a moment
    insertJob(db, { status: 'queued', createdAt: '2026-11-10T11:59:00.000Z' });
    expect(workerSeemsDown(listActiveJobs(db), now)).toBe(true);
    insertJob(db, { status: 'running', createdAt: '2026-11-10T11:58:00.000Z' });
    expect(workerSeemsDown(listActiveJobs(db), now)).toBe(false);
  });
});

describe('job formatting helpers', () => {
  it('computes durations', () => {
    expect(jobDurationMs({ status: 'queued', startedAt: null, finishedAt: null }, now)).toBeNull();
    expect(jobDurationMs({ status: 'running', startedAt: '2026-11-10T11:59:00.000Z', finishedAt: null }, now)).toBe(60_000);
    expect(jobDurationMs({ status: 'succeeded', startedAt: '2026-11-10T11:00:00.000Z', finishedAt: '2026-11-10T11:00:02.500Z' }, now)).toBe(
      2500,
    );
  });

  it('summarizes scalar stats and params', () => {
    expect(summarizeStats({ findings: 12, new: 3, nested: { a: 1 }, list: [1, 2], ok: true, extra: 'x' }, 3)).toBe(
      'findings: 12 · new: 3 · list: 2 items · +2 more',
    );
    expect(summarizeStats(null)).toBe('');
    expect(formatParams({ project: 'web', limit: 5, force: true })).toBe('project=web limit=5 force=true');
    expect(formatParams({})).toBe('');
  });
});

describe('staleness', () => {
  const base = { osvMaxAgeHours: 24, refreshMaxAgeDays: 7, now };

  it('warns about missing or old OSV data and an old Refresh all', () => {
    expect(stalenessWarnings({ ...base, feeds: [], lastRefreshAt: null })).toEqual([
      'The OSV database has never been synced.',
      'No Refresh all has succeeded yet.',
    ]);
    const w = stalenessWarnings({
      ...base,
      feeds: [
        { feed: 'osv:npm', lastSuccessAt: '2026-11-08T12:00:00.000Z' },
        { feed: 'osv:SwiftURL', lastSuccessAt: null },
        { feed: 'osv:PyPI', lastSuccessAt: '2026-11-10T11:00:00.000Z' },
        { feed: 'kev', lastSuccessAt: null },
      ],
      lastRefreshAt: '2026-11-01T12:00:00.000Z',
    });
    expect(w).toHaveLength(2);
    expect(w[0]).toContain('osv:npm (synced 2 days ago)');
    expect(w[0]).toContain('osv:SwiftURL (never synced)');
    expect(w[0]).not.toContain('PyPI');
    expect(w[1]).toContain('9 days ago');
  });

  it('is quiet when everything is fresh', () => {
    expect(
      stalenessWarnings({
        ...base,
        feeds: [{ feed: 'osv:npm', lastSuccessAt: '2026-11-10T06:00:00.000Z' }],
        lastRefreshAt: '2026-11-09T12:00:00.000Z',
      }),
    ).toEqual([]);
  });

  it('reads feeds and the last succeeded top-level refresh-all from the DB', () => {
    const db = openDb(':memory:');
    db.insert(feedState).values({ feed: 'osv:npm', lastSuccessAt: '2026-11-10T06:00:00.000Z' }).run();
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-09T11:00:00.000Z',
      finishedAt: '2026-11-09T12:00:00.000Z',
    });
    const config = { staleness: { osv_max_age_hours: 24, refresh_max_age_days: 7 } };
    expect(getStalenessWarnings(db, config, now)).toEqual([]);
    expect(getStalenessWarnings(db, { staleness: { osv_max_age_hours: 1, refresh_max_age_days: 0.5 } }, now)).toHaveLength(2);
  });
});
