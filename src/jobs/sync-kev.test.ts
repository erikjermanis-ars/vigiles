import { sql } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { openDb } from '../lib/db/client';
import { kev } from '../lib/db/schema';
import { getFeedState } from '../lib/signals/feed-state';
import { jsonResponse, fakeJobContext, kevFeed, stubFetch } from '../lib/signals/test-support';
import { runSyncKev } from './sync-kev';

const feed = kevFeed([
  { cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' },
  { cveID: 'CVE-2023-4966', dateAdded: '2023-10-18' },
]);

describe('sync-kev job', () => {
  it('replaces the kev table and reports the count', async () => {
    const db = openDb(':memory:');
    const ctx = fakeJobContext(db, 'sync-kev');
    const stats = await runSyncKev(ctx, { fetchFn: stubFetch(() => jsonResponse(feed)) });

    expect(stats).toEqual({ catalogVersion: '2026.11.10', dateReleased: '2026-11-10T15:00:00.000Z', count: 2 });
    expect(db.select().from(kev).all()).toHaveLength(2);
    expect(getFeedState(db, 'kev')).toMatchObject({ lastError: null, meta: { catalogVersion: '2026.11.10', count: 2 } });
    expect(ctx.logs).toEqual(['KEV catalog 2026.11.10 (released 2026-11-10T15:00:00.000Z): 2 CVEs']);
  });

  it('warns when the declared count disagrees with the entries', async () => {
    const db = openDb(':memory:');
    const ctx = fakeJobContext(db, 'sync-kev');
    await runSyncKev(ctx, { fetchFn: stubFetch(() => jsonResponse({ ...feed, count: 3 })) });
    expect(ctx.logs[0]).toBe('warning: catalog says count=3 but lists 2 entries');
  });

  it('fails, keeps the old catalog and records lastError on a bad download', async () => {
    const db = openDb(':memory:');
    await runSyncKev(fakeJobContext(db, 'sync-kev'), { fetchFn: stubFetch(() => jsonResponse(feed)) });
    const before = getFeedState(db, 'kev')!;

    await expect(
      runSyncKev(fakeJobContext(db, 'sync-kev'), { fetchFn: stubFetch(() => jsonResponse({ ...feed, vulnerabilities: [] })) }),
    ).rejects.toThrow(/KEV feed failed validation/);
    await expect(
      runSyncKev(fakeJobContext(db, 'sync-kev'), { fetchFn: stubFetch(() => new Response('', { status: 502, statusText: 'Bad Gateway' })) }),
    ).rejects.toThrow(/HTTP 502/);

    expect(db.select().from(kev).all()).toHaveLength(2);
    const after = getFeedState(db, 'kev')!;
    expect(after.lastSuccessAt).toBe(before.lastSuccessAt);
    expect(after.meta).toEqual(before.meta);
    expect(after.lastError).toMatch(/HTTP 502/);
  });

  it('records lastError when writing the catalog fails', async () => {
    const db = openDb(':memory:');
    db.run(sql`DROP TABLE kev`);
    await expect(runSyncKev(fakeJobContext(db, 'sync-kev'), { fetchFn: stubFetch(() => jsonResponse(feed)) })).rejects.toThrow();
    expect(getFeedState(db, 'kev')).toMatchObject({ lastSuccessAt: null, lastError: expect.stringMatching(/no such table: kev/) });
  });

  it('does not record a feed failure when the user cancels', async () => {
    const db = openDb(':memory:');
    const ctx = fakeJobContext(db, 'sync-kev');
    const fetchFn = stubFetch(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init!.signal!.addEventListener('abort', () => reject(init!.signal!.reason));
        }),
    );
    const pending = runSyncKev(ctx, { fetchFn });
    ctx.controller.abort();
    await expect(pending).rejects.toThrow();
    expect(getFeedState(db, 'kev')).toBeUndefined();
  });
});
