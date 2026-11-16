import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KEV_FEED_URL } from '../lib/signals/kev-feed';
import { jsonResponse, kevFeed, stubFetch } from '../lib/signals/test-support';
import { tempDir } from './git-test-support';
import { kevDateIndex, kevRansomwareFor, loadKev } from './kev-cache';

let dir: string;
let file: string;
let clock: Date;
let down: boolean;
let feed: ReturnType<typeof kevFeed>;

const fetchFn = stubFetch((url, init) => {
  init?.signal?.throwIfAborted();
  if (url !== KEV_FEED_URL) return new Response(null, { status: 404 });
  if (down) throw new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') });
  return jsonResponse(feed);
});

const load = (extra: { force?: boolean; signal?: AbortSignal; maxAgeHours?: number } = {}) =>
  loadKev({ kevFile: file, fetchFn, now: () => clock, ...extra });

beforeEach(() => {
  dir = tempDir('vigiles-plugin-kev-');
  file = path.join(dir, 'cache', 'kev.json');
  clock = new Date('2026-11-12T10:00:00Z');
  down = false;
  fetchFn.calls.length = 0;
  const base = kevFeed([
    { cveID: 'CVE-2026-1000', dateAdded: '2026-10-02' },
    { cveID: 'CVE-2026-0500', dateAdded: '2026-09-01' },
  ]);
  feed = {
    ...base,
    vulnerabilities: base.vulnerabilities.map((v, i) => ({ ...v, knownRansomwareCampaignUse: i === 0 ? 'Known' : 'Unknown' })),
  };
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('loadKev', () => {
  it('downloads and caches the catalog when there is no copy', async () => {
    const r = await load();
    expect(r).toMatchObject({ available: true, fetched: true, warnings: [], catalogDate: '2026-11-10T15:00:00.000Z' });
    expect(r.index.get('CVE-2026-1000')).toEqual({ dateAdded: '2026-10-02', ransomware: 'Known' });
    expect(r.index.get('CVE-2026-0500')).toEqual({ dateAdded: '2026-09-01', ransomware: 'Unknown' });
    const cached = JSON.parse(readFileSync(file, 'utf8')) as { fetchedAt: string; feed: { vulnerabilities: unknown[] } };
    expect(cached.fetchedAt).toBe(clock.toISOString());
    expect(cached.feed.vulnerabilities).toHaveLength(2);
  });

  it('serves a fresh copy without fetching, and refreshes a stale one or when forced', async () => {
    await load();
    clock = new Date(clock.getTime() + 23 * 3_600_000);
    expect((await load()).fetched).toBe(false);
    expect(fetchFn.calls).toHaveLength(1);
    expect((await load({ force: true })).fetched).toBe(true);
    clock = new Date(clock.getTime() + 25 * 3_600_000);
    expect((await load()).fetched).toBe(true);
    expect(fetchFn.calls).toHaveLength(3);
  });

  it('falls back to the cached copy with a warning when a refresh fails', async () => {
    await load();
    down = true;
    clock = new Date(clock.getTime() + 48 * 3_600_000);
    const r = await load();
    expect(r.available).toBe(true);
    expect(r.index.size).toBe(2);
    expect(r.warnings).toEqual([
      'CISA KEV catalog could not be refreshed (fetch failed (ECONNREFUSED)); using the copy released 2026-11-10',
    ]);
  });

  it('is unavailable, loudly, with no copy and no network', async () => {
    down = true;
    const r = await load();
    expect(r).toMatchObject({ available: false, catalogDate: null, fetched: false });
    expect(r.index.size).toBe(0);
    expect(r.warnings[0]).toMatch(/^CISA KEV catalog unavailable \(fetch failed \(ECONNREFUSED\)\).*P0\/P1/);
    expect(existsSync(file)).toBe(false);
  });

  it('ignores a corrupt cache and refetches', async () => {
    await load();
    writeFileSync(file, '{"format":1,"fetchedAt":"2026-11-12T10:00:00Z","feed":{"vulnerabilities":[]}}');
    const r = await load();
    expect(r.fetched).toBe(true);
    expect(r.warnings[0]).toMatch(/^ignoring the cached KEV catalog/);
    expect((await load()).warnings).toEqual([]);
  });

  it('rejects an empty feed from the network like the POC (keeps the cached copy)', async () => {
    await load();
    feed = { ...feed, count: 0, vulnerabilities: [] };
    const r = await load({ force: true });
    expect(r.index.size).toBe(2);
    expect(r.warnings[0]).toMatch(/could not be refreshed \(KEV feed failed validation/);
  });

  it('rethrows a cancellation', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(load({ signal: ac.signal })).rejects.toThrow();
  });
});

describe('index helpers', () => {
  it('maps to the cve → dateAdded index and picks the ransomware flag of the first matching CVE', async () => {
    const { index } = await load();
    expect(kevDateIndex(index)).toEqual(
      new Map([
        ['CVE-2026-1000', '2026-10-02'],
        ['CVE-2026-0500', '2026-09-01'],
      ]),
    );
    expect(kevRansomwareFor(['CVE-2026-1000', 'CVE-2026-0500'], index)).toBe('Unknown');
    expect(kevRansomwareFor(['CVE-2026-1000'], index)).toBe('Known');
    expect(kevRansomwareFor(['CVE-2026-9999'], index)).toBeNull();
  });
});
