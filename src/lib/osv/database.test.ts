import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { feedState } from '../db/schema';
import {
  ecosystemsWithFeedState,
  ensureOsvZips,
  OsvDatabaseUnavailableError,
  osvDbDate,
  osvZipPath,
  refreshOsvZip,
  selectSyncEcosystems,
} from './database';

const ZIP_V1 = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(64, 1)]);
const ZIP_V2 = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(128, 2)]);
const LAST_MODIFIED = 'Tue, 27 Oct 2026 16:48:18 GMT';

let server: Server;
let baseUrl: string;
let body = ZIP_V1;
let etag = '"v1"';
let requests: IncomingHttpHeaders[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    requests.push(req.headers);
    if (req.url === '/npm/all.zip' || req.url === '/SwiftURL/all.zip') {
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { ETag: etag });
        res.end();
        return;
      }
      res.writeHead(200, { ETag: etag, 'Last-Modified': LAST_MODIFIED, 'Content-Length': body.length, 'Content-Type': 'application/zip' });
      res.end(body);
    } else if (req.url === '/Broken/all.zip') {
      res.writeHead(200, { 'Content-Length': 5 });
      res.end('hello');
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

let db: Db;
let dir: string;

beforeEach(() => {
  db = openDb(':memory:');
  dir = mkdtempSync(path.join(tmpdir(), 'vigiles-osvdb-'));
  body = ZIP_V1;
  etag = '"v1"';
  requests = [];
  return () => rmSync(dir, { recursive: true, force: true });
});

const feed = (eco: string) =>
  db
    .select()
    .from(feedState)
    .where(eq(feedState.feed, `osv:${eco}`))
    .get();

describe('refreshOsvZip', () => {
  it('downloads into the osv-scanner layout and records feed_state', async () => {
    const r = await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    const file = osvZipPath(dir, 'npm');
    expect(file).toBe(path.join(dir, 'osv-scalibr', 'npm', 'all.zip'));
    expect(r).toMatchObject({ status: 'downloaded', bytes: ZIP_V1.length, etag: '"v1"', lastModified: LAST_MODIFIED });
    expect(readFileSync(file)).toEqual(ZIP_V1);
    expect(statSync(file).mtime.toUTCString()).toBe(LAST_MODIFIED); // mtime = data date
    expect(feed('npm')).toMatchObject({ lastError: null, meta: { etag: '"v1"', bytes: ZIP_V1.length, path: file } });
    expect(feed('npm')!.lastSuccessAt).not.toBeNull();
    expect(requests[0]!['if-none-match']).toBeUndefined();
  });

  it('sends conditional headers and keeps the file on 304', async () => {
    await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    const r = await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    expect(r.status).toBe('not_modified');
    expect(requests[1]).toMatchObject({ 'if-none-match': '"v1"', 'if-modified-since': LAST_MODIFIED });
    expect(feed('npm')!.meta).toMatchObject({ etag: '"v1"', bytes: ZIP_V1.length });
  });

  it('replaces the file atomically when the server has a newer one', async () => {
    await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    body = ZIP_V2;
    etag = '"v2"';
    const r = await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    expect(r).toMatchObject({ status: 'downloaded', bytes: ZIP_V2.length, etag: '"v2"' });
    expect(readFileSync(osvZipPath(dir, 'npm'))).toEqual(ZIP_V2);
    expect(readdirSync(path.dirname(osvZipPath(dir, 'npm')))).toEqual(['all.zip']); // no temp files left
  });

  it('rethrows other failures from ensureOsvZips', async () => {
    await expect(ensureOsvZips(db, ['Broken'], { baseUrl, osvDbDir: dir })).rejects.toThrow(/not a zip/);
  });

  it('does not send conditional headers when the zip is missing', async () => {
    await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    rmSync(osvZipPath(dir, 'npm'));
    const r = await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    expect(r.status).toBe('downloaded');
    expect(requests[1]!['if-none-match']).toBeUndefined();
  });

  it('records the error, keeps lastSuccessAt, and rethrows', async () => {
    await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    const ok = feed('npm')!.lastSuccessAt;
    await expect(refreshOsvZip(db, 'npm', { baseUrl: 'http://127.0.0.1:1', osvDbDir: dir })).rejects.toThrow(/OSV npm database: /);
    expect(feed('npm')).toMatchObject({ lastSuccessAt: ok });
    expect(feed('npm')!.lastError).toMatch(/fetch failed/);
    expect(existsSync(osvZipPath(dir, 'npm'))).toBe(true);
  });

  it('reports a 404 as an ecosystem without a database, with no feed_state row', async () => {
    await expect(refreshOsvZip(db, 'CocoaPods', { baseUrl, osvDbDir: dir })).rejects.toThrow(OsvDatabaseUnavailableError);
    expect(feed('CocoaPods')).toBeUndefined();
  });

  it('on a 404, drops a feed row that never synced (it would keep the staleness banner up for good)', async () => {
    // An earlier attempt failed before OSV could answer 404, which left a failure-only row.
    await expect(refreshOsvZip(db, 'CocoaPods', { baseUrl: 'http://127.0.0.1:1', osvDbDir: dir })).rejects.toThrow(/fetch failed/);
    expect(feed('CocoaPods')).toMatchObject({ lastSuccessAt: null });
    // A database that once synced keeps its row, so its old zip still reads as stale.
    const synced = '2026-10-01T00:00:00.000Z';
    db.insert(feedState).values({ feed: 'osv:Gone', lastAttemptAt: synced, lastSuccessAt: synced }).run();
    expect(ecosystemsWithFeedState(db).sort()).toEqual(['CocoaPods', 'Gone']);

    await expect(refreshOsvZip(db, 'CocoaPods', { baseUrl, osvDbDir: dir })).rejects.toThrow(OsvDatabaseUnavailableError);
    await expect(refreshOsvZip(db, 'Gone', { baseUrl, osvDbDir: dir })).rejects.toThrow(OsvDatabaseUnavailableError);

    expect(feed('CocoaPods')).toBeUndefined();
    expect(feed('Gone')).toMatchObject({ lastSuccessAt: synced });
  });

  it('rejects a download that is not a zip and leaves no file behind', async () => {
    await expect(refreshOsvZip(db, 'Broken', { baseUrl, osvDbDir: dir })).rejects.toThrow(/not a zip/);
    expect(readdirSync(path.join(dir, 'osv-scalibr', 'Broken'))).toEqual([]);
  });

  it('honours cancellation without recording a feed failure', async () => {
    await refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir });
    const before = feed('npm');
    const controller = new AbortController();
    controller.abort();
    await expect(refreshOsvZip(db, 'npm', { baseUrl, osvDbDir: dir, signal: controller.signal })).rejects.toThrow();
    expect(feed('npm')).toEqual(before);
    expect(readFileSync(osvZipPath(dir, 'npm'))).toEqual(ZIP_V1);
  });

  it('rejects ecosystem names that could leave the database directory', async () => {
    for (const bad of ['../npm', 'a/b', '..', 'npm\\x', '']) {
      await expect(refreshOsvZip(db, bad, { baseUrl, osvDbDir: dir })).rejects.toThrow(/invalid OSV ecosystem name/);
    }
    expect(osvZipPath(dir, 'crates.io')).toBe(path.join(dir, 'osv-scalibr', 'crates.io', 'all.zip'));
    expect(osvZipPath(dir, 'Alpine:v3.20')).toBe(path.join(dir, 'osv-scalibr', 'Alpine:v3.20', 'all.zip'));
    expect(requests).toEqual([]);
  });
});

describe('ensureOsvZips / osvDbDate', () => {
  it('downloads only missing zips and reports the oldest mtime', async () => {
    expect(osvDbDate(dir, ['npm'])).toBeNull();
    const first = await ensureOsvZips(db, ['npm', 'SwiftURL', 'CocoaPods'], { baseUrl, osvDbDir: dir });
    expect(first.downloaded.map((r) => r.ecosystem)).toEqual(['npm', 'SwiftURL']);
    expect(first.unavailable).toEqual(['CocoaPods']);
    const second = await ensureOsvZips(db, ['npm', 'SwiftURL'], { baseUrl, osvDbDir: dir });
    expect(second).toEqual({ downloaded: [], unavailable: [] });
    expect(osvDbDate(dir, ['npm', 'SwiftURL', 'PyPI'])).toBe(new Date(LAST_MODIFIED).toISOString());
  });
});

describe('selectSyncEcosystems', () => {
  it('unions configured, in-use and already synced ecosystems, defaulting to npm', () => {
    expect(selectSyncEcosystems([], [])).toEqual(['npm']);
    expect(selectSyncEcosystems([], [], [])).toEqual(['npm']);
    expect(selectSyncEcosystems(['PyPI'], ['npm', 'SwiftURL', 'npm'])).toEqual(['PyPI', 'SwiftURL', 'npm']);
    expect(selectSyncEcosystems(['PyPI'], ['npm'], ['Go', 'npm'])).toEqual(['Go', 'PyPI', 'npm']);
    expect(selectSyncEcosystems([], [], ['Go'])).toEqual(['Go']);
  });
});

describe('ecosystemsWithFeedState', () => {
  it('lists the ecosystems of osv:* feed rows only, ignoring invalid names', () => {
    const db = openDb(':memory:');
    db.insert(feedState)
      .values([{ feed: 'osv:npm' }, { feed: 'osv:Go' }, { feed: 'osv:crates.io' }, { feed: 'kev' }, { feed: 'epss' }, { feed: 'osv:../x' }])
      .run();
    expect(ecosystemsWithFeedState(db).sort()).toEqual(['Go', 'crates.io', 'npm']);
  });
});
