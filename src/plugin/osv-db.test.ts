import { existsSync, readFileSync, rmSync, statSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { osvZipPath, type FetchFn } from '../lib/osv/zip';
import { tempDir } from './git-test-support';
import { ensureOsvDatabases, readSidecar, sidecarPath } from './osv-db';

const ZIP_V1 = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(64, 1)]);
const ZIP_V2 = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(128, 2)]);
const LAST_MODIFIED_V1 = 'Tue, 27 Oct 2026 16:48:18 GMT';
const LAST_MODIFIED_V2 = 'Wed, 11 Nov 2026 08:00:00 GMT';
const BASE = 'https://osv.test';

interface Server {
  body: Buffer;
  etag: string;
  lastModified: string;
  /** Ecosystems answered with 404 */
  missing: Set<string>;
  /** Throw a network error instead of answering */
  down: boolean;
  requests: { url: string; headers: Record<string, string> }[];
}

let dir: string;
let server: Server;
let clock: Date;
const now = () => clock;

const fetchFn: FetchFn = async (url, init) => {
  const headers = { ...(init?.headers as Record<string, string>) };
  server.requests.push({ url, headers });
  init?.signal?.throwIfAborted();
  if (server.down) throw new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND osv.test') });
  const eco = decodeURIComponent(url.slice(BASE.length + 1).replace(/\/all\.zip$/, ''));
  if (server.missing.has(eco)) return new Response(null, { status: 404 });
  if (headers['If-None-Match'] === server.etag) return new Response(null, { status: 304, headers: { etag: server.etag } });
  return new Response(new Uint8Array(server.body), {
    status: 200,
    headers: { etag: server.etag, 'last-modified': server.lastModified, 'content-length': String(server.body.length) },
  });
};

const ensure = (ecosystems: string[], extra: { force?: boolean; signal?: AbortSignal } = {}) =>
  ensureOsvDatabases(ecosystems, { osvDbDir: dir, baseUrl: BASE, fetchFn, now, ...extra });

beforeEach(() => {
  dir = tempDir('vigiles-plugin-osvdb-');
  clock = new Date('2026-11-12T10:00:00Z');
  server = { body: ZIP_V1, etag: '"v1"', lastModified: LAST_MODIFIED_V1, missing: new Set(), down: false, requests: [] };
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('ensureOsvDatabases', () => {
  it('downloads missing databases into the osv-scanner layout with a sidecar', async () => {
    const r = await ensure(['npm', 'SwiftURL']);
    expect(r).toEqual({ unavailable: [], downloaded: ['SwiftURL', 'npm'], warnings: [], dbDate: new Date(LAST_MODIFIED_V1).toISOString() });
    expect(readFileSync(path.join(dir, 'osv-scalibr', 'npm', 'all.zip'))).toEqual(ZIP_V1);
    expect(readSidecar(dir, 'npm')).toEqual({
      etag: '"v1"',
      lastModified: LAST_MODIFIED_V1,
      bytes: ZIP_V1.length,
      path: osvZipPath(dir, 'npm'),
      checkedAt: clock.toISOString(),
    });
    expect(server.requests.map((q) => q.url)).toEqual([`${BASE}/SwiftURL/all.zip`, `${BASE}/npm/all.zip`]);
  });

  it('does not re-check a database checked within maxAgeHours, unless forced', async () => {
    await ensure(['npm']);
    clock = new Date(clock.getTime() + 23 * 3_600_000);
    expect((await ensure(['npm'])).downloaded).toEqual([]);
    expect(server.requests).toHaveLength(1);
    const forced = await ensure(['npm'], { force: true });
    expect(server.requests).toHaveLength(2);
    expect(forced.downloaded).toEqual([]); // 304
  });

  it('re-checks a stale database with a conditional request and keeps it on 304', async () => {
    await ensure(['npm']);
    clock = new Date(clock.getTime() + 25 * 3_600_000);
    const r = await ensure(['npm']);
    expect(r.downloaded).toEqual([]);
    expect(server.requests[1]!.headers['If-None-Match']).toBe('"v1"');
    expect(server.requests[1]!.headers['If-Modified-Since']).toBe(LAST_MODIFIED_V1);
    expect(readSidecar(dir, 'npm').checkedAt).toBe(clock.toISOString());
    await ensure(['npm']);
    expect(server.requests).toHaveLength(2);
  });

  it('replaces a stale database when the server has a new one', async () => {
    await ensure(['npm']);
    Object.assign(server, { body: ZIP_V2, etag: '"v2"', lastModified: LAST_MODIFIED_V2 });
    clock = new Date(clock.getTime() + 25 * 3_600_000);
    const r = await ensure(['npm']);
    expect(r.downloaded).toEqual(['npm']);
    expect(r.dbDate).toBe(new Date(LAST_MODIFIED_V2).toISOString());
    expect(readFileSync(osvZipPath(dir, 'npm'))).toEqual(ZIP_V2);
    expect(readSidecar(dir, 'npm').etag).toBe('"v2"');
  });

  it('keeps a stale database with a dated warning when the refresh fails', async () => {
    await ensure(['npm']);
    const checkedAt = readSidecar(dir, 'npm').checkedAt;
    server.down = true;
    clock = new Date(clock.getTime() + 25 * 3_600_000);
    const r = await ensure(['npm']);
    expect(r.downloaded).toEqual([]);
    expect(r.warnings).toEqual([
      expect.stringMatching(
        /^OSV npm database could not be refreshed \(fetch failed \(getaddrinfo ENOTFOUND osv\.test\)\); matched against the copy from 2026-10-27$/,
      ),
    ]);
    expect(r.dbDate).toBe(new Date(LAST_MODIFIED_V1).toISOString());
    expect(readFileSync(osvZipPath(dir, 'npm'))).toEqual(ZIP_V1);
    expect(readSidecar(dir, 'npm').checkedAt).toBe(checkedAt); // the next run tries again
  });

  it('fails when a missing database cannot be downloaded', async () => {
    server.down = true;
    await expect(ensure(['npm'])).rejects.toThrow(/^OSV npm database could not be downloaded: fetch failed/);
    expect(existsSync(osvZipPath(dir, 'npm'))).toBe(false);
  });

  it('reports ecosystems OSV has no database for as unavailable', async () => {
    server.missing.add('CocoaPods');
    const r = await ensure(['CocoaPods', 'npm']);
    expect(r.unavailable).toEqual(['CocoaPods']);
    expect(r.downloaded).toEqual(['npm']);
    expect(r.dbDate).toBe(new Date(LAST_MODIFIED_V1).toISOString());
    expect(existsSync(sidecarPath(dir, 'CocoaPods'))).toBe(false);
  });

  it('re-checks a zip without a sidecar (e.g. copied from the POC) using its mtime', async () => {
    await ensure(['npm']);
    rmSync(sidecarPath(dir, 'npm'));
    const mtime = statSync(osvZipPath(dir, 'npm')).mtimeMs;
    const r = await ensure(['npm']);
    expect(server.requests).toHaveLength(2);
    expect(server.requests[1]!.headers['If-None-Match']).toBeUndefined();
    expect(server.requests[1]!.headers['If-Modified-Since']).toBe(new Date(mtime).toUTCString());
    expect(r.warnings).toEqual([]);
    expect(readSidecar(dir, 'npm').checkedAt).toBe(clock.toISOString());
  });

  it('rethrows a cancellation and rejects invalid ecosystem names', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(ensure(['npm'], { signal: ac.signal })).rejects.toThrow();
    await expect(ensure(['../etc'])).rejects.toThrow(/invalid OSV ecosystem name/);
  });
});
