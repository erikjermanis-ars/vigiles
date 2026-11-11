import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { DataPaths } from '../lib/config/load';
import { VigilesConfigSchema } from '../lib/config/schema';
import { openDb, type Db } from '../lib/db/client';
import { feedState, projects, scans } from '../lib/db/schema';
import type { JobContext } from '../lib/jobs/types';
import type { ProjectProfile } from '../lib/types';
import { ecosystemsInUse, run } from './sync-osv';

const ZIP = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(32, 7)]);
let server: Server;
let baseUrl: string;
const served: string[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    served.push(req.url ?? '');
    if (req.url === '/npm/all.zip' || req.url === '/Go/all.zip') {
      if (req.headers['if-none-match'] === '"e1"') {
        res.writeHead(304, { ETag: '"e1"' });
        res.end();
        return;
      }
      res.writeHead(200, { ETag: '"e1"', 'Last-Modified': 'Tue, 10 Nov 2026 08:00:00 GMT', 'Content-Length': ZIP.length });
      res.end(ZIP);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const profile = (id: string): ProjectProfile => ({
  id,
  name: id,
  enabled: true,
  repo_path: '/nowhere',
  ref: 'main',
  fetch_before_scan: false,
  exclude: [],
  owners: [],
  criticality: 'low',
  exposure: 'internal',
  data_classes: [],
  runtime: {},
  deployments: [],
  third_party_services: [],
  mitigations: '',
  notes: '',
});

let db: Db;
let dir: string;

function addProject(id: string, enabled: boolean, scanRows: { status: 'succeeded' | 'failed'; lockfiles: string[] }[]): void {
  db.insert(projects)
    .values({ id, name: id, enabled, repoPath: '/nowhere', ref: 'main', profile: profile(id), profileHash: 'h' })
    .run();
  for (const s of scanRows)
    db.insert(scans)
      .values({ projectId: id, ref: 'main', ...s })
      .run();
}

function context(ecosystems: string[]): JobContext {
  const paths: DataPaths = { root: dir, db: ':memory:', osvDb: path.join(dir, 'osv-db'), snapshots: dir, logs: dir, scratch: dir };
  return {
    db,
    jobId: 1,
    type: 'sync-osv',
    params: {},
    config: VigilesConfigSchema.parse({
      osv: { ecosystems, base_url: baseUrl },
      triage: { active_config: 'c', configs: [{ name: 'c', prompt_version: 'v1', model: 'm', effort: 'high', code_access: true }] },
    }),
    paths,
    root: process.cwd(),
    signal: new AbortController().signal,
    log: () => {},
    progress: () => {},
    throwIfCancelled: () => {},
    runChild: async () => ({}),
  };
}

beforeEach(() => {
  db = openDb(':memory:');
  dir = mkdtempSync(path.join(tmpdir(), 'vigiles-sync-osv-'));
  served.length = 0;
  return () => rmSync(dir, { recursive: true, force: true });
});

describe('ecosystemsInUse', () => {
  it("takes each enabled project's latest succeeded scan", () => {
    addProject('web', true, [
      { status: 'succeeded', lockfiles: ['package-lock.json', 'ios/Podfile.lock'] },
      { status: 'failed', lockfiles: [] },
    ]);
    addProject('api', true, [
      { status: 'succeeded', lockfiles: ['Cargo.lock'] },
      { status: 'succeeded', lockfiles: ['go.mod'] },
    ]);
    addProject('ios', false, [{ status: 'succeeded', lockfiles: ['Package.resolved'] }]);
    expect(ecosystemsInUse(db).sort()).toEqual(['CocoaPods', 'Go', 'npm']);
  });
});

describe('sync-osv job', () => {
  it('refreshes configured and in-use ecosystems, reporting ones OSV does not publish', async () => {
    addProject('web', true, [{ status: 'succeeded', lockfiles: ['package-lock.json', 'ios/Podfile.lock'] }]);
    const first = (await run(context(['Go']))) as { ecosystems: Record<string, { status: string }> };
    expect(Object.fromEntries(Object.entries(first.ecosystems).map(([k, v]) => [k, v.status]))).toEqual({
      CocoaPods: 'unavailable',
      Go: 'downloaded',
      npm: 'downloaded',
    });
    expect(
      db
        .select()
        .from(feedState)
        .all()
        .map((f) => f.feed)
        .sort(),
    ).toEqual(['osv:Go', 'osv:npm']);

    const second = (await run(context(['Go']))) as { ecosystems: Record<string, { status: string }> };
    expect(second.ecosystems.npm!.status).toBe('not_modified');
  });

  it('keeps refreshing an ecosystem synced before, even when nothing uses it any more', async () => {
    // Go was downloaded for a project that has since been disabled; the staleness banner still checks osv:Go.
    db.insert(feedState).values({ feed: 'osv:Go', lastSuccessAt: '2026-01-01T00:00:00.000Z' }).run();
    addProject('api', false, [{ status: 'succeeded', lockfiles: ['go.mod'] }]);
    const stats = (await run(context([]))) as { ecosystems: Record<string, { status: string }> };
    expect(Object.keys(stats.ecosystems)).toEqual(['Go']);
    expect(served).toEqual(['/Go/all.zip']);
    expect(
      db
        .select()
        .from(feedState)
        .all()
        .find((f) => f.feed === 'osv:Go')!.lastSuccessAt,
    ).not.toBe('2026-01-01T00:00:00.000Z');
  });

  it('syncs npm when nothing is configured or in use', async () => {
    await run(context([]));
    expect(served).toEqual(['/npm/all.zip']);
  });

  it('fails the job (after trying the rest) when an ecosystem cannot be refreshed', async () => {
    await expect(run(context(['../escape', 'Go']))).rejects.toThrow(/invalid OSV ecosystem name/);
    expect(served).toContain('/Go/all.zip');
  });
});
