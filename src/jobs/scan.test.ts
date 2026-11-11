import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { asc, eq } from 'drizzle-orm';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { DataPaths } from '../lib/config/load';
import { VigilesConfigSchema } from '../lib/config/schema';
import { openDb, type Db } from '../lib/db/client';
import { events, findings, inventory, jobRuns, projects, scans } from '../lib/db/schema';
import type { JobContext } from '../lib/jobs/types';
import { osvZipPath } from '../lib/osv/database';
import type { ProjectProfile } from '../lib/types';
import { failInterruptedScans, resultsByLockfile, run, scanCoverageGaps, unreadableLockfiles } from './scan';

const tmp = mkdtempSync(path.join(tmpdir(), 'vigiles-scan-job-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

// ---------- a throwaway git repo standing in for a client project ----------
const repo = path.join(tmp, 'repo');
const git = (...args: string[]) =>
  execFileSync('git', ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], {
    encoding: 'utf8',
  }).trim();

function writeRepoFile(file: string, content: string): void {
  mkdirSync(path.dirname(path.join(repo, file)), { recursive: true });
  writeFileSync(path.join(repo, file), content);
}

function packageLock(vulnVersion: string): string {
  return JSON.stringify({
    name: 'demo',
    lockfileVersion: 3,
    packages: {
      '': { name: 'demo', dependencies: { web: '^1.0.0' } },
      'node_modules/web': { version: '1.0.0', dependencies: { vuln: '^1.0.0' } },
      'node_modules/vuln': { version: vulnVersion },
    },
  });
}

function commit(vulnVersion: string): string {
  writeRepoFile('package-lock.json', packageLock(vulnVersion));
  git('add', '-A');
  git('commit', '-q', '--allow-empty', '-m', `vuln ${vulnVersion}`);
  return git('rev-parse', 'HEAD');
}

mkdirSync(repo, { recursive: true });
execFileSync('git', ['init', '-q', '-b', 'main', repo]);
writeRepoFile('package.json', '{"name":"demo","dependencies":{"web":"^1.0.0"}}');
writeRepoFile('src/app.ts', "import { serve } from 'web';\nserve();\n");
writeRepoFile('src/app.test.ts', "import { serve } from 'web';\n");
writeRepoFile('supabase/functions/x/deno.json', '{}');
writeRepoFile('supabase/functions/x/deno.lock', '{"version":"4"}');
mkdirSync(path.join(repo, 'linked'), { recursive: true });
symlinkSync('../package-lock.json', path.join(repo, 'linked', 'package-lock.json'));

// ---------- a fake osv-scanner ----------
/** Packages the fake reports for the root package-lock.json; rewritten per test step. */
const specFile = path.join(tmp, 'osv-spec.json');
const callsFile = path.join(tmp, 'osv-calls.jsonl');
const fakeBin = path.join(tmp, 'fake-osv-scanner.cjs');
writeFileSync(
  fakeBin,
  `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
// '-L <parser>:<path>' (an empty parser lets osv-scanner pick one); results report the bare path.
const lockfiles = args.filter((a, i) => args[i - 1] === '-L').map((a) => (a.startsWith('/') ? a : a.slice(a.indexOf(':') + 1)));
fs.appendFileSync(${JSON.stringify(callsFile)}, JSON.stringify({ lockfiles, db: process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, args }) + '\\n');
const deno = lockfiles.find((l) => l.endsWith('deno.lock'));
if (deno) { console.error('could not determine extractor suitable to this file: "' + deno + '"'); process.exit(127); }
const packages = JSON.parse(fs.readFileSync(${JSON.stringify(specFile)}, 'utf8'));
const out = args[args.indexOf('--output-file') + 1];
fs.writeFileSync(out, JSON.stringify({ results: lockfiles.map((l) => ({ source: { path: l, type: 'lockfile' }, packages })) }));
process.exit(packages.some((p) => p.vulnerabilities) ? 1 : 0);
`,
);
chmodSync(fakeBin, 0o755);

function vulnRecord(modified: string) {
  return {
    id: 'GHSA-vuln-0001',
    aliases: ['CVE-2026-0001'],
    summary: 'bad',
    modified,
    database_specific: { severity: 'HIGH' },
    affected: [
      { package: { ecosystem: 'npm', name: 'vuln' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] },
    ],
  };
}

function osvReports(vulnVersion: string, opts: { vulnerable: boolean; modified?: string }) {
  const vuln: Record<string, unknown> = { package: { name: 'vuln', version: vulnVersion, ecosystem: 'npm' } };
  if (opts.vulnerable) {
    vuln.groups = [{ ids: ['GHSA-vuln-0001'], aliases: ['GHSA-vuln-0001', 'CVE-2026-0001'], max_severity: '7.5' }];
    vuln.vulnerabilities = [vulnRecord(opts.modified ?? '2026-01-01T00:00:00Z')];
  }
  writeFileSync(specFile, JSON.stringify([{ package: { name: 'web', version: '1.0.0', ecosystem: 'npm' } }, vuln]));
}

const calls = () =>
  existsSync(callsFile)
    ? readFileSync(callsFile, 'utf8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as { lockfiles: string[]; db: string; args: string[] })
    : [];

// ---------- job context ----------
const dataRoot = path.join(tmp, 'data');
const paths: DataPaths = {
  root: dataRoot,
  db: ':memory:',
  osvDb: path.join(dataRoot, 'osv-db'),
  snapshots: path.join(dataRoot, 'snapshots'),
  logs: path.join(dataRoot, 'logs'),
  scratch: path.join(dataRoot, 'scratch'),
};
for (const dir of [paths.osvDb, paths.snapshots, paths.logs, paths.scratch]) mkdirSync(dir, { recursive: true });
// The npm database is present, so the scan never downloads (and base_url points nowhere).
mkdirSync(path.dirname(osvZipPath(paths.osvDb, 'npm')), { recursive: true });
writeFileSync(osvZipPath(paths.osvDb, 'npm'), 'PK\x03\x04');

const config = VigilesConfigSchema.parse({
  bin: { osv_scanner: fakeBin, git: 'git' },
  osv: { base_url: 'http://127.0.0.1:9' },
  triage: { active_config: 'c', configs: [{ name: 'c', prompt_version: 'v1', model: 'm', effort: 'high', code_access: true }] },
});

const profile: ProjectProfile = {
  id: 'demo',
  name: 'Demo',
  enabled: true,
  repo_path: repo,
  ref: 'main',
  fetch_before_scan: false,
  exclude: [],
  owners: [],
  criticality: 'medium',
  exposure: 'internal',
  data_classes: [],
  runtime: {},
  deployments: [],
  third_party_services: [],
  mitigations: '',
  notes: '',
};

let db: Db;
let logs: string[];

function context(params: Record<string, unknown>): JobContext {
  const jobId = db.insert(jobRuns).values({ type: 'scan', params, status: 'running' }).returning({ id: jobRuns.id }).get().id;
  return {
    db,
    jobId,
    type: 'scan',
    params,
    config,
    paths,
    root: process.cwd(),
    signal: new AbortController().signal,
    log: (m) => logs.push(m),
    progress: () => {},
    throwIfCancelled: () => {},
    runChild: async () => ({}),
  };
}

async function scanJob(params: Record<string, unknown> = { project: 'demo' }) {
  const ctx = context(params);
  const stats = (await run(ctx)) as { projects: Record<string, Record<string, unknown>> };
  db.update(jobRuns).set({ status: 'succeeded' }).where(eq(jobRuns.id, ctx.jobId)).run();
  return { jobId: ctx.jobId, summary: stats.projects.demo! };
}

beforeEach(() => {
  db = openDb(':memory:');
  logs = [];
  rmSync(callsFile, { force: true });
  db.insert(projects).values({ id: 'demo', name: 'Demo', enabled: false, repoPath: repo, ref: 'main', profile, profileHash: 'h' }).run();
});

describe('scan job (end to end with a fake osv-scanner)', () => {
  it('scans a commit, skips lockfiles it cannot match without failing, and diffs on rescans', async () => {
    const sha1 = commit('1.0.0');
    osvReports('1.0.0', { vulnerable: true });
    // A scan left running by a job that no longer runs.
    const stale = db.insert(scans).values({ projectId: 'demo', jobRunId: 999, ref: 'main', status: 'running' }).returning().get();

    const first = await scanJob(); // the project is disabled but named explicitly
    expect(db.select().from(scans).where(eq(scans.id, stale.id)).get()).toMatchObject({ status: 'failed', error: 'interrupted' });

    const scan = db
      .select()
      .from(scans)
      .where(eq(scans.id, first.summary.scanId as number))
      .get()!;
    expect(scan).toMatchObject({
      status: 'succeeded',
      commitSha: sha1,
      lockfiles: ['linked/package-lock.json', 'package-lock.json', 'supabase/functions/x/deno.lock'],
      coverageGaps: ['linked/package-lock.json', 'supabase/functions/x/deno.json', 'supabase/functions/x/deno.lock'],
      osvDbDate: expect.any(String),
    });
    expect(scan.stats).toMatchObject({ lockfiles: 3, lockfilesSkipped: 2, packages: 2, vulnerablePackages: 1, created: 1 });
    expect(first.summary.skippedLockfiles).toEqual(['linked/package-lock.json', 'supabase/functions/x/deno.lock']);
    expect((first.summary.warnings as string[]).join('\n')).toMatch(/symlink[\s\S]*cannot parse this lockfile type/);

    // osv-scanner ran offline against our DB dir; the symlinked lockfile never reached it, deno.lock was retried away.
    const snapshot = path.join(paths.snapshots, 'demo', sha1);
    expect(calls().map((c) => c.lockfiles)).toEqual([
      [path.join(snapshot, 'package-lock.json'), path.join(snapshot, 'supabase/functions/x/deno.lock')],
      [path.join(snapshot, 'package-lock.json')],
    ]);
    expect(calls()[0]!.db).toBe(paths.osvDb);
    expect(calls()[0]!.args).toContain('--offline');

    const f = db.select().from(findings).get()!;
    expect(f).toMatchObject({
      lockfile: 'package-lock.json',
      ecosystem: 'npm',
      packageName: 'vuln',
      osvId: 'GHSA-vuln-0001',
      status: 'open',
      origin: 'baseline',
      installedVersions: ['1.0.0'],
      fixedVersions: ['1.0.1'],
      direct: false,
      devOnly: false,
      paths: [['web', 'vuln']],
      importSites: [{ file: 'src/app.ts', line: 1, specifier: 'web', via: 'web' }],
      advisoryModified: '2026-01-01T00:00:00Z',
    });
    expect(db.select().from(inventory).where(eq(inventory.scanId, scan.id)).all()).toHaveLength(2);
    expect(db.select().from(projects).get()!.lastScanId).toBe(scan.id);

    // Same commit again: nothing changes, no events.
    const second = await scanJob();
    expect(second.summary).toMatchObject({ created: 0, updated: 1, factsChanged: 0, fixed: 0, advisoryChanged: 0 });
    expect(db.select().from(events).where(eq(events.jobRunId, second.jobId)).all()).toEqual([]);

    // The advisory is revised upstream.
    osvReports('1.0.0', { vulnerable: true, modified: '2026-02-01T00:00:00Z' });
    const third = await scanJob();
    expect(third.summary).toMatchObject({ advisoryChanged: 1, created: 0 });

    // Upgrade past the fix: fixed.
    commit('1.0.1');
    osvReports('1.0.1', { vulnerable: false });
    const fourth = await scanJob();
    expect(fourth.summary).toMatchObject({ fixed: 1, findingsTotalOpen: 0 });
    expect(db.select().from(findings).get()).toMatchObject({ status: 'fixed', resolvedAt: expect.any(String) });
    expect(
      db
        .select()
        .from(events)
        .orderBy(asc(events.id))
        .all()
        .map((e) => [e.type, e.jobRunId]),
    ).toEqual([
      ['created', first.jobId],
      ['advisory_changed', third.jobId],
      ['fixed', fourth.jobId],
    ]);
  });

  it('scans only enabled projects when none is named', async () => {
    commit('1.0.0');
    osvReports('1.0.0', { vulnerable: false });
    expect(await run(context({}))).toEqual({ projects: {} });
    expect(calls()).toEqual([]);
  });

  it('rejects an unknown or malformed project parameter', async () => {
    await expect(run(context({ project: 'nope' }))).rejects.toThrow(/unknown project "nope"/);
    await expect(run(context({ project: true }))).rejects.toThrow(/params.project/);
  });

  it('marks the scan failed with the error and rethrows', async () => {
    commit('1.0.0');
    writeFileSync(specFile, 'not json');
    const err = await run(context({ project: 'demo' })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/scan failed for demo/);
    // The per-project summaries ride on the error, so the failed job row keeps them.
    expect((err as { stats?: unknown }).stats).toEqual({ projects: { demo: { error: expect.stringMatching(/osv-scanner exited/) } } });
    const scan = db.select().from(scans).all().at(-1)!;
    expect(scan.status).toBe('failed');
    expect(scan.error).toMatch(/osv-scanner exited/);
    expect(db.select().from(findings).all()).toEqual([]);
  });
});

describe('failInterruptedScans', () => {
  const DEAD = 999_001;
  const alive = (pid: number) => pid !== DEAD;
  const job = (status: 'running' | 'succeeded', pid: number | null) =>
    db.insert(jobRuns).values({ type: 'scan', status, pid }).returning({ id: jobRuns.id }).get().id;
  const scan = (jobRunId: number | null) =>
    db.insert(scans).values({ projectId: 'demo', jobRunId, ref: 'main', status: 'running' }).returning({ id: scans.id }).get().id;
  const statusOf = (id: number) => db.select().from(scans).where(eq(scans.id, id)).get()!.status;

  it('reclaims scans of finished, dead or legacy jobs, but not those of a live process or the current job', () => {
    const own = job('running', null);
    const ids = {
      own: scan(own),
      liveCli: scan(job('running', 4242)),
      deadWorker: scan(job('running', DEAD)),
      legacyRow: scan(job('running', null)),
      finished: scan(job('succeeded', 4242)),
      missingJob: scan(123_456),
      noJob: scan(null),
    };

    failInterruptedScans({ db, jobId: own }, alive);

    expect(Object.fromEntries(Object.entries(ids).map(([k, id]) => [k, statusOf(id)]))).toEqual({
      own: 'running',
      liveCli: 'running',
      deadWorker: 'failed',
      legacyRow: 'failed',
      finished: 'failed',
      missingJob: 'failed',
      noJob: 'failed',
    });
  });
});

describe('resultsByLockfile', () => {
  const pkg = (name: string) => ({ name, version: '1.0.0', ecosystem: 'npm', dev: false, groups: [] });

  it('maps absolute source paths back to repo-relative lockfiles and merges repeats', () => {
    const map = resultsByLockfile(
      '/snap',
      ['package-lock.json', 'backend/package-lock.json'],
      [
        { path: '/snap/backend/package-lock.json', packages: [pkg('a')] },
        { path: '/snap/package-lock.json', packages: [pkg('b')] },
        { path: 'snap/backend/package-lock.json', packages: [pkg('c')] }, // scalibr-style, no leading slash
      ],
    );
    expect([...map.keys()].sort()).toEqual(['backend/package-lock.json', 'package-lock.json']);
    expect(map.get('backend/package-lock.json')!.packages.map((p) => p.name)).toEqual(['a', 'c']);
  });

  it('refuses a source it cannot place instead of dropping its packages', () => {
    expect(() => resultsByLockfile('/snap', ['package-lock.json'], [{ path: '/elsewhere/package-lock.json', packages: [] }])).toThrow(
      /not one of the scanned lockfiles/,
    );
  });
});

describe('scanCoverageGaps / unreadableLockfiles', () => {
  it('lists manifests without a matched lockfile plus the unmatched lockfiles', () => {
    expect(
      scanCoverageGaps(
        ['package.json', 'package-lock.json', 'fn/deno.json', 'fn/deno.lock', 'ios/Podfile', 'ios/Podfile.lock'],
        ['package-lock.json'],
        ['fn/deno.lock', 'ios/Podfile.lock'],
        [],
      ),
    ).toEqual(['fn/deno.json', 'fn/deno.lock', 'ios/Podfile', 'ios/Podfile.lock']);
  });

  it('flags symlinked and missing lockfiles', () => {
    const snap = path.join(tmp, 'snap-check');
    mkdirSync(path.join(snap, 'a'), { recursive: true });
    writeFileSync(path.join(snap, 'package-lock.json'), '{}');
    symlinkSync('/etc/hosts', path.join(snap, 'a', 'package-lock.json'));
    expect(unreadableLockfiles(snap, ['package-lock.json', 'a/package-lock.json', 'gone/package-lock.json'])).toEqual([
      'a/package-lock.json',
      'gone/package-lock.json',
    ]);
  });
});
