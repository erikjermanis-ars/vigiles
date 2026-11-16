import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { loadPolicy, loadVigilesConfig } from '../lib/config/load';
import { openDb } from '../lib/db/client';
import { findings as findingsTable, projects, scans, triageConfigs } from '../lib/db/schema';
import { buildImportIndex } from '../lib/inventory/import-sites';
import { discoverLockfiles, excludeMatcher } from '../lib/inventory/lockfiles';
import { observeScan } from '../lib/inventory/observe';
import { applyScanResult } from '../lib/inventory/persist-scan';
import { loadNpmGraph, resultsByLockfile } from '../lib/inventory/scan-results';
import { parseOsvOutput } from '../lib/osv/output';
import type { OsvScanRun, RunOsvScannerOptions } from '../lib/osv/scanner';
import { enrichOpenFindings } from '../lib/signals/enrich';
import { EPSS_API_URL } from '../lib/signals/epss';
import { KEV_FEED_URL, parseKevFeed, replaceKevCatalog } from '../lib/signals/kev';
import { epssApiStub, jsonResponse, kevFeed, stubFetch } from '../lib/signals/test-support';
import { triageProfileHash } from '../lib/triage/profile';
import { loadFindingContext } from '../lib/triage/runner';
import { findingInputHash } from '../lib/triage/state';
import { ProjectProfileSchema } from '../lib/types';
import { createTestRepo, tempDir, type TestRepo } from './git-test-support';
import { pluginPaths, repoPaths, type PluginPaths } from './paths';
import { ProfileMissingError } from './profile';
import { assertSafeRef, findingId, InvalidRefError, KEEP_SNAPSHOTS, loadTriageConfig, pruneSnapshots, readScanResult, runScan } from './scan';
import type { ScanResult } from './types';

const ROOT = process.cwd();
const fixture = (f: string) => readFileSync(path.join(ROOT, 'test/fixtures/scan', f), 'utf8');
const OSV_FIXTURE = parseOsvOutput(JSON.parse(fixture('osv-output.json')));
const IOS_LOCKFILE = 'ios/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved';
const OSV_BASE = 'https://osv.test';
const ZIP = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(32, 7)]);
const ZIP_DATE = 'Tue, 10 Nov 2026 08:00:00 GMT';

const PROFILE_YAML = `
id: demo-app
name: Demo App
ref: origin/main
exclude: []
criticality: high
exposure: internet-facing
data_classes: [pii]
runtime: { language: typescript }
deployments: [{ env: production, hosting: Linux container }]
mitigations: none known
notes: fixture
`;

const KEV = (() => {
  const feed = kevFeed([{ cveID: 'CVE-2026-1000', dateAdded: '2026-10-02' }]);
  return { ...feed, vulnerabilities: feed.vulnerabilities.map((v) => ({ ...v, knownRansomwareCampaignUse: 'Known' })) };
})();
const EPSS = { 'CVE-2026-1000': 0.62, 'CVE-2026-2000': 0.02 };
const epssStub = epssApiStub(EPSS);

let kevDown = false;
let epssDown = false;
const fetchFn = stubFetch((url, init) => {
  init?.signal?.throwIfAborted();
  if (url.startsWith(OSV_BASE)) {
    return new Response(new Uint8Array(ZIP), {
      status: 200,
      headers: { 'last-modified': ZIP_DATE, etag: '"z"', 'content-length': String(ZIP.length) },
    });
  }
  if (url === KEV_FEED_URL) {
    if (kevDown) throw new TypeError('fetch failed', { cause: new Error('ENOTFOUND') });
    return jsonResponse(KEV);
  }
  if (url.startsWith(EPSS_API_URL)) {
    if (epssDown) return new Response('down', { status: 503, statusText: 'Service Unavailable' });
    return epssStub(url, init);
  }
  throw new Error(`unexpected request ${url}`);
});

/** Stands in for osv-scanner: answers with the fixture output for the lockfiles it is given (paths rewritten). */
const scannerCalls: RunOsvScannerOptions[] = [];
async function fakeOsvScanner(opts: RunOsvScannerOptions): Promise<OsvScanRun> {
  scannerCalls.push(opts);
  const results = opts.lockfiles.flatMap((abs) => {
    const hit = OSV_FIXTURE.find((r) => abs.endsWith(r.path.replace(/^\/snapshot/, '')));
    return hit ? [{ ...hit, path: abs }] : [];
  });
  return { results, durationMs: 1, exitCode: 1, warnings: '', unsupported: [] };
}

let repo: TestRepo;
let cache: string;
let plugin: PluginPaths;
let firstSha: string;

const scan = (extra: Partial<Parameters<typeof runScan>[0]> = {}) =>
  runScan({
    repoRoot: repo.root,
    plugin,
    toolVersion: '0.1.0-test',
    bins: { git: 'git', osvScanner: '/nonexistent/osv-scanner', claude: '/nonexistent/claude' },
    osvBaseUrl: OSV_BASE,
    fetchFn,
    runOsvScanner: fakeOsvScanner,
    clock: () => new Date('2026-11-12T10:00:00Z'),
    ...extra,
  });

const gitStatus = () => execFileSync('git', ['-C', repo.root, 'status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' });

beforeAll(() => {
  repo = createTestRepo('vigiles-plugin-scan-');
  repo.write('package.json', JSON.stringify({ name: 'fixture-app', dependencies: { 'web-framework': '^2.0.0', 'cli-tool': '^1.0.0' } }));
  repo.write('package-lock.json', fixture('package-lock.json'));
  repo.write(IOS_LOCKFILE, '{"pins":[],"version":2}\n');
  repo.write('src/server.ts', "import { serve } from 'web-framework/server';\nserve();\n");
  repo.write('.vigiles/profile.yaml', PROFILE_YAML);
  repo.write('.vigiles/.gitignore', 'report.md\n');
  firstSha = repo.commit('init');
  cache = tempDir('vigiles-plugin-cache-');
  plugin = pluginPaths({ assetRoot: ROOT, env: { ...process.env, VIGILES_CACHE_DIR: cache } });
});
afterAll(() => {
  repo.cleanup();
  rmSync(cache, { recursive: true, force: true });
});
beforeEach(() => {
  kevDown = false;
  epssDown = false;
  scannerCalls.length = 0;
});

describe('runScan', () => {
  let result: ScanResult;
  beforeAll(async () => {
    result = await scan();
  });

  it('audits HEAD on the current branch and records what it read', () => {
    expect(result).toMatchObject({
      format: 1,
      toolVersion: '0.1.0-test',
      scannedAt: '2026-11-12T10:00:00.000Z',
      repoRoot: repo.root,
      projectId: 'demo-app',
      projectName: 'Demo App',
      ref: 'HEAD',
      branch: 'main',
      commit: firstSha,
      uncommittedDependencyFiles: [],
      lockfiles: [IOS_LOCKFILE, 'package-lock.json'],
      skippedLockfiles: [],
      ecosystems: ['SwiftURL', 'npm'],
      warnings: [],
      data: {
        osvDbDate: new Date(ZIP_DATE).toISOString(),
        kevCatalogDate: KEV.dateReleased,
        kevAvailable: true,
        epssDate: '2026-11-09',
        epssFailedCves: 0,
      },
      profileHash: triageProfileHash(ProjectProfileSchema.parse({ ...(parseYaml(PROFILE_YAML) as object), repo_path: '/any' })),
      policyHash: loadPolicy(ROOT).hash,
      triageConfig: loadTriageConfig(ROOT),
      stats: { packages: 8, vulnerablePackages: 4 },
    });
    expect(result.triageConfig).toMatchObject({
      name: 'v3-opus-high-code',
      promptVersion: 'v3',
      model: 'opus',
      effort: 'high',
      codeAccess: true,
    });
    expect(result.triageConfig.promptFingerprint).toMatch(/^v3@[0-9a-f]{8}$/);
    expect(result.snapshotDir).toBe(path.join(cache, 'snapshots', repoPaths(repo.root, 'demo-app', plugin).projectKey, firstSha));
    expect(existsSync(path.join(result.snapshotDir, 'src/server.ts'))).toBe(true);
    // The committed .vigiles/ (profile, verdicts) is not code: triage must not grep earlier verdicts.
    expect(existsSync(path.join(result.snapshotDir, '.vigiles'))).toBe(false);
  });

  it('runs osv-scanner offline over the snapshot with the Vigiles config', () => {
    // (beforeAll ran it; the call log was reset by beforeEach, so scan again)
    return scan().then(() => {
      expect(scannerCalls).toHaveLength(1);
      expect(scannerCalls[0]).toMatchObject({
        osvDbDir: path.join(cache, 'osv-db'),
        scratchDir: path.join(cache, 'scratch'),
        configFile: path.join(ROOT, 'config/osv-scanner.toml'),
        lockfiles: [path.join(result.snapshotDir, IOS_LOCKFILE), path.join(result.snapshotDir, 'package-lock.json')],
      });
      expect(existsSync(path.join(cache, 'osv-db/osv-scalibr/npm/all.zip'))).toBe(true);
      expect(existsSync(path.join(cache, 'osv-db/osv-scalibr/SwiftURL/all.zip'))).toBe(true);
    });
  });

  it('produces the findings with signals, sorted by id', () => {
    expect(result.findings.map((f) => f.id)).toEqual([
      'GHSA-aaaa-bbbb-cccc npm:vuln-pkg package-lock.json',
      'GHSA-dev0-dev0-dev0 npm:glob-ish package-lock.json',
      `GHSA-swft-swft-swft SwiftURL:github.com/example/swift-lib ${IOS_LOCKFILE}`,
      'GHSA-zzzz-yyyy-xxxx npm:vuln-pkg package-lock.json',
    ]);
    const kev = result.findings[0]!;
    expect(kev).toMatchObject({
      installedVersions: ['0.9.0', '1.0.0'],
      cves: ['CVE-2026-1000'],
      inKev: true,
      kevDateAdded: '2026-10-02',
      kevRansomware: 'Known',
      epss: 0.62,
      cvssScore: 9.8,
      priority: 'P0',
      malicious: false,
      importSites: [expect.objectContaining({ file: 'src/server.ts', line: 1, via: 'web-framework' })],
    });
    expect(kev.inputHash).toMatch(/^[0-9a-f]{16}$/);
    const swift = result.findings[2]!;
    expect(swift).toMatchObject({ inKev: false, kevRansomware: null, epss: 0.02, priority: 'P3', direct: null });
    expect(findingId(swift)).toBe(swift.id);
  });

  it('keeps only the advisories the findings name', () => {
    expect(Object.keys(result.advisories)).toEqual([
      'GHSA-aaaa-bbbb-cccc',
      'GHSA-dev0-dev0-dev0',
      'GHSA-swft-swft-swft',
      'GHSA-zzzz-yyyy-xxxx',
    ]);
    expect(result.advisories['GHSA-aaaa-bbbb-cccc']).toMatchObject({
      cves: ['CVE-2026-1000'],
      summary: 'Prototype pollution in vuln-pkg',
      cvssScore: 9.8,
      severityLabel: 'CRITICAL',
      modified: '2026-10-01T00:00:00Z',
      raw: expect.objectContaining({ id: 'GHSA-aaaa-bbbb-cccc' }),
    });
  });

  it('writes scan.json to the cache and nothing to the repository', () => {
    const file = repoPaths(repo.root, 'demo-app', plugin).scanFile;
    expect(file.startsWith(path.join(cache, 'repos'))).toBe(true);
    expect(readScanResult(file)).toEqual(result);
    expect(gitStatus()).toBe('');
  });

  it('matches the POC dashboard for the same commit: priorities, signals and triage input hashes', async () => {
    const db = openDb(':memory:');
    const files = execFileSync('git', ['-C', repo.root, 'ls-tree', '-r', '--name-only', firstSha], { encoding: 'utf8' }).trim().split('\n');
    // config sync (src/lib/config/load.ts loadProjects + sync.ts)
    const pocProfile = ProjectProfileSchema.parse({ ...(parseYaml(PROFILE_YAML) as object), repo_path: repo.root });
    db.insert(projects)
      .values({
        id: pocProfile.id,
        name: pocProfile.name,
        repoPath: repo.root,
        ref: pocProfile.ref,
        profile: pocProfile,
        profileHash: 'x',
        triageProfileHash: triageProfileHash(pocProfile),
      })
      .run();
    const vigiles = loadVigilesConfig(ROOT);
    const def = vigiles.triage.configs.find((c) => c.name === vigiles.triage.active_config)!;
    const configRow = db
      .insert(triageConfigs)
      .values({
        name: def.name,
        promptVersion: def.prompt_version,
        model: def.model,
        effort: def.effort,
        codeAccess: def.code_access,
        active: true,
      })
      .returning()
      .get();
    // scan job (src/jobs/scan.ts scanProject/matchLockfiles) over the same snapshot
    const scanId = db.insert(scans).values({ projectId: pocProfile.id, ref: pocProfile.ref }).returning({ id: scans.id }).get().id;
    const snapshot = result.snapshotDir;
    const { lockfiles } = discoverLockfiles(files, pocProfile);
    const osv = await fakeOsvScanner({ bin: 'x', osvDbDir: 'x', scratchDir: 'x', lockfiles: lockfiles.map((l) => path.join(snapshot, l)) });
    const byLockfile = resultsByLockfile(snapshot, lockfiles, osv.results);
    const isExcluded = excludeMatcher(pocProfile.exclude);
    const observation = observeScan(
      lockfiles.map((lockfile) => ({
        lockfile,
        packages: byLockfile.get(lockfile)?.packages ?? [],
        npmGraph: loadNpmGraph(snapshot, lockfile, () => {}),
      })),
      {
        importIndex: () =>
          buildImportIndex(
            snapshot,
            files.filter((f) => !isExcluded(f)),
          ),
      },
    );
    applyScanResult(db, { projectId: pocProfile.id, scanId, jobRunId: null, observation, lockfiles, osvDbDate: null });
    // sync-kev + enrich
    replaceKevCatalog(db, parseKevFeed(KEV));
    await enrichOpenFindings(db, { thresholds: loadPolicy(ROOT).policy.thresholds, fetchFn });

    const rows = db.select().from(findingsTable).where(eq(findingsTable.projectId, pocProfile.id)).all();
    expect(rows).toHaveLength(result.findings.length);
    for (const row of rows) {
      const ours = result.findings.find((f) => f.id === findingId(row))!;
      expect(ours, findingId(row)).toBeDefined();
      const ctx = loadFindingContext(db, row);
      expect({
        priority: ours.priority,
        priorityReasons: ours.priorityReasons,
        inKev: ours.inKev,
        kevDateAdded: ours.kevDateAdded,
        kevRansomware: ours.kevRansomware,
        epss: ours.epss,
        epssPercentile: ours.epssPercentile,
        cvssScore: ours.cvssScore,
        inputHash: ours.inputHash,
        importSites: ours.importSites,
        instances: ours.instances,
      }).toEqual({
        priority: row.priority,
        priorityReasons: row.priorityReasons,
        inKev: row.inKev,
        kevDateAdded: row.kevDateAdded,
        kevRansomware: row.inKev ? ctx.kevRansomware : null,
        epss: row.epss,
        epssPercentile: row.epssPercentile,
        cvssScore: row.cvssScore,
        inputHash: findingInputHash(db, row, configRow),
        importSites: row.importSites,
        instances: row.instances,
      });
    }
  });
});

describe('runScan options and edge cases', () => {
  it('warns about uncommitted lockfile and manifest changes when auditing HEAD', async () => {
    repo.write('package-lock.json', fixture('package-lock.json').replace('"version": "1.0.0"', '"version": "1.0.1"'));
    repo.write('web/package.json', '{}');
    try {
      const r = await scan();
      expect(r.uncommittedDependencyFiles).toEqual(['package-lock.json', 'web/package.json']);
      expect(r.warnings).toEqual([expect.stringMatching(/^uncommitted changes to package-lock.json, web\/package.json are not audited/)]);
      expect(r.commit).toBe(firstSha);
    } finally {
      repo.git(['checkout', '--', 'package-lock.json']);
      rmSync(path.join(repo.root, 'web'), { recursive: true, force: true });
    }
  });

  it('audits another ref without the uncommitted check, and reports a detached HEAD as no branch', async () => {
    repo.git(['checkout', '-q', '-b', 'feature']);
    repo.git(['rm', '-q', IOS_LOCKFILE]);
    const featureSha = repo.commit('drop ios');
    repo.git(['checkout', '-q', 'main']);
    repo.write('package.json', '{"dirty":true}');
    try {
      const r = await scan({ ref: 'feature' });
      expect(r).toMatchObject({
        ref: 'feature',
        branch: 'feature',
        commit: featureSha,
        lockfiles: ['package-lock.json'],
        uncommittedDependencyFiles: [],
      });
      expect(r.findings.map((f) => f.ecosystem)).not.toContain('SwiftURL');
    } finally {
      repo.git(['checkout', '--', 'package.json']);
    }
    repo.git(['checkout', '-q', '--detach', featureSha]);
    try {
      const r = await scan();
      expect(r).toMatchObject({ ref: 'HEAD', branch: null, commit: featureSha });
    } finally {
      repo.git(['checkout', '-q', 'main']);
    }
  });

  it('only fetches remote-tracking refs', async () => {
    const r = await scan({ fetch: true });
    expect(r.warnings).toEqual(['--fetch: HEAD is not a remote-tracking ref (e.g. origin/main); nothing was fetched']);
    await expect(scan({ ref: 'origin/nope' })).rejects.toThrow(/^cannot resolve origin\/nope to a commit/);
  });

  it('refuses a --ref git could read as an option or a refspec, before running any git command', async () => {
    const refs = repo.git(['for-each-ref']);
    for (const ref of [
      'origin/--upload-pack=touch PWNED; git-upload-pack',
      'origin/main:refs/heads/injected',
      'origin/+main:refs/remotes/origin/main',
      '--output=/tmp/x',
    ]) {
      await expect(scan({ ref, fetch: true }), ref).rejects.toBeInstanceOf(InvalidRefError);
    }
    await expect(scan({ ref: 'a:b' })).rejects.toThrow(/^--ref "a:b" is not a branch, tag, remote-tracking ref or commit$/);
    expect(repo.git(['for-each-ref'])).toBe(refs);
    expect(existsSync(path.join(repo.root, 'PWNED'))).toBe(false);
  });

  it('works without KEV and EPSS, saying so, and keeps the previous EPSS scores', async () => {
    const kevFile = plugin.kevFile;
    rmSync(kevFile, { force: true });
    kevDown = true;
    epssDown = true;
    const r = await scan();
    expect(r.data).toMatchObject({ kevAvailable: false, kevCatalogDate: null, epssFailedCves: 2 });
    expect(r.warnings).toEqual([
      expect.stringMatching(/^CISA KEV catalog unavailable/),
      expect.stringMatching(/^EPSS lookup failed for 2 CVE\(s\) \(batch 1\/1: GET .* HTTP 503 Service Unavailable\)/),
    ]);
    const kev = r.findings[0]!;
    expect(kev).toMatchObject({ inKev: false, kevRansomware: null, epss: 0.62 }); // EPSS from the previous scan.json
    expect(kev.priority).toBe('P1'); // EPSS 0.62 ≥ epss_high without the KEV flag
  });

  it('fails clearly without a profile', async () => {
    const other = createTestRepo('vigiles-plugin-noprofile-');
    try {
      other.write('package-lock.json', '{}');
      other.commit();
      await expect(
        runScan({ repoRoot: other.root, plugin, toolVersion: 'x', fetchFn, runOsvScanner: fakeOsvScanner }),
      ).rejects.toBeInstanceOf(ProfileMissingError);
    } finally {
      other.cleanup();
    }
  });

  it('keeps the last few snapshots of the repository', async () => {
    const key = repoPaths(repo.root, 'demo-app', plugin).projectKey;
    const dir = path.join(plugin.snapshotsDir, key);
    for (let i = 0; i < 3; i++) {
      repo.write('src/server.ts', `import { serve } from 'web-framework/server';\nserve(${i});\n`);
      repo.commit(`change ${i}`);
      await scan();
    }
    const head = repo.git(['rev-parse', 'HEAD']);
    const kept = readdirSync(dir).filter((n) => /^[0-9a-f]{40}$/.test(n));
    expect(kept).toHaveLength(KEEP_SNAPSHOTS);
    expect(kept).toContain(head);
  });
});

describe('assertSafeRef', () => {
  it('accepts branches, tags, remote-tracking refs, shas and ~/^ suffixes; refuses option and refspec syntax', () => {
    for (const ref of ['HEAD', 'main', 'origin/main', 'origin/feature/x', 'v1.2.3', 'a1b2c3d4e5f6', 'HEAD~1', 'main^', 'release-2026.11']) {
      expect(() => assertSafeRef(ref), ref).not.toThrow();
    }
    for (const ref of ['', '-x', 'origin/--upload-pack=x', 'origin/a:refs/heads/b', 'origin/+a', 'a..b', 'HEAD@{1}', 'a b', 'a\\b', 'a/.b', 'a//b']) {
      expect(() => assertSafeRef(ref), ref).toThrow(InvalidRefError);
    }
  });
});

describe('pruneSnapshots', () => {
  it('keeps the current snapshot and the most recent others, and clears old temp dirs', () => {
    const root = tempDir('vigiles-prune-');
    try {
      const now = Date.parse('2026-11-12T10:00:00Z');
      const make = (name: string, ageHours: number) => {
        const d = path.join(root, 'proj', name);
        mkdirSync(d, { recursive: true });
        writeFileSync(path.join(d, 'f'), 'x');
        const t = new Date(now - ageHours * 3_600_000);
        utimesSync(d, t, t);
      };
      const sha = (c: string) => c.repeat(40);
      make(sha('a'), 50); // current, oldest
      make(sha('b'), 1);
      make(sha('c'), 2);
      make(sha('d'), 3);
      make(`${sha('e')}.tmp-123`, 30);
      make(`${sha('f')}.tmp-456`, 1); // may still be in use
      const removed = pruneSnapshots(root, 'proj', sha('a'), 3, now);
      expect(removed.sort()).toEqual([`${sha('e')}.tmp-123`, sha('d')].sort());
      expect(readdirSync(path.join(root, 'proj')).sort()).toEqual([sha('a'), sha('b'), sha('c'), `${sha('f')}.tmp-456`].sort());
      expect(pruneSnapshots(root, 'missing', sha('a'))).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
