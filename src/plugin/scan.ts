/**
 * `vigiles scan`: the POC's scan + enrich for one repository, without the DB (src/jobs/scan.ts scanProject and
 * matchLockfiles, src/lib/signals/enrich.ts). It resolves the audited ref, snapshots the commit, discovers
 * lockfiles, matches them offline with osv-scanner, computes dependency facts and import sites, adds KEV/EPSS
 * signals and the base priority, and computes each finding's triage input hash exactly like
 * src/lib/triage/state.ts findingInputHash, so a verdict cached under that hash is valid for the same inputs the
 * dashboard would see. The result goes to <cache>/repos/<projectKey>/scan.json; nothing is written to the repository.
 */
import { readdirSync, readFileSync, rmSync, statSync, utimesSync } from 'node:fs';
import path from 'node:path';
import { loadPolicy, loadVigilesConfig } from '../lib/config/load';
import { ensureSnapshot, gitFetch, gitLsTree, gitResolveRef, isFetchableBranch } from '../lib/git';
import { buildImportIndex } from '../lib/inventory/import-sites';
import { discoverLockfiles, excludeMatcher, lockfileEcosystem } from '../lib/inventory/lockfiles';
import { observeScan, type LockfileScan, type ObservedFinding, type ScanObservation } from '../lib/inventory/observe';
import { loadNpmGraph, resultsByLockfile, scanCoverageGaps, unreadableLockfiles } from '../lib/inventory/scan-results';
import { runOsvScanner as defaultRunOsvScanner, type OsvScanRun, type RunOsvScannerOptions } from '../lib/osv/scanner';
import { osvDbDate, type FetchFn } from '../lib/osv/zip';
import { computeFindingSignals, type EnrichRow } from '../lib/signals/compute';
import { normalizeCves } from '../lib/signals/cve';
import { fetchEpssScores } from '../lib/signals/epss';
import { errorMessage } from '../lib/signals/http';
import { computeInputHash, promptFingerprint } from '../lib/triage/input-hash';
import { triageProfileHash } from '../lib/triage/profile';
import { currentBranch, listRemotes, uncommittedDependencyFiles } from './git-info';
import { kevDateIndex, kevRansomwareFor, loadKev } from './kev-cache';
import { ensureOsvDatabases } from './osv-db';
import { bins as defaultBins, ensureDir, repoPaths, writeFileAtomic, type Bins, type PluginPaths } from './paths';
import { loadProfile, toProjectProfile } from './profile';
import { STATE_FORMAT, type ScanAdvisory, type ScanFinding, type ScanResult, type TriageConfig } from './types';

/** Snapshots kept per repository (the current one included). */
export const KEEP_SNAPSHOTS = 3;

// ---------- the audited ref ----------

/** `--ref` is not something Vigiles audits (the CLI maps it to exit 2). */
export class InvalidRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidRefError';
  }
}

/** Whitespace and control characters, `:` (a refspec or `rev:path`), `\\`, `..` (a range) and `@{` (reflog). */
// oxlint-disable-next-line no-control-regex -- control characters are what this rejects
const UNSAFE_REF = /[\x00-\x20\x7f:\\]|\.\.|@\{/;

/**
 * Refuses a --ref that is not a branch, tag, remote-tracking ref or commit (`~`/`^` suffixes are fine, e.g.
 * HEAD~1): no component may start with `-` (an option to git), `+` (a forced refspec) or `.`. The ref reaches
 * git's argv, and the skill runs the CLI without a permission prompt.
 */
export function assertSafeRef(ref: string): void {
  const bad =
    ref === '' ||
    UNSAFE_REF.test(ref) ||
    ref.split('/').some((s) => s === '' || s.startsWith('-') || s.startsWith('+') || s.startsWith('.'));
  if (bad) throw new InvalidRefError(`--ref ${JSON.stringify(ref)} is not a branch, tag, remote-tracking ref or commit`);
}

// ---------- configuration ----------

/** The active triage config of `<assetRoot>/config/vigiles.yaml`, with the fingerprint of its prompt files. */
export function loadTriageConfig(assetRoot: string): TriageConfig {
  const { triage } = loadVigilesConfig(assetRoot);
  // The schema guarantees active_config names one of the configs.
  const def = triage.configs.find((c) => c.name === triage.active_config)!;
  return {
    name: def.name,
    promptVersion: def.prompt_version,
    promptFingerprint: promptFingerprint(def.prompt_version, assetRoot),
    model: def.model,
    effort: def.effort,
    codeAccess: def.code_access,
    concurrency: triage.concurrency,
    timeoutMinutes: triage.timeout_minutes,
    maxBudgetUsd: triage.max_budget_usd_per_run,
  };
}

// ---------- findings ----------

/** Stable, readable finding id: `<osvId> <ecosystem>:<package> <lockfile>`. */
export function findingId(f: Pick<ObservedFinding, 'osvId' | 'ecosystem' | 'packageName' | 'lockfile'>): string {
  return `${f.osvId} ${f.ecosystem}:${f.packageName} ${f.lockfile}`;
}

type HashFacts = Pick<
  ObservedFinding,
  | 'installedVersions'
  | 'fixedVersions'
  | 'direct'
  | 'devOnly'
  | 'paths'
  | 'instances'
  | 'importSites'
  | 'importSiteCount'
  | 'advisoryModified'
>;

/**
 * The triage input hash of a finding: the same inputs, in the same way, as src/lib/triage/state.ts
 * findingInputHash (the advisory record's `modified` first, else the finding's; the triage-visible profile hash;
 * the prompt fingerprint; model, effort and code access of the config).
 */
export function scanInputHash(
  f: HashFacts,
  advisoryModified: string | null | undefined,
  projectProfileHash: string,
  config: Pick<TriageConfig, 'promptFingerprint' | 'model' | 'effort' | 'codeAccess'>,
): string {
  return computeInputHash({
    advisoryModified: advisoryModified ?? f.advisoryModified ?? null,
    installedVersions: f.installedVersions,
    fixedVersions: f.fixedVersions,
    direct: f.direct,
    devOnly: f.devOnly,
    paths: f.paths,
    instances: f.instances,
    importSites: f.importSites,
    importSiteCount: f.importSiteCount,
    projectProfileHash,
    promptVersion: config.promptFingerprint,
    model: config.model,
    effort: config.effort,
    codeAccess: config.codeAccess,
  });
}

type AdvisoryRecord = ScanObservation['advisories'][number];

export function toScanAdvisory(a: AdvisoryRecord): ScanAdvisory {
  return {
    osvId: a.osvId,
    aliases: a.aliases ?? [],
    cves: a.cves ?? [],
    summary: a.summary ?? null,
    details: a.details ?? null,
    cvssVector: a.cvssVector ?? null,
    cvssScore: a.cvssScore ?? null,
    severityLabel: a.severityLabel ?? null,
    cwes: a.cwes ?? [],
    references: a.references ?? [],
    published: a.published ?? null,
    modified: a.modified ?? null,
    withdrawn: a.withdrawn ?? null,
    malicious: a.malicious ?? false,
    raw: a.raw,
  };
}

// ---------- scan.json ----------

/** The last scan.json, or null when there is none. Throws when it exists but is not a scan of this format. */
export function readScanResult(file: string): ScanResult | null {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
  const value = JSON.parse(text) as Partial<ScanResult>;
  if (value?.format !== STATE_FORMAT || !Array.isArray(value.findings))
    throw new Error(`${file} is not a Vigiles scan (format ${STATE_FORMAT})`);
  return value as ScanResult;
}

function previousEpss(file: string): Map<string, { epss: number | null; epssPercentile: number | null }> {
  try {
    return new Map((readScanResult(file)?.findings ?? []).map((f) => [f.id, { epss: f.epss, epssPercentile: f.epssPercentile }]));
  } catch {
    return new Map();
  }
}

// ---------- snapshots ----------

/**
 * Keeps the `keep` most recently used snapshots of one repository (the current one always, and it counts as just
 * used) and removes the others, plus temp directories a crashed run left behind more than a day ago.
 */
export function pruneSnapshots(
  snapshotsDir: string,
  projectKey: string,
  currentSha: string,
  keep = KEEP_SNAPSHOTS,
  now = Date.now(),
): string[] {
  const dir = path.join(snapshotsDir, projectKey);
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  try {
    utimesSync(path.join(dir, currentSha), new Date(now), new Date(now));
  } catch {
    // not there: nothing to mark
  }
  const removed: string[] = [];
  const others: { name: string; mtime: number }[] = [];
  for (const name of names) {
    const st = statSync(path.join(dir, name), { throwIfNoEntry: false });
    if (!st?.isDirectory()) continue;
    if (/^[0-9a-f]{40,64}$/i.test(name)) {
      if (name !== currentSha) others.push({ name, mtime: st.mtimeMs });
    } else if (name.includes('.tmp-') && now - st.mtimeMs > 86_400_000) {
      rmSync(path.join(dir, name), { recursive: true, force: true });
      removed.push(name);
    }
  }
  others.sort((a, b) => b.mtime - a.mtime);
  for (const { name } of others.slice(Math.max(0, keep - 1))) {
    rmSync(path.join(dir, name), { recursive: true, force: true });
    removed.push(name);
  }
  return removed;
}

// ---------- scan ----------

export interface RunScanOptions {
  /** Top-level directory of the audited repository (findRepoRoot) */
  repoRoot: string;
  plugin: PluginPaths;
  toolVersion: string;
  /** Default 'HEAD': the checked-out commit */
  ref?: string;
  /** `git fetch` a remote-tracking ref (origin/main) before resolving it */
  fetch?: boolean;
  /** Re-check the OSV databases and the KEV catalog now, however recent */
  refreshDb?: boolean;
  bins?: Bins;
  signal?: AbortSignal;
  /** Progress lines (not warnings) */
  progress?: (line: string) => void;
  /** Data freshness: OSV databases and the KEV catalog are re-checked once older than this (default 24) */
  maxAgeHours?: number;
  osvBaseUrl?: string;
  // Injectable for tests.
  fetchFn?: FetchFn;
  runOsvScanner?: (opts: RunOsvScannerOptions) => Promise<OsvScanRun>;
  clock?: () => Date;
}

interface MatchResult {
  matched: string[];
  skipped: string[];
  ecosystems: string[];
  lockfileScans: LockfileScan[];
}

interface ScanContext {
  opts: RunScanOptions;
  bins: Bins;
  clock: () => Date;
  progress: (line: string) => void;
  warn: (message: string) => void;
  warnings: string[];
}

/** src/jobs/scan.ts matchLockfiles: OSV databases, one osv-scanner run, results paired with npm graphs. */
async function matchLockfiles(ctx: ScanContext, snapshot: string, lockfiles: string[]): Promise<MatchResult> {
  const { opts, warn, progress } = ctx;
  const { osvDbDir, scratchDir, assetRoot } = opts.plugin;
  const ecosystemOf = (lockfile: string) => lockfileEcosystem(lockfile)!;
  const skipped: string[] = [];
  const skip = (files: string[], reason: string) => {
    if (!files.length) return;
    skipped.push(...files);
    warn(`${reason}; not audited: ${files.join(', ')}`);
  };

  skip(unreadableLockfiles(snapshot, lockfiles), 'lockfile is a symlink or missing from the snapshot');
  let candidates = lockfiles.filter((l) => !skipped.includes(l));

  progress('OSV databases');
  ensureDir(osvDbDir);
  const dbs = await ensureOsvDatabases([...new Set(candidates.map(ecosystemOf))].sort(), {
    osvDbDir,
    baseUrl: opts.osvBaseUrl,
    maxAgeHours: opts.maxAgeHours,
    force: opts.refreshDb,
    signal: opts.signal,
    fetchFn: opts.fetchFn,
    now: ctx.clock,
    log: progress,
  });
  for (const w of dbs.warnings) warn(w);
  for (const eco of dbs.unavailable) {
    skip(
      candidates.filter((l) => ecosystemOf(l) === eco),
      `OSV has no ${eco} database`,
    );
  }
  candidates = candidates.filter((l) => !skipped.includes(l));
  opts.signal?.throwIfAborted();

  progress(`osv-scanner (${candidates.length} lockfile${candidates.length === 1 ? '' : 's'})`);
  ensureDir(scratchDir);
  const absolute = new Map(candidates.map((l) => [path.join(snapshot, l), l]));
  let osv: OsvScanRun;
  try {
    osv = await (opts.runOsvScanner ?? defaultRunOsvScanner)({
      bin: ctx.bins.osvScanner,
      osvDbDir,
      lockfiles: [...absolute.keys()],
      scratchDir,
      signal: opts.signal,
      configFile: path.join(assetRoot, 'config/osv-scanner.toml'),
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(
        `osv-scanner not found (${ctx.bins.osvScanner}); install it (e.g. \`brew install osv-scanner\`) or set VIGILES_OSV_SCANNER_BIN`,
        {
          cause: err,
        },
      );
    }
    throw err;
  }
  if (osv.warnings) progress(`osv-scanner: ${osv.warnings.split('\n').slice(0, 5).join(' | ')}`);
  skip(
    osv.unsupported.map((abs) => absolute.get(abs) ?? abs),
    'osv-scanner cannot parse this lockfile type',
  );
  const matched = candidates.filter((l) => !skipped.includes(l));
  opts.signal?.throwIfAborted();

  progress('dependency facts');
  const byLockfile = resultsByLockfile(snapshot, matched, osv.results);
  const lockfileScans: LockfileScan[] = matched.map((lockfile) => {
    const result = byLockfile.get(lockfile);
    if (!result) warn(`osv-scanner found no packages in ${lockfile}`);
    return { lockfile, packages: result?.packages ?? [], npmGraph: loadNpmGraph(snapshot, lockfile, warn) };
  });
  return { matched, skipped: [...skipped].sort(), ecosystems: [...new Set(matched.map(ecosystemOf))].sort(), lockfileScans };
}

async function fetchIfRequested(ctx: ScanContext, ref: string): Promise<void> {
  const { opts } = ctx;
  if (!opts.fetch) return;
  const remote = ref.split('/')[0]!;
  const remotes = (await listRemotes(ctx.bins.git, opts.repoRoot)).map((r) => r.name);
  if (!ref.includes('/') || !remotes.includes(remote)) {
    ctx.warn(`--fetch: ${ref} is not a remote-tracking ref (e.g. origin/main); nothing was fetched`);
    return;
  }
  if (!isFetchableBranch(ref.slice(remote.length + 1))) {
    throw new InvalidRefError(`--fetch needs <remote>/<branch> with a plain branch name; ${JSON.stringify(ref)} is not one`);
  }
  ctx.progress(`git fetch ${ref}`);
  const error = await gitFetch(ctx.bins.git, opts.repoRoot, ref, opts.signal);
  if (error) ctx.warn(`${error}; audited the existing ${ref}`);
}

export async function runScan(opts: RunScanOptions): Promise<ScanResult> {
  const warnings: string[] = [];
  const ctx: ScanContext = {
    opts,
    bins: opts.bins ?? defaultBins(),
    clock: opts.clock ?? (() => new Date()),
    progress: opts.progress ?? (() => {}),
    warn: (m) => warnings.push(m),
    warnings,
  };
  const { repoRoot, plugin, signal } = opts;
  const git = ctx.bins.git;
  const ref = opts.ref ?? 'HEAD';
  assertSafeRef(ref);

  // 1. Profile, policy and triage config.
  const { profile, warnings: profileWarnings } = loadProfile(path.join(repoRoot, '.vigiles', 'profile.yaml'));
  profileWarnings.forEach(ctx.warn);
  const projectProfile = toProjectProfile(profile, repoRoot);
  const profileHash = triageProfileHash(projectProfile);
  const policy = loadPolicy(plugin.assetRoot);
  const triageConfig = loadTriageConfig(plugin.assetRoot);
  const paths = repoPaths(repoRoot, profile.id, plugin);
  const isExcluded = excludeMatcher(profile.exclude);

  // 2. The audited commit.
  await fetchIfRequested(ctx, ref);
  signal?.throwIfAborted();
  let resolved: { sha: string; date: string };
  try {
    resolved = await gitResolveRef(git, repoRoot, ref);
  } catch (err) {
    throw new Error(`cannot resolve ${ref} to a commit in ${repoRoot} (${errorMessage(err).split('\n')[0]})`, { cause: err });
  }
  const { sha, date } = resolved;
  const branch = ref === 'HEAD' ? await currentBranch(git, repoRoot) : ref;
  ctx.progress(`auditing ${ref === 'HEAD' ? `HEAD (${branch ?? 'detached'})` : ref} at ${sha.slice(0, 10)} (${date.slice(0, 10)})`);

  // 3. Dependency files the commit does not have yet.
  let uncommitted: string[] = [];
  if (ref === 'HEAD') {
    uncommitted = await uncommittedDependencyFiles(git, repoRoot, isExcluded);
    if (uncommitted.length) {
      ctx.warn(
        `uncommitted changes to ${uncommitted.join(', ')} are not audited (Vigiles reads the last commit); commit them and re-run to include them`,
      );
    }
  }

  // 4. Snapshot of the commit (shared with triage), keeping the last few.
  ctx.progress('snapshot');
  ensureDir(plugin.snapshotsDir);
  const snapshot = await ensureSnapshot(git, plugin.snapshotsDir, paths.projectKey, repoRoot, sha, { log: ctx.progress, signal });
  pruneSnapshots(plugin.snapshotsDir, paths.projectKey, sha);

  // 5. Lockfiles → osv-scanner → dependency facts.
  const files = await gitLsTree(git, repoRoot, sha);
  const { lockfiles } = discoverLockfiles(files, profile);
  ctx.progress(`${lockfiles.length} lockfile(s): ${lockfiles.join(', ') || '(none)'}`);
  if (lockfiles.length === 0) ctx.warn(`no lockfiles found at ${sha.slice(0, 10)}; nothing was audited`);
  const match = await matchLockfiles(ctx, snapshot, lockfiles);
  const coverageGaps = scanCoverageGaps(files, match.matched, match.skipped, profile.exclude);
  const observation = observeScan(match.lockfileScans, {
    importIndex: () =>
      buildImportIndex(
        snapshot,
        files.filter((f) => !isExcluded(f)),
      ),
  });
  signal?.throwIfAborted();

  // 6. Signals (src/lib/signals/enrich.ts, per finding).
  ctx.progress('CISA KEV catalog');
  ensureDir(plugin.cacheDir);
  const kev = await loadKev({
    kevFile: plugin.kevFile,
    maxAgeHours: opts.maxAgeHours,
    force: opts.refreshDb,
    signal,
    fetchFn: opts.fetchFn,
    now: ctx.clock,
  });
  kev.warnings.forEach(ctx.warn);

  const advisories = new Map(observation.advisories.map((a) => [a.osvId, a]));
  const cves = normalizeCves(observation.findings.flatMap((f) => advisories.get(f.osvId)?.cves ?? []));
  ctx.progress(`EPSS (${cves.length} CVE${cves.length === 1 ? '' : 's'})`);
  const epss = await fetchEpssScores(cves, { fetchFn: opts.fetchFn, signal });
  if (epss.errors.length) {
    ctx.warn(
      `EPSS lookup failed for ${epss.failedCves.size} CVE(s) (${epss.errors.join('; ')}); their findings keep the previous scan's ` +
        'score where there is one and are otherwise ranked without EPSS',
    );
  }

  const stored = previousEpss(paths.scanFile);
  const sources = { kevIndex: kevDateIndex(kev.index), epss, thresholds: policy.policy.thresholds };
  const findings: ScanFinding[] = observation.findings.map((f, i) => {
    const adv = advisories.get(f.osvId);
    const id = findingId(f);
    const previous = stored.get(id);
    const row: EnrichRow = {
      id: i,
      projectId: profile.id,
      osvId: f.osvId,
      priority: null,
      inKev: false,
      epss: previous?.epss ?? null,
      epssPercentile: previous?.epssPercentile ?? null,
      enrichedAt: null,
      advisory: adv
        ? {
            cves: adv.cves ?? [],
            cvssScore: adv.cvssScore ?? null,
            severityLabel: adv.severityLabel ?? null,
            malicious: adv.malicious ?? false,
          }
        : null,
      exposure: profile.exposure,
      criticality: profile.criticality,
    };
    const s = computeFindingSignals(row, sources);
    return {
      id,
      lockfile: f.lockfile,
      ecosystem: f.ecosystem,
      packageName: f.packageName,
      osvId: f.osvId,
      installedVersions: f.installedVersions,
      fixedVersions: f.fixedVersions,
      direct: f.direct,
      devOnly: f.devOnly,
      paths: f.paths,
      instances: f.instances,
      importSites: f.importSites,
      importSiteCount: f.importSiteCount,
      advisoryModified: f.advisoryModified,
      cves: s.cves,
      malicious: s.malicious,
      inKev: s.inKev,
      kevDateAdded: s.kevDateAdded,
      kevRansomware: s.inKev ? kevRansomwareFor(s.cves, kev.index) : null,
      epss: s.epss,
      epssPercentile: s.epssPercentile,
      cvssScore: s.cvssScore,
      priority: s.priority,
      priorityReasons: s.priorityReasons,
      // 7. The verdict cache key.
      inputHash: scanInputHash(f, adv?.modified, profileHash, triageConfig),
    };
  });
  findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // 8. Only the advisories the findings name.
  const scanAdvisories: Record<string, ScanAdvisory> = {};
  for (const osvId of [...new Set(findings.map((f) => f.osvId))].sort()) {
    const adv = advisories.get(osvId);
    if (adv) scanAdvisories[osvId] = toScanAdvisory(adv);
  }

  const result: ScanResult = {
    format: STATE_FORMAT,
    toolVersion: opts.toolVersion,
    scannedAt: ctx.clock().toISOString(),
    repoRoot,
    projectId: profile.id,
    projectName: profile.name,
    ref,
    branch,
    commit: sha,
    commitDate: date,
    uncommittedDependencyFiles: uncommitted,
    snapshotDir: snapshot,
    lockfiles,
    skippedLockfiles: match.skipped,
    coverageGaps,
    ecosystems: match.ecosystems,
    warnings,
    data: {
      osvDbDate: osvDbDate(plugin.osvDbDir, match.ecosystems),
      kevCatalogDate: kev.catalogDate,
      kevAvailable: kev.available,
      epssDate: epss.date,
      epssFailedCves: epss.failedCves.size,
    },
    triageConfig,
    profileHash,
    policyHash: policy.hash,
    stats: { packages: observation.packages, vulnerablePackages: observation.vulnerablePackages },
    findings,
    advisories: scanAdvisories,
  };
  writeFileAtomic(paths.scanFile, `${JSON.stringify(result, null, 2)}\n`);
  return result;
}
