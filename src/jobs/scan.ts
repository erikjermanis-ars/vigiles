/**
 * `scan` job (spec §6, §7): per project, resolve the ref (after an optional fetch), snapshot the
 * commit, discover lockfiles, match them offline with osv-scanner, compute dependency facts, and
 * diff the result against the project's findings.
 */
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { and, eq, isNull, notInArray, or } from 'drizzle-orm';
import { projects, scans } from '../lib/db/schema';
import { ensureSnapshot, gitFetch, gitLsTree, gitResolveRef } from '../lib/git';
import { buildImportIndex, type ImportIndex } from '../lib/inventory/import-sites';
import { discoverLockfiles, excludeMatcher, findCoverageGaps, lockfileEcosystem } from '../lib/inventory/lockfiles';
import { NpmLockfileError, parsePackageLock, type NpmLockGraph } from '../lib/inventory/npm-lock';
import { observeScan, type LockfileScan } from '../lib/inventory/observe';
import { applyScanResult, type ScanDiffStats } from '../lib/inventory/persist-scan';
import { ensureOsvZips, osvDbDate } from '../lib/osv/database';
import type { OsvSourceResult } from '../lib/osv/output';
import { runOsvScanner } from '../lib/osv/scanner';
import { isProcessAlive, liveRunningJobs } from '../lib/jobs/queue';
import { CancelledError, type JobContext, type JobHandler } from '../lib/jobs/types';

type ProjectRow = typeof projects.$inferSelect;

export interface ProjectScanSummary extends Partial<ScanDiffStats> {
  scanId: number;
  commit?: string;
  coverageGaps?: string[];
  skippedLockfiles?: string[];
  warnings?: string[];
  durationMs?: number;
  error?: string;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function selectProjects(ctx: JobContext): ProjectRow[] {
  const requested = ctx.params.project;
  if (requested !== undefined) {
    if (typeof requested !== 'string' || requested === '') throw new Error('params.project must be a project id');
    const row = ctx.db.select().from(projects).where(eq(projects.id, requested)).get();
    if (!row) throw new Error(`unknown project "${requested}" (no projects/${requested}.yaml)`);
    return [row];
  }
  return ctx.db.select().from(projects).where(eq(projects.enabled, true)).orderBy(projects.id).all();
}

function realpathOrSelf(file: string): string {
  try {
    return realpathSync(file);
  } catch {
    return file;
  }
}

/**
 * Maps osv-scanner's source paths back to repo-relative lockfiles. osv-scanner can report one
 * source more than once (one result per extractor); those are merged. A result that maps to no
 * lockfile means the output is not understood, and guessing would turn findings into false
 * "fixed" ones, so it throws.
 */
export function resultsByLockfile(snapshot: string, lockfiles: string[], results: OsvSourceResult[]): Map<string, OsvSourceResult> {
  const byAbsolute = new Map<string, string>();
  for (const lf of lockfiles) {
    const abs = path.join(snapshot, lf);
    byAbsolute.set(abs, lf);
    byAbsolute.set(realpathOrSelf(abs), lf);
  }
  const out = new Map<string, OsvSourceResult>();
  for (const r of results) {
    const absolute = path.isAbsolute(r.path) ? r.path : `/${r.path}`;
    const lf = byAbsolute.get(r.path) ?? byAbsolute.get(path.resolve(absolute)) ?? byAbsolute.get(realpathOrSelf(absolute));
    if (!lf) throw new Error(`osv-scanner reported a source that is not one of the scanned lockfiles: ${r.path}`);
    const prev = out.get(lf);
    out.set(lf, prev ? { path: prev.path, packages: [...prev.packages, ...r.packages] } : r);
  }
  return out;
}

/**
 * Lockfiles that are not regular files in the snapshot. A symlink committed as a lockfile could
 * point anywhere on this machine, and osv-scanner and the npm parser would read through it.
 */
export function unreadableLockfiles(snapshot: string, lockfiles: string[]): string[] {
  return lockfiles.filter((lf) => !lstatSync(path.join(snapshot, lf), { throwIfNoEntry: false })?.isFile());
}

function loadNpmGraph(snapshot: string, lockfile: string, warn: (m: string) => void): NpmLockGraph | null {
  if (path.posix.basename(lockfile) !== 'package-lock.json') return null;
  try {
    return parsePackageLock(readFileSync(path.join(snapshot, lockfile), 'utf8'), lockfile);
  } catch (err) {
    if (!(err instanceof NpmLockfileError)) throw err;
    // Matching still works without the graph; only direct/dev-only/paths/import sites are lost.
    warn(`${err.message} Dependency facts for ${lockfile} are unknown.`);
    return null;
  }
}

type Timed = <T>(name: string, fn: () => Promise<T> | T) => Promise<T>;

interface ScanHooks {
  step(text: string): void;
  warn(message: string): void;
  timed: Timed;
}

interface MatchResult {
  /** Lockfiles osv-scanner matched */
  matched: string[];
  /** Lockfiles found but not matched; their findings are left as they are */
  skipped: string[];
  /** Ecosystems of the matched lockfiles */
  ecosystems: string[];
  lockfileScans: LockfileScan[];
}

/**
 * Makes sure each ecosystem's OSV database is present, runs osv-scanner once over every lockfile
 * it can match, and pairs each lockfile's packages with its npm graph (package-lock.json only).
 */
async function matchLockfiles(
  ctx: JobContext,
  projectId: string,
  snapshot: string,
  lockfiles: string[],
  hooks: ScanHooks,
): Promise<MatchResult> {
  const { db, config, paths } = ctx;
  const ecosystemOf = (lockfile: string) => lockfileEcosystem(lockfile)!;
  const skipped: string[] = [];
  const skip = (files: string[], reason: string) => {
    if (!files.length) return;
    skipped.push(...files);
    hooks.warn(`${reason}; not matched: ${files.join(', ')}`);
  };

  skip(unreadableLockfiles(snapshot, lockfiles), 'lockfile is a symlink or missing from the snapshot');
  let candidates = lockfiles.filter((l) => !skipped.includes(l));

  hooks.step('OSV databases');
  const dbs = await hooks.timed('osvDownloadMs', () =>
    ensureOsvZips(db, [...new Set(candidates.map(ecosystemOf))].sort(), {
      baseUrl: config.osv.base_url,
      osvDbDir: paths.osvDb,
      signal: ctx.signal,
    }),
  );
  for (const d of dbs.downloaded) ctx.log(`${projectId}: downloaded missing OSV ${d.ecosystem} database (${d.bytes} bytes)`);
  for (const eco of dbs.unavailable) {
    skip(
      candidates.filter((l) => ecosystemOf(l) === eco),
      `OSV has no ${eco} database`,
    );
  }
  candidates = candidates.filter((l) => !skipped.includes(l));
  ctx.throwIfCancelled();

  hooks.step('osv-scanner');
  const absolute = new Map(candidates.map((l) => [path.join(snapshot, l), l]));
  const osv = await hooks.timed('osvScannerMs', () =>
    runOsvScanner({
      bin: config.bin.osv_scanner,
      osvDbDir: paths.osvDb,
      lockfiles: [...absolute.keys()],
      scratchDir: paths.scratch,
      signal: ctx.signal,
      configFile: path.join(ctx.root, 'config/osv-scanner.toml'),
    }),
  );
  if (osv.warnings) ctx.log(`${projectId}: osv-scanner: ${osv.warnings.split('\n').slice(0, 5).join(' | ')}`);
  skip(
    osv.unsupported.map((abs) => absolute.get(abs) ?? abs),
    `osv-scanner cannot parse this lockfile type`,
  );
  const matched = candidates.filter((l) => !skipped.includes(l));
  ctx.throwIfCancelled();

  hooks.step('dependency facts');
  const byLockfile = resultsByLockfile(snapshot, matched, osv.results);
  const lockfileScans: LockfileScan[] = matched.map((lockfile) => {
    const result = byLockfile.get(lockfile);
    if (!result) hooks.warn(`osv-scanner found no packages in ${lockfile}`);
    return { lockfile, packages: result?.packages ?? [], npmGraph: loadNpmGraph(snapshot, lockfile, hooks.warn) };
  });
  return { matched, skipped: [...skipped].sort(), ecosystems: [...new Set(matched.map(ecosystemOf))].sort(), lockfileScans };
}

/**
 * Manifests with no matched lockfile, plus the lockfiles that could not be matched: both are
 * dependencies matching cannot see (spec §7.2: gaps are reported, not hidden).
 */
export function scanCoverageGaps(files: string[], matched: string[], skipped: string[], exclude: string[]): string[] {
  return [...new Set([...findCoverageGaps(files, matched, exclude), ...skipped])].sort();
}

async function scanProject(ctx: JobContext, project: ProjectRow, label: string): Promise<ProjectScanSummary> {
  const started = Date.now();
  const { db, paths } = ctx;
  const git = ctx.config.bin.git;
  const profile = project.profile;
  const warnings: string[] = [];
  const warn = (m: string) => {
    warnings.push(m);
    ctx.log(`${project.id}: warning: ${m}`);
  };
  const step = (text: string) => ctx.progress(`${label} ${project.id}: ${text}`);
  const timings: Record<string, number> = {};
  const timed: Timed = async (name, fn) => {
    const t = Date.now();
    try {
      return await fn();
    } finally {
      timings[name] = Date.now() - t;
    }
  };

  const scanId = db
    .insert(scans)
    .values({ projectId: project.id, jobRunId: ctx.jobId, ref: project.ref, status: 'running' })
    .returning({ id: scans.id })
    .get().id;
  ctx.log(`${project.id}: scan #${scanId} of ${project.ref}`);

  try {
    let fetchError: string | null = null;
    if (profile.fetch_before_scan) {
      step('git fetch');
      fetchError = await timed('fetchMs', () => gitFetch(git, project.repoPath, project.ref, ctx.signal));
      if (fetchError) warn(`${fetchError}; scanning the existing ${project.ref}`);
    }
    ctx.throwIfCancelled();

    const { sha, date } = await gitResolveRef(git, project.repoPath, project.ref);
    db.update(scans)
      .set({ commitSha: sha, commitDate: date, fetched: profile.fetch_before_scan && !fetchError, fetchError })
      .where(eq(scans.id, scanId))
      .run();
    ctx.log(`${project.id}: ${project.ref} → ${sha.slice(0, 10)} (${date})`);

    step('snapshot');
    const snapshot = await timed('snapshotMs', () => ensureSnapshot(git, paths.snapshots, project.id, project.repoPath, sha, {
        log: (m) => ctx.log(`${project.id}: ${m}`),
        signal: ctx.signal,
      }),
    );
    const files = await gitLsTree(git, project.repoPath, sha);
    const { lockfiles, coverageGaps: manifestGaps } = discoverLockfiles(files, profile);
    db.update(scans).set({ lockfiles, coverageGaps: manifestGaps }).where(eq(scans.id, scanId)).run();
    ctx.log(`${project.id}: ${lockfiles.length} lockfile(s): ${lockfiles.join(', ') || '(none)'}`);
    if (lockfiles.length === 0) warn('no lockfiles found; every open finding will resolve');
    ctx.throwIfCancelled();

    const { matched, skipped, ecosystems, lockfileScans } = await matchLockfiles(ctx, project.id, snapshot, lockfiles, {
      step,
      warn,
      timed,
    });
    const coverageGaps = scanCoverageGaps(files, matched, skipped, profile.exclude);
    if (coverageGaps.length) ctx.log(`${project.id}: coverage gaps (not matched): ${coverageGaps.join(', ')}`);

    const isExcluded = excludeMatcher(profile.exclude);
    let index: ImportIndex | undefined;
    const observation = await timed('factsMs', () =>
      observeScan(lockfileScans, {
        importIndex: () =>
          (index = buildImportIndex(
            snapshot,
            files.filter((f) => !isExcluded(f)),
          )),
      }),
    );

    step('diff');
    const stats = await timed('persistMs', () =>
      applyScanResult(db, {
        projectId: project.id,
        scanId,
        jobRunId: ctx.jobId,
        observation,
        lockfiles,
        skippedLockfiles: skipped,
        coverageGaps,
        osvDbDate: osvDbDate(paths.osvDb, ecosystems),
        extraStats: {
          ecosystems,
          lockfilesSkipped: skipped.length,
          importFilesScanned: index?.filesScanned ?? 0,
          warnings,
          timings: { ...timings, totalMs: Date.now() - started },
        },
      }),
    );
    ctx.log(
      `${project.id}: ${stats.packages} packages, ${stats.vulnerablePackages} vulnerable; ` +
        `findings +${stats.created} created, ${stats.updated} still open, ${stats.fixed} fixed, ` +
        `${stats.noLongerMatches} no longer match, ${stats.reopened} reopened, ${stats.advisoryChanged} advisory changed; ` +
        `${stats.findingsTotalOpen} open`,
    );
    return { scanId, commit: sha, ...stats, coverageGaps, skippedLockfiles: skipped, warnings, durationMs: Date.now() - started };
  } catch (err) {
    const cancelled = err instanceof CancelledError || ctx.signal.aborted;
    db.update(scans)
      .set({ status: 'failed', error: cancelled ? 'cancelled' : errorMessage(err), finishedAt: new Date().toISOString() })
      .where(eq(scans.id, scanId))
      .run();
    throw err;
  }
}

/**
 * Scans left `running` by a job that is no longer running: its row is finished, or its process is gone
 * (worker crash or restart, killed CLI). Scans of a job another live process is running (an inline CLI scan
 * next to the worker) are left alone.
 */
export function failInterruptedScans(ctx: Pick<JobContext, 'db' | 'jobId'>, alive: (pid: number) => boolean = isProcessAlive): void {
  const live = [ctx.jobId, ...liveRunningJobs(ctx.db, {}, alive).map((j) => j.id)];
  ctx.db
    .update(scans)
    .set({ status: 'failed', error: 'interrupted', finishedAt: new Date().toISOString() })
    .where(and(eq(scans.status, 'running'), or(isNull(scans.jobRunId), notInArray(scans.jobRunId, live))))
    .run();
}

/**
 * params.project: one project id (scanned even when disabled); otherwise every enabled project.
 * A failing project does not stop the others, but fails the job at the end (the per-project summaries are
 * kept on the failed row). Refresh all goes on to enrich and decide after a failed scan, then fails too.
 */
export const run: JobHandler = async (ctx) => {
  failInterruptedScans(ctx);
  const targets = selectProjects(ctx);
  if (targets.length === 0) {
    ctx.log('no enabled projects');
    return { projects: {} };
  }
  const summaries: Record<string, ProjectScanSummary | { error: string }> = {};
  const failures: string[] = [];
  for (const [i, project] of targets.entries()) {
    ctx.throwIfCancelled();
    try {
      summaries[project.id] = await scanProject(ctx, project, `${i + 1}/${targets.length}`);
    } catch (err) {
      if (err instanceof CancelledError || ctx.signal.aborted) throw err;
      const message = errorMessage(err);
      summaries[project.id] = { error: message };
      failures.push(`${project.id}: ${message}`);
      ctx.log(`${project.id}: scan FAILED: ${message}`);
    }
  }
  if (failures.length) throw Object.assign(new Error(`scan failed for ${failures.join('; ')}`), { stats: { projects: summaries } });
  return { projects: summaries };
};
