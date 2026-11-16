/**
 * Turning an osv-scanner run over a commit snapshot into per-lockfile inputs for observeScan, without the DB:
 * which lockfiles can be read, which result belongs to which lockfile, the npm graph of each package-lock.json,
 * and what matching could not see. src/jobs/scan.ts re-exports these.
 */
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { OsvSourceResult } from '../osv/output';
import { findCoverageGaps } from './lockfiles';
import { NpmLockfileError, parsePackageLock, type NpmLockGraph } from './npm-lock';

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

/**
 * The dependency graph of a package-lock.json in the snapshot (null for any other lockfile). An unparsable
 * lockfile is a warning, not an error: matching still works without the graph.
 */
export function loadNpmGraph(snapshot: string, lockfile: string, warn: (m: string) => void): NpmLockGraph | null {
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

/**
 * Manifests with no matched lockfile, plus the lockfiles that could not be matched: both are
 * dependencies matching cannot see (spec §7.2: gaps are reported, not hidden).
 */
export function scanCoverageGaps(files: string[], matched: string[], skipped: string[], exclude: string[]): string[] {
  return [...new Set([...findCoverageGaps(files, matched, exclude), ...skipped])].sort();
}
