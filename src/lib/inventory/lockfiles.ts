/**
 * Lockfile discovery and coverage gaps (spec §7.2). Works on the file list of a commit
 * (`git ls-tree`), never on a working tree.
 */
import path from 'node:path';
import picomatch from 'picomatch';
import type { ProjectProfile } from '../types';

/** OSV ecosystem names, as used by osv-scanner and in the offline DB layout. */
export type OsvEcosystem = 'npm' | 'SwiftURL' | 'PyPI' | 'Go' | 'crates.io' | 'RubyGems' | 'Packagist' | 'CocoaPods' | 'Pub' | 'Maven';

interface LockfileRule {
  test: (basename: string) => boolean;
  ecosystem: OsvEcosystem;
}

const exact = (name: string) => (b: string) => b === name;

const LOCKFILE_RULES: LockfileRule[] = [
  { test: exact('package-lock.json'), ecosystem: 'npm' },
  { test: exact('pnpm-lock.yaml'), ecosystem: 'npm' },
  { test: exact('yarn.lock'), ecosystem: 'npm' },
  { test: exact('bun.lock'), ecosystem: 'npm' },
  { test: exact('deno.lock'), ecosystem: 'npm' },
  { test: exact('Package.resolved'), ecosystem: 'SwiftURL' },
  { test: exact('Podfile.lock'), ecosystem: 'CocoaPods' },
  { test: (b) => /^requirements.*\.txt$/.test(b), ecosystem: 'PyPI' },
  { test: exact('poetry.lock'), ecosystem: 'PyPI' },
  { test: exact('uv.lock'), ecosystem: 'PyPI' },
  { test: exact('Pipfile.lock'), ecosystem: 'PyPI' },
  { test: exact('go.mod'), ecosystem: 'Go' },
  { test: exact('Cargo.lock'), ecosystem: 'crates.io' },
  { test: exact('Gemfile.lock'), ecosystem: 'RubyGems' },
  { test: exact('composer.lock'), ecosystem: 'Packagist' },
  { test: exact('pubspec.lock'), ecosystem: 'Pub' },
  { test: exact('gradle.lockfile'), ecosystem: 'Maven' },
];

/**
 * Manifests and the lockfile basenames that cover them. A manifest is a coverage gap when no
 * covering lockfile sits in its directory or any ancestor directory.
 */
const MANIFEST_COVERAGE: Record<string, (lockfileBasename: string) => boolean> = {
  'package.json': (b) => ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'].includes(b),
  'deno.json': exact('deno.lock'),
  'deno.jsonc': exact('deno.lock'),
  'Package.swift': exact('Package.resolved'),
  Podfile: exact('Podfile.lock'),
  'pyproject.toml': (b) => ['poetry.lock', 'uv.lock', 'Pipfile.lock'].includes(b) || /^requirements.*\.txt$/.test(b),
  'Cargo.toml': exact('Cargo.lock'),
  Gemfile: exact('Gemfile.lock'),
  'composer.json': exact('composer.lock'),
  'pubspec.yaml': exact('pubspec.lock'),
  'build.gradle': exact('gradle.lockfile'),
  'build.gradle.kts': exact('gradle.lockfile'),
};

export function lockfileEcosystem(file: string): OsvEcosystem | null {
  const base = path.posix.basename(file);
  return LOCKFILE_RULES.find((r) => r.test(base))?.ecosystem ?? null;
}

export function isLockfile(file: string): boolean {
  return lockfileEcosystem(file) !== null;
}

function hasNodeModulesSegment(file: string): boolean {
  return file.split('/').includes('node_modules');
}

export function excludeMatcher(globs: string[]): (file: string) => boolean {
  if (globs.length === 0) return () => false;
  const isMatch = picomatch(globs, { dot: true });
  return (file) => isMatch(file);
}

/**
 * The directory a lockfile covers. Xcode keeps SwiftPM's Package.resolved inside the
 * .xcodeproj/.xcworkspace bundle, but it pins packages for the directory that holds the bundle.
 */
export function lockfileCoverageDir(lockfile: string): string {
  const dir = path.posix.dirname(lockfile);
  const segments = dir === '.' ? [] : dir.split('/');
  const bundle = segments.findIndex((s) => s.endsWith('.xcodeproj') || s.endsWith('.xcworkspace'));
  const kept = bundle === -1 ? segments : segments.slice(0, bundle);
  return kept.join('/');
}

function isSameOrAncestorDir(ancestor: string, dir: string): boolean {
  return ancestor === '' || dir === ancestor || dir.startsWith(`${ancestor}/`);
}

/** Manifests with no covering lockfile in their directory or an ancestor (spec §7.2), sorted. */
export function findCoverageGaps(files: string[], lockfiles: string[], exclude: string[] = []): string[] {
  const isExcluded = excludeMatcher(exclude);
  const covering = lockfiles.map((l) => ({ base: path.posix.basename(l), dir: lockfileCoverageDir(l) }));
  const gaps: string[] = [];
  for (const file of files) {
    const covers = MANIFEST_COVERAGE[path.posix.basename(file)];
    if (!covers || hasNodeModulesSegment(file) || isExcluded(file)) continue;
    const dir = path.posix.dirname(file) === '.' ? '' : path.posix.dirname(file);
    const covered = covering.some((l) => covers(l.base) && isSameOrAncestorDir(l.dir, dir));
    if (!covered) gaps.push(file);
  }
  return gaps.sort();
}

export interface LockfileDiscovery {
  lockfiles: string[];
  coverageGaps: string[];
}

export class LockfileDiscoveryError extends Error {}

/**
 * Picks the lockfiles to scan from a commit's file list. An explicit `profile.lockfiles` list is
 * used as is (and must exist at the commit); otherwise known lockfile names are matched and the
 * profile's `exclude` globs applied.
 */
export function discoverLockfiles(files: string[], profile: Pick<ProjectProfile, 'exclude' | 'lockfiles'>): LockfileDiscovery {
  let lockfiles: string[];
  if (profile.lockfiles && profile.lockfiles.length > 0) {
    const present = new Set(files);
    const missing = profile.lockfiles.filter((l) => !present.has(l));
    if (missing.length) {
      throw new LockfileDiscoveryError(`lockfiles listed in the profile are missing at this commit: ${missing.join(', ')}`);
    }
    const unknown = profile.lockfiles.filter((l) => !isLockfile(l));
    if (unknown.length) {
      throw new LockfileDiscoveryError(`not a supported lockfile name: ${unknown.join(', ')}`);
    }
    lockfiles = [...new Set(profile.lockfiles)];
  } else {
    const isExcluded = excludeMatcher(profile.exclude);
    lockfiles = files.filter((f) => isLockfile(f) && !hasNodeModulesSegment(f) && !isExcluded(f));
  }
  lockfiles.sort();
  return { lockfiles, coverageGaps: findCoverageGaps(files, lockfiles, profile.exclude) };
}
