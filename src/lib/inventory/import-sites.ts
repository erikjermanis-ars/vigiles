/**
 * Import sites (spec §7.3): a cheap static hint of where the code uses a package. Scans the
 * snapshot's source files once per scan and indexes every bare module specifier by package name.
 */
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { ImportSite } from '../types';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts']);
/**
 * Directories whose files are tests or stories (spec §7.3), Storybook config, or installed packages.
 * Kept to unambiguous names: hiding a real runtime import is worse than listing a test helper.
 */
const SKIPPED_DIRS = new Set(['node_modules', '__tests__', '__mocks__', 'stories', '.storybook']);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
/** How many import sites a finding stores and the triage prompt lists (findings.import_site_count keeps the full count). */
export const MAX_IMPORT_SITES = 20;

/** Runtime source files only: no tests, stories (files or a stories/ directory), Storybook config, type declarations or node_modules. */
export function isScannableSource(file: string): boolean {
  const segments = file.split('/');
  const base = segments[segments.length - 1]!;
  if (segments.slice(0, -1).some((s) => SKIPPED_DIRS.has(s))) return false;
  if (!SOURCE_EXTENSIONS.has(path.posix.extname(base))) return false;
  if (/\.d\.[cm]?ts$/.test(base)) return false;
  return !/\.(test|spec|stories)\.[^/]+$/.test(base);
}

export type ImportSiteKind = 'source' | 'config' | 'script';

/**
 * What kind of file an import site is in, for the prompt: `config` for tool and framework config
 * files at the package root (`next.config.ts`, `vitest.config.mts`, `eslint.config.js`, `jest.setup.ts`,
 * `.eslintrc.cjs`), `script` for files under the package root's `scripts/` directory, and `source` for
 * everything else (which may still be tooling).
 *
 * Only the package root counts: tools read their config from there, while a `*.config.ts` deeper in
 * the tree (NestJS's `src/config/database.config.ts`, a `src/site.config.ts`) or a `src/app/scripts/`
 * route is application code that a "config"/"script" tag would wrongly play down.
 *
 * @param packageDir the lockfile's directory, repo-relative ('' for the repository root)
 */
export function importSiteKind(file: string, packageDir = ''): ImportSiteKind {
  const prefix = packageDir ? `${packageDir}/` : '';
  if (!file.startsWith(prefix)) return 'source';
  const segments = file.slice(prefix.length).split('/');
  const base = segments[0]!;
  if (segments.length === 1 && (/.\.(config|setup)\.[cm]?[jt]sx?$/.test(base) || /^\.[^/]*rc\.[cm]?[jt]s$/.test(base))) return 'config';
  if (segments.length > 1 && segments[0] === 'scripts') return 'script';
  return 'source';
}

export interface SpecifierHit {
  specifier: string;
  /** 1-based line where the import/require statement starts */
  line: number;
}

const IMPORT_PATTERNS = [
  // import x from 'p' / import { a } from 'p' / export * from 'p' / import type { T } from 'p' (may span lines;
  // the span may not cross another import/export keyword, so the reported line is the statement's own)
  /\b(?:import|export)\s(?:(?!\b(?:import|export)\b)[^'"`;])*?\bfrom\s*(['"])([^'"\n]+)\1/g,
  // import 'p' (side effects only)
  /\bimport\s*(['"])([^'"\n]+)\1/g,
  // require('p'), import('p')
  /\b(?:require|import)\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g,
];

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineIndexAt(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** Every module specifier in a source file, with the line its statement starts on. */
export function extractImportSpecifiers(source: string): SpecifierHit[] {
  const starts = lineStarts(source);
  const hits: SpecifierHit[] = [];
  const seen = new Set<string>();
  for (const pattern of IMPORT_PATTERNS) {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(source); m; m = pattern.exec(source)) {
      const idx = lineIndexAt(starts, m.index);
      const before = source.slice(starts[idx]!, m.index).trimStart();
      if (before.startsWith('//') || before.startsWith('*') || before.startsWith('/*')) continue;
      const specifier = m[2]!;
      const key = `${idx}\0${specifier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ specifier, line: idx + 1 });
    }
  }
  return hits.sort((a, b) => a.line - b.line || a.specifier.localeCompare(b.specifier));
}

/** 'lodash/merge' → 'lodash', '@scope/pkg/sub' → '@scope/pkg'; null for relative, absolute, URL and builtin specifiers. */
export function packageNameFromSpecifier(specifier: string): string | null {
  if (/^[./#~]/.test(specifier) || /^[a-z][a-z0-9+.-]*:/i.test(specifier)) return null;
  const parts = specifier.split('/');
  // '@/components/x' is a path alias, not a scope
  if (specifier.startsWith('@')) return parts[0]!.length > 1 && parts[1] ? `${parts[0]}/${parts[1]}` : null;
  return parts[0] || null;
}

interface IndexedSite {
  file: string;
  line: number;
  specifier: string;
}

export interface ImportIndex {
  /** Sites by package name, sorted by file then line */
  byPackage: Map<string, IndexedSite[]>;
  filesScanned: number;
}

/** Indexes the given repo-relative files under `rootDir`. Missing, oversized and symlinked files are skipped. */
export function buildImportIndex(rootDir: string, files: string[]): ImportIndex {
  const byPackage = new Map<string, IndexedSite[]>();
  let filesScanned = 0;
  for (const file of [...files].sort()) {
    if (!isScannableSource(file)) continue;
    const full = path.join(rootDir, file);
    // lstat: a symlink in the snapshot could point outside it
    const st = lstatSync(full, { throwIfNoEntry: false });
    if (!st?.isFile() || st.size > MAX_FILE_BYTES) continue;
    filesScanned++;
    for (const hit of extractImportSpecifiers(readFileSync(full, 'utf8'))) {
      const pkg = packageNameFromSpecifier(hit.specifier);
      if (!pkg) continue;
      const site = { file, line: hit.line, specifier: hit.specifier };
      const list = byPackage.get(pkg);
      if (list) list.push(site);
      else byPackage.set(pkg, [site]);
    }
  }
  return { byPackage, filesScanned };
}

/**
 * Which lockfile directory a source file belongs to: the deepest one containing it, so a
 * monorepo's backend/ and dashboard/ lockfiles only see their own code. '' is the repo root.
 */
export function owningDir(file: string, lockfileDirs: string[]): string | null {
  let best: string | null = null;
  for (const dir of lockfileDirs) {
    const inside = dir === '' || file.startsWith(`${dir}/`);
    if (inside && (best === null || dir.length > best.length)) best = dir;
  }
  return best;
}

export interface ImportSiteQuery {
  /** Directory of the lockfile ('' for the repo root) */
  lockfileDir: string;
  /** Directories of every npm lockfile in the scan (to scope files to the nearest one) */
  allLockfileDirs: string[];
  /** Packages to look for: the vulnerable package itself for direct instances, plus the direct deps at the head of transitive instances' paths */
  packages: string[];
  max?: number;
}

export interface ImportSiteResult {
  /** At most `max` sites, sorted by file and line */
  sites: ImportSite[];
  /** Every matching site, before the cap */
  total: number;
}

/**
 * Sites importing any of `packages` (or a subpath of one). Picks round-robin across packages so
 * each one is represented before the cap, then sorts by file and line. `total` is the uncapped count.
 */
export function searchImportSites(index: ImportIndex, q: ImportSiteQuery): ImportSiteResult {
  const max = q.max ?? MAX_IMPORT_SITES;
  const perPackage = [...new Set(q.packages)].map((pkg) =>
    (index.byPackage.get(pkg) ?? [])
      .filter((s) => owningDir(s.file, q.allLockfileDirs) === q.lockfileDir)
      .map((s): ImportSite => ({ ...s, via: pkg })),
  );
  const total = perPackage.reduce((n, list) => n + list.length, 0);
  const picked: ImportSite[] = [];
  for (let round = 0; picked.length < max; round++) {
    let any = false;
    for (const list of perPackage) {
      const site = list[round];
      if (!site) continue;
      any = true;
      if (picked.length < max) picked.push(site);
    }
    if (!any) break;
  }
  const sites = picked.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.via.localeCompare(b.via));
  return { sites, total };
}

/** The capped sites only (see searchImportSites). */
export function findImportSites(index: ImportIndex, q: ImportSiteQuery): ImportSite[] {
  return searchImportSites(index, q).sites;
}
