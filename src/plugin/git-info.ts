/**
 * Small read-only git queries the plugin needs besides src/lib/git: the current branch, remotes, the remote's
 * default branch, and uncommitted dependency files. Every command is local (no network) and none writes to the
 * repository: `git status` runs with --no-optional-locks so it never refreshes the index.
 */
import path from 'node:path';
import { isLockfile } from '../lib/inventory/lockfiles';
import { runChecked } from '../lib/proc';

const TIMEOUT_MS = 15_000;

/** Manifests whose edits change what gets installed (src/lib/inventory/lockfiles.ts MANIFEST_COVERAGE keys). */
export const MANIFEST_NAMES = [
  'package.json',
  'deno.json',
  'deno.jsonc',
  'Package.swift',
  'Podfile',
  'pyproject.toml',
  'Cargo.toml',
  'Gemfile',
  'composer.json',
  'pubspec.yaml',
  'build.gradle',
  'build.gradle.kts',
] as const;

/** Lockfile basenames (src/lib/inventory/lockfiles.ts LOCKFILE_RULES), as git pathspecs. */
const LOCKFILE_PATHSPECS = [
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'deno.lock',
  'Package.resolved',
  'Podfile.lock',
  'requirements*.txt',
  'poetry.lock',
  'uv.lock',
  'Pipfile.lock',
  'go.mod',
  'Cargo.lock',
  'Gemfile.lock',
  'composer.lock',
  'pubspec.lock',
  'gradle.lockfile',
];

export function isDependencyFile(file: string): boolean {
  if (file.split('/').includes('node_modules')) return false;
  return isLockfile(file) || (MANIFEST_NAMES as readonly string[]).includes(path.posix.basename(file));
}

/** The checked-out branch, or null when HEAD is detached. */
export async function currentBranch(git: string, repo: string): Promise<string | null> {
  const r = await runChecked(git, ['-C', repo, 'symbolic-ref', '--quiet', '--short', 'HEAD'], { timeoutMs: TIMEOUT_MS, okCodes: [0, 1] });
  const name = r.stdout.trim();
  return r.code === 0 && name ? name : null;
}

export interface GitRemote {
  name: string;
  /** Fetch URL with any credentials removed */
  url: string;
}

/**
 * Removes credentials from a remote URL: the password always, and the user name too for http(s), where it is
 * usually a token. scp-like `git@host:org/repo.git` has no secret and is kept as is.
 */
export function stripCredentials(url: string): string {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) return url;
  try {
    const u = new URL(url);
    if (!u.username && !u.password) return url;
    u.password = '';
    if (u.protocol === 'http:' || u.protocol === 'https:') u.username = '';
    return u.toString();
  } catch {
    return url.replace(/\/\/[^/@]*@/, '//');
  }
}

export async function listRemotes(git: string, repo: string): Promise<GitRemote[]> {
  const r = await runChecked(git, ['-C', repo, 'remote', '-v'], { timeoutMs: TIMEOUT_MS });
  const out = new Map<string, string>();
  for (const line of r.stdout.split('\n')) {
    const m = /^(\S+)\s+(\S+)\s+\(fetch\)$/.exec(line.trim());
    if (m && !out.has(m[1]!)) out.set(m[1]!, stripCredentials(m[2]!));
  }
  return [...out].map(([name, url]) => ({ name, url })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

async function refExists(git: string, repo: string, ref: string): Promise<boolean> {
  const r = await runChecked(git, ['-C', repo, 'rev-parse', '--verify', '--quiet', `${ref}^{commit}`], {
    timeoutMs: TIMEOUT_MS,
    okCodes: [0, 1, 128],
  });
  return r.code === 0;
}

/** origin's default branch as a remote-tracking ref (`origin/main`), from refs/remotes/origin/HEAD, else origin/main or origin/master. */
export async function defaultRemoteBranch(git: string, repo: string): Promise<string | null> {
  const r = await runChecked(git, ['-C', repo, 'symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD'], {
    timeoutMs: TIMEOUT_MS,
    okCodes: [0, 1, 128],
  });
  const target = r.code === 0 ? r.stdout.trim() : '';
  if (target.startsWith('refs/remotes/')) return target.slice('refs/remotes/'.length);
  for (const candidate of ['origin/main', 'origin/master']) {
    if (await refExists(git, repo, candidate)) return candidate;
  }
  return null;
}

/**
 * Lockfiles and manifests with uncommitted changes in the working tree or the index (modified, added, deleted,
 * renamed or untracked), repo-relative. Files under node_modules or matching `isExcluded` are left out.
 */
export async function uncommittedDependencyFiles(
  git: string,
  repo: string,
  isExcluded: (file: string) => boolean = () => false,
): Promise<string[]> {
  const pathspecs = [...LOCKFILE_PATHSPECS, ...MANIFEST_NAMES].map((name) => `:(glob)**/${name}`);
  const r = await runChecked(
    git,
    ['-C', repo, '--no-optional-locks', 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--', ...pathspecs],
    { timeoutMs: 60_000 },
  );
  const files = new Set<string>();
  const records = r.stdout.split('\0');
  for (let i = 0; i < records.length; i++) {
    const record = records[i]!;
    if (record.length < 4) continue;
    const status = record.slice(0, 2);
    files.add(record.slice(3));
    // A rename or copy is followed by its original path.
    if (status.includes('R') || status.includes('C')) {
      const original = records[++i];
      if (original) files.add(original);
    }
  }
  return [...files].filter((f) => isDependencyFile(f) && !isExcluded(f)).sort();
}
