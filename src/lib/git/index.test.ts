import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensureSnapshot, isScrubbedPath, readSnapshotInfo, scrubSnapshot, snapshotDir } from './index';

// realpath: macOS tmpdir() is a symlink (/var -> /private/var)
const tmp = realpathSync(mkdtempSync(path.join(tmpdir(), 'vigiles-git-')));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const gitEnv = {
  ...process.env,
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 't',
  GIT_AUTHOR_EMAIL: 't@example.com',
  GIT_COMMITTER_NAME: 't',
  GIT_COMMITTER_EMAIL: 't@example.com',
};
const git = (repo: string, args: string[], input?: string) =>
  execFileSync('git', ['-C', repo, ...args], { env: gitEnv, input, encoding: 'utf8' }).trim();

const repo = path.join(tmp, 'repo');
const snapshots = path.join(tmp, 'snapshots');
let sha: string;
let submoduleSha: string;
/** Every byte value, repeated past one pipe chunk so blob bodies span chunk boundaries. */
const binary = Buffer.alloc(300_000, 0);
for (let i = 0; i < binary.length; i++) binary[i] = (i * 31 + (i >> 8)) & 0xff;

function write(rel: string, content: string | Buffer) {
  const full = path.join(repo, rel);
  mkdirSync(path.dirname(full), { recursive: true });
  writeFileSync(full, content);
}

beforeAll(() => {
  mkdirSync(repo);
  git(repo, ['init', '-q', '-b', 'main']);
  write('package.json', '{"name":"t"}\n');
  write('src/index.ts', 'export const x = 1;\n');
  write('src/ignored.ts', 'export const hidden = 1;\n');
  write('src/subst.ts', '// $Format:%H$\n');
  write('.gitattributes', 'src/ignored.ts export-ignore\nsrc/subst.ts export-subst\n');
  write('bin/run.sh', '#!/bin/sh\necho hi\n');
  chmodSync(path.join(repo, 'bin/run.sh'), 0o755);
  write('assets/blob.bin', binary);
  write('empty.txt', '');
  write('.ENV', 'SECRET=1\n');
  write('config/.env.production', 'SECRET=2\n');
  write('.envs/x', 'SECRET=3\n');
  write('.claude/settings.json', '{"permissions":{}}\n');
  write('nested/.Claude/x.md', 'x\n');
  write('weird name\twith tab.txt', 'tab\n');
  symlinkSync('/etc/hosts', path.join(repo, 'hosts-link'));
  symlinkSync('../src', path.join(repo, 'assets/src-link'));
  git(repo, ['add', '-A']);
  // A submodule entry (gitlink): its commit is not in this repo.
  submoduleSha = 'a'.repeat(40);
  git(repo, ['update-index', '--add', '--cacheinfo', `160000,${submoduleSha},vendor/sub`]);
  git(repo, ['commit', '-q', '-m', 'init']);
  sha = git(repo, ['rev-parse', 'HEAD']);
});

const modeOf = (p: string) => statSync(p).mode & 0o777;

describe('ensureSnapshot', () => {
  it('writes every tracked regular file from the object database', async () => {
    const logs: string[] = [];
    const dir = await ensureSnapshot('git', snapshots, 'p', repo, sha, { log: (m) => logs.push(m) });
    expect(dir).toBe(snapshotDir(snapshots, 'p', sha));
    expect(logs).toEqual([expect.stringMatching(/^snapshot [0-9a-f]{10}: not written: /)]);

    expect(readFileSync(path.join(dir, 'package.json'), 'utf8')).toBe('{"name":"t"}\n');
    expect(readFileSync(path.join(dir, 'src/index.ts'), 'utf8')).toBe('export const x = 1;\n');
    // export-ignore no longer hides tracked code, and export-subst no longer rewrites it
    expect(readFileSync(path.join(dir, 'src/ignored.ts'), 'utf8')).toBe('export const hidden = 1;\n');
    expect(readFileSync(path.join(dir, 'src/subst.ts'), 'utf8')).toBe('// $Format:%H$\n');
    expect(readFileSync(path.join(dir, '.gitattributes'), 'utf8')).toContain('export-ignore');
    // binary-safe across chunk boundaries
    expect(readFileSync(path.join(dir, 'assets/blob.bin')).equals(binary)).toBe(true);
    expect(readFileSync(path.join(dir, 'empty.txt'), 'utf8')).toBe('');
    expect(readFileSync(path.join(dir, 'weird name\twith tab.txt'), 'utf8')).toBe('tab\n');

    // modes: 0600 regular, 0700 executable, 0700 directories
    expect(modeOf(path.join(dir, 'package.json'))).toBe(0o600);
    expect(modeOf(path.join(dir, 'bin/run.sh'))).toBe(0o700);
    expect(modeOf(path.join(dir, 'src'))).toBe(0o700);
    expect(modeOf(dir)).toBe(0o700);
  });

  it('never writes symlinks, submodules, .git, .claude or .env* paths', async () => {
    const dir = await ensureSnapshot('git', snapshots, 'p', repo, sha);
    for (const rel of [
      '.ENV',
      'config/.env.production',
      '.envs',
      '.claude',
      'nested/.Claude',
      'hosts-link',
      'assets/src-link',
      'vendor/sub',
      'vendor',
    ]) {
      expect(lstatSync(path.join(dir, rel), { throwIfNoEntry: false }), rel).toBeUndefined();
    }
    const all = (d: string): string[] =>
      readdirSync(d, { withFileTypes: true }).flatMap((e) => {
        const full = path.join(d, e.name);
        expect(e.isSymbolicLink(), full).toBe(false);
        return e.isDirectory() ? all(full) : [path.relative(dir, full)];
      });
    expect(all(dir).sort()).toEqual(
      [
        '.gitattributes',
        '.vigiles-snapshot-complete',
        'assets/blob.bin',
        'bin/run.sh',
        'empty.txt',
        'package.json',
        'src/ignored.ts',
        'src/index.ts',
        'src/subst.ts',
        'weird name\twith tab.txt',
      ].sort(),
    );
  });

  it('records what it skipped in the marker and logs it', async () => {
    const info = readSnapshotInfo(snapshotDir(snapshots, 'p', sha));
    expect(info).toMatchObject({
      format: 2,
      sha,
      source: 'objects',
      files: 9,
      skipped: { symlinks: 2, submodules: 1, scrubbed: 5, unsafe: 0, unwritable: 0 },
    });
    expect(info!.skippedExamples).toEqual(
      expect.arrayContaining(['hosts-link (symlink)', 'assets/src-link (symlink)', 'vendor/sub (submodule)']),
    );
    // scrubbed paths are counted but not named
    expect(info!.skippedExamples!.join(' ')).not.toMatch(/\.env|\.claude/i);

    const logs: string[] = [];
    await ensureSnapshot('git', path.join(tmp, 'snapshots-log'), 'p', repo, sha, { log: (m) => logs.push(m) });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toMatch(/not written: 2 symlink\(s\), 1 submodule\(s\), 5 \.git\/\.claude\/\.env\* path\(s\)/);
  });

  it('is cached by sha: a complete snapshot is not rebuilt', async () => {
    const dir = await ensureSnapshot('git', snapshots, 'p', repo, sha);
    writeFileSync(path.join(dir, 'sentinel'), 'x');
    expect(await ensureSnapshot('git', snapshots, 'p', repo, sha)).toBe(dir);
    expect(existsSync(path.join(dir, 'sentinel'))).toBe(true);
    rmSync(path.join(dir, 'sentinel'));
  });

  it('is safe under concurrent calls for the same commit and leaves no temp dirs', async () => {
    const root = path.join(tmp, 'snapshots-concurrent');
    const dirs = await Promise.all([1, 2, 3, 4].map(() => ensureSnapshot('git', root, 'p', repo, sha)));
    expect(new Set(dirs).size).toBe(1);
    expect(readdirSync(path.join(root, 'p'))).toEqual([sha]);
    expect(readFileSync(path.join(dirs[0]!, 'assets/blob.bin')).equals(binary)).toBe(true);
  });

  it('rejects a non-sha and an unknown commit without leaving anything behind', async () => {
    const root = path.join(tmp, 'snapshots-bad');
    await expect(ensureSnapshot('git', root, 'p', repo, '../../x')).rejects.toThrow(/not a commit sha/);
    await expect(ensureSnapshot('git', root, 'p', repo, 'b'.repeat(40))).rejects.toThrow(/ls-tree/);
    expect(readdirSync(path.join(root, 'p'))).toEqual([]);
  });

  it('stops on an aborted signal and leaves no temp dir', async () => {
    const root = path.join(tmp, 'snapshots-abort');
    await expect(ensureSnapshot('git', root, 'p', repo, sha, { signal: AbortSignal.abort() })).rejects.toThrow(/cancelled/);
    expect(readdirSync(path.join(root, 'p'))).toEqual([]);
  });

  it('skips unsafe and case-variant secret paths from a hand-crafted tree, writing nothing outside', async () => {
    const blob = git(repo, ['hash-object', '-w', '--stdin'], 'evil\n');
    const inner = git(repo, ['mktree'], `100644 blob ${blob}\tx\n`);
    const tree = git(
      repo,
      ['mktree'],
      [
        `040000 tree ${inner}\t..`,
        `040000 tree ${inner}\t.GIT`,
        `100644 blob ${blob}\t.`,
        `100644 blob ${blob}\tok.txt`,
        `040000 tree ${inner}\tdir`,
      ]
        .map((l) => `${l}\n`)
        .join(''),
    );
    const evil = git(repo, ['commit-tree', tree, '-m', 'evil']);
    const root = path.join(tmp, 'snapshots-evil', 'inner');
    const dir = await ensureSnapshot('git', root, 'p', repo, evil);
    expect(readFileSync(path.join(dir, 'ok.txt'), 'utf8')).toBe('evil\n');
    expect(readFileSync(path.join(dir, 'dir/x'), 'utf8')).toBe('evil\n');
    expect(readdirSync(dir).sort()).toEqual(['.vigiles-snapshot-complete', 'dir', 'ok.txt']);
    expect(existsSync(path.join(root, 'p', 'x'))).toBe(false);
    expect(existsSync(path.join(root, 'x'))).toBe(false);
    expect(readSnapshotInfo(dir)?.skipped).toMatchObject({ unsafe: 2, scrubbed: 1 });
  });

  it('does not let a tracked entry named like the completion marker break or fake the snapshot', async () => {
    const blob = git(repo, ['hash-object', '-w', '--stdin'], 'tracked\n');
    const inner = git(repo, ['mktree'], `100644 blob ${blob}\tx\n`);
    for (const [i, entry] of [
      `040000 tree ${inner}\t.vigiles-snapshot-complete`,
      `100644 blob ${blob}\t.VIGILES-Snapshot-Complete`,
    ].entries()) {
      const tree = git(repo, ['mktree'], `${entry}\n100644 blob ${blob}\tok.txt\n`);
      const commit = git(repo, ['commit-tree', tree, '-m', 'marker']);
      const root = path.join(tmp, `snapshots-marker-${i}`);
      const dir = await ensureSnapshot('git', root, 'p', repo, commit);
      expect(readdirSync(dir).sort()).toEqual(['.vigiles-snapshot-complete', 'ok.txt']);
      expect(readSnapshotInfo(dir)).toMatchObject({ source: 'objects', sha: commit, files: 1, skipped: { unsafe: 1 } });
      expect(readSnapshotInfo(dir)!.skippedExamples).toEqual([expect.stringMatching(/\(reserved name\)$/)]);
    }
  });

  it('writes one file per case-insensitive name and counts the collisions instead of failing', async () => {
    const one = git(repo, ['hash-object', '-w', '--stdin'], 'one\n');
    const two = git(repo, ['hash-object', '-w', '--stdin'], 'two\n');
    const inner = git(repo, ['mktree'], `100644 blob ${two}\ty\n`);
    const tree = git(
      repo,
      ['mktree'],
      [`100644 blob ${one}\tA.txt`, `100644 blob ${two}\ta.txt`, `100644 blob ${one}\tx`, `040000 tree ${inner}\tX`]
        .map((l) => `${l}\n`)
        .join(''),
    );
    const commit = git(repo, ['commit-tree', tree, '-m', 'case']);
    const dir = await ensureSnapshot('git', path.join(tmp, 'snapshots-case'), 'p', repo, commit);
    const info = readSnapshotInfo(dir)!;
    const caseInsensitive = existsSync(path.join(dir, 'a.TXT'));
    // a case-insensitive volume (the macOS default) keeps the first of each pair
    expect(info.skipped!.unwritable).toBe(caseInsensitive ? 2 : 0);
    expect(info.files).toBe(caseInsensitive ? 2 : 4);
    expect(readFileSync(path.join(dir, 'A.txt'), 'utf8')).toBe('one\n');
    expect(readFileSync(path.join(dir, 'X', 'y'), 'utf8')).toBe('two\n');
  });

  it('fails on a missing blob and on a cat-file timeout, leaving no temp dir', async () => {
    const tree = git(repo, ['mktree', '--missing'], `100644 blob ${'c'.repeat(40)}\tgone.txt\n`);
    const commit = git(repo, ['commit-tree', tree, '-m', 'missing']);
    const root = path.join(tmp, 'snapshots-missing');
    await expect(ensureSnapshot('git', root, 'p', repo, commit)).rejects.toThrow(/cat-file: expected blob c{40} for gone\.txt/);
    await expect(ensureSnapshot('git', root, 'p', repo, sha, { timeoutMs: 1 })).rejects.toThrow(/cat-file --batch timed out/);
    expect(readdirSync(path.join(root, 'p'))).toEqual([]);
  });

  it('keeps a legacy git-archive snapshot but re-scrubs it once', async () => {
    const root = path.join(tmp, 'snapshots-legacy');
    const dir = snapshotDir(root, 'p', sha);
    const outside = path.join(tmp, 'outside');
    mkdirSync(path.join(outside, 'deep'), { recursive: true });
    writeFileSync(path.join(outside, '.env'), 'OUTSIDE=1\n');
    writeFileSync(path.join(outside, 'deep', 'keep.txt'), 'keep\n');
    mkdirSync(path.join(dir, '.envs'), { recursive: true });
    mkdirSync(path.join(dir, 'src', '.env.d'), { recursive: true });
    writeFileSync(path.join(dir, '.envs', 'x'), 'SECRET\n');
    writeFileSync(path.join(dir, 'src', '.env.d', 'y'), 'SECRET\n');
    writeFileSync(path.join(dir, 'src', 'a.ts'), 'a\n');
    writeFileSync(path.join(dir, '.git'), 'gitdir: /elsewhere\n');
    symlinkSync(outside, path.join(dir, '.claude'));
    symlinkSync(outside, path.join(dir, 'linked-dir'));
    symlinkSync('/etc/hosts', path.join(dir, 'hosts'));
    writeFileSync(path.join(dir, '.vigiles-snapshot-complete'), `${sha}\n`);

    const logs: string[] = [];
    expect(await ensureSnapshot('git', root, 'p', repo, sha, { log: (m) => logs.push(m) })).toBe(dir);
    // not rebuilt: legacy content stays, nothing from git is added
    expect(readFileSync(path.join(dir, 'src', 'a.ts'), 'utf8')).toBe('a\n');
    expect(existsSync(path.join(dir, 'package.json'))).toBe(false);
    expect(readdirSync(dir).sort()).toEqual(['.vigiles-snapshot-complete', 'src']);
    expect(readdirSync(path.join(dir, 'src'))).toEqual(['a.ts']);
    // symlink targets are untouched
    expect(readFileSync(path.join(outside, '.env'), 'utf8')).toBe('OUTSIDE=1\n');
    expect(existsSync(path.join(outside, 'deep', 'keep.txt'))).toBe(true);
    expect(readSnapshotInfo(dir)).toEqual({ format: 2, sha, source: 'archive' });
    expect(logs).toEqual([expect.stringMatching(/re-scrubbed a legacy/)]);

    // marked: the next call does not scrub again
    writeFileSync(path.join(dir, '.env'), 'late\n');
    await ensureSnapshot('git', root, 'p', repo, sha);
    expect(existsSync(path.join(dir, '.env'))).toBe(true);
  });
});

describe('scrubSnapshot', () => {
  it('removes .env*/.claude/.git entries of any type and symlinks, without following symlinks', () => {
    const dir = path.join(tmp, 'scrub');
    const outside = path.join(tmp, 'scrub-outside');
    mkdirSync(path.join(outside, '.claude'), { recursive: true });
    writeFileSync(path.join(outside, '.env'), 'x');
    for (const d of ['.envs', '.env.d', 'a/.ENV.local.d', 'a/b', '.Git', 'x/.CLAUDE']) mkdirSync(path.join(dir, d), { recursive: true });
    for (const f of [
      '.envs/x',
      '.env.d/x',
      'a/.ENV.local.d/x',
      'a/b/.env',
      'a/b/keep.ts',
      '.Git/config',
      'x/.CLAUDE/s.json',
      '.envrc',
      'keep.md',
    ]) {
      writeFileSync(path.join(dir, f), 'x');
    }
    symlinkSync(outside, path.join(dir, '.claude'));
    symlinkSync(outside, path.join(dir, 'a', 'link'));
    symlinkSync(path.join(outside, '.env'), path.join(dir, 'a', '.env.link'));

    scrubSnapshot(dir);

    const remaining = (d: string): string[] =>
      readdirSync(d, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? remaining(path.join(d, e.name)) : [path.relative(dir, path.join(d, e.name))],
      );
    expect(remaining(dir).sort()).toEqual(['a/b/keep.ts', 'keep.md']);
    expect(readdirSync(path.join(dir, 'x'))).toEqual([]);
    // never followed: the outside targets survive
    expect(existsSync(path.join(outside, '.env'))).toBe(true);
    expect(existsSync(path.join(outside, '.claude'))).toBe(true);
  });

  it('ignores a directory that disappeared', () => {
    expect(() => scrubSnapshot(path.join(tmp, 'does-not-exist'))).not.toThrow();
  });
});

describe('isScrubbedPath', () => {
  it('matches any segment case-insensitively', () => {
    for (const p of [
      '.env',
      '.ENV.local',
      'a/.envrc',
      '.envs/x',
      'a/.Env.d/b',
      '.claude/settings.json',
      'x/.CLAUDE',
      '.git/config',
      'sub/.GIT',
    ]) {
      expect(isScrubbedPath(p), p).toBe(true);
    }
    for (const p of ['env', 'a/env.ts', '.github/workflows/ci.yml', '.gitignore', '.claudeignore', 'docs/environment.md', 'a.env']) {
      expect(isScrubbedPath(p), p).toBe(false);
    }
  });
});
