/** Temporary git repositories for the plugin tests. Not used at runtime. */
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

/** Git without the user's global/system config, with a fixed identity. */
export const GIT_TEST_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 't',
  GIT_AUTHOR_EMAIL: 't@example.com',
  GIT_COMMITTER_NAME: 't',
  GIT_COMMITTER_EMAIL: 't@example.com',
};

export interface TestRepo {
  root: string;
  git(args: string[]): string;
  write(rel: string, content: string | Buffer): void;
  /** `git add -A && git commit`, returns the new sha */
  commit(message?: string): string;
  cleanup(): void;
}

/** A realpath'd temp directory (macOS tmpdir() is a symlink). */
export function tempDir(prefix: string): string {
  return realpathSync(mkdtempSync(path.join(tmpdir(), prefix)));
}

export function createTestRepo(prefix = 'vigiles-plugin-repo-'): TestRepo {
  const base = tempDir(prefix);
  const root = path.join(base, 'repo');
  mkdirSync(root);
  const git = (args: string[]) => execFileSync('git', ['-C', root, ...args], { env: GIT_TEST_ENV, encoding: 'utf8' }).trim();
  git(['init', '-q', '-b', 'main']);
  return {
    root,
    git,
    write(rel, content) {
      const full = path.join(root, rel);
      mkdirSync(path.dirname(full), { recursive: true });
      writeFileSync(full, content);
    },
    commit(message = 'commit') {
      git(['add', '-A']);
      git(['commit', '-q', '--allow-empty', '-m', message]);
      return git(['rev-parse', 'HEAD']);
    },
    cleanup() {
      rmSync(base, { recursive: true, force: true });
    },
  };
}
