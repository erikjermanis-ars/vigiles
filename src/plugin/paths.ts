/**
 * Where the plugin finds its assets (prompts, policy, osv-scanner config), keeps its cache, and writes its
 * per-repository files. See src/plugin/types.ts for the file layout.
 */
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { runChecked } from '../lib/proc';

export interface PluginPaths {
  /** Directory holding prompts/triage/* and config/{policy.yaml,vigiles.yaml,osv-scanner.toml} */
  assetRoot: string;
  cacheDir: string;
  /** OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: <cache>/osv-db/osv-scalibr/<Ecosystem>/all.zip */
  osvDbDir: string;
  kevFile: string;
  snapshotsDir: string;
  scratchDir: string;
}

export interface RepoPaths {
  repoRoot: string;
  /** <repo>/.vigiles */
  vigilesDir: string;
  profileFile: string;
  verdictsFile: string;
  reportFile: string;
  gitignoreFile: string;
  /** `<projectId>-<hash of the repo path>`: names this repo's cache entries */
  projectKey: string;
  /** <cache>/repos/<projectKey> */
  stateDir: string;
  scanFile: string;
  failuresFile: string;
}

export interface Bins {
  git: string;
  osvScanner: string;
  claude: string;
}

export function bins(env: NodeJS.ProcessEnv = process.env): Bins {
  return {
    git: env.VIGILES_GIT_BIN || 'git',
    osvScanner: env.VIGILES_OSV_SCANNER_BIN || 'osv-scanner',
    claude: env.VIGILES_CLAUDE_BIN || 'claude',
  };
}

function isAssetRoot(dir: string): boolean {
  return existsSync(path.join(dir, 'config', 'policy.yaml')) && existsSync(path.join(dir, 'prompts', 'triage'));
}

/**
 * The asset root: $VIGILES_ASSET_ROOT, else the first directory at or above `start` holding config/policy.yaml
 * and prompts/triage. In the bundle `start` is plugin/bin (→ plugin/); in dev it is src/plugin (→ the repo root).
 */
export function findAssetRoot(start?: string, env: NodeJS.ProcessEnv = process.env): string {
  if (env.VIGILES_ASSET_ROOT) {
    const root = path.resolve(env.VIGILES_ASSET_ROOT);
    if (!isAssetRoot(root)) throw new Error(`VIGILES_ASSET_ROOT=${root} has no config/policy.yaml and prompts/triage`);
    return root;
  }
  let dir = start ?? scriptDir();
  for (;;) {
    if (isAssetRoot(dir)) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error(`cannot find the Vigiles assets (config/policy.yaml, prompts/triage) above ${start ?? scriptDir()}`);
    dir = parent;
  }
}

function scriptDir(): string {
  const entry = process.argv[1];
  if (!entry) return process.cwd();
  try {
    return path.dirname(realpathSync(entry));
  } catch {
    return path.dirname(path.resolve(entry));
  }
}

/** $VIGILES_CACHE_DIR, else $XDG_CACHE_HOME/vigiles, else ~/.cache/vigiles. */
export function cacheDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.VIGILES_CACHE_DIR) return path.resolve(env.VIGILES_CACHE_DIR);
  if (env.XDG_CACHE_HOME) return path.join(path.resolve(env.XDG_CACHE_HOME), 'vigiles');
  return path.join(homedir(), '.cache', 'vigiles');
}

export function pluginPaths(opts: { assetRoot?: string; env?: NodeJS.ProcessEnv } = {}): PluginPaths {
  const env = opts.env ?? process.env;
  const cache = cacheDir(env);
  return {
    assetRoot: opts.assetRoot ?? findAssetRoot(undefined, env),
    cacheDir: cache,
    osvDbDir: path.join(cache, 'osv-db'),
    kevFile: path.join(cache, 'kev.json'),
    snapshotsDir: path.join(cache, 'snapshots'),
    scratchDir: path.join(cache, 'scratch'),
  };
}

export function projectKey(projectId: string, repoRoot: string): string {
  let real = repoRoot;
  try {
    real = realpathSync(repoRoot);
  } catch {
    // keep the given path
  }
  return `${projectId}-${createHash('sha256').update(real).digest('hex').slice(0, 8)}`;
}

export function repoPaths(repoRoot: string, projectId: string, plugin: Pick<PluginPaths, 'cacheDir'>): RepoPaths {
  const vigilesDir = path.join(repoRoot, '.vigiles');
  const key = projectKey(projectId, repoRoot);
  const stateDir = path.join(plugin.cacheDir, 'repos', key);
  return {
    repoRoot,
    vigilesDir,
    profileFile: path.join(vigilesDir, 'profile.yaml'),
    verdictsFile: path.join(vigilesDir, 'verdicts.json'),
    reportFile: path.join(vigilesDir, 'report.md'),
    gitignoreFile: path.join(vigilesDir, '.gitignore'),
    projectKey: key,
    stateDir,
    scanFile: path.join(stateDir, 'scan.json'),
    failuresFile: path.join(stateDir, 'triage-failures.json'),
  };
}

/** The repository containing `cwd` (its top-level directory). */
export async function findRepoRoot(cwd: string, git: string): Promise<string> {
  try {
    const r = await runChecked(git, ['-C', cwd, 'rev-parse', '--show-toplevel'], { timeoutMs: 15_000 });
    return r.stdout.trim();
  } catch (err) {
    throw new Error(`${cwd} is not inside a git repository (Vigiles reads lockfiles and code from git)`, { cause: err });
  }
}

/** Creates a directory (and parents) readable only by the user. */
export function ensureDir(dir: string): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/** Writes through a temp file in the same directory and renames it into place. */
export function writeFileAtomic(file: string, text: string): void {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`;
  try {
    writeFileSync(tmp, text, { mode: 0o644 });
    renameSync(tmp, file);
  } finally {
    rmSync(tmp, { force: true });
  }
}

export const VIGILES_GITIGNORE =
  '# Written by Vigiles. Commit this directory (profile.yaml, verdicts.json and this file); report.md is regenerated on every run.\nreport.md\n';

// ---------- files in <repo>/.vigiles ----------

/**
 * A file or directory in <repo>/.vigiles that is a symlink or not what it should be. The repository is not
 * trusted to point these elsewhere: a committed `.vigiles/profile.yaml -> ../.env` must never be read (its
 * content would reach error messages), and a symlinked `.vigiles/` must never be written into.
 */
export class UnsafeRepoFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeRepoFileError';
  }
}

function errnoCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | null)?.code;
}

/** Throws UnsafeRepoFileError when `dir` is a symlink or not a directory (a missing one is fine). */
export function assertRealDirectory(dir: string): void {
  const st = lstatSync(dir, { throwIfNoEntry: false });
  if (!st) return;
  if (st.isSymbolicLink()) {
    throw new UnsafeRepoFileError(`${dir} is a symlink; Vigiles only uses a real directory there. Replace it with a directory`);
  }
  if (!st.isDirectory()) throw new UnsafeRepoFileError(`${dir} is not a directory`);
}

/**
 * Reads a regular file in a real (not symlinked) directory without following a symlink: O_NOFOLLOW, then
 * fstat of the opened descriptor. A missing file throws the ENOENT error as readFileSync does. O_NONBLOCK
 * keeps a FIFO from blocking the open.
 */
export function readRegularFile(file: string): string {
  assertRealDirectory(path.dirname(file));
  let fd: number;
  try {
    fd = openSync(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (err) {
    if (errnoCode(err) === 'ELOOP' || errnoCode(err) === 'EMLINK') {
      throw new UnsafeRepoFileError(`${file} is a symlink; Vigiles only reads a regular file there. Replace it with a real file`);
    }
    throw err;
  }
  try {
    if (!fstatSync(fd).isFile()) throw new UnsafeRepoFileError(`${file} is not a regular file`);
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/**
 * writeFileAtomic for a file in <repo>/.vigiles: refuses a symlinked directory. The rename replaces a symlink
 * at the file itself instead of writing through it.
 */
export function writeRepoFile(file: string, text: string): void {
  assertRealDirectory(path.dirname(file));
  writeFileAtomic(file, text);
}
