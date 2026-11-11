/**
 * Git access to target repos (spec §3.4, §7.1). Read-only except `git fetch`, which only updates
 * remote-tracking refs. Never touches the working tree.
 */
import { spawn } from 'node:child_process';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';
import { runChecked, runProcess } from '../proc';

const GIT_ENV = {
  ...process.env,
  GIT_TERMINAL_PROMPT: '0',
  GIT_SSH_COMMAND: process.env.GIT_SSH_COMMAND ?? 'ssh -o BatchMode=yes -o ConnectTimeout=15',
};

export interface ResolvedRef {
  sha: string;
  /** Committer date, ISO-8601 */
  date: string;
}

export async function gitResolveRef(git: string, repoPath: string, ref: string): Promise<ResolvedRef> {
  const r = await runChecked(git, ['-C', repoPath, 'rev-parse', '--verify', `${ref}^{commit}`], { env: GIT_ENV, timeoutMs: 15_000 });
  const sha = r.stdout.trim();
  const d = await runChecked(git, ['-C', repoPath, 'show', '-s', '--format=%cI', sha], { env: GIT_ENV, timeoutMs: 15_000 });
  return { sha, date: new Date(d.stdout.trim()).toISOString() };
}

/**
 * For refs like `origin/main`, runs `git fetch origin main`. Returns an error message instead of
 * throwing so a scan can continue on the existing ref (spec §14 fetch_before_scan).
 */
export async function gitFetch(git: string, repoPath: string, ref: string, signal?: AbortSignal): Promise<string | null> {
  const m = /^([^/]+)\/(.+)$/.exec(ref);
  if (!m) return null; // local branch or sha: nothing to fetch
  const [, remote, branch] = m;
  const r = await runProcess(git, ['-C', repoPath, 'fetch', '--quiet', '--no-tags', remote!, branch!], {
    env: GIT_ENV,
    timeoutMs: 90_000,
    signal,
  });
  if (r.timedOut) return 'git fetch timed out after 90s';
  if (r.code !== 0) return `git fetch failed: ${r.stderr.trim().slice(0, 500)}`;
  return null;
}

/** All tracked file paths at a commit (repo-relative, forward slashes). */
export async function gitLsTree(git: string, repoPath: string, sha: string): Promise<string[]> {
  const r = await runChecked(git, ['-C', repoPath, 'ls-tree', '-r', '--name-only', '-z', sha], {
    env: GIT_ENV,
    timeoutMs: 30_000,
  });
  return r.stdout.split('\0').filter(Boolean);
}

/** Reads one file's content at a commit. */
export async function gitShowFile(git: string, repoPath: string, sha: string, file: string): Promise<string> {
  const r = await runChecked(git, ['-C', repoPath, 'show', `${sha}:${file}`], { env: GIT_ENV, timeoutMs: 30_000 });
  return r.stdout;
}

// ---------------------------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------------------------

const COMPLETE_MARKER = '.vigiles-snapshot-complete';
const SNAPSHOT_FORMAT = 2;
const DEFAULT_SNAPSHOT_TIMEOUT_MS = 5 * 60_000;
const MAX_SKIPPED_EXAMPLES = 20;
/** Per-path write failures that skip the file instead of failing the snapshot. */
const UNWRITABLE_CODES = new Set(['EEXIST', 'ENOTDIR', 'EISDIR', 'ENAMETOOLONG', 'EILSEQ']);

export interface SnapshotSkipped {
  /** Symlinks (mode 120000). Never written, so nothing in a snapshot points outside it. */
  symlinks: number;
  /** Submodules (mode 160000). Their commits are not in this repo's object database. */
  submodules: number;
  /** Paths with a segment named `.git`/`.claude` or starting with `.env` (case-insensitive). */
  scrubbed: number;
  /**
   * Paths with an empty, `.` or `..` segment (only a hand-crafted tree contains these), and
   * top-level entries named like the completion marker.
   */
  unsafe: number;
  /** Paths the filesystem refused, e.g. `README` next to `readme` on a case-insensitive volume. */
  unwritable: number;
}

/** Stored as JSON in the snapshot's completion marker. */
export interface SnapshotInfo {
  format: typeof SNAPSHOT_FORMAT;
  sha: string;
  /**
   * `objects`: written blob by blob from the object database. `archive`: a legacy `git archive`
   * snapshot (which honoured export-ignore/export-subst) that was re-scrubbed in place.
   */
  source: 'objects' | 'archive';
  /** Regular files written (objects only). */
  files?: number;
  bytes?: number;
  skipped?: SnapshotSkipped;
  /** Up to 20 skipped paths with their reason; scrubbed paths are not listed. */
  skippedExamples?: string[];
}

export interface SnapshotOptions {
  /** Receives one line when a new snapshot left tracked entries out (symlinks, submodules, ...). */
  log?: (message: string) => void;
  signal?: AbortSignal;
  /** For the `git cat-file` stream (default 5 min). */
  timeoutMs?: number;
}

export function snapshotDir(snapshotsRoot: string, projectId: string, sha: string): string {
  return path.join(snapshotsRoot, projectId, sha);
}

function isScrubbedName(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === '.git' || lower === '.claude' || lower.startsWith('.env');
}

/**
 * True when a snapshot must never contain this repo-relative path: any segment named `.git` or
 * `.claude`, or starting with `.env`, compared case-insensitively (macOS volumes are
 * case-insensitive, so `.ENV` is just as readable). Spec §7.1.
 */
export function isScrubbedPath(relPath: string): boolean {
  return relPath.split('/').some(isScrubbedName);
}

function isUnsafePath(relPath: string): boolean {
  return relPath.split('/').some((s) => s === '' || s === '.' || s === '..');
}

/**
 * A tracked top-level entry named like the completion marker (case-insensitive, as the volume is)
 * would be overwritten by the marker or, as a directory, make writing the marker fail for every
 * scan of that commit.
 */
function isReservedPath(relPath: string): boolean {
  return relPath.split('/', 1)[0]!.toLowerCase() === COMPLETE_MARKER;
}

/** The completion marker's info, or null when the snapshot is incomplete or missing. */
export function readSnapshotInfo(dir: string): SnapshotInfo | null {
  let raw: string;
  try {
    raw = readFileSync(path.join(dir, COMPLETE_MARKER), 'utf8');
  } catch {
    return null;
  }
  try {
    const info = JSON.parse(raw) as SnapshotInfo;
    if (info && typeof info === 'object' && info.format === SNAPSHOT_FORMAT) return info;
  } catch {
    // legacy marker: the bare sha
  }
  return { format: SNAPSHOT_FORMAT, sha: raw.trim(), source: 'archive' };
}

/**
 * Writes the tracked files of <sha> to <snapshots>/<project>/<sha>/ (cached by SHA) and returns that
 * directory. Files come straight from the object database (`git ls-tree` + one `git cat-file
 * --batch`), so `.gitattributes` export-ignore/export-subst cannot hide or rewrite code, and
 * ignored/untracked files are never present. Regular files are written 0600 (0700 when
 * executable); symlinks and submodules are skipped, and so is every path the scrub rules cover
 * (`.git`, `.claude`, `.env*`), which is therefore never written at all.
 *
 * The tree is built in a unique temp dir, marked complete, then renamed into place, so concurrent
 * calls for the same commit are safe. A legacy `git archive` snapshot (bare-sha marker) is kept but
 * re-scrubbed once.
 */
export async function ensureSnapshot(
  git: string,
  snapshotsRoot: string,
  projectId: string,
  repoPath: string,
  sha: string,
  opts: SnapshotOptions = {},
): Promise<string> {
  if (!/^[0-9a-f]{4,64}$/i.test(sha)) throw new Error(`ensureSnapshot: not a commit sha: ${JSON.stringify(sha)}`);
  const dir = snapshotDir(snapshotsRoot, projectId, sha);
  if (isCompleteSnapshot(dir, sha, opts.log)) return dir;
  mkdirSync(path.dirname(dir), { recursive: true, mode: 0o700 });
  // Unique temp dir: concurrent calls for the same commit (e.g. parallel triage runs) must not collide.
  const tmp = mkdtempSync(`${dir}.tmp-`);
  try {
    const info = await writeTreeFromObjects(git, repoPath, sha, tmp, opts);
    writeFileSync(path.join(tmp, COMPLETE_MARKER), `${JSON.stringify(info)}\n`, { mode: 0o600 });
    const summary = describeSkipped(info);
    if (summary) opts.log?.(summary);
    publishSnapshot(tmp, dir);
    return dir;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function isCompleteSnapshot(dir: string, sha: string, log?: (message: string) => void): boolean {
  const marker = path.join(dir, COMPLETE_MARKER);
  let raw: string;
  try {
    raw = readFileSync(marker, 'utf8');
  } catch {
    return false;
  }
  try {
    if ((JSON.parse(raw) as SnapshotInfo | null)?.format === SNAPSHOT_FORMAT) return true;
  } catch {
    // legacy marker
  }
  // Extracted by `git archive` with the old scrub, which kept `.env*` directories and symlinks.
  scrubSnapshot(dir);
  const info: SnapshotInfo = { format: SNAPSHOT_FORMAT, sha, source: 'archive' };
  const tmpMarker = `${marker}.${process.pid}-${Math.random().toString(36).slice(2)}`;
  writeFileSync(tmpMarker, `${JSON.stringify(info)}\n`, { mode: 0o600 });
  renameSync(tmpMarker, marker);
  log?.(`snapshot ${sha.slice(0, 10)}: re-scrubbed a legacy git-archive snapshot`);
  return true;
}

function errCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | null)?.code;
}

/** Renames the finished temp dir into place unless a concurrent call already did. */
function publishSnapshot(tmp: string, dir: string): void {
  for (let attempt = 0; ; attempt++) {
    try {
      renameSync(tmp, dir);
      return;
    } catch (err) {
      if (!['ENOTEMPTY', 'EEXIST', 'ENOTDIR'].includes(errCode(err) ?? '')) throw err;
      if (existsSync(path.join(dir, COMPLETE_MARKER))) return; // a concurrent call finished first
      if (attempt >= 2) throw err;
      rmSync(dir, { recursive: true, force: true }); // an incomplete leftover
    }
  }
}

function describeSkipped(info: SnapshotInfo): string | null {
  const s = info.skipped;
  if (!s) return null;
  const parts = [
    s.symlinks && `${s.symlinks} symlink(s)`,
    s.submodules && `${s.submodules} submodule(s)`,
    s.unsafe && `${s.unsafe} unsafe path(s)`,
    s.unwritable && `${s.unwritable} unwritable path(s)`,
    s.scrubbed && `${s.scrubbed} .git/.claude/.env* path(s)`,
  ].filter(Boolean);
  if (!parts.length) return null;
  const examples = info.skippedExamples?.length ? ` (e.g. ${info.skippedExamples.slice(0, 5).join(', ')})` : '';
  return `snapshot ${info.sha.slice(0, 10)}: not written: ${parts.join(', ')}${examples}`;
}

interface BlobEntry {
  oid: string;
  /** Repo-relative, forward slashes, already checked by isUnsafePath/isScrubbedPath */
  path: string;
  mode: number;
}

async function writeTreeFromObjects(
  git: string,
  repoPath: string,
  sha: string,
  dest: string,
  opts: SnapshotOptions,
): Promise<SnapshotInfo> {
  const ls = await runChecked(git, ['-C', repoPath, 'ls-tree', '-r', '-z', sha], {
    env: GIT_ENV,
    timeoutMs: 60_000,
    signal: opts.signal,
    maxBuffer: 1024 * 1024 * 1024,
  });
  const skipped: SnapshotSkipped = { symlinks: 0, submodules: 0, scrubbed: 0, unsafe: 0, unwritable: 0 };
  const examples: string[] = [];
  const skip = (kind: keyof SnapshotSkipped, file: string, why: string = kind) => {
    skipped[kind]++;
    if (kind !== 'scrubbed' && examples.length < MAX_SKIPPED_EXAMPLES) examples.push(`${file} (${why})`);
  };

  const blobs: BlobEntry[] = [];
  for (const record of ls.stdout.split('\0')) {
    if (!record) continue;
    // `<mode> SP <type> SP <oid> TAB <path>`; the path may itself contain tabs.
    const tab = record.indexOf('\t');
    const [mode = '', type = '', oid = ''] = (tab === -1 ? record : record.slice(0, tab)).split(' ');
    const file = tab === -1 ? '' : record.slice(tab + 1);
    if (tab === -1 || !/^[0-9a-f]{40,64}$/.test(oid)) throw new Error(`git ls-tree: unexpected output: ${record.slice(0, 200)}`);
    if (isUnsafePath(file)) skip('unsafe', JSON.stringify(file), 'unsafe path');
    else if (isScrubbedPath(file)) skip('scrubbed', file);
    else if (isReservedPath(file)) skip('unsafe', file, 'reserved name');
    else if (mode === '120000') skip('symlinks', file, 'symlink');
    else if (mode === '160000' || type === 'commit') skip('submodules', file, 'submodule');
    else if (type === 'blob' && /^100[0-7]{3}$/.test(mode)) {
      blobs.push({ oid, path: file, mode: (parseInt(mode, 8) & 0o111) !== 0 ? 0o700 : 0o600 });
    } else skip('unsafe', file, `mode ${mode} ${type}`);
  }

  const writer = new BlobWriter(dest, blobs, (entry, code) => skip('unwritable', entry.path, code));
  try {
    if (blobs.length > 0) {
      await streamGit(git, ['-C', repoPath, 'cat-file', '--batch'], {
        input: blobs.map((b) => `${b.oid}\n`).join(''),
        onStdout: (chunk) => writer.push(chunk),
        timeoutMs: opts.timeoutMs ?? DEFAULT_SNAPSHOT_TIMEOUT_MS,
        signal: opts.signal,
      });
    }
    writer.finish();
  } finally {
    writer.close();
  }
  return {
    format: SNAPSHOT_FORMAT,
    sha,
    source: 'objects',
    files: writer.files,
    bytes: writer.bytes,
    skipped,
    ...(examples.length ? { skippedExamples: examples } : {}),
  };
}

/**
 * Parses `git cat-file --batch` output (`<oid> SP blob SP <size> LF <bytes> LF`, one per requested
 * line, in request order) as raw Buffers and writes each blob to its own new file. Files are
 * opened with O_CREAT|O_EXCL|O_NOFOLLOW, and only directories this writer created exist in the
 * tree, so nothing is ever written through a symlink or over another file.
 */
class BlobWriter {
  files = 0;
  bytes = 0;
  private index = 0;
  private state: 'header' | 'body' | 'newline' = 'header';
  private header: Buffer[] = [];
  private headerBytes = 0;
  private remaining = 0;
  private fd: number | null = null;
  private readonly dirs = new Set<string>();

  constructor(
    private readonly root: string,
    private readonly entries: BlobEntry[],
    private readonly onUnwritable: (entry: BlobEntry, code: string) => void,
  ) {}

  push(chunk: Buffer): void {
    let off = 0;
    while (off < chunk.length) {
      if (this.state === 'header') {
        const nl = chunk.indexOf(0x0a, off);
        const end = nl === -1 ? chunk.length : nl;
        this.headerBytes += end - off;
        if (this.headerBytes > 1024) throw new Error('git cat-file: malformed output (header line too long)');
        this.header.push(chunk.subarray(off, end));
        if (nl === -1) return;
        off = nl + 1;
        const line = Buffer.concat(this.header).toString('utf8');
        this.header = [];
        this.headerBytes = 0;
        this.startBlob(line);
      } else if (this.state === 'body') {
        const n = Math.min(this.remaining, chunk.length - off);
        if (this.fd !== null) {
          writeFully(this.fd, chunk.subarray(off, off + n));
          this.bytes += n;
        }
        off += n;
        this.remaining -= n;
        if (this.remaining === 0) this.endBlob();
      } else {
        if (chunk[off] !== 0x0a) throw new Error('git cat-file: malformed output (no newline after object)');
        off++;
        this.index++;
        this.state = 'header';
      }
    }
  }

  /** Throws unless every requested object was read completely. */
  finish(): void {
    if (this.index !== this.entries.length || this.state !== 'header' || this.headerBytes > 0) {
      throw new Error(`git cat-file: output ended after ${this.index} of ${this.entries.length} objects`);
    }
  }

  close(): void {
    if (this.fd !== null) closeSync(this.fd);
    this.fd = null;
  }

  private startBlob(line: string): void {
    const entry = this.entries[this.index];
    const m = /^([0-9a-f]+) (\S+) (\d+)$/.exec(line);
    if (!entry || !m || m[1] !== entry.oid || m[2] !== 'blob') {
      throw new Error(`git cat-file: expected blob ${entry?.oid ?? '(none)'} for ${entry?.path ?? '?'}, got: ${line.slice(0, 200)}`);
    }
    this.remaining = Number(m[3]);
    this.fd = this.open(entry);
    this.state = 'body';
    if (this.remaining === 0) this.endBlob();
  }

  private endBlob(): void {
    if (this.fd !== null) {
      closeSync(this.fd);
      this.fd = null;
      this.files++;
    }
    this.state = 'newline';
  }

  private open(entry: BlobEntry): number | null {
    const full = path.join(this.root, ...entry.path.split('/'));
    try {
      const parent = path.dirname(full);
      if (!this.dirs.has(parent)) {
        mkdirSync(parent, { recursive: true, mode: 0o700 });
        this.dirs.add(parent);
      }
      const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW;
      return openSync(full, flags, entry.mode);
    } catch (err) {
      const code = errCode(err);
      if (code && UNWRITABLE_CODES.has(code)) {
        this.onUnwritable(entry, code);
        return null; // the body is still consumed, just not written
      }
      throw err;
    }
  }
}

function writeFully(fd: number, buf: Buffer): void {
  let off = 0;
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
}

/**
 * Spawns git (never a shell) and hands its stdout to `onStdout` as raw Buffers: runProcess decodes
 * stdout as UTF-8, which would corrupt binary blobs. Rejects on a non-zero exit, timeout or abort,
 * or when `onStdout` throws (the child is then killed).
 */
function streamGit(
  git: string,
  args: string[],
  opts: { input: string; onStdout: (chunk: Buffer) => void; timeoutMs: number; signal?: AbortSignal },
): Promise<void> {
  const what = `git ${args
    .filter((a) => a !== '-C')
    .slice(1)
    .join(' ')}`;
  return new Promise((resolve, reject) => {
    const child = spawn(git, args, { env: GIT_ENV, stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    let failure: Error | null = null;
    let settled = false;
    const fail = (err: Error) => {
      failure ??= err;
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    };
    const timer = setTimeout(() => fail(new Error(`${what} timed out after ${Math.round(opts.timeoutMs / 1000)}s`)), opts.timeoutMs);
    const onAbort = () => fail(new Error(`${what} was cancelled`));
    const settle = (err: Error | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolve();
    };
    if (opts.signal?.aborted) onAbort();
    else opts.signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout.on('data', (chunk: Buffer) => {
      if (failure) return;
      try {
        opts.onStdout(chunk);
      } catch (err) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (d: string) => {
      if (stderr.length < 64 * 1024) stderr += d;
    });
    child.stdin.on('error', () => {
      // git may exit before reading all of stdin (fatal error or killed); the exit code reports it
    });
    child.on('error', (err) => settle(err));
    child.on('close', (code, signal) => {
      if (failure) settle(failure);
      else if (code !== 0) settle(new Error(`${what} exited ${code ?? signal}: ${stderr.trim().slice(0, 2000)}`));
      else settle(null);
    });
    child.stdin.end(opts.input);
  });
}

/**
 * Removes, anywhere in the tree, every entry named `.claude`/`.git` or starting with `.env`
 * (case-insensitive) whatever its type (file, directory, symlink), and every symlink; it recurses
 * only into real directories, never through a symlink (spec §7.1). Snapshots written by
 * ensureSnapshot contain none of these; this cleans legacy `git archive` snapshots, whose symlinks
 * could point outside the snapshot. Entries removed concurrently are ignored.
 */
export function scrubSnapshot(dir: string): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch (err) {
    if (errCode(err) === 'ENOENT' || errCode(err) === 'ENOTDIR') return;
    throw err;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry);
    const st = lstatSync(full, { throwIfNoEntry: false });
    if (!st) continue;
    if (isScrubbedName(entry) || st.isSymbolicLink()) rmSync(full, { recursive: true, force: true });
    else if (st.isDirectory()) scrubSnapshot(full);
  }
}
