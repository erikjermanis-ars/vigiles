/** Runs osv-scanner in offline mode over a set of lockfiles (spec §7.4). */
import { existsSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import path from 'node:path';
import { minimalEnv, runProcess } from '../proc';
import { parseOsvOutput, type OsvSourceResult } from './output';

export interface RunOsvScannerOptions {
  bin: string;
  /** OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY */
  osvDbDir: string;
  /** Absolute lockfile paths */
  lockfiles: string[];
  /** Where the temporary JSON output goes */
  scratchDir: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  /**
   * Vigiles-owned osv-scanner config passed with --config. Without it, an osv-scanner.toml committed
   * in the scanned repo next to a lockfile could silently ignore vulnerabilities (verified on 2.7.1).
   */
  configFile?: string;
}

export interface OsvScanRun {
  results: OsvSourceResult[];
  durationMs: number;
  exitCode: number;
  /** osv-scanner's warnings (stderr), trimmed */
  warnings: string;
  /** Lockfiles (as passed) osv-scanner has no extractor for, e.g. deno.lock in 2.7.1; they were not scanned */
  unsupported: string[];
}

// osv-scanner exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found, 128 = no packages found.
const OK_EXIT_CODES = new Set([0, 1, 128]);
const DEFAULT_TIMEOUT_MS = 10 * 60_000;

/**
 * `--offline` and `--no-resolve` keep the scan offline: without them osv-scanner resolves transitive
 * dependencies of manifest-like files (requirements.txt) through deps.dev, sending the dependency
 * list out. `--no-call-analysis=all` stops it from running language toolchains on the snapshot.
 *
 * Every lockfile goes in as `-L :<path>`. `-L` reads `<parse-as>:<path>`, so a ':' anywhere in a
 * repo path (a directory named `a:b`) would otherwise be taken as a parse-as type and fail the
 * whole run; the empty prefix means "detect the type". osv-scanner still reports the unprefixed
 * path (in `source.path` and in its no-extractor error; verified on 2.7.1), so callers keep keying
 * lockfiles by the plain path.
 */
export function osvScannerArgs(lockfiles: string[], outputFile: string, configFile?: string): string[] {
  return [
    'scan',
    'source',
    '--offline',
    '--offline-vulnerabilities',
    '--no-resolve',
    '--no-call-analysis=all',
    '--format',
    'json',
    '--all-packages',
    '--verbosity',
    'warn',
    '--output-file',
    outputFile,
    ...(configFile ? ['--config', configFile] : []),
    ...lockfiles.flatMap((l) => ['-L', `:${l}`]),
  ];
}

function realpathOrSelf(file: string): string {
  try {
    return realpathSync(file);
  } catch {
    return path.resolve(file);
  }
}

const NO_EXTRACTOR = /could not determine extractor suitable to this file: "([^"\n]+)"/;

/**
 * The lockfile osv-scanner rejected because it has no extractor for it (it then aborts the whole
 * run with exit 127), or null when the failure is something else.
 */
export function unsupportedLockfile(stderr: string, lockfiles: string[]): string | null {
  const m = NO_EXTRACTOR.exec(stderr);
  if (!m) return null;
  const reported = realpathOrSelf(m[1]!);
  return lockfiles.find((l) => l === m[1] || realpathOrSelf(l) === reported) ?? null;
}

type SingleRun = { kind: 'ok'; run: Omit<OsvScanRun, 'unsupported'> } | { kind: 'unsupported'; lockfile: string; durationMs: number };

async function runOnce(opts: RunOsvScannerOptions, lockfiles: string[]): Promise<SingleRun> {
  const outputFile = path.join(opts.scratchDir, `osv-scanner-${process.pid}-${Date.now()}.json`);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  try {
    const r = await runProcess(opts.bin, osvScannerArgs(lockfiles, outputFile, opts.configFile), {
      // It needs no credentials, and it parses lockfiles from client repos.
      env: minimalEnv({ OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: opts.osvDbDir }),
      signal: opts.signal,
      timeoutMs,
    });
    if (r.aborted) throw new Error('osv-scanner was cancelled');
    if (r.timedOut) throw new Error(`osv-scanner timed out after ${Math.round(timeoutMs / 1000)}s`);
    const stderr = r.stderr.trim();
    if (r.code === null || !OK_EXIT_CODES.has(r.code)) {
      const unsupported = unsupportedLockfile(stderr, lockfiles);
      if (unsupported) return { kind: 'unsupported', lockfile: unsupported, durationMs: r.durationMs };
      throw new Error(`osv-scanner exited ${r.code ?? r.signal}: ${stderr.slice(0, 2000) || r.stdout.trim().slice(0, 2000)}`);
    }
    if (!existsSync(outputFile)) {
      if (r.code === 128) return { kind: 'ok', run: { results: [], durationMs: r.durationMs, exitCode: r.code, warnings: stderr } };
      throw new Error(`osv-scanner exited ${r.code} without writing ${outputFile}: ${stderr.slice(0, 2000)}`);
    }
    const results = parseOsvOutput(JSON.parse(readFileSync(outputFile, 'utf8')));
    return { kind: 'ok', run: { results, durationMs: r.durationMs, exitCode: r.code, warnings: stderr.slice(0, 4000) } };
  } finally {
    rmSync(outputFile, { force: true });
  }
}

/**
 * One osv-scanner run over all lockfiles. A lockfile osv-scanner cannot parse at all (no extractor)
 * would fail the run for every lockfile, so it is dropped and the run repeated without it; that
 * check happens before the database loads, so a retry costs well under a second.
 */
export async function runOsvScanner(opts: RunOsvScannerOptions): Promise<OsvScanRun> {
  let remaining = [...opts.lockfiles];
  const unsupported: string[] = [];
  let spentMs = 0;
  while (remaining.length > 0) {
    const r = await runOnce(opts, remaining);
    if (r.kind === 'ok') return { ...r.run, durationMs: spentMs + r.run.durationMs, unsupported };
    spentMs += r.durationMs;
    unsupported.push(r.lockfile);
    remaining = remaining.filter((l) => l !== r.lockfile);
  }
  return { results: [], durationMs: spentMs, exitCode: 0, warnings: '', unsupported };
}
