/**
 * Child-process helper used for git, osv-scanner, npm and claude.
 * Never uses a shell: arguments are passed as an array.
 */
import { spawn } from 'node:child_process';

export interface RunOptions {
  cwd?: string;
  /** Full environment for the child. Defaults to process.env. Pass `minimalEnv()` for claude. */
  env?: NodeJS.ProcessEnv;
  /** Written to stdin, then stdin is closed. */
  input?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Cap on captured stdout/stderr bytes each (default 64 MB). */
  maxBuffer?: number;
}

export interface RunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  aborted: boolean;
  durationMs: number;
}

export class ProcessError extends Error {
  constructor(
    message: string,
    public result: RunResult,
  ) {
    super(message);
  }
}

export function runProcess(cmd: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
  const started = Date.now();
  const maxBuffer = opts.maxBuffer ?? 64 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let aborted = false;
    let settled = false;

    const kill = () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        }, 3000).unref();
      }
    };
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          kill();
        }, opts.timeoutMs)
      : undefined;
    const onAbort = () => {
      aborted = true;
      kill();
    };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d: string) => {
      if (stdout.length < maxBuffer) stdout += d;
    });
    child.stderr.on('data', (d: string) => {
      if (stderr.length < maxBuffer) stderr += d;
    });
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      reject(err);
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      resolve({ code, signal, stdout, stderr, timedOut, aborted, durationMs: Date.now() - started });
    });
    child.stdin.on('error', () => {
      // child may exit before reading stdin; ignore EPIPE
    });
    if (opts.input !== undefined) child.stdin.end(opts.input);
    else child.stdin.end();
  });
}

/** Runs and throws ProcessError unless exit code is in `okCodes` (default [0]). */
export async function runChecked(cmd: string, args: string[], opts: RunOptions & { okCodes?: number[] } = {}): Promise<RunResult> {
  const r = await runProcess(cmd, args, opts);
  const ok = opts.okCodes ?? [0];
  if (r.timedOut) throw new ProcessError(`${cmd} timed out after ${opts.timeoutMs}ms`, r);
  if (r.aborted) throw new ProcessError(`${cmd} was cancelled`, r);
  if (r.code === null || !ok.includes(r.code)) {
    throw new ProcessError(`${cmd} ${args.slice(0, 3).join(' ')} exited ${r.code ?? r.signal}: ${r.stderr.trim().slice(0, 2000)}`, r);
  }
  return r;
}

/** Minimal environment for untrusted-input subprocesses (claude). Never forwards API keys. */
export function minimalEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: Record<string, string> = {};
  for (const k of ['HOME', 'PATH', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'SHELL']) {
    const v = process.env[k];
    if (v) env[k] = v;
  }
  env.LANG ??= 'en_US.UTF-8';
  return { ...env, ...extra } as NodeJS.ProcessEnv;
}
