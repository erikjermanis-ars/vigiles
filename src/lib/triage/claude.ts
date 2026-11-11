/**
 * Runs one triage through the locked-down `claude -p` invocation (spec §3.5, §9.5) and parses
 * its JSON result. The prompt goes on stdin; the child gets minimalEnv() so an API key in the
 * caller's shell can't switch billing or leak.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { minimalEnv, runProcess, type RunResult } from '../proc';
import { TriageOutputSchema, type TriageOutput, type TriageRunStatus } from '../types';

export const CODE_TOOLS = 'Read,Grep,Glob';

export interface ClaudeArgsInput {
  model: string;
  effort: string;
  codeAccess: boolean;
  systemPrompt: string;
  schemaJson: string;
  maxBudgetUsd: number;
}

export function buildClaudeArgs(i: ClaudeArgsInput): string[] {
  // prettier-ignore
  return [
    '-p',
    '--model', i.model,
    '--effort', i.effort,
    '--restricted',
    '--safe-mode',
    '--strict-mcp-config',
    '--tools', i.codeAccess ? CODE_TOOLS : '',
    '--permission-mode', 'dontAsk',
    '--system-prompt', i.systemPrompt,
    '--json-schema', i.schemaJson,
    '--output-format', 'json',
    '--no-session-persistence',
    '--max-budget-usd', String(i.maxBudgetUsd),
  ];
}

export interface ClaudeTriageRequest extends ClaudeArgsInput {
  /** Path or name of the claude binary (config.bin.claude) */
  bin: string;
  /** Code access: cwd = snapshotDir. No code: cwd = a fresh empty directory under scratchDir. */
  snapshotDir?: string;
  scratchDir?: string;
  userPrompt: string;
  timeoutMs: number;
  signal?: AbortSignal;
  /** Default 2: one retry on is_error / non-zero exit / invalid output (spec §9.5) */
  maxAttempts?: number;
}

export interface ClaudeTriageResult {
  status: TriageRunStatus;
  output: TriageOutput | null;
  /** The CLI's JSON result of the last attempt that produced one */
  raw: Record<string, unknown> | null;
  modelResolved: string | null;
  /** Cost, tokens, turns and duration are totals across attempts (the true price of the result). */
  costUsd: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  cacheReadTokens: number | null;
  numTurns: number | null;
  durationMs: number | null;
  attempts: number;
  error: string | null;
  /** Errors of earlier attempts that were retried */
  retriedErrors: string[];
  /** Tool calls the CLI refused (e.g. a Read outside the snapshot); audit signal */
  permissionDenials: number;
}

// ---------- parsing one attempt ----------

export interface AttemptMetrics {
  costUsd: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  cacheReadTokens: number | null;
  numTurns: number | null;
  durationMs: number | null;
}

export interface ParsedAttempt {
  status: TriageRunStatus;
  output: TriageOutput | null;
  raw: Record<string, unknown> | null;
  modelResolved: string | null;
  metrics: AttemptMetrics;
  error: string | null;
  permissionDenials: number;
  /** Whether a second attempt could plausibly succeed */
  retryable: boolean;
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * The CLI's result object. `--output-format json` prints exactly one object, but a stray line before it
 * (an update notice or warning on stdout) must not turn a paid, successful run into a failure.
 */
export function parseCliStdout(stdout: string): Record<string, unknown> | null {
  const whole = asRecord(tryParseJson(stdout.trim()));
  if (whole) return whole;
  const lines = stdout.split('\n').filter((l) => l.trim());
  for (let i = lines.length - 1; i >= 0; i--) {
    const obj = asRecord(tryParseJson(lines[i]!.trim()));
    if (obj && obj.type === 'result') return obj;
  }
  return null;
}

/**
 * The resolved model ID (configs use aliases like `opus`). modelUsage normally has one key; if the
 * CLI also used a helper model, prefer the key that matches the requested alias.
 */
export function resolveModel(raw: Record<string, unknown>, requested: string): string | null {
  const keys = Object.keys(asRecord(raw.modelUsage) ?? {});
  return keys.find((k) => k.includes(requested)) ?? keys[0] ?? null;
}

export function metricsFrom(raw: Record<string, unknown> | null, wallMs: number): AttemptMetrics {
  const usage = asRecord(raw?.usage) ?? {};
  const fresh = num(usage.input_tokens);
  const created = num(usage.cache_creation_input_tokens);
  return {
    costUsd: num(raw?.total_cost_usd),
    // Everything billed as non-cached input; input_tokens alone is usually a handful of tokens.
    inputTokens: fresh === null && created === null ? null : (fresh ?? 0) + (created ?? 0),
    outputTokens: num(usage.output_tokens),
    cacheReadTokens: num(usage.cache_read_input_tokens),
    numTurns: num(raw?.num_turns),
    durationMs: num(raw?.duration_ms) ?? wallMs,
  };
}

function firstLine(s: string, max = 500): string {
  const line =
    s
      .trim()
      .split('\n')
      .find((l) => l.trim()) ?? '';
  return line.slice(0, max);
}

/** Classifies one finished CLI process. Pure, so every path is unit-testable. */
export function parseAttempt(run: RunResult, requestedModel: string): ParsedAttempt {
  const base = { output: null, raw: null, modelResolved: null, permissionDenials: 0 };
  const empty = metricsFrom(null, run.durationMs);
  if (run.aborted) return { ...base, status: 'cancelled', metrics: empty, error: 'cancelled', retryable: false };
  if (run.timedOut) return { ...base, status: 'timeout', metrics: empty, error: `timed out after ${run.durationMs} ms`, retryable: false };

  const raw = parseCliStdout(run.stdout);
  if (!raw) {
    const why = run.code === 0 ? 'stdout is not a JSON object' : `exited ${run.code ?? run.signal}`;
    const detail = firstLine(run.stderr) || firstLine(run.stdout);
    return { ...base, status: 'failed', metrics: empty, error: `claude ${why}${detail ? `: ${detail}` : ''}`, retryable: true };
  }

  const common = {
    raw,
    modelResolved: resolveModel(raw, requestedModel),
    metrics: metricsFrom(raw, run.durationMs),
    permissionDenials: Array.isArray(raw.permission_denials) ? raw.permission_denials.length : 0,
  };
  if (raw.is_error === true || run.code !== 0) {
    const subtype = typeof raw.subtype === 'string' ? raw.subtype : 'error';
    const detail = typeof raw.result === 'string' ? firstLine(raw.result) : firstLine(run.stderr);
    return {
      ...common,
      output: null,
      status: 'failed',
      error: `claude ${subtype}${run.code !== 0 ? ` (exit ${run.code ?? run.signal})` : ''}${detail ? `: ${detail}` : ''}`,
      // Retrying a budget overrun would just spend the budget a second time.
      retryable: subtype !== 'error_max_budget_usd',
    };
  }

  const candidate = raw.structured_output ?? (typeof raw.result === 'string' ? tryParseJson(raw.result) : undefined);
  const parsed = TriageOutputSchema.safeParse(candidate);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .slice(0, 3)
      .map((i) => `${i.path.map(String).join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    return { ...common, output: null, status: 'invalid', error: `invalid structured output: ${issues}`, retryable: true };
  }
  return { ...common, output: parsed.data, status: 'ok', error: null, retryable: false };
}

// ---------- running ----------

function addNullable(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return a + b;
}

function sumMetrics(a: AttemptMetrics, b: AttemptMetrics): AttemptMetrics {
  return {
    costUsd: addNullable(a.costUsd, b.costUsd),
    inputTokens: addNullable(a.inputTokens, b.inputTokens),
    outputTokens: addNullable(a.outputTokens, b.outputTokens),
    cacheReadTokens: addNullable(a.cacheReadTokens, b.cacheReadTokens),
    numTurns: addNullable(a.numTurns, b.numTurns),
    durationMs: addNullable(a.durationMs, b.durationMs),
  };
}

async function runOnce(req: ClaudeTriageRequest, cwd: string): Promise<ParsedAttempt> {
  let run: RunResult;
  try {
    run = await runProcess(req.bin, buildClaudeArgs(req), {
      cwd,
      env: minimalEnv(),
      input: req.userPrompt,
      timeoutMs: req.timeoutMs,
      signal: req.signal,
    });
  } catch (err) {
    // Spawn failure (binary missing, cwd gone): retrying won't help.
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: 'failed',
      output: null,
      raw: null,
      modelResolved: null,
      metrics: metricsFrom(null, 0),
      error: `could not start ${req.bin}: ${message}`,
      permissionDenials: 0,
      retryable: false,
    };
  }
  return parseAttempt(run, req.model);
}

const NO_METRICS: AttemptMetrics = {
  costUsd: null,
  inputTokens: null,
  outputTokens: null,
  cacheReadTokens: null,
  numTurns: null,
  durationMs: null,
};

/** Runs the triage with one retry and returns the final, typed result. Never throws for CLI failures. */
export async function runClaudeTriage(req: ClaudeTriageRequest): Promise<ClaudeTriageResult> {
  const maxAttempts = req.maxAttempts ?? 2;
  let cwd: string;
  let tempDir: string | null = null;
  if (req.codeAccess) {
    if (!req.snapshotDir) throw new Error('runClaudeTriage: snapshotDir is required with code access');
    cwd = req.snapshotDir;
  } else {
    if (!req.scratchDir) throw new Error('runClaudeTriage: scratchDir is required without code access');
    mkdirSync(req.scratchDir, { recursive: true, mode: 0o700 });
    tempDir = mkdtempSync(path.join(req.scratchDir, 'triage-nocode-'));
    cwd = tempDir;
  }

  try {
    let metrics = NO_METRICS;
    let permissionDenials = 0;
    let lastRaw: Record<string, unknown> | null = null;
    let last: ParsedAttempt | null = null;
    let attempts = 0;
    const retriedErrors: string[] = [];

    while (attempts < maxAttempts && !req.signal?.aborted) {
      if (last) retriedErrors.push(`attempt ${attempts}: ${last.status}: ${last.error ?? ''}`);
      attempts++;
      last = await runOnce(req, cwd);
      metrics = sumMetrics(metrics, last.metrics);
      permissionDenials += last.permissionDenials;
      lastRaw = last.raw ?? lastRaw;
      if (last.status === 'ok' || !last.retryable) break;
    }

    return {
      status: last?.status ?? 'cancelled',
      output: last?.output ?? null,
      raw: lastRaw,
      modelResolved: lastRaw ? resolveModel(lastRaw, req.model) : null,
      ...metrics,
      attempts,
      error: last ? last.error : 'cancelled before start',
      retriedErrors,
      permissionDenials,
    };
  } finally {
    if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  }
}

/** `claude --version`, e.g. "2.1.318 (Claude Code)". Recorded on every triage run (spec §17). */
export async function getClaudeVersion(bin: string, signal?: AbortSignal): Promise<string> {
  const r = await runProcess(bin, ['--version'], { env: minimalEnv(), timeoutMs: 30_000, signal });
  const version = r.stdout.trim().split('\n')[0]?.trim() ?? '';
  if (r.code !== 0 || !version) {
    throw new Error(`\`${bin} --version\` failed (exit ${r.code ?? r.signal}): ${firstLine(r.stderr) || 'no output'}`);
  }
  return version;
}
