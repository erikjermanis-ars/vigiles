import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { RunResult } from '../proc';
import {
  buildClaudeArgs,
  getClaudeVersion,
  parseAttempt,
  parseCliStdout,
  resolveModel,
  runClaudeTriage,
  type ClaudeTriageRequest,
} from './claude';

const FAKE = path.join(import.meta.dirname, '../../../test/fake-claude/claude.mjs');

let tmp: string;
let snapshotDir: string;
let scratchDir: string;
beforeAll(() => {
  tmp = mkdtempSync(path.join(os.tmpdir(), 'vigiles-claude-test-'));
  snapshotDir = path.join(tmp, 'snapshot');
  scratchDir = path.join(tmp, 'scratch');
  mkdirSync(snapshotDir);
  writeFileSync(path.join(snapshotDir, 'package.json'), '{}');
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let counter = 0;
function request(directives: string, overrides: Partial<ClaudeTriageRequest> = {}): ClaudeTriageRequest {
  const state = path.join(tmp, `state-${++counter}`);
  return {
    bin: FAKE,
    model: 'sonnet',
    effort: 'high',
    codeAccess: true,
    systemPrompt: 'You are a triage analyst.',
    schemaJson: '{"type":"object"}',
    maxBudgetUsd: 3,
    snapshotDir,
    scratchDir,
    userPrompt: `Triage this.\n${directives} FAKE_CLAUDE_STATE=${state}\n`,
    timeoutMs: 20_000,
    ...overrides,
  };
}

function recorded(file: string): { argv: string[]; cwd: string; cwdEntries: string[]; envKeys: string[]; stdin: string }[] {
  return readFileSync(file, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
}

describe('buildClaudeArgs', () => {
  const base = { model: 'opus', effort: 'high', systemPrompt: 'SYS', schemaJson: '{"type":"object"}', maxBudgetUsd: 3 };

  it('builds the locked-down invocation from spec §3.5', () => {
    expect(buildClaudeArgs({ ...base, codeAccess: true })).toEqual([
      '-p',
      '--model',
      'opus',
      '--effort',
      'high',
      '--restricted',
      '--safe-mode',
      '--strict-mcp-config',
      '--tools',
      'Read,Grep,Glob',
      '--permission-mode',
      'dontAsk',
      '--system-prompt',
      'SYS',
      '--json-schema',
      '{"type":"object"}',
      '--output-format',
      'json',
      '--no-session-persistence',
      '--max-budget-usd',
      '3',
    ]);
  });

  it('gives no tools at all without code access', () => {
    const args = buildClaudeArgs({ ...base, codeAccess: false, maxBudgetUsd: 0.5 });
    expect(args[args.indexOf('--tools') + 1]).toBe('');
    expect(args.slice(-2)).toEqual(['--max-budget-usd', '0.5']);
    expect(args).not.toContain('Read,Grep,Glob');
  });
});

describe('runClaudeTriage with the fake CLI', () => {
  it('runs in the snapshot with a minimal env and parses a successful result', async () => {
    const record = path.join(tmp, 'record-ok.jsonl');
    process.env.ANTHROPIC_API_KEY = 'sk-should-not-leak';
    try {
      const req = request(`FAKE_CLAUDE_MODE=ok FAKE_CLAUDE_RECORD=${record}`);
      const r = await runClaudeTriage(req);
      expect(r).toMatchObject({
        status: 'ok',
        modelResolved: 'claude-sonnet-fake-1',
        costUsd: 0.0125,
        inputTokens: 510,
        outputTokens: 300,
        cacheReadTokens: 2000,
        numTurns: 4,
        durationMs: 1500,
        attempts: 1,
        error: null,
        retriedErrors: [],
      });
      expect(r.output?.verdict).toBe('likely_affected');
      expect(r.raw?.session_id).toBe('fake-session');

      const [call] = recorded(record);
      expect(call!.argv).toEqual(buildClaudeArgs(req));
      expect(call!.cwd).toBe(realpath(snapshotDir));
      expect(call!.stdin).toBe(req.userPrompt);
      expect(call!.envKeys).not.toContain('ANTHROPIC_API_KEY');
      // macOS adds __CF_USER_TEXT_ENCODING to every child process by itself.
      const allowed = ['HOME', 'PATH', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'SHELL', '__CF_USER_TEXT_ENCODING'];
      expect(call!.envKeys.filter((k) => !allowed.includes(k))).toEqual([]);
    } finally {
      delete process.env.ANTHROPIC_API_KEY;
    }
  });

  it('runs without code in a fresh empty directory under scratch and removes it afterwards', async () => {
    const record = path.join(tmp, 'record-nocode.jsonl');
    const req = request(`FAKE_CLAUDE_MODE=ok FAKE_CLAUDE_RECORD=${record}`, { codeAccess: false, snapshotDir: undefined });
    const r = await runClaudeTriage(req);
    expect(r.status).toBe('ok');
    const [call] = recorded(record);
    expect(call!.cwd.startsWith(realpath(scratchDir))).toBe(true);
    expect(path.basename(call!.cwd)).toMatch(/^triage-nocode-/);
    expect(call!.cwdEntries).toEqual([]);
    expect(call!.argv[call!.argv.indexOf('--tools') + 1]).toBe('');
    expect(existsSync(call!.cwd)).toBe(false);
    expect(readdirSync(scratchDir)).toEqual([]);
  });

  it('accepts a notice line printed before the result object without retrying', async () => {
    const r = await runClaudeTriage(request('FAKE_CLAUDE_MODE=noisy,invalid'));
    expect(r).toMatchObject({ status: 'ok', attempts: 1, costUsd: 0.0125, retriedErrors: [] });
  });

  it.each([
    ['invalid,ok', 'ok', 2],
    ['is_error,ok', 'ok', 2],
    ['exit,ok', 'ok', 2],
    ['garbage,ok', 'ok', 2],
    ['invalid,invalid', 'invalid', 2],
    ['missing,missing', 'invalid', 2],
    ['is_error,is_error', 'failed', 2],
    ['exit,exit', 'failed', 2],
    ['budget,ok', 'failed', 1],
  ] as const)('mode %s → %s after %i attempt(s)', async (modes, status, attempts) => {
    const r = await runClaudeTriage(request(`FAKE_CLAUDE_MODE=${modes}`));
    expect(r.status).toBe(status);
    expect(r.attempts).toBe(attempts);
    expect(r.retriedErrors).toHaveLength(attempts - 1);
    if (status === 'ok') {
      expect(r.output).not.toBeNull();
      expect(r.error).toBeNull();
    } else {
      expect(r.output).toBeNull();
      expect(r.error).toBeTruthy();
    }
  });

  it('sums cost and tokens across attempts and keeps the error of each retry', async () => {
    const r = await runClaudeTriage(request('FAKE_CLAUDE_MODE=invalid,ok'));
    expect(r.costUsd).toBeCloseTo(0.025);
    expect(r.outputTokens).toBe(600);
    expect(r.numTurns).toBe(8);
    expect(r.retriedErrors[0]).toMatch(/^attempt 1: invalid: invalid structured output: verdict:/);
  });

  it('reports useful errors', async () => {
    const exit = await runClaudeTriage(request('FAKE_CLAUDE_MODE=exit'));
    expect(exit.error).toBe('claude exited 2: fake claude: something broke');
    const budget = await runClaudeTriage(request('FAKE_CLAUDE_MODE=budget'));
    expect(budget.error).toMatch(/^claude error_max_budget_usd \(exit 1\)/);
    expect(budget.costUsd).toBe(0.0125);
  });

  it('times out without retrying', async () => {
    const r = await runClaudeTriage(request('FAKE_CLAUDE_MODE=hang', { timeoutMs: 400 }));
    expect(r.status).toBe('timeout');
    expect(r.attempts).toBe(1);
    expect(r.error).toMatch(/^timed out after \d+ ms$/);
  });

  it('stops when the job is cancelled', async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 300);
    const r = await runClaudeTriage(request('FAKE_CLAUDE_MODE=hang', { signal: controller.signal }));
    expect(r.status).toBe('cancelled');
    expect(r.attempts).toBe(1);

    const pre = await runClaudeTriage(request('FAKE_CLAUDE_MODE=ok', { signal: AbortSignal.abort() }));
    expect(pre).toMatchObject({ status: 'cancelled', attempts: 0 });
  });
  it('fails clearly when the binary does not exist', async () => {
    const r = await runClaudeTriage(request('', { bin: path.join(tmp, 'no-such-claude') }));
    expect(r.status).toBe('failed');
    expect(r.attempts).toBe(1);
    expect(r.error).toMatch(/^could not start .*no-such-claude: .*ENOENT/);
  });

  it('reads the CLI version', async () => {
    await expect(getClaudeVersion(FAKE)).resolves.toBe('0.0.0-fake (Claude Code)');
    await expect(getClaudeVersion(path.join(tmp, 'nope'))).rejects.toThrow(/ENOENT/);
  });
});

describe('parseAttempt', () => {
  const run = (stdout: string, extra: Partial<RunResult> = {}): RunResult => ({
    code: 0,
    signal: null,
    stdout,
    stderr: '',
    timedOut: false,
    aborted: false,
    durationMs: 42,
    ...extra,
  });

  it('finds the result object after stray stdout lines, but not in arbitrary JSON lines', () => {
    expect(parseCliStdout('notice\n{"type":"result","is_error":false}\n')).toEqual({ type: 'result', is_error: false });
    expect(parseCliStdout('{"type":"result","n":1}')).toEqual({ type: 'result', n: 1 });
    expect(parseCliStdout('notice\n{"other":1}\n')).toBeNull();
    expect(parseCliStdout('')).toBeNull();
    expect(parseCliStdout('[1,2]')).toBeNull();
  });

  it('treats a non-zero exit as a failure even when stdout looks successful', () => {
    const p = parseAttempt(run('{"type":"result","is_error":false,"structured_output":{}}', { code: 1 }), 'opus');
    expect(p.status).toBe('failed');
    expect(p.retryable).toBe(true);
  });

  it('falls back to the result text when structured_output is absent', () => {
    const output = {
      verdict: 'not_affected',
      confidence: 'high',
      runtime_usage: 'not_used',
      vulnerable_code_used: 'no',
      attacker_reachable: 'no',
      deployment_conditions_met: 'unknown',
      summary: 's',
      evidence: [],
      exploit_conditions: 'e',
      remediation: 'r',
      workaround: null,
      suggested_action: 'log',
      suggested_action_reason: 'x',
    };
    const p = parseAttempt(run(JSON.stringify({ is_error: false, result: JSON.stringify(output) })), 'opus');
    expect(p.status).toBe('ok');
    expect(p.metrics.durationMs).toBe(42);
  });

  it('resolves the model from modelUsage, preferring the requested alias', () => {
    expect(resolveModel({ modelUsage: { 'claude-haiku-5-5': {}, 'claude-opus-5-5': {} } }, 'opus')).toBe('claude-opus-5-5');
    expect(resolveModel({ modelUsage: { 'claude-x-1': {} } }, 'claude-x-1')).toBe('claude-x-1');
    expect(resolveModel({ modelUsage: { 'claude-x-1': {} } }, 'sonnet')).toBe('claude-x-1');
    expect(resolveModel({}, 'opus')).toBeNull();
  });
});

function realpath(p: string): string {
  // macOS tmp dirs live behind the /var → /private/var symlink; process.cwd() reports the real path.
  return realpathSync(p);
}
