#!/usr/bin/env node
/**
 * Fake `claude` CLI for tests. It never calls a model. Its behaviour is driven by directives in
 * the prompt on stdin, because the real runner passes claude a minimal environment (no custom env
 * vars get through):
 *
 *   FAKE_CLAUDE_MODE=<m1>[,<m2>...]  behaviour per attempt (with STATE; otherwise only m1 is used)
 *       ok | noisy | invalid | missing | is_error | budget | exit | garbage | hang
 *   FAKE_CLAUDE_STATE=<file>         attempt counter file, so a retry can behave differently
 *   FAKE_CLAUDE_RECORD=<file>        appends {argv, cwd, cwdEntries, envKeys, stdin} as a JSON line
 *   FAKE_CLAUDE_VERDICT=<verdict>    verdict for ok output (default likely_affected)
 *
 * `claude --version` prints "0.0.0-fake (Claude Code)".
 */
import { appendFileSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';

const argv = process.argv.slice(2);
if (argv[0] === '--version') {
  process.stdout.write('0.0.0-fake (Claude Code)\n');
  process.exit(0);
}

const stdin = readFileSync(0, 'utf8');
const directive = (name) => stdin.match(new RegExp(`FAKE_CLAUDE_${name}=([^\\s<&]+)`))?.[1];
const argOf = (flag) => {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
};

const record = directive('RECORD');
if (record) {
  const line = {
    argv,
    cwd: process.cwd(),
    cwdEntries: readdirSync(process.cwd()),
    envKeys: Object.keys(process.env).sort(),
    stdin,
  };
  appendFileSync(record, `${JSON.stringify(line)}\n`);
}

const state = directive('STATE');
let attempt = 1;
if (state) {
  attempt = existsSync(state) ? Number(readFileSync(state, 'utf8')) + 1 : 1;
  writeFileSync(state, String(attempt));
}
const modes = (directive('MODE') ?? 'ok').split(',');
const mode = modes[Math.min(attempt, modes.length) - 1];

const model = argOf('--model') ?? 'unknown';
const output = {
  verdict: directive('VERDICT') ?? 'likely_affected',
  confidence: 'medium',
  runtime_usage: 'server',
  vulnerable_code_used: 'yes',
  attacker_reachable: 'unknown',
  deployment_conditions_met: 'yes',
  summary: 'Fake triage summary.',
  evidence: [{ file: 'src/app/api/example/route.ts', line: 3, note: 'parses the request body' }],
  exploit_conditions: 'An unauthenticated POST with a crafted body.',
  remediation: 'Upgrade to the fixed version.',
  workaround: null,
  suggested_action: 'digest',
  suggested_action_reason: 'Reachable in principle but not proven.',
};

function result(extra = {}) {
  return {
    type: 'result',
    subtype: 'success',
    is_error: false,
    num_turns: 4,
    duration_ms: 1500,
    total_cost_usd: 0.0125,
    usage: { input_tokens: 10, output_tokens: 300, cache_read_input_tokens: 2000, cache_creation_input_tokens: 500 },
    modelUsage: { [`claude-${model}-fake-1`]: { inputTokens: 10, outputTokens: 300 } },
    structured_output: output,
    result: JSON.stringify(output),
    permission_denials: [],
    session_id: 'fake-session',
    terminal_reason: 'completed',
    ...extra,
  };
}

const print = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);

switch (mode) {
  case 'ok':
    print(result());
    break;
  case 'noisy': // a notice line on stdout before the result object
    process.stdout.write('A new version of Claude Code is available.\n');
    print(result());
    break;
  case 'invalid':
    print(result({ structured_output: { ...output, verdict: 'maybe' }, result: 'not json' }));
    break;
  case 'missing':
    print(result({ structured_output: undefined, result: 'I could not decide.' }));
    break;
  case 'is_error':
    print(result({ subtype: 'error_during_execution', is_error: true, structured_output: undefined, result: 'API Error: overloaded' }));
    break;
  case 'budget':
    print(result({ subtype: 'error_max_budget_usd', is_error: true, structured_output: undefined, result: '' }));
    process.exitCode = 1;
    break;
  case 'exit':
    process.stderr.write('fake claude: something broke\n');
    process.exitCode = 2;
    break;
  case 'garbage':
    process.stdout.write('this is not json\n');
    break;
  case 'hang':
    setInterval(() => {}, 1000);
    break;
  default:
    process.stderr.write(`fake claude: unknown mode ${mode}\n`);
    process.exitCode = 3;
}
