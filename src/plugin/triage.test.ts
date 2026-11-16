import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ClaudeTriageRequest, ClaudeTriageResult } from '../lib/triage/claude';
import { MAX_CONSECUTIVE_CLI_FAILURES } from '../lib/triage/concurrency';
import { promptFingerprint } from '../lib/triage/input-hash';
import { triageProfileHash } from '../lib/triage/profile';
import { loadTriagePrompt, renderUserPrompt } from '../lib/triage/prompt';
import { buildPromptInputs } from '../lib/triage/runner';
import type { ProjectProfile } from '../lib/types';
import { makeAdvisory, makeFinding, makeOutput, makeScan, makeVerdict, PROFILE, TRIAGE_CONFIG } from './report-fixtures';
import {
  accountProblem,
  compareCandidates,
  formatWallTime,
  promptInputsFor,
  runTriage,
  selectFindings,
  StaleScanError,
  type RunTriageOptions,
} from './triage';
import type { ScanFinding, ScanResult } from './types';
import { loadFailures, loadVerdicts, VerdictStore } from './verdicts';

const ROOT = path.join(import.meta.dirname, '../..');
const FAKE = path.join(ROOT, 'test/fake-claude/claude.mjs');
const tmp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'vigiles-plugin-triage-')));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
let n = 0;
const fresh = (name: string) => path.join(tmp, `${++n}-${name}`);

const profile: ProjectProfile = { ...PROFILE, repo_path: '/repos/demo-web' };
const fingerprint = promptFingerprint('v3', ROOT);

function okResult(
  o: Partial<ClaudeTriageResult> = {},
  output = makeOutput({ verdict: 'affected', suggested_action: 'ping' }),
): ClaudeTriageResult {
  return {
    status: 'ok',
    output,
    raw: {},
    modelResolved: 'claude-opus-5-5',
    costUsd: 0.1,
    inputTokens: 1,
    outputTokens: 1,
    cacheReadTokens: 0,
    numTurns: 3,
    durationMs: 2000,
    attempts: 1,
    error: null,
    retriedErrors: [],
    permissionDenials: 0,
    ...o,
  };
}

function failResult(error: string, status: ClaudeTriageResult['status'] = 'failed'): ClaudeTriageResult {
  return okResult({ status, output: null, error, costUsd: 0.05 });
}

// ---------- fixtures ----------

const fA = makeFinding({ osvId: 'GHSA-aaaa', packageName: 'axios', priority: 'P2', epss: 0.2, cvssScore: 7.5 });
const fB = makeFinding({ osvId: 'GHSA-bbbb', packageName: 'braces', priority: 'P1', epss: null, cvssScore: 9.8 });
const fC = makeFinding({ osvId: 'GHSA-cccc', packageName: 'cookie', priority: 'P1', epss: 0.6, cves: ['CVE-2026-0003'] });
const fD = makeFinding({ osvId: 'GHSA-dddd', packageName: 'debug', priority: 'P3' });
const fMal = makeFinding({ osvId: 'MAL-2026-1', packageName: 'evil-pkg', priority: 'P0', malicious: true });
const fCur = makeFinding({ osvId: 'GHSA-eeee', packageName: 'express', priority: 'P0', inKev: true });
const all = [fA, fB, fC, fD, fMal, fCur];
const advisories = all.map((f) => makeAdvisory({ osvId: f.osvId, malicious: f.malicious, cves: f.cves, aliases: f.cves }));

function scanFor(findings: ScanFinding[] = all, o: Partial<ScanResult> = {}): ScanResult {
  return makeScan(findings, advisories, {
    triageConfig: { ...TRIAGE_CONFIG, codeAccess: false, promptFingerprint: fingerprint },
    profileHash: triageProfileHash(profile),
    ...o,
  });
}

function storeWithCurrent(): VerdictStore {
  return new VerdictStore([makeVerdict(fCur), makeVerdict(fA, {}, { inputHash: 'stale' })]);
}

function options(o: Partial<RunTriageOptions> & Pick<RunTriageOptions, 'runClaude'>): RunTriageOptions & { lines: string[] } {
  const lines: string[] = [];
  return {
    scan: scanFor(),
    profile,
    assetRoot: ROOT,
    verdicts: storeWithCurrent(),
    verdictsFile: fresh('verdicts.json'),
    failures: {},
    failuresFile: fresh('failures.json'),
    scratchDir: path.join(tmp, 'scratch'),
    concurrency: 1,
    log: (l) => lines.push(l),
    now: () => new Date('2026-11-12T10:00:00.000Z'),
    lines,
    ...o,
  };
}

// ---------- tests ----------

describe('promptInputsFor', () => {
  it('builds exactly what the POC runner builds for the same finding, advisory and profile', () => {
    const finding = makeFinding({
      osvId: 'GHSA-xxxx-yyyy-zzzz',
      packageName: 'next',
      installedVersions: ['15.1.0', '14.2.3'],
      fixedVersions: ['stale-from-scanner'],
      direct: true,
      devOnly: false,
      paths: [['next'], ['@sentry/nextjs', 'next']],
      importSites: [{ file: 'src/app/page.tsx', line: 3, specifier: 'next/image', via: 'next' }],
      importSiteCount: 7,
      inKev: true,
      kevDateAdded: '2025-03-21',
      kevRansomware: 'Known',
      epss: 0.93,
      epssPercentile: 0.998,
      cvssScore: null,
      cves: ['CVE-2025-29927'],
    });
    const advisory = makeAdvisory({
      osvId: finding.osvId,
      aliases: ['CVE-2025-29927'],
      cves: ['CVE-2025-29927'],
      summary: 'Authorization bypass in Next.js middleware',
      details: 'Long details <advisory>with a tag</advisory>.',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      cvssScore: 9.1,
      severityLabel: 'CRITICAL',
      cwes: ['CWE-285'],
      references: ['https://example.com/a'],
      raw: {
        id: finding.osvId,
        affected: [
          {
            package: { name: 'next', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '15.0.0' }, { fixed: '15.2.3' }] }],
          },
          { package: { name: 'other', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9' }] }] },
        ],
      },
    });
    const code = { access: true, workdir: '/snap', commitSha: 'abc', ref: 'main', commitDate: '2026-11-10' } as const;
    const ctx = { project: { profile }, scan: null, advisory: { ...advisory }, kevRansomware: 'Known' };

    const mine = promptInputsFor(finding, advisory, profile, code);
    const poc = buildPromptInputs({ ...finding } as never, ctx as never, code);
    expect(mine).toEqual(poc);
    expect(mine.advisory.fixedVersions).toEqual(['15.2.3']);
    expect(mine.signals.cvssScore).toBe(9.1);

    const template = loadTriagePrompt(ROOT, 'v3').userTemplate;
    expect(renderUserPrompt(template, mine)).toBe(renderUserPrompt(template, poc));

    // Not in KEV: no ransomware note, in both.
    const notKev = { ...finding, inKev: false };
    expect(promptInputsFor(notKev, advisory, profile, code)).toEqual(buildPromptInputs(notKev as never, ctx as never, code));
    expect(promptInputsFor(notKev, advisory, profile, code).signals.kevRansomware).toBeNull();
  });
});

describe('selectFindings', () => {
  it('skips malicious findings and current verdicts and orders like the POC (priority, EPSS, CVSS, id)', () => {
    const s = selectFindings(scanFor(), storeWithCurrent());
    expect(s.eligible.map((f) => f.packageName)).toEqual(['cookie', 'braces', 'axios', 'debug']);
    expect(s.alreadyCurrent).toBe(1);
    expect(s.malicious).toBe(1);
  });

  it('force re-triages current verdicts but never malicious packages', () => {
    const s = selectFindings(scanFor(), storeWithCurrent(), { force: true });
    expect(s.eligible.map((f) => f.packageName)).toEqual(['express', 'cookie', 'braces', 'axios', 'debug']);
  });

  it('only matches OSV ids, CVE aliases and finding ids case-insensitively and reports what matched nothing', () => {
    const s = selectFindings(scanFor(), storeWithCurrent(), { only: ['cve-2026-0003', 'ghsa-dddd', fB.id, 'GHSA-eeee', 'CVE-1999-0001'] });
    expect(s.eligible.map((f) => f.packageName)).toEqual(['cookie', 'braces', 'debug']);
    expect(s.alreadyCurrent).toBe(1);
    expect(s.unmatched).toEqual(['CVE-1999-0001']);
  });

  it('compareCandidates breaks ties by id', () => {
    const x = makeFinding({ osvId: 'GHSA-1', packageName: 'b', priority: 'P2' });
    const y = makeFinding({ osvId: 'GHSA-1', packageName: 'a', priority: 'P2' });
    expect([x, y].sort(compareCandidates).map((f) => f.packageName)).toEqual(['a', 'b']);
  });
});

describe('runTriage', () => {
  it('runs the candidates in order with the scan config and saves each verdict as soon as it arrives', async () => {
    const requests: ClaudeTriageRequest[] = [];
    const seenOnDisk: number[] = [];
    const o = options({
      limit: 3,
      failures: { [fB.id]: { inputHash: fB.inputHash, error: 'old failure', at: 'x' } },
      runClaude: async (req) => {
        requests.push(req);
        // What is on disk when this run starts: the verdicts of the earlier runs (plus none from the start).
        seenOnDisk.push(existsSync(o.verdictsFile) ? loadVerdicts(o.verdictsFile).store.size : 0);
        if (req.userPrompt.includes('braces')) return okResult();
        if (req.userPrompt.includes('axios')) return failResult('claude error_max_turns: too many turns');
        return okResult({}, makeOutput({ verdict: 'not_affected', suggested_action: 'log' }));
      },
    });
    const summary = await runTriage(o);

    expect(requests).toHaveLength(3);
    expect(seenOnDisk).toEqual([0, 3, 4]);
    const r = requests[0]!;
    expect(r).toMatchObject({
      model: 'opus',
      effort: 'high',
      codeAccess: false,
      maxBudgetUsd: 3,
      timeoutMs: 600_000,
      maxAttempts: 2,
      scratchDir: o.scratchDir,
      snapshotDir: undefined,
    });
    expect(r.systemPrompt).toBe(loadTriagePrompt(ROOT, 'v3').system);
    expect(r.userPrompt).toContain('cookie');

    const { store } = loadVerdicts(o.verdictsFile);
    const saved = store.get(fC)!;
    expect(saved).toMatchObject({
      inputHash: fC.inputHash,
      config: 'v3-opus-high-code',
      prompt: fingerprint,
      model: 'claude-opus-5-5',
      triagedAt: '2026-11-12T10:00:00.000Z',
      ref: 'main',
      costUsd: 0.1,
      durationMs: 2000,
    });
    expect(store.current(fB)?.output.verdict).toBe('affected');

    const failures = loadFailures(o.failuresFile);
    expect(Object.keys(failures)).toEqual([fA.id]);
    expect(failures[fA.id]).toEqual({
      inputHash: fA.inputHash,
      error: 'claude error_max_turns: too many turns',
      at: '2026-11-12T10:00:00.000Z',
    });

    expect(summary).toMatchObject({
      eligible: 4,
      selected: 3,
      ok: 2,
      failed: 1,
      cancelled: 0,
      remaining: 1,
      alreadyCurrent: 1,
      malicious: 1,
    });
    expect(summary.costUsd).toBeCloseTo(0.25);
    expect(o.lines[0]).toBe('Triaging 3 findings with v3-opus-high-code (concurrency 1); 1 already have a current verdict');
    expect(o.lines[1]).toMatch(/^\[1\/3\] ok cookie@1\.0\.0 GHSA-cccc → suggests Logged \(not_affected, \d+s\)$/);
    expect(o.lines[2]).toMatch(/^\[2\/3\] ok braces@1\.0\.0 GHSA-bbbb → suggests Fix now \(affected, \d+s\)$/);
    expect(o.lines[3]).toMatch(/^\[3\/3\] failed axios@1\.0\.0 GHSA-aaaa: claude error_max_turns: too many turns \(\d+s\)$/);
    expect(o.lines[4]).toMatch(/^Triage done: 2 ok, 1 failed in \d+s · \$0\.25 at API list price$/);
    expect(o.lines[5]).toBe('1 finding still needs triage; run triage again to continue.');
  });

  it('stops starting new runs when claude is not logged in', async () => {
    let calls = 0;
    const o = options({
      concurrency: 1,
      runClaude: async () => {
        calls++;
        return failResult('claude error_during_execution: Invalid API key · Please run /login');
      },
    });
    const summary = await runTriage(o);
    expect(calls).toBe(1);
    expect(summary.stopReason).toMatch(/not logged in.*\/login/);
    expect(summary).toMatchObject({ failed: 1, remaining: 3 });
    expect(o.lines.some((l) => l.startsWith('Stopped early. Claude Code is not logged in'))).toBe(true);
  });

  // The exact message the CLI printed when the POC hit the subscription limit (triage_runs 731-735).
  const FIVE_HOUR_LIMIT = "claude success (exit 1): You've hit your 5-hour limit · resets 9:40pm (Europe/Zagreb)";

  it('stops at the first run that hits a usage limit, with the CLI wording', async () => {
    let calls = 0;
    const o = options({
      runClaude: async () => {
        calls++;
        return failResult(FIVE_HOUR_LIMIT);
      },
    });
    const summary = await runTriage(o);
    expect(calls).toBe(1);
    expect(summary.stopReason).toMatch(/^Claude Code hit a usage or rate limit: .*5-hour limit.*Wait for the limit to reset/);
    expect(summary).toMatchObject({ failed: 1, remaining: 3 });
  });

  it(`stops after ${MAX_CONSECUTIVE_CLI_FAILURES} CLI failures in a row (an outage), like the POC triage job`, async () => {
    const errors = [
      'claude error_during_execution (exit 1): API Error: 529 {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}',
      'claude error_during_execution (exit 1): API Error: Connection error.',
      'claude error_during_execution (exit 1): API Error: 529 overloaded_error',
    ];
    let calls = 0;
    const o = options({
      scan: scanFor([fA, fB, fC, fD, makeFinding({ osvId: 'GHSA-ffff', packageName: 'fresh', priority: 'P3' })], {}),
      verdicts: new VerdictStore(),
      runClaude: async () => failResult(errors[calls++ % errors.length]!),
    });
    o.scan.advisories['GHSA-ffff'] = makeAdvisory({ osvId: 'GHSA-ffff' });
    const summary = await runTriage(o);
    expect(calls).toBe(MAX_CONSECUTIVE_CLI_FAILURES);
    expect(summary).toMatchObject({ failed: 3, remaining: 2 });
    expect(summary.stopReason).toMatch(/^Claude failed for 3 findings in a row \(a usage limit or an outage\?\)\. Last error: .*overloaded_error/);
    expect(o.lines.some((l) => l.startsWith('Stopped early. Claude failed for 3 findings in a row'))).toBe(true);
  });

  it('does not count setup failures or runs between successes toward the breaker', async () => {
    // fail, ok, fail, fail, setup failure (attempts 0), ok: never three CLI failures in a row.
    const results = [
      failResult('claude error_during_execution: API Error: 529 overloaded'),
      okResult(),
      failResult('claude error_during_execution: API Error: 529 overloaded'),
      failResult('claude error_during_execution: API Error: 529 overloaded'),
      { ...failResult('setup failed: no snapshot'), attempts: 0 },
      okResult(),
    ];
    const findings = Array.from({ length: 6 }, (_, i) => makeFinding({ osvId: `GHSA-b${i}`, packageName: `p${i}`, priority: 'P2' }));
    const scan = makeScan(
      findings,
      findings.map((f) => makeAdvisory({ osvId: f.osvId })),
      { triageConfig: { ...TRIAGE_CONFIG, codeAccess: false, promptFingerprint: fingerprint }, profileHash: triageProfileHash(profile) },
    );
    let calls = 0;
    const summary = await runTriage(options({ scan, verdicts: new VerdictStore(), runClaude: async () => results[calls++]! }));
    expect(calls).toBe(6);
    expect(summary).toMatchObject({ ok: 2, failed: 4, stopReason: null });
  });

  it('on interrupt, records no failure for the cancelled run and starts no new ones', async () => {
    const controller = new AbortController();
    let calls = 0;
    const o = options({
      signal: controller.signal,
      runClaude: async () => {
        calls++;
        controller.abort();
        return failResult('cancelled', 'cancelled');
      },
    });
    const summary = await runTriage(o);
    expect(calls).toBe(1);
    expect(summary).toMatchObject({ cancelled: 1, failed: 0, interrupted: true, remaining: 4 });
    expect(existsSync(o.failuresFile)).toBe(false);
  });

  it('records a setup failure when the advisory is missing and goes on', async () => {
    const scan = scanFor([fD, fC]);
    delete scan.advisories[fD.osvId];
    const o = options({ scan, runClaude: async () => okResult() });
    const summary = await runTriage(o);
    expect(summary).toMatchObject({ ok: 1, failed: 1 });
    expect(loadFailures(o.failuresFile)[fD.id]?.error).toBe('setup failed: advisory GHSA-dddd is missing from the scan');
  });

  it('refuses to run when the prompt or the profile changed after the scan', async () => {
    const runClaude = async () => okResult();
    await expect(runTriage(options({ runClaude, profile: { ...profile, notes: 'edited' } }))).rejects.toThrow(StaleScanError);
    const stalePrompt = scanFor(all, { triageConfig: { ...TRIAGE_CONFIG, promptFingerprint: 'v3@00000000' } });
    await expect(runTriage(options({ runClaude, scan: stalePrompt }))).rejects.toThrow(/prompt changed since the last scan/);
  });

  it('does nothing (and prepares nothing) when every finding is current', async () => {
    const store = new VerdictStore([fA, fB, fC, fD, fCur].map((f) => makeVerdict(f)));
    const summary = await runTriage(options({ verdicts: store, runClaude: async () => okResult() }));
    expect(summary).toMatchObject({ eligible: 0, selected: 0, remaining: 0, alreadyCurrent: 5 });
  });
});

describe('runTriage with the fake claude CLI and a real code snapshot', () => {
  const repo = path.join(tmp, 'repo');
  const gitEnv = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 't',
    GIT_AUTHOR_EMAIL: 't@example.com',
    GIT_COMMITTER_NAME: 't',
    GIT_COMMITTER_EMAIL: 't@example.com',
  };
  const git = (args: string[]) => execFileSync('git', ['-C', repo, ...args], { env: gitEnv, encoding: 'utf8' }).trim();
  let sha = '';

  beforeAll(() => {
    mkdirSync(path.join(repo, 'src'), { recursive: true });
    git(['init', '-q', '-b', 'main']);
    writeFileSync(path.join(repo, 'src/index.ts'), "import next from 'next';\n");
    writeFileSync(path.join(repo, '.env'), 'SECRET=1\n');
    git(['add', 'src/index.ts']);
    git(['commit', '-q', '-m', 'init']);
    sha = git(['rev-parse', 'HEAD']);
  });

  it('runs claude in the snapshot with code tools and stores the verdict', async () => {
    const record = path.join(tmp, 'record.jsonl');
    const finding = makeFinding({ osvId: 'GHSA-fake', packageName: 'next', priority: 'P1' });
    const advisory = makeAdvisory({ osvId: finding.osvId, details: `FAKE_CLAUDE_MODE=ok FAKE_CLAUDE_RECORD=${record}` });
    const snapshotDir = path.join(tmp, 'snapshots', 'demo-web-12345678', sha);
    const scan = makeScan([finding], [advisory], {
      repoRoot: repo,
      commit: sha,
      snapshotDir,
      triageConfig: { ...TRIAGE_CONFIG, promptFingerprint: fingerprint },
      profileHash: triageProfileHash(profile),
    });
    const o = options({ scan, claudeBin: FAKE, runClaude: undefined });
    const summary = await runTriage(o);
    expect(summary).toMatchObject({ ok: 1, failed: 0 });

    const call = JSON.parse(readFileSync(record, 'utf8').trim()) as { argv: string[]; cwd: string; cwdEntries: string[]; stdin: string };
    expect(realpathSync(call.cwd)).toBe(realpathSync(snapshotDir));
    expect(call.cwdEntries).toContain('src');
    expect(call.cwdEntries).not.toContain('.env');
    expect(call.argv.join(' ')).toContain('--tools Read,Grep,Glob');
    expect(call.argv.join(' ')).toContain('--model opus --effort high');
    expect(call.stdin).toContain(`at commit ${sha} (ref main, committed 2026-11-10T16:20:00+01:00)`);

    const v = loadVerdicts(o.verdictsFile).store.current(finding)!;
    expect(v.model).toBe('claude-opus-fake-1');
    expect(v.commit).toBe(sha);
    expect(v.output.verdict).toBe('likely_affected');
  });
});

describe('helpers', () => {
  it('accountProblem only flags failures no other finding could get past', () => {
    expect(accountProblem({ status: 'failed', error: 'could not start claude: spawn claude ENOENT' }, 'claude')).toMatch(
      /installed and on PATH/,
    );
    expect(accountProblem({ status: 'failed', error: "claude error_during_execution: You've hit your usage limit" }, 'claude')).toMatch(
      /usage or rate limit/,
    );
    expect(accountProblem({ status: 'failed', error: 'claude error_during_execution: API Error: overloaded' }, 'claude')).toBeNull();
    // The CLI's real wording (stored in the POC's triage_runs), and other limit messages.
    for (const error of [
      "claude success (exit 1): You've hit your 5-hour limit · resets 9:40pm (Europe/Zagreb)",
      'claude success (exit 1): You’ve hit your weekly limit · resets Nov 14, 9am',
      'claude success: Claude AI usage limit reached|1762790400',
      'claude success: 5-hour limit reached ∙ resets 3pm',
    ]) {
      expect(accountProblem({ status: 'failed', error }, 'claude'), error).toMatch(/usage or rate limit/);
    }
    // Outages are not account problems (the consecutive-failure breaker handles them).
    expect(accountProblem({ status: 'failed', error: 'claude error_during_execution (exit 1): API Error: Connection error.' }, 'claude')).toBeNull();
    // The model's answer (a result that is not is_error) is not the CLI's message, whatever it talks about.
    const answer = { type: 'result', subtype: 'success', is_error: false, result: 'The rate limit is exceeded only on /login' };
    expect(accountProblem({ status: 'failed', error: `claude success (exit 1): ${answer.result}`, raw: answer }, 'claude')).toBeNull();
    const limit = { type: 'result', subtype: 'success', is_error: true, result: "You've hit your 5-hour limit · resets 9:40pm" };
    expect(accountProblem({ status: 'failed', error: `claude success (exit 1): ${limit.result}`, raw: limit }, 'claude')).toMatch(/usage/);
    expect(accountProblem({ status: 'invalid', error: 'invalid structured output: 401' }, 'claude')).toBeNull();
  });

  it('formatWallTime', () => {
    expect(formatWallTime(4_400)).toBe('4s');
    expect(formatWallTime(125_000)).toBe('2m 05s');
  });
});
