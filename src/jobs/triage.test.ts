import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { DataPaths } from '../lib/config/load';
import { VigilesConfigSchema } from '../lib/config/schema';
import { openDb, type Db } from '../lib/db/client';
import { jobRuns, triageRuns } from '../lib/db/schema';
import { CancelledError, type JobContext } from '../lib/jobs/types';
import { findingInputHash } from '../lib/triage/state';
import { seedConfig, seedFinding, seedLabel, seedProject } from '../lib/triage/test-support';
import { MAX_CONSECUTIVE_CLI_FAILURES, run } from './triage';

const ROOT = path.join(import.meta.dirname, '../..');
const FAKE = path.join(ROOT, 'test/fake-claude/claude.mjs');

let tmp: string;
let repo: string;
let sha: string;
beforeAll(() => {
  tmp = mkdtempSync(path.join(os.tmpdir(), 'vigiles-triage-job-'));
  repo = path.join(tmp, 'repo');
  mkdirSync(path.join(repo, 'src/app/api/x'), { recursive: true });
  mkdirSync(path.join(repo, '.claude'));
  writeFileSync(path.join(repo, 'src/app/api/x/route.ts'), "import { z } from 'zod';\n");
  writeFileSync(path.join(repo, '.env'), 'SECRET=1\n');
  writeFileSync(path.join(repo, '.claude/settings.json'), '{}');
  const git = (...args: string[]) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
  git('init', '-q');
  git('add', '-A');
  git('-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-qm', 'init');
  sha = git('rev-parse', 'HEAD');
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let db: Db;
let scanId: number;
let dataDir: string;
beforeEach(() => {
  db = openDb(':memory:');
  ({ scanId } = seedProject(db, { repoPath: repo, commitSha: sha }));
  seedConfig(db, 'cfg-code', { codeAccess: true });
  seedConfig(db, 'cfg-nocode', { codeAccess: false, model: 'haiku' });
  dataDir = mkdtempSync(path.join(tmp, 'data-'));
});

function makeCtx(params: Record<string, unknown>, controller = new AbortController(), triage: Record<string, unknown> = {}) {
  const logs: string[] = [];
  const progress: string[] = [];
  const paths: DataPaths = {
    root: dataDir,
    db: ':memory:',
    osvDb: path.join(dataDir, 'osv-db'),
    snapshots: path.join(dataDir, 'snapshots'),
    logs: path.join(dataDir, 'logs'),
    scratch: path.join(dataDir, 'scratch'),
  };
  const config = VigilesConfigSchema.parse({
    bin: { claude: FAKE, git: 'git' },
    triage: {
      active_config: 'cfg-code',
      max_per_run: 25,
      concurrency: 2,
      timeout_minutes: 0.5,
      ...triage,
      configs: [
        { name: 'cfg-code', prompt_version: 'v1', model: 'sonnet', effort: 'high', code_access: true },
        { name: 'cfg-nocode', prompt_version: 'v1', model: 'haiku', effort: 'high', code_access: false },
      ],
    },
  });
  const ctx: JobContext = {
    db,
    jobId: 77,
    type: 'triage',
    params,
    config,
    paths,
    root: ROOT,
    signal: controller.signal,
    log: (m) => logs.push(m),
    progress: (p) => progress.push(p),
    throwIfCancelled: () => {
      if (controller.signal.aborted) throw new CancelledError();
    },
    runChild: async () => ({}),
  };
  return { ctx, logs, progress, controller };
}

const runsOf = (findingId: number) => db.select().from(triageRuns).where(eq(triageRuns.findingId, findingId)).all();
const recorded = (file: string) =>
  readFileSync(file, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as { argv: string[]; cwd: string; cwdEntries: string[]; stdin: string });

describe('triage job', () => {
  it('triages pending findings in the code snapshot and stores every run', async () => {
    const record = path.join(dataDir, 'record.jsonl');
    const a = seedFinding(db, { scanId, priority: 'P1', details: `FAKE_CLAUDE_RECORD=${record}` });
    const b = seedFinding(db, { scanId, priority: 'P2', details: `FAKE_CLAUDE_RECORD=${record} FAKE_CLAUDE_VERDICT=not_affected` });
    const { ctx, logs, progress } = makeCtx({ tag: 'smoke' });

    const stats = await run(ctx);
    expect(stats).toEqual({
      config: 'cfg-code',
      selected: 2,
      ok: 2,
      failed: 0,
      invalid: 0,
      timeout: 0,
      cancelled: 0,
      costUsd: 0.025,
      remaining: 0,
    });
    expect(progress[0]).toBe('triage 0/2');
    expect(progress.at(-1)).toBe('triage 2/2');
    expect(logs.some((l) => l.includes('claude 0.0.0-fake (Claude Code)'))).toBe(true);
    expect(logs.some((l) => l.startsWith(`#${b.id} ${b.osvId} zod (P2): ok not_affected/medium → digest · $0.0125`))).toBe(true);

    const [runA] = runsOf(a.id);
    expect(runA).toMatchObject({
      configName: 'cfg-code',
      jobRunId: 77,
      inputHash: findingInputHash(db, a, seedlessConfig('cfg-code', true)),
      status: 'ok',
      modelResolved: 'claude-sonnet-fake-1',
      claudeVersion: '0.0.0-fake (Claude Code)',
      costUsd: 0.0125,
      inputTokens: 510,
      outputTokens: 300,
      cacheReadTokens: 2000,
      numTurns: 4,
      durationMs: 1500,
      attempts: 1,
      error: null,
      tag: 'smoke',
    });
    expect(runA!.output?.verdict).toBe('likely_affected');
    expect(runA!.raw?.type).toBe('result');
    expect(runA!.prompt).toContain('<advisory>');
    expect(runA!.prompt).toContain(`commit ${sha}`);

    // claude ran inside the scrubbed snapshot of the scanned commit
    const calls = recorded(record);
    expect(calls).toHaveLength(2);
    const snapshot = path.join(dataDir, 'snapshots', 'demo', sha);
    for (const call of calls) {
      expect(call.cwd.endsWith(snapshot)).toBe(true);
      expect(call.cwdEntries).toContain('src');
      expect(call.cwdEntries).not.toContain('.env');
      expect(call.cwdEntries).not.toContain('.claude');
      expect(call.argv[call.argv.indexOf('--tools') + 1]).toBe('Read,Grep,Glob');
    }

    // Nothing changed, so a second run has nothing to do.
    const again = await run(makeCtx({}).ctx);
    expect(again).toMatchObject({ selected: 0, ok: 0, remaining: 0 });
  });

  it('caps automatic retries of failing findings at two stored runs', async () => {
    const f = seedFinding(db, { scanId, details: 'FAKE_CLAUDE_MODE=budget' });
    const first = await run(makeCtx({}).ctx);
    expect(first).toMatchObject({ selected: 1, failed: 1, ok: 0 });
    expect(runsOf(f.id)[0]).toMatchObject({ status: 'failed', attempts: 1, error: 'claude error_max_budget_usd (exit 1)' });

    expect(await run(makeCtx({}).ctx)).toMatchObject({ selected: 1, failed: 1 });
    expect(await run(makeCtx({}).ctx)).toMatchObject({ selected: 0 });
    expect(await run(makeCtx({ force: true }).ctx)).toMatchObject({ selected: 1 });
    expect(runsOf(f.id)).toHaveLength(3);
  });

  it('keeps retrying a finding whose runs failed for infrastructure reasons (no JSON, API errors)', async () => {
    const crash = seedFinding(db, { scanId, priority: 'P0', details: 'FAKE_CLAUDE_MODE=exit' });
    const overloaded = seedFinding(db, { scanId, priority: 'P0', details: 'FAKE_CLAUDE_MODE=is_error' });
    for (let i = 0; i < 3; i++) expect(await run(makeCtx({}).ctx)).toMatchObject({ selected: 2, failed: 2 });
    expect(runsOf(crash.id)).toHaveLength(3);
    expect(runsOf(overloaded.id)[0]!.error).toMatch(/API Error: overloaded/);
    expect(runsOf(overloaded.id)).toHaveLength(3);
  });

  it('runs no-code configs without tools in an empty scratch directory', async () => {
    const record = path.join(dataDir, 'record-nocode.jsonl');
    const f = seedFinding(db, { scanId, details: `FAKE_CLAUDE_RECORD=${record}` });
    const stats = await run(makeCtx({ config: 'cfg-nocode', findings: [f.id] }).ctx);
    expect(stats).toMatchObject({ config: 'cfg-nocode', selected: 1, ok: 1 });
    const [call] = recorded(record);
    expect(call!.cwdEntries).toEqual([]);
    expect(call!.cwd).toContain(path.join(path.basename(dataDir), 'scratch', 'triage-nocode-'));
    expect(call!.argv[call!.argv.indexOf('--tools') + 1]).toBe('');
    expect(call!.stdin).toContain('No code is available for this triage.');
    expect(runsOf(f.id)[0]).toMatchObject({ configName: 'cfg-nocode', modelResolved: 'claude-haiku-fake-1' });
  });

  it('applies limit, explicit findings and project filters', async () => {
    const ids = Array.from({ length: 3 }, () => seedFinding(db, { scanId }).id);
    expect(await run(makeCtx({ limit: 2 }).ctx)).toMatchObject({ selected: 2, remaining: 1 });
    expect(await run(makeCtx({ findings: [ids[2]!] }).ctx)).toMatchObject({ selected: 1, remaining: 0 });
    expect(await run(makeCtx({ project: 'demo' }).ctx)).toMatchObject({ selected: 0 });
    await expect(run(makeCtx({ project: 'nope' }).ctx)).rejects.toThrow(/unknown project "nope"/);
  });

  it('fails, before running claude, when explicitly requested findings cannot be triaged', async () => {
    const done = seedFinding(db, { scanId });
    const fixed = seedFinding(db, { scanId, status: 'fixed' });
    const pending = seedFinding(db, { scanId });
    await run(makeCtx({ findings: [done.id] }).ctx);
    const { ctx, logs } = makeCtx({ findings: [done.id, fixed.id, pending.id, 4242] });

    await expect(run(ctx)).rejects.toThrow(
      new RegExp(
        `^3 of 4 requested finding\\(s\\) cannot be triaged under cfg-code, so nothing was run\\. #${done.id}: it already has an ok run`,
      ),
    );
    expect(logs).toEqual([
      expect.stringMatching(new RegExp(`^#${done.id} cannot be triaged under cfg-code: it already has an ok run`)),
      `#${fixed.id} cannot be triaged under cfg-code: the finding is fixed, not open`,
      '#4242 cannot be triaged under cfg-code: no such finding',
    ]);
    expect(runsOf(pending.id)).toHaveLength(0);
    expect(runsOf(done.id)).toHaveLength(1);
  });

  it('triages a disabled project only when it is named explicitly', async () => {
    const off = seedProject(db, { id: 'off', enabled: false, repoPath: repo, commitSha: sha });
    const f = seedFinding(db, { scanId: off.scanId, projectId: 'off' });
    expect(await run(makeCtx({}).ctx)).toMatchObject({ selected: 0 });
    expect(await run(makeCtx({ project: 'off' }).ctx)).toMatchObject({ selected: 1, ok: 1 });
    expect(await run(makeCtx({ findings: [f.id], force: true }).ctx)).toMatchObject({ selected: 1, ok: 1 });
  });

  it('refuses to start while another live process runs a triage job', async () => {
    const f = seedFinding(db, { scanId });
    // The parent of this test process stands in for another live process (the worker, or a CLI).
    const other = db.insert(jobRuns).values({ type: 'triage', status: 'running', pid: process.ppid, parentId: 5 }).returning().get();
    await expect(run(makeCtx({}).ctx)).rejects.toThrow(
      new RegExp(`^another triage job is running: triage#${other.id} \\(pid ${process.ppid}`),
    );
    expect(runsOf(f.id)).toHaveLength(0);

    // A row left running by a process that is gone does not block.
    const gone = execFileSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
    db.update(jobRuns)
      .set({ pid: Number(gone) })
      .where(eq(jobRuns.id, other.id))
      .run();
    expect(await run(makeCtx({}).ctx)).toMatchObject({ selected: 1, ok: 1 });
  });

  it('of two triage jobs that start together, only the later one gives way; a stale row with our own pid never blocks', async () => {
    const f = seedFinding(db, { scanId, priority: 'P1' });
    const insertRunning = (startedAt: string, pid: number) =>
      db.insert(jobRuns).values({ type: 'triage', status: 'running', pid, startedAt }).returning({ id: jobRuns.id }).get().id;
    const t = '2026-11-10T10:00:00.000Z';
    const first = insertRunning(t, process.ppid);
    const second = insertRunning(t, process.ppid); // same instant: the id breaks the tie
    const ctxOf = (jobId: number) => ({ ...makeCtx({}).ctx, jobId });

    // `second` sees `first` (earlier by id) and gives way; `first` ignores `second` (which will give way) and runs.
    await expect(run(ctxOf(second))).rejects.toThrow(new RegExp(`another triage job is running: triage#${first}`));
    expect(runsOf(f.id)).toHaveLength(0);
    expect(await run(ctxOf(first))).toMatchObject({ selected: 1, ok: 1 });

    // A later start always gives way to an earlier one, whatever the ids.
    db.update(jobRuns).set({ startedAt: '2026-11-10T09:59:59.999Z' }).where(eq(jobRuns.id, second)).run();
    await expect(run({ ...ctxOf(first), params: { force: true } })).rejects.toThrow(new RegExp(`triage#${second}`));

    // A running row that names this process's pid was left by an earlier process with the same pid.
    db.update(jobRuns).set({ status: 'failed' }).run();
    const stale = insertRunning(t, process.pid);
    const own = insertRunning('2026-11-10T11:00:00.000Z', process.pid);
    expect(stale).toBeLessThan(own);
    expect(await run({ ...ctxOf(own), params: { force: true } })).toMatchObject({ selected: 1, ok: 1 });
  });

  it('gives the slot of a setup failure to the next finding in line', async () => {
    const broken = seedProject(db, { id: 'broken', repoPath: path.join(tmp, 'missing-repo'), commitSha: sha });
    const brokenIds = Array.from({ length: 2 }, () => seedFinding(db, { scanId: broken.scanId, projectId: 'broken', priority: 'P0' }).id);
    const healthy = Array.from({ length: 3 }, () => seedFinding(db, { scanId, priority: 'P2' }).id);
    const { ctx, logs } = makeCtx({}, undefined, { max_per_run: 3 });

    const stats = await run(ctx);

    expect(stats).toMatchObject({ selected: 5, failed: 2, ok: 3, remaining: 0 });
    expect(logs).toContain('2 setup failure(s) did not run claude; taking 2 more finding(s) from the backlog');
    expect([...brokenIds, ...healthy].map((id) => runsOf(id).length)).toEqual([1, 1, 1, 1, 1]);
    // Setup failures use up no retries: the broken findings come first again next time.
    const next = await run(makeCtx({}, undefined, { max_per_run: 2 }).ctx);
    expect(next).toMatchObject({ selected: 2, failed: 2, ok: 0 });
  });

  it('records a failed run when the snapshot cannot be made', async () => {
    const broken = seedProject(db, { id: 'broken', repoPath: path.join(tmp, 'missing-repo'), commitSha: sha });
    const f = seedFinding(db, { scanId: broken.scanId, projectId: 'broken' });
    const stats = await run(makeCtx({}).ctx);
    expect(stats).toMatchObject({ selected: 1, failed: 1 });
    const [r] = runsOf(f.id);
    expect(r).toMatchObject({ status: 'failed', attempts: 0, prompt: '' });
    expect(r!.error).toMatch(/^setup failed: /);
  });

  it('stops on cancel and stores the interrupted run as cancelled', async () => {
    const f = seedFinding(db, { scanId, details: 'FAKE_CLAUDE_MODE=hang' });
    const { ctx, controller } = makeCtx({});
    setTimeout(() => controller.abort(), 500);
    await expect(run(ctx)).rejects.toBeInstanceOf(CancelledError);
    expect(runsOf(f.id)[0]).toMatchObject({ status: 'cancelled', attempts: 1 });
  });

  it('rejects unknown configs and bad params', async () => {
    await expect(run(makeCtx({ config: 'nope' }).ctx)).rejects.toThrow(/unknown triage config "nope"/);
    await expect(run(makeCtx({ limit: -1 }).ctx)).rejects.toThrow();
  });

  it('rejects unknown params instead of silently running a full batch', async () => {
    const f = seedFinding(db, { scanId });
    await expect(run(makeCtx({ finding: [f.id] }).ctx)).rejects.toThrow(/finding/);
    expect(runsOf(f.id)).toHaveLength(0);
    // The params the CLI, the Jobs page, the Finding page and refresh-all send are all accepted.
    const ok = { config: 'cfg-code', project: 'demo', findings: [f.id], limit: 1, force: true, tag: 't', sample: 1 };
    seedLabel(db, f.id); // a sample is drawn from labeled findings
    await expect(run(makeCtx(ok).ctx)).resolves.toMatchObject({ selected: 1, ok: 1 });
    await expect(run(makeCtx({ findings: String(f.id), force: 'true' }).ctx)).resolves.toMatchObject({ selected: 1, ok: 1 });
  });

  it('does not truncate an explicit sample or finding list to max_per_run', async () => {
    const seeded = Array.from({ length: 3 }, () => seedFinding(db, { scanId }));
    for (const f of seeded) seedLabel(db, f.id);
    const small = { max_per_run: 2 };
    expect(await run(makeCtx({}, undefined, small).ctx)).toMatchObject({ selected: 2, remaining: 1 });
    expect(await run(makeCtx({ sample: 3, force: true }, undefined, small).ctx)).toMatchObject({ selected: 3, remaining: 0 });
    expect(await run(makeCtx({ findings: seeded.map((f) => f.id), force: true }, undefined, small).ctx)).toMatchObject({ selected: 3 });
    expect(await run(makeCtx({ sample: 3, force: true, limit: 1 }, undefined, small).ctx)).toMatchObject({ selected: 1, remaining: 2 });
  });

  it(`stops starting findings after ${MAX_CONSECUTIVE_CLI_FAILURES} consecutive CLI failures (usage limit, outage)`, async () => {
    const ids = Array.from({ length: 6 }, () => seedFinding(db, { scanId, details: 'FAKE_CLAUDE_MODE=is_error' }).id);
    const { ctx, logs } = makeCtx({}, undefined, { concurrency: 1 });
    await expect(run(ctx)).rejects.toThrow(/claude failed for 3 findings in a row, 3 not started.*API Error: overloaded/);
    const stored = ids.map((id) => runsOf(id).length);
    expect(stored).toEqual([1, 1, 1, 0, 0, 0]);
    expect(logs.some((l) => l.startsWith('done: 0 ok, 3 not ok'))).toBe(true);
  });

  it('does not trip the breaker on setup failures, invalid output or isolated CLI failures', async () => {
    const broken = seedProject(db, { id: 'broken', repoPath: path.join(tmp, 'missing-repo'), commitSha: sha });
    for (let i = 0; i < 3; i++) seedFinding(db, { scanId: broken.scanId, projectId: 'broken', priority: 'P0' });
    seedFinding(db, { scanId, priority: 'P1', details: 'FAKE_CLAUDE_MODE=is_error' });
    seedFinding(db, { scanId, priority: 'P1', details: 'FAKE_CLAUDE_MODE=is_error' });
    seedFinding(db, { scanId, priority: 'P2', details: 'FAKE_CLAUDE_MODE=invalid' });
    seedFinding(db, { scanId, priority: 'P2', details: 'FAKE_CLAUDE_MODE=is_error' });
    seedFinding(db, { scanId, priority: 'P2', details: 'FAKE_CLAUDE_MODE=is_error' });
    seedFinding(db, { scanId, priority: 'P3', details: 'FAKE_CLAUDE_MODE=ok' }); // below min priority: not selected
    const stats = await run(makeCtx({}, undefined, { concurrency: 1 }).ctx);
    expect(stats).toMatchObject({ selected: 8, failed: 7, invalid: 1, ok: 0 });
  });
});

/** The triage_configs row shape findingInputHash needs (only the hashed fields matter). */
function seedlessConfig(name: string, codeAccess: boolean) {
  return { name, promptVersion: 'v1', model: 'sonnet', effort: 'high', codeAccess, active: true, createdAt: '' };
}
