import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, describe, expect, it } from 'vitest';
import type { DataPaths } from '../config/load';
import { VigilesConfigSchema } from '../config/schema';
import { openDb, type Db } from '../db/client';
import { advisories, findings, kev, projects, scans, triageRuns } from '../db/schema';
import { loadTriagePrompt } from './prompt';
import { buildPromptInputs, forEachConcurrent, loadFindingContext, triageFinding, type TriageEnv } from './runner';
import { resolveTriageState } from './state';
import { seedConfig, seedFinding, seedProject } from './test-support';

const ROOT = path.join(import.meta.dirname, '../../..');
const FAKE = path.join(ROOT, 'test/fake-claude/claude.mjs');
const tmp = mkdtempSync(path.join(os.tmpdir(), 'vigiles-runner-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('forEachConcurrent', () => {
  it('never runs more than `concurrency` items at once and runs each item once', async () => {
    let inFlight = 0;
    let peak = 0;
    const seen: number[] = [];
    const started = await forEachConcurrent([1, 2, 3, 4, 5, 6, 7], 3, new AbortController().signal, async (item) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await sleep(5 + (item % 3) * 5);
      seen.push(item);
      inFlight--;
    });
    expect(started).toBe(7);
    expect(peak).toBe(3);
    expect(seen.sort()).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('stops starting new items once the signal aborts, but lets running ones finish', async () => {
    const controller = new AbortController();
    const finished: number[] = [];
    const started = await forEachConcurrent([1, 2, 3, 4, 5], 2, controller.signal, async (item) => {
      if (item === 2) controller.abort();
      await sleep(10);
      finished.push(item);
    });
    expect(started).toBe(2);
    expect(finished.sort()).toEqual([1, 2]);
  });

  it('on an error, waits for in-flight items, starts no new ones and rethrows the first error', async () => {
    const finished: number[] = [];
    const run = forEachConcurrent([1, 2, 3, 4], 2, new AbortController().signal, async (item) => {
      if (item === 1) throw new Error('boom');
      await sleep(30);
      finished.push(item);
    });
    await expect(run).rejects.toThrow('boom');
    // Item 2 was already running when item 1 failed: it finished before the rejection. 3 and 4 never started.
    expect(finished).toEqual([2]);
  });

  it('handles an empty list', async () => {
    await expect(forEachConcurrent([], 2, new AbortController().signal, async () => {})).resolves.toBe(0);
  });
});

describe('buildPromptInputs', () => {
  it('takes ranges and fixed versions for this package from the OSV record and KEV ransomware only when listed', () => {
    const db = openDb(':memory:');
    const { scanId } = seedProject(db);
    const f = seedFinding(db, { scanId, packageName: 'zod', osvId: 'GHSA-kev-1' });
    db.update(findings)
      .set({ fixedVersions: ['stale'] })
      .run();
    const finding = db.select().from(findings).get()!;

    const ctx = loadFindingContext(db, finding);
    expect(ctx.scan?.id).toBe(scanId);
    const code = { access: false } as const;
    const inputs = buildPromptInputs(finding, ctx, code);
    expect(inputs.advisory.affectedRanges).toEqual(['SEMVER: introduced 0, fixed 9.9.9']);
    expect(inputs.advisory.fixedVersions).toEqual(['9.9.9']);
    expect(inputs.dependency.fixedVersions).toEqual(['stale']);
    expect(inputs.signals.kevRansomware).toBeNull();
    expect(inputs.profile.id).toBe('demo');

    db.update(advisories)
      .set({ cves: ['CVE-2026-1'] })
      .where(eq(advisories.osvId, f.osvId))
      .run();
    db.insert(kev).values({ cve: 'CVE-2026-1', ransomware: 'Known' }).run();
    const withKev = loadFindingContext(db, finding);
    expect(withKev.kevRansomware).toBe('Known');
    // The ransomware flag is shown only when the finding itself is marked as in KEV (enrich decides that).
    expect(buildPromptInputs(finding, withKev, code).signals.kevRansomware).toBeNull();
    expect(buildPromptInputs({ ...finding, inKev: true }, withKev, code).signals.kevRansomware).toBe('Known');
  });

  it('passes per-version instances and the uncapped import-site count to the prompt', () => {
    const db = openDb(':memory:');
    const { scanId } = seedProject(db);
    seedFinding(db, { scanId });
    const instances = [{ version: '1.0.0', direct: true, devOnly: false, paths: [['zod']] }];
    db.update(findings).set({ instances, importSiteCount: 57 }).run();
    const finding = db.select().from(findings).get()!;
    const inputs = buildPromptInputs(finding, loadFindingContext(db, finding), { access: false });
    expect(inputs.dependency.instances).toEqual(instances);
    expect(inputs.dependency.importSiteCount).toBe(57);
  });

  it('fails clearly when the advisory row is missing', () => {
    const db = openDb(':memory:');
    const { scanId } = seedProject(db);
    const f = seedFinding(db, { scanId });
    expect(() => loadFindingContext(db, { ...f, osvId: 'GHSA-missing' })).toThrow(/advisory GHSA-missing not found/);
  });
});

describe('triageFinding', () => {
  function env(db: Db, codeAccess: boolean, snapshotDir: string): TriageEnv {
    const dataDir = mkdtempSync(path.join(tmp, 'data-'));
    const paths: DataPaths = {
      root: dataDir,
      db: ':memory:',
      osvDb: path.join(dataDir, 'osv-db'),
      snapshots: path.join(dataDir, 'snapshots'),
      logs: path.join(dataDir, 'logs'),
      scratch: path.join(dataDir, 'scratch'),
    };
    mkdirSync(paths.scratch, { recursive: true });
    const config = VigilesConfigSchema.parse({
      bin: { claude: FAKE, git: 'git' },
      triage: {
        active_config: 'cfg',
        timeout_minutes: 0.5,
        configs: [{ name: 'cfg', prompt_version: 'v1', model: 'sonnet', effort: 'high', code_access: codeAccess }],
      },
    });
    return {
      db,
      config,
      paths,
      triageConfig: seedConfig(db, 'cfg', { codeAccess }),
      prompt: loadTriagePrompt(ROOT, 'v1'),
      claudeVersion: 'fake',
      jobRunId: 5,
      tag: null,
      signal: new AbortController().signal,
      snapshots: async () => snapshotDir,
    };
  }

  it.each([true, false])('stores the scan and commit the prompt was built from (code access %s; review #5/#10/#15)', async (codeAccess) => {
    const db = openDb(':memory:');
    const { scanId } = seedProject(db, { commitSha: 'abc123' });
    const finding = seedFinding(db, { scanId });
    const snapshotDir = mkdtempSync(path.join(tmp, 'snap-'));
    const e = env(db, codeAccess, snapshotDir);
    const snapshotShas: string[] = [];
    e.snapshots = async (_project, _repo, sha) => {
      snapshotShas.push(sha);
      return snapshotDir;
    };
    const state = resolveTriageState(db, finding, e.triageConfig, 'P2');

    // The project already has a newer scan of another commit (that did not refresh this finding):
    // the run must point at the scan its facts and snapshot came from, not the project's latest.
    const newer = db
      .insert(scans)
      .values({ projectId: 'demo', ref: 'origin/main', commitSha: 'def456', status: 'succeeded' })
      .returning({ id: scans.id })
      .get();
    db.update(projects).set({ lastScanId: newer.id }).where(eq(projects.id, 'demo')).run();

    const { runId, result } = await triageFinding(e, { finding, state });
    // A later rescan moving the finding on must not change what the stored run points at.
    db.update(findings).set({ lastSeenScanId: newer.id }).where(eq(findings.id, finding.id)).run();

    expect(result.status).toBe('ok');
    const run = db.select().from(triageRuns).where(eq(triageRuns.id, runId)).get()!;
    expect(run).toMatchObject({ scanId, commitSha: 'abc123', inputHash: state.inputHash });
    expect(snapshotShas).toEqual(codeAccess ? ['abc123'] : []);
    if (codeAccess) expect(run.prompt).toContain(`at commit abc123`);
  });

  it('keeps the scan when the snapshot could not be prepared', async () => {
    const db = openDb(':memory:');
    const { scanId } = seedProject(db, { commitSha: 'abc123' });
    const finding = seedFinding(db, { scanId });
    const e = env(db, true, tmp);
    e.snapshots = async () => {
      throw new Error('git archive failed');
    };
    const state = resolveTriageState(db, finding, e.triageConfig, 'P2');
    const { runId, result } = await triageFinding(e, { finding, state });
    expect(result).toMatchObject({ status: 'failed', attempts: 0 });
    expect(result.error).toMatch(/setup failed: git archive failed/);
    expect(db.select().from(triageRuns).where(eq(triageRuns.id, runId)).get()).toMatchObject({ scanId, commitSha: 'abc123', prompt: '' });
  });

  it('stores no scan when the prompt could not be built', async () => {
    const db = openDb(':memory:');
    const { scanId } = seedProject(db);
    const finding = seedFinding(db, { scanId });
    const e = env(db, false, tmp);
    const state = resolveTriageState(db, finding, e.triageConfig, 'P2');
    const { runId, result } = await triageFinding(e, { finding: { ...finding, osvId: 'GHSA-missing' }, state });
    expect(result.status).toBe('failed');
    expect(db.select().from(triageRuns).where(eq(triageRuns.id, runId)).get()).toMatchObject({ scanId: null, commitSha: null });
  });
});
