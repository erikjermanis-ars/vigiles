import { describe, expect, it } from 'vitest';
import type { VigilesConfig } from '../lib/config/schema';
import { CancelledError, JobFailedError, type JobContext } from '../lib/jobs/types';
import type { JobType } from '../lib/types';
import { PipelineFailedError, refreshAllSteps, run, runPipeline, type PipelineDeps, type PipelineStats } from './refresh-all';

const config = { triage: { max_per_run: 7 } } as VigilesConfig;
const steps = refreshAllSteps(config);

/** A fake runChild: records calls; `outcomes` makes a step fail with the given error. */
function harness(outcomes: Partial<Record<JobType, Error>> = {}) {
  const calls: { type: JobType; params: Record<string, unknown> }[] = [];
  const logs: string[] = [];
  const progress: string[] = [];
  let nextId = 100;
  const deps: PipelineDeps = {
    async runChild(type, params = {}) {
      calls.push({ type, params });
      const err = outcomes[type];
      if (err) throw err;
      return { ran: type, id: nextId++ };
    },
    log: (m) => logs.push(m),
    progress: (p) => progress.push(p),
  };
  return { deps, calls, logs, progress };
}

const failed = (type: JobType, msg = 'boom') => new JobFailedError(type, 1, msg);

describe('refresh-all pipeline', () => {
  it('runs every step in spec order, passing the triage cap', async () => {
    const h = harness();
    const stats = await runPipeline(steps, h.deps);

    expect(h.calls).toEqual([
      { type: 'sync-osv', params: {} },
      { type: 'sync-kev', params: {} },
      { type: 'scan', params: {} },
      { type: 'enrich', params: {} },
      { type: 'triage', params: { limit: 7 } },
      { type: 'decide', params: {} },
    ]);
    expect(h.progress).toEqual([
      'step 1/6: sync-osv',
      'step 2/6: sync-kev',
      'step 3/6: scan',
      'step 4/6: enrich',
      'step 5/6: triage',
      'step 6/6: decide',
    ]);
    expect(stats.warnings).toEqual([]);
    expect(stats.failedSteps).toEqual([]);
    expect(stats.steps.scan).toEqual({ status: 'succeeded', stats: { ran: 'scan', id: 102 } });
    expect(Object.keys(stats.steps)).toHaveLength(6);
  });

  it.each(['sync-osv', 'sync-kev', 'triage'] as const)('a failed %s is a warning and the pipeline continues', async (type) => {
    const h = harness({ [type]: failed(type, 'network down') });
    const stats = await runPipeline(steps, h.deps);

    expect(h.calls.map((c) => c.type)).toEqual(['sync-osv', 'sync-kev', 'scan', 'enrich', 'triage', 'decide']);
    expect(stats.steps[type]).toEqual({ status: 'failed', error: `${type} (#1) failed: network down` });
    expect(stats.steps.decide?.status).toBe('succeeded');
    expect(stats.warnings).toHaveLength(1);
    expect(stats.warnings[0]).toMatch(new RegExp(`^${type} \\(#1\\) failed: network down; continuing`));
    expect(h.logs).toEqual([`warning: ${stats.warnings[0]}`]);
    expect(stats.failedSteps).toEqual([]);
  });

  it('a failed scan lets enrich, triage and decide run, and is reported as a failed step', async () => {
    const h = harness({ scan: failed('scan', 'scan failed for web: git exited 128') });
    const stats = await runPipeline(steps, h.deps);

    expect(h.calls.map((c) => c.type)).toEqual(['sync-osv', 'sync-kev', 'scan', 'enrich', 'triage', 'decide']);
    expect(stats.steps.scan).toEqual({ status: 'failed', error: 'scan (#1) failed: scan failed for web: git exited 128' });
    expect(stats.steps.decide?.status).toBe('succeeded');
    expect(stats.failedSteps).toEqual(['scan']);
    expect(stats.warnings).toHaveLength(1);
    expect(h.logs[0]).toMatch(/^warning: scan \(#1\) failed: .*; continuing \(.*the refresh fails at the end\)$/);
  });

  it('collects one warning per soft failure', async () => {
    const h = harness({ 'sync-osv': failed('sync-osv'), 'sync-kev': failed('sync-kev'), triage: failed('triage') });
    const stats = await runPipeline(steps, h.deps);
    expect(stats.warnings).toHaveLength(3);
    expect(stats.steps.decide?.status).toBe('succeeded');
  });

  it.each(['enrich', 'decide'] as const)('a failed %s fails the pipeline and stops it', async (type) => {
    const err = failed(type);
    const h = harness({ [type]: err });
    await expect(runPipeline(steps, h.deps)).rejects.toBe(err);
    const order = steps.map((s) => s.type);
    expect(h.calls.map((c) => c.type)).toEqual(order.slice(0, order.indexOf(type) + 1));
  });

  it.each(['sync-osv', 'scan', 'triage'] as const)('cancellation propagates at once even from the soft step %s', async (type) => {
    const h = harness({ [type]: new CancelledError() });
    await expect(runPipeline(steps, h.deps)).rejects.toBeInstanceOf(CancelledError);
    expect(h.calls.at(-1)!.type).toBe(type);
  });

  it('an enrich failure after a failed scan still stops the pipeline at once', async () => {
    const err = failed('enrich');
    const h = harness({ scan: failed('scan'), enrich: err });
    await expect(runPipeline(steps, h.deps)).rejects.toBe(err);
    expect(h.calls.map((c) => c.type)).toEqual(['sync-osv', 'sync-kev', 'scan', 'enrich']);
  });

  it('an unexpected error (not a child job failure) propagates even from a soft step', async () => {
    const h = harness({ triage: new Error('database is locked') });
    await expect(runPipeline(steps, h.deps)).rejects.toThrow('database is locked');
    expect(h.calls.map((c) => c.type)).not.toContain('decide');
  });
});

describe('refresh-all job handler', () => {
  it('runs the pipeline through ctx with the configured triage cap and returns its stats', async () => {
    const h = harness({ 'sync-kev': failed('sync-kev', 'offline') });
    const ctx = { ...h.deps, config } as unknown as JobContext;

    const stats = await run(ctx);

    expect(h.calls.map((c) => [c.type, c.params])).toEqual([
      ['sync-osv', {}],
      ['sync-kev', {}],
      ['scan', {}],
      ['enrich', {}],
      ['triage', { limit: 7 }],
      ['decide', {}],
    ]);
    expect(stats).toMatchObject({ steps: { 'sync-kev': { status: 'failed' }, decide: { status: 'succeeded' } } });
    expect((stats as { warnings: string[] }).warnings).toHaveLength(1);
    expect(h.logs.at(-1)).toBe('done with 1 warning(s)');
  });

  it('fails the job after the last step when the scan failed, keeping the stats on the error', async () => {
    const h = harness({ scan: failed('scan', 'scan failed for web: boom') });
    const ctx = { ...h.deps, config } as unknown as JobContext;

    const err = await run(ctx).catch((e: unknown) => e);

    expect(h.calls.map((c) => c.type)).toEqual(['sync-osv', 'sync-kev', 'scan', 'enrich', 'triage', 'decide']);
    expect(err).toBeInstanceOf(PipelineFailedError);
    const e = err as PipelineFailedError;
    expect(e.message.split('\n')).toEqual(['refresh completed with failures: scan', 'scan (#1) failed: scan failed for web: boom']);
    expect(e.stack).toBe(e.message);
    const stats: PipelineStats = e.stats;
    expect(stats.failedSteps).toEqual(['scan']);
    expect(stats.steps.decide?.status).toBe('succeeded');
    expect(h.logs.at(-1)).toBe('done; failed: scan (1 warning(s))');
  });
});
