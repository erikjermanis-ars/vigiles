import { execFileSync } from 'node:child_process';
import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { jobRuns } from '../db/schema';
import { describeLiveJob, isProcessAlive, liveRunningJobs } from './queue';

const DEAD_PID = Number(execFileSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' }));

describe('isProcessAlive', () => {
  it('is true for a running process and false for one that exited or a bogus pid', () => {
    expect(isProcessAlive(process.pid)).toBe(true);
    expect(isProcessAlive(DEAD_PID)).toBe(false);
    for (const bogus of [0, -1, Number.NaN, 1.5]) expect(isProcessAlive(bogus)).toBe(false);
  });
});

describe('liveRunningJobs', () => {
  let db: Db;
  beforeEach(() => {
    db = openDb(':memory:');
  });
  const insert = (values: Partial<typeof jobRuns.$inferInsert>) =>
    db
      .insert(jobRuns)
      .values({ type: 'scan', status: 'running', ...values })
      .returning({ id: jobRuns.id })
      .get().id;

  it('lists running rows whose owner process is alive, optionally by type and top-level only', () => {
    const top = insert({ type: 'refresh-all', pid: process.pid, startedAt: '2026-11-10T10:00:00.000Z' });
    const child = insert({ type: 'triage', pid: process.pid, parentId: top });
    const cli = insert({ type: 'triage', pid: 4242 });
    insert({ type: 'triage', pid: DEAD_PID }); // its process is gone
    insert({ type: 'triage', pid: null }); // predates pid tracking
    insert({ type: 'triage', pid: process.pid, status: 'succeeded' });
    const alive = (pid: number) => pid === process.pid || pid === 4242;

    expect(liveRunningJobs(db, {}, alive).map((j) => j.id)).toEqual([top, child, cli]);
    expect(liveRunningJobs(db, { type: 'triage' }, alive).map((j) => j.id)).toEqual([child, cli]);
    expect(liveRunningJobs(db, { type: 'triage', topLevelOnly: true }, alive).map((j) => j.id)).toEqual([cli]);
    // The real check (process.kill(pid, 0)): ours is alive, an exited process is not.
    const deadTop = insert({ pid: DEAD_PID });
    const real = liveRunningJobs(db).map((j) => j.id);
    expect(real).toEqual(expect.arrayContaining([top, child]));
    expect(real).not.toContain(deadTop);

    const [first] = liveRunningJobs(db, {}, alive);
    expect(describeLiveJob(first!)).toBe(`refresh-all#${top} (pid ${process.pid}, started 2026-11-10T10:00:00.000Z)`);
  });
});
