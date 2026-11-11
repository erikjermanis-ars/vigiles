import { eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { openDb } from '../lib/db/client';
import { events, findings } from '../lib/db/schema';
import { CancelledError } from '../lib/jobs/types';
import { getFeedState } from '../lib/signals/feed-state';
import { parseKevFeed, replaceKevCatalog } from '../lib/signals/kev';
import { epssApiStub, fakeJobContext, kevFeed, seedAdvisory, seedFinding, seedProject, stubFetch } from '../lib/signals/test-support';
import { runEnrich } from './enrich';

function setup() {
  const db = openDb(':memory:');
  seedProject(db, 'web', 'internet-facing', 'high');
  replaceKevCatalog(db, parseKevFeed(kevFeed([{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }])));
  seedAdvisory(db, 'GHSA-jfh8-c2jp-5v3q', { cves: ['CVE-2021-44228'], cvssScore: 10 });
  seedAdvisory(db, 'GHSA-low', { cves: ['CVE-2025-00002'], severityLabel: 'LOW' });
  const kevId = seedFinding(db, 'web', 'GHSA-jfh8-c2jp-5v3q');
  const lowId = seedFinding(db, 'web', 'GHSA-low');
  return { db, kevId, lowId };
}

describe('enrich job', () => {
  it('uses thresholds from config/policy.yaml and tags events with the job id', async () => {
    const { db, lowId } = setup();
    const ctx = fakeJobContext(db, 'enrich');

    const first = await runEnrich(ctx, { fetchFn: epssApiStub({ 'CVE-2021-44228': 0.94, 'CVE-2025-00002': 0.01 }) });
    expect(first).toMatchObject({ findings: 2, byPriority: { P0: 1, P1: 0, P2: 0, P3: 1 }, escalated: 0 });
    expect(ctx.logs[0]).toMatch(/^thresholds from policy [0-9a-f]{12}: \{"epss_high":/);

    const ctx2 = fakeJobContext(db, 'enrich');
    const second = await runEnrich(ctx2, { fetchFn: epssApiStub({ 'CVE-2021-44228': 0.94, 'CVE-2025-00002': 0.15 }) });
    expect(second).toMatchObject({ escalated: 1, byPriority: { P0: 1, P1: 0, P2: 1, P3: 0 } });

    const ev = db.select().from(events).where(eq(events.findingId, lowId)).all();
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ type: 'escalated', jobRunId: ctx2.jobId });
    expect(db.select().from(findings).where(eq(findings.id, lowId)).get()).toMatchObject({ priority: 'P2', cvssScore: 2, epss: 0.15 });
  });

  it('stops with CancelledError when cancelled before the first EPSS batch', async () => {
    const { db, kevId } = setup();
    const ctx = fakeJobContext(db, 'enrich');
    ctx.controller.abort();
    const fetchFn = stubFetch(() => new Response('{}'));
    await expect(runEnrich(ctx, { fetchFn })).rejects.toBeInstanceOf(CancelledError);
    expect(fetchFn.calls).toHaveLength(0);
    expect(db.select().from(findings).where(eq(findings.id, kevId)).get()!.enrichedAt).toBeNull();
  });

  it('stops between EPSS batches when cancelled mid-run and writes nothing', async () => {
    const { db } = setup();
    const many = Array.from({ length: 150 }, (_, i) => `CVE-2024-${String(i + 1).padStart(5, '0')}`);
    seedAdvisory(db, 'GHSA-many', { cves: many, cvssScore: 5 });
    seedFinding(db, 'web', 'GHSA-many');
    const ctx = fakeJobContext(db, 'enrich');
    const scores = epssApiStub({});
    const fetchFn = stubFetch((url) => {
      ctx.controller.abort(); // the user cancels while batch 1 is in flight; the batch itself succeeds
      return scores(url);
    });

    await expect(runEnrich(ctx, { fetchFn })).rejects.toBeInstanceOf(CancelledError);
    expect(fetchFn.calls).toHaveLength(1);
    expect(db.select().from(findings).all().every((f) => f.enrichedAt === null)).toBe(true);
    expect(getFeedState(db, 'epss')).toBeUndefined();
  });
});
