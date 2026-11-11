import { eq } from 'drizzle-orm';
import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { events, findings, projects } from '../db/schema';
import { computeFindingSignals, enrichOpenFindings, type EnrichRow, type SignalSources } from './enrich';
import { getFeedState, recordFeedSuccess } from './feed-state';
import { parseKevFeed, replaceKevCatalog } from './kev';
import { epssApiStub, kevFeed, seedAdvisory, seedFinding, seedProject, stubFetch, THRESHOLDS } from './test-support';

const LOG4SHELL = 'CVE-2021-44228';
const NEXT_MW = 'CVE-2025-29927';
const OTHER = 'CVE-2025-00001';

describe('computeFindingSignals', () => {
  const row: EnrichRow = {
    id: 1,
    projectId: 'web',
    osvId: 'GHSA-aaaa-bbbb-cccc',
    priority: 'P2',
    inKev: false,
    epss: 0.2,
    epssPercentile: 0.9,
    enrichedAt: '2026-11-01T00:00:00.000Z',
    advisory: { cves: [NEXT_MW, OTHER.toLowerCase()], cvssScore: null, severityLabel: 'MODERATE', malicious: false },
    exposure: 'vpn',
    criticality: 'medium',
  };
  const src = (over: Partial<SignalSources> = {}): SignalSources => ({
    kevIndex: new Map(),
    epss: {
      scores: new Map([
        [NEXT_MW, { epss: 0.3, percentile: 0.95, date: null }],
        [OTHER, { epss: 0.6, percentile: 0.99, date: null }],
      ]),
      failedCves: new Set(),
    },
    thresholds: THRESHOLDS,
    ...over,
  });

  it('takes the max EPSS over normalized CVEs and falls back to the severity label', () => {
    const s = computeFindingSignals(row, src());
    expect(s).toMatchObject({
      cves: [OTHER, NEXT_MW],
      epss: 0.6,
      epssPercentile: 0.99,
      cvssScore: 4.0,
      priority: 'P1',
      priorityReasons: ['EPSS 0.6 ≥ 0.5'],
    });
    expect(s.escalation).toEqual(['priority P2 → P1', 'EPSS crossed 0.5 (0.2 → 0.6)']);
  });

  it('keeps the stored EPSS when one of its CVEs was in a failed batch and no scored CVE beats it', () => {
    const s = computeFindingSignals(
      row,
      src({ epss: { scores: new Map([[NEXT_MW, { epss: 0.15, percentile: 0.8, date: null }]]), failedCves: new Set([OTHER]) } }),
    );
    expect(s).toMatchObject({ epss: 0.2, epssPercentile: 0.9, priority: 'P2', escalation: [] });
  });

  it('takes a higher fresh score from the CVEs that were scored even when another batch failed', () => {
    const s = computeFindingSignals(
      row,
      src({ epss: { scores: new Map([[NEXT_MW, { epss: 0.9, percentile: 1, date: null }]]), failedCves: new Set([OTHER]) } }),
    );
    expect(s).toMatchObject({ epss: 0.9, epssPercentile: 1, priority: 'P1', priorityReasons: ['EPSS 0.9 ≥ 0.5'] });
    expect(s.escalation).toEqual(['priority P2 → P1', 'EPSS crossed 0.5 (0.2 → 0.9)']);
  });

  it('keeps an unknown EPSS unknown when every CVE failed', () => {
    const s = computeFindingSignals(
      { ...row, epss: null, epssPercentile: null },
      src({ epss: { scores: new Map(), failedCves: new Set([NEXT_MW, OTHER]) } }),
    );
    expect(s).toMatchObject({ epss: null, epssPercentile: null, priority: 'P3', escalation: [] });
  });

  it('clears EPSS when the API has no score for any of its CVEs', () => {
    const s = computeFindingSignals(row, src({ epss: { scores: new Map(), failedCves: new Set() } }));
    expect(s).toMatchObject({ epss: null, epssPercentile: null, priority: 'P3' });
  });

  it('does not report escalation on the first enrichment', () => {
    expect(computeFindingSignals({ ...row, enrichedAt: null, priority: null }, src()).escalation).toEqual([]);
  });

  it('flags MAL- findings as malicious even without an advisory row', () => {
    const s = computeFindingSignals({ ...row, osvId: 'MAL-2025-1234', advisory: null }, src());
    expect(s).toMatchObject({
      malicious: true,
      cves: [],
      epss: null,
      cvssScore: null,
      priority: 'P0',
      priorityReasons: ['malicious package (MAL-2025-1234)'],
    });
  });
});

describe('enrichOpenFindings', () => {
  let db: Db;
  let ids: Record<string, number>;
  const scores = { [LOG4SHELL]: 0.94424, [NEXT_MW]: 0.08, [OTHER]: 0.02 };

  const finding = (id: number) => db.select().from(findings).where(eq(findings.id, id)).get()!;
  const escalations = () => db.select().from(events).where(eq(events.type, 'escalated')).all();
  const run = (fetchFn: ReturnType<typeof stubFetch>, jobRunId = 7, at = '2026-11-10T10:00:00.000Z') =>
    enrichOpenFindings(db, { thresholds: THRESHOLDS, fetchFn, jobRunId, now: () => at });

  beforeEach(() => {
    db = openDb(':memory:');
    seedProject(db, 'web', 'internet-facing', 'high');
    seedProject(db, 'tool', 'internal', 'low');
    replaceKevCatalog(db, parseKevFeed(kevFeed([{ cveID: LOG4SHELL, dateAdded: '2021-12-10' }])));

    seedAdvisory(db, 'GHSA-jfh8-c2jp-5v3q', { cves: [LOG4SHELL], cvssScore: 10 });
    seedAdvisory(db, 'GHSA-f82v-jwr5-mffw', { cves: [NEXT_MW, OTHER], cvssScore: 9.1 });
    seedAdvisory(db, 'MAL-2025-1234', { malicious: true });
    seedAdvisory(db, 'GHSA-only-label', { severityLabel: 'HIGH' });
    seedAdvisory(db, 'GHSA-no-signal');

    ids = {
      kevWeb: seedFinding(db, 'web', 'GHSA-jfh8-c2jp-5v3q'),
      kevTool: seedFinding(db, 'tool', 'GHSA-jfh8-c2jp-5v3q'),
      nextWeb: seedFinding(db, 'web', 'GHSA-f82v-jwr5-mffw'),
      nextTool: seedFinding(db, 'tool', 'GHSA-f82v-jwr5-mffw'),
      mal: seedFinding(db, 'tool', 'MAL-2025-1234'),
      label: seedFinding(db, 'tool', 'GHSA-only-label'),
      none: seedFinding(db, 'tool', 'GHSA-no-signal'),
      fixed: seedFinding(db, 'web', 'GHSA-f82v-jwr5-mffw', { lockfile: 'old/package-lock.json', status: 'fixed' }),
    };
  });

  it('writes signals and base priority for every open finding', async () => {
    const fetchFn = epssApiStub(scores);
    const stats = await run(fetchFn);

    expect(fetchFn.calls).toHaveLength(1);
    expect(new URL(fetchFn.calls[0]!.url).searchParams.get('cve')).toBe([LOG4SHELL, OTHER, NEXT_MW].sort().join(','));

    expect(finding(ids.kevWeb!)).toMatchObject({
      priority: 'P0',
      priorityReasons: ['in CISA KEV since 2021-12-10', 'asset internet-facing', 'criticality high'],
      inKev: true,
      kevDateAdded: '2021-12-10',
      epss: 0.94424,
      epssPercentile: 1, // the stub serves min(1, epss + 0.3)
      cvssScore: 10,
      enrichedAt: '2026-11-10T10:00:00.000Z',
      updatedAt: '2026-11-10T10:00:00.000Z',
    });
    expect(finding(ids.kevTool!)).toMatchObject({ priority: 'P1', priorityReasons: ['in CISA KEV since 2021-12-10', 'EPSS 0.94 ≥ 0.5'] });
    expect(finding(ids.nextWeb!)).toMatchObject({
      priority: 'P1',
      priorityReasons: ['CVSS 9.1 ≥ 9 on internet-facing asset'],
      inKev: false,
      kevDateAdded: null,
      epss: 0.08,
      cvssScore: 9.1,
    });
    expect(finding(ids.nextTool!)).toMatchObject({ priority: 'P2', priorityReasons: ['CVSS 9.1 ≥ 7'] });
    expect(finding(ids.mal!)).toMatchObject({ priority: 'P0', priorityReasons: ['malicious package (MAL-2025-1234)'], epss: null });
    expect(finding(ids.label!)).toMatchObject({ priority: 'P2', cvssScore: 7, priorityReasons: ['CVSS 7 ≥ 7'] });
    expect(finding(ids.none!)).toMatchObject({ priority: 'P3', cvssScore: null, priorityReasons: ['no CVSS/EPSS signal'] });
    expect(finding(ids.fixed!)).toMatchObject({ priority: null, enrichedAt: null });

    expect(stats).toEqual({
      findings: 7,
      cves: 3,
      byPriority: { P0: 2, P1: 2, P2: 2, P3: 1 },
      inKev: 2,
      escalated: 0,
      epssFetched: 3,
      epssFailed: 0,
      disabledSkipped: 0,
    });
    expect(escalations()).toEqual([]);
    expect(getFeedState(db, 'epss')).toMatchObject({
      lastSuccessAt: '2026-11-10T10:00:00.000Z',
      lastError: null,
      meta: { cves: 3, date: '2026-11-09' },
    });
  });

  it('is idempotent: a second run with the same feeds writes no events', async () => {
    await run(epssApiStub(scores));
    const stats = await run(epssApiStub(scores), 8);
    expect(stats.escalated).toBe(0);
    expect(escalations()).toEqual([]);
  });

  it('writes escalated events for upward moves only', async () => {
    await run(epssApiStub(scores), 7, '2026-11-01T00:00:00.000Z');

    // Next day: the Next.js CVE lands in KEV, its EPSS jumps, and Log4Shell's EPSS drops (no event for that).
    replaceKevCatalog(
      db,
      parseKevFeed(
        kevFeed([
          { cveID: LOG4SHELL, dateAdded: '2021-12-10' },
          { cveID: NEXT_MW, dateAdded: '2026-11-02' },
        ]),
      ),
    );
    const stats = await run(epssApiStub({ ...scores, [NEXT_MW]: 0.62, [LOG4SHELL]: 0.4 }), 8, '2026-11-02T00:00:00.000Z');

    expect(stats.escalated).toBe(2);
    const byFinding = new Map(escalations().map((e) => [e.findingId, e]));
    expect([...byFinding.keys()].sort()).toEqual([ids.nextWeb, ids.nextTool].sort());

    expect(byFinding.get(ids.nextWeb!)).toMatchObject({
      jobRunId: 8,
      at: '2026-11-02T00:00:00.000Z',
      data: {
        from: { priority: 'P1', inKev: false, epss: 0.08 },
        to: { priority: 'P0', inKev: true, epss: 0.62 },
        reasons: ['priority P1 → P0', 'added to CISA KEV', 'EPSS crossed 0.5 (0.08 → 0.62)'],
        priorityReasons: ['in CISA KEV since 2026-11-02', 'asset internet-facing', 'criticality high'],
      },
    });
    expect(byFinding.get(ids.nextTool!)!.data).toMatchObject({
      from: { priority: 'P2', inKev: false, epss: 0.08 },
      to: { priority: 'P1', inKev: true, epss: 0.62 },
    });
    expect(finding(ids.kevWeb!)).toMatchObject({ priority: 'P0', epss: 0.4 });
  });

  it('keeps previous EPSS values and records the error when the EPSS API fails', async () => {
    await run(epssApiStub(scores), 7, '2026-11-01T00:00:00.000Z');
    const down = stubFetch(() => new Response('maintenance', { status: 503, statusText: 'Service Unavailable' }));
    const logs: string[] = [];
    const stats = await enrichOpenFindings(db, {
      thresholds: THRESHOLDS,
      fetchFn: down,
      log: (m) => logs.push(m),
      now: () => '2026-11-02T00:00:00.000Z',
    });

    expect(stats).toMatchObject({ findings: 7, epssFetched: 0, epssFailed: 3, escalated: 0 });
    expect(finding(ids.kevTool!)).toMatchObject({ epss: 0.94424, priority: 'P1', enrichedAt: '2026-11-02T00:00:00.000Z' });
    expect(finding(ids.nextWeb!)).toMatchObject({ epss: 0.08 });
    expect(getFeedState(db, 'epss')).toMatchObject({
      lastAttemptAt: '2026-11-02T00:00:00.000Z',
      lastSuccessAt: '2026-11-01T00:00:00.000Z',
      lastError: expect.stringContaining('HTTP 503'),
      meta: { cves: 3, date: '2026-11-09' },
    });
    expect(logs.some((l) => l.startsWith('warning: EPSS batch 1/1'))).toBe(true);
  });

  it('records success with zero CVEs and makes no request', async () => {
    const empty = openDb(':memory:');
    seedProject(empty, 'web', 'internet-facing', 'high');
    seedAdvisory(empty, 'GHSA-no-signal');
    seedFinding(empty, 'web', 'GHSA-no-signal');
    const fetchFn = epssApiStub({});
    const logs: string[] = [];
    await enrichOpenFindings(empty, { thresholds: THRESHOLDS, fetchFn, log: (m) => logs.push(m) });
    expect(fetchFn.calls).toHaveLength(0);
    expect(getFeedState(empty, 'epss')).toMatchObject({ lastError: null, meta: { cves: 0, date: null } });
    expect(logs).toContain('warning: the KEV catalog is empty (run sync-kev); no finding will be marked in KEV');
  });

  it('assumes the worst exposure when a finding has no project row', async () => {
    seedFinding(db, 'ghost', 'GHSA-jfh8-c2jp-5v3q');
    const logs: string[] = [];
    await enrichOpenFindings(db, { thresholds: THRESHOLDS, fetchFn: epssApiStub(scores), log: (m) => logs.push(m) });
    const ghost = db.select().from(findings).where(eq(findings.projectId, 'ghost')).get()!;
    expect(ghost.priority).toBe('P0');
    expect(logs.some((l) => l.includes('project "ghost" has no profile row'))).toBe(true);
  });

  it('skips findings of disabled projects: no signals written, no escalation events', async () => {
    await run(epssApiStub(scores), 7, '2026-11-01T00:00:00.000Z');
    db.update(projects).set({ enabled: false }).where(eq(projects.id, 'tool')).run();
    const before = finding(ids.nextTool!);
    const logs: string[] = [];
    const fetchFn = epssApiStub({ ...scores, [OTHER]: 0.99 }); // would escalate nextTool
    const stats = await enrichOpenFindings(db, {
      thresholds: THRESHOLDS,
      fetchFn,
      jobRunId: 8,
      now: () => '2026-11-10T10:00:00.000Z',
      log: (m) => logs.push(m),
    });

    expect(stats).toMatchObject({ findings: 2, disabledSkipped: 5 });
    expect(finding(ids.nextTool!)).toEqual(before);
    expect(finding(ids.nextWeb!).enrichedAt).toBe('2026-11-10T10:00:00.000Z');
    expect(escalations().every((e) => e.findingId !== ids.nextTool)).toBe(true);
    expect(logs).toContain('5 open finding(s) of disabled projects skipped');
  });

  it('does not clobber an existing feed_state success when nothing failed', async () => {
    recordFeedSuccess(db, 'epss', { cves: 1, date: '2026-10-01' }, '2026-10-01T00:00:00.000Z');
    await run(epssApiStub(scores));
    expect(getFeedState(db, 'epss')).toMatchObject({ lastSuccessAt: '2026-11-10T10:00:00.000Z', meta: { cves: 3, date: '2026-11-09' } });
  });
});
