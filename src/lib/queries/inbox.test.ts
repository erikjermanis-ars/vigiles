import { eq } from 'drizzle-orm';
import { beforeEach, describe, expect, it } from 'vitest';
import { parsePolicy } from '../config/load';
import { openDb, type Db } from '../db/client';
import { events, findings } from '../db/schema';
import { decideAll } from '../policy/decide';
import { insertConfig, insertEvent, insertFinding, insertJob, insertProject, insertTriageRun, triageOutput } from '../eval/test-fixtures';
import {
  firstSentence,
  getInbox,
  groupInboxItems,
  inboxSinceAnchor,
  lastSucceededRefreshAll,
  loggedFindingsHref,
  type InboxItem,
} from './inbox';

function item(o: Partial<InboxItem>): InboxItem {
  return {
    findingId: 1,
    projectId: 'web',
    projectName: 'Web',
    packageName: 'next',
    lockfile: 'package-lock.json',
    osvId: 'GHSA-x',
    vulnId: 'GHSA-x',
    action: 'ping',
    priority: 'P1',
    priorityReasons: [],
    verdict: null,
    confidence: null,
    summary: null,
    ruleId: 'r',
    fixedVersions: [],
    installedVersions: ['1.0.0'],
    devOnly: false,
    direct: true,
    malicious: false,
    ...o,
  };
}

describe('firstSentence', () => {
  it('takes the first sentence without splitting version numbers', () => {
    expect(firstSentence('Upgrade next to 16.2.13 now. Then redeploy.')).toBe('Upgrade next to 16.2.13 now.');
    expect(firstSentence('No stop at all')).toBe('No stop at all');
    expect(firstSentence('Sharp runs on uploads, e.g. profile photos, i.e. user input. It is reachable.')).toBe(
      'Sharp runs on uploads, e.g. profile photos, i.e. user input.',
    );
    expect(firstSentence('Affected? Yes.')).toBe('Affected?');
    expect(firstSentence('   ')).toBeNull();
    expect(firstSentence(null)).toBeNull();
    expect(firstSentence('x'.repeat(300), 10)).toBe(`${'x'.repeat(9)}…`);
  });
});

describe('groupInboxItems', () => {
  it('groups per (project, package), picks the highest fixed version and orders by urgency', () => {
    const groups = groupInboxItems([
      item({ findingId: 1, packageName: 'next', priority: 'P1', osvId: 'GHSA-2', vulnId: 'CVE-2', fixedVersions: ['15.3.3', '14.2.30'] }),
      item({ findingId: 2, packageName: 'next', priority: 'P0', osvId: 'GHSA-1', vulnId: 'CVE-1', fixedVersions: ['15.10.0'] }),
      item({ findingId: 3, packageName: 'zod', priority: 'P2', fixedVersions: [] }),
      item({ findingId: 4, packageName: 'next', projectId: 'api', projectName: 'Api', priority: 'P1' }),
    ]);
    expect(groups.map((g) => `${g.projectId}/${g.packageName}`)).toEqual(['web/next', 'api/next', 'web/zod']);
    expect(groups[0]!.items.map((i) => i.findingId)).toEqual([2, 1]);
    expect(groups[0]!.upgradeTo).toBe('15.10.0');
    expect(groups[0]!.topPriority).toBe('P0');
    expect(groups[2]!.upgradeTo).toBeNull();
    expect(groups[0]!.advisoryCount).toBe(2);
    expect(groups[0]!.withoutFix).toBe(0);
    expect(groups[2]!.withoutFix).toBe(1);
  });

  it('counts one advisory found in two lockfiles once, and says which advisories the upgrade does not fix', () => {
    const [g] = groupInboxItems([
      item({ findingId: 1, osvId: 'GHSA-a', vulnId: 'CVE-A', lockfile: 'backend/package-lock.json', fixedVersions: ['1.5.0'] }),
      item({ findingId: 2, osvId: 'GHSA-a', vulnId: 'CVE-A', lockfile: 'dashboard/package-lock.json', fixedVersions: ['1.5.0'] }),
      item({ findingId: 3, osvId: 'GHSA-b', vulnId: 'CVE-B', lockfile: 'backend/package-lock.json', fixedVersions: [] }),
      // a GIT-range commit is no release to upgrade to
      item({
        findingId: 4,
        osvId: 'GHSA-c',
        vulnId: 'CVE-C',
        lockfile: 'backend/package-lock.json',
        fixedVersions: ['0a1b2c3d4e5f60718293a4b5c6d7e8f901234567'],
      }),
    ]);
    expect(g!.items).toHaveLength(4);
    expect(g!.advisoryCount).toBe(3);
    expect(g!.upgradeTo).toBe('1.5.0');
    expect(g!.withoutFix).toBe(2);
    expect(g!.lockfiles).toEqual(['backend/package-lock.json', 'dashboard/package-lock.json']);
    expect(g!.items.map((i) => i.findingId)).toEqual([1, 2, 3, 4]);
  });

  it('upgrades to the fix on the installed line, the highest across the group', () => {
    const [g] = groupInboxItems([
      item({
        findingId: 1,
        packageName: 'storybook',
        osvId: 'GHSA-sb',
        installedVersions: ['10.5.5'],
        fixedVersions: ['9.1.21', '10.6.2', '11.0.0-alpha.6'],
      }),
      item({ findingId: 2, packageName: 'storybook', osvId: 'GHSA-sb2', installedVersions: ['10.5.5'], fixedVersions: ['10.5.9'] }),
    ]);
    expect(g!.upgradeTo).toBe('10.6.2');
  });
});

describe('groupInboxItems with malicious packages', () => {
  it('keeps malicious advisories out of the upgrade target and the without-fix count', () => {
    const [mal] = groupInboxItems([item({ findingId: 1, packageName: 'evil', osvId: 'MAL-1', vulnId: 'MAL-1', malicious: true })]);
    expect(mal).toMatchObject({ malicious: 1, upgradeTo: null, withoutFix: 0, advisoryCount: 1 });

    const [mixed] = groupInboxItems([
      item({ findingId: 1, osvId: 'MAL-2', vulnId: 'MAL-2', malicious: true, fixedVersions: [] }),
      item({ findingId: 2, osvId: 'GHSA-a', vulnId: 'CVE-A', fixedVersions: ['1.2.0'] }),
      item({ findingId: 3, osvId: 'GHSA-b', vulnId: 'CVE-B', fixedVersions: [] }),
    ]);
    expect(mixed).toMatchObject({ malicious: 1, upgradeTo: '1.2.0', withoutFix: 1, advisoryCount: 3 });
  });
});

describe('getInbox', () => {
  let db: Db;
  let scanId: number;

  beforeEach(() => {
    db = openDb(':memory:');
    scanId = insertProject(db, 'web').scanId;
  });

  it('is empty without data', () => {
    const inbox = getInbox(db, 'since');
    expect(inbox.sinceFallback).toBe(true);
    expect(inbox.totals).toEqual({ findings: 0, open: 0 });
    expect(inbox.ping).toEqual([]);
  });

  it('groups ping and digest findings, counts logged and undecided, and uses the active triage summary', () => {
    const cfg = insertConfig(db);
    const a = insertFinding(db, scanId, { packageName: 'next', action: 'ping', cves: ['CVE-2026-1'], fixedVersions: ['16.2.13'] });
    insertFinding(db, scanId, { packageName: 'next', action: 'ping', fixedVersions: ['16.3.0'] });
    insertFinding(db, scanId, { packageName: 'zod', action: 'digest', advisorySummary: 'Zod is slow. Very slow.' });
    insertFinding(db, scanId, { packageName: 'sharp', action: 'log' });
    insertFinding(db, scanId, { packageName: 'sharp', action: null });
    insertFinding(db, scanId, { packageName: 'old', action: 'ping', status: 'fixed' });
    const run = insertTriageRun(db, a.id, cfg, { output: triageOutput({ verdict: 'likely_affected', confidence: 'medium' }) });
    db.update(findings).set({ activeTriageRunId: run.id }).where(eq(findings.id, a.id)).run();

    const inbox = getInbox(db, 'all');
    expect(inbox.counts).toEqual({
      pingMessages: 1,
      pingFindings: 2,
      digestMessages: 1,
      digestFindings: 1,
      logged: 1,
      undecided: 1,
      unenriched: 1,
    });
    expect(inbox.totals).toEqual({ findings: 6, open: 5 });
    const next = inbox.ping[0]!;
    expect(next.upgradeTo).toBe('16.3.0');
    const first = next.items.find((i) => i.findingId === a.id)!;
    expect(first.vulnId).toBe('CVE-2026-1');
    expect(first.verdict).toBe('likely_affected');
    expect(first.confidence).toBe('medium');
    expect(first.summary).toBe('The upload route passes user files to the vulnerable function.');
    expect(inbox.digest[0]!.items[0]!.summary).toBe('Zod is slow.');
  });

  it('shows no verdict when the active triage run is a failed one', () => {
    const cfg = insertConfig(db);
    const f = insertFinding(db, scanId, { action: 'ping' });
    // A failed run that still carries a (stale) output must not surface as the finding's verdict.
    const run = insertTriageRun(db, f.id, cfg, { status: 'failed', output: triageOutput({ verdict: 'not_affected' }) });
    db.update(findings).set({ activeTriageRunId: run.id }).where(eq(findings.id, f.id)).run();
    const item = getInbox(db, 'all').ping[0]!.items[0]!;
    expect(item.verdict).toBeNull();
    expect(item.summary).toBe(`Summary of ${f.osvId}.`);
  });

  it('"since last refresh" keeps findings with qualifying events after the previous succeeded refresh-all finished', () => {
    const before = insertFinding(db, scanId, { packageName: 'a', action: 'ping' });
    const created = insertFinding(db, scanId, { packageName: 'b', action: 'ping' });
    const decided = insertFinding(db, scanId, { packageName: 'c', action: 'digest' });
    const fixedOnly = insertFinding(db, scanId, { packageName: 'd', action: 'ping' });
    const atBoundary = insertFinding(db, scanId, { packageName: 'e', action: 'ping' });
    const byFailedRun = insertFinding(db, scanId, { packageName: 'f', action: 'ping' });
    const standalone = insertFinding(db, scanId, { packageName: 'g', action: 'digest' });
    const loggedChanged = insertFinding(db, scanId, { packageName: 'h', action: 'log' });
    insertFinding(db, scanId, { packageName: 'i', action: 'log' }); // logged, unchanged
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-01T00:00:00.000Z',
      finishedAt: '2026-11-01T00:10:00.000Z',
    });
    // A refresh-all that failed after its scan: what it created must still show up.
    insertJob(db, { type: 'refresh-all', status: 'failed', startedAt: '2026-11-03T00:00:00.000Z', finishedAt: '2026-11-03T00:05:00.000Z' });
    const latest = insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    insertJob(db, { type: 'refresh-all', status: 'failed', startedAt: '2026-11-06T00:00:00.000Z' });
    insertEvent(db, before.id, 'created', '2026-11-01T00:05:00.000Z'); // during the previous refresh
    insertEvent(db, atBoundary.id, 'created', '2026-11-01T00:10:00.000Z'); // exactly when it finished: excluded
    insertEvent(db, byFailedRun.id, 'created', '2026-11-03T00:01:00.000Z');
    insertEvent(db, standalone.id, 'escalated', '2026-11-04T12:00:00.000Z');
    insertEvent(db, created.id, 'created', '2026-11-05T00:01:00.000Z');
    insertEvent(db, decided.id, 'decision_changed', '2026-11-05T00:09:00.000Z');
    insertEvent(db, fixedOnly.id, 'fixed', '2026-11-05T00:09:00.000Z'); // not a qualifying type
    insertEvent(db, loggedChanged.id, 'decision_changed', '2026-11-05T00:09:00.000Z');

    expect(lastSucceededRefreshAll(db)?.id).toBe(latest);
    expect(inboxSinceAnchor(db).sinceAt).toBe('2026-11-01T00:10:00.000Z');
    const since = getInbox(db, 'since');
    expect(since.sinceFallback).toBe(false);
    expect(since.lastRefresh?.id).toBe(latest);
    expect(since.ping.flatMap((g) => g.items.map((i) => i.findingId)).sort((x, y) => x - y)).toEqual([created.id, byFailedRun.id]);
    expect(since.digest.flatMap((g) => g.items.map((i) => i.findingId)).sort((x, y) => x - y)).toEqual([decided.id, standalone.id]);
    expect(since.counts.logged).toBe(1);
    expect(since.loggedIds).toEqual([loggedChanged.id]);
    expect(loggedFindingsHref(since)).toBe(`/findings?action=log&ids=${loggedChanged.id}`);

    const all = getInbox(db, 'all');
    expect(all.counts.pingFindings).toBe(5);
    expect(all.counts.logged).toBe(2);
    expect(loggedFindingsHref(all)).toBe('/findings?action=log');
  });

  it('links to no findings when nothing logged changed since the previous refresh', () => {
    insertFinding(db, scanId, { action: 'log' });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-01T00:00:00.000Z',
      finishedAt: '2026-11-01T00:10:00.000Z',
    });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    const since = getInbox(db, 'since');
    expect(since.counts.logged).toBe(0);
    expect(loggedFindingsHref(since)).toBeNull();
  });

  it('shows every open finding while fewer than two refresh-all runs have succeeded', () => {
    const f = insertFinding(db, scanId, { action: 'ping' });
    const only = insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    // A child refresh-all (not top-level) never counts as a previous refresh.
    insertJob(db, { type: 'refresh-all', status: 'succeeded', parentId: only, finishedAt: '2026-11-05T00:09:00.000Z' });
    insertEvent(db, f.id, 'created', '2026-11-04T00:00:00.000Z');
    const inbox = getInbox(db, 'since');
    expect(inbox.sinceFallback).toBe(true);
    expect(inbox.sinceAt).toBeNull();
    expect(inbox.lastRefresh?.id).toBe(only);
    expect(inbox.previousRefresh).toBeNull();
    expect(inbox.counts.pingFindings).toBe(1);
  });

  it('leaves out findings of disabled projects in both views', () => {
    const other = insertProject(db, 'legacy', { enabled: false });
    const shown = insertFinding(db, scanId, { action: 'ping' });
    const hidden = insertFinding(db, other.scanId, { projectId: 'legacy', action: 'ping' });
    insertFinding(db, other.scanId, { projectId: 'legacy', action: 'log' });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-01T00:00:00.000Z',
      finishedAt: '2026-11-01T00:10:00.000Z',
    });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    insertEvent(db, shown.id, 'created', '2026-11-05T00:01:00.000Z');
    insertEvent(db, hidden.id, 'created', '2026-11-05T00:01:00.000Z');
    for (const view of ['since', 'all'] as const) {
      const inbox = getInbox(db, view);
      expect(inbox.ping.flatMap((g) => g.items.map((i) => i.findingId))).toEqual([shown.id]);
      expect(inbox.counts.logged).toBe(0);
      expect(inbox.disabled).toEqual({ projectIds: ['legacy'], open: 2 });
      expect(inbox.totals).toEqual({ findings: 1, open: 1 });
    }
    // The "all logged" link stays on the projects the Inbox shows.
    expect(loggedFindingsHref(getInbox(db, 'all'))).toBe('/findings?action=log&project=web');
  });

  it('counts undecided findings that enrich has not scored yet', () => {
    insertFinding(db, scanId, { action: null });
    const enriched = insertFinding(db, scanId, { action: null });
    db.update(findings).set({ enrichedAt: '2026-11-01T00:00:00.000Z' }).where(eq(findings.id, enriched.id)).run();
    expect(getInbox(db, 'all').counts).toMatchObject({ undecided: 2, unenriched: 1 });
  });

  it('marks malicious findings so the card shows the fixed remediation instead of an upgrade', () => {
    insertFinding(db, scanId, { packageName: 'evil', osvId: 'MAL-2026-1', action: 'ping', malicious: true });
    insertFinding(db, scanId, { packageName: 'next', action: 'ping', fixedVersions: ['1.0.1'] });
    const groups = getInbox(db, 'all').ping;
    const evil = groups.find((g) => g.packageName === 'evil')!;
    expect(evil.items[0]!.malicious).toBe(true);
    expect(evil).toMatchObject({ malicious: 1, upgradeTo: null, withoutFix: 0 });
    expect(groups.find((g) => g.packageName === 'next')).toMatchObject({ malicious: 0, upgradeTo: '1.0.1' });
  });

  it('counts reopened and advisory_changed events, but not fixed or no_longer_matches', () => {
    const reopened = insertFinding(db, scanId, { packageName: 'a', action: 'ping' });
    const advisory = insertFinding(db, scanId, { packageName: 'b', action: 'digest' });
    const gone = insertFinding(db, scanId, { packageName: 'c', action: 'ping' });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-01T00:00:00.000Z',
      finishedAt: '2026-11-01T00:10:00.000Z',
    });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    insertEvent(db, reopened.id, 'reopened', '2026-11-05T00:01:00.000Z');
    insertEvent(db, advisory.id, 'advisory_changed', '2026-11-05T00:01:00.000Z');
    insertEvent(db, gone.id, 'no_longer_matches', '2026-11-05T00:01:00.000Z');
    const since = getInbox(db, 'since');
    expect(since.ping.flatMap((g) => g.items.map((i) => i.findingId))).toEqual([reopened.id]);
    expect(since.digest.flatMap((g) => g.items.map((i) => i.findingId))).toEqual([advisory.id]);
  });

  it('anchors at the refresh that finished before the latest one, even when ids are out of finish order', () => {
    const f = insertFinding(db, scanId, { action: 'ping' });
    // #a started first but finished last (overlapping runs): it is the latest, #b the previous.
    const a = insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:30:00.000Z',
    });
    const b = insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:05:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    insertEvent(db, f.id, 'decision_changed', '2026-11-05T00:20:00.000Z'); // the latest refresh's decide
    const anchor = inboxSinceAnchor(db);
    expect([anchor.latest?.id, anchor.previous?.id]).toEqual([a, b]);
    expect(anchor.sinceAt).toBe('2026-11-05T00:10:00.000Z');
    expect(getInbox(db, 'since').counts.pingFindings).toBe(1);
    expect(lastSucceededRefreshAll(db)?.id).toBe(a);
  });

  it('falls back to all open findings when no refresh-all has succeeded', () => {
    insertFinding(db, scanId, { action: 'ping' });
    insertJob(db, { type: 'refresh-all', status: 'failed', startedAt: '2026-11-06T00:00:00.000Z' });
    const inbox = getInbox(db, 'since');
    expect(inbox.sinceFallback).toBe(true);
    expect(inbox.counts.pingFindings).toBe(1);
  });
});

describe('getInbox with events written by the decide job (review #1/#14)', () => {
  // P1 with a verdict of affected → ping; any other P1 → digest; everything else → log.
  const POLICY = parsePolicy(`
thresholds: { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9.0, cvss_high: 7.0 }
rules:
  - { id: p1-affected, when: { priority: P1, verdict: [affected, likely_affected] }, then: ping }
  - { id: p1-other, when: { priority: P1 }, then: digest }
  - { id: default, when: {}, then: log }
`);

  it('still shows a finding first decided by a Refresh all that then failed, after the next one leaves it unchanged', () => {
    const db = openDb(':memory:');
    const { scanId } = insertProject(db, 'web');
    insertConfig(db, 'cfg-a', true);
    const f = insertFinding(db, scanId, { packageName: 'zod' });
    // As enrich leaves it: EPSS 0.6 on an internet-facing, high-criticality project is P1.
    db.update(findings).set({ epss: 0.6, enrichedAt: '2026-11-03T00:02:00.000Z' }).where(eq(findings.id, f.id)).run();
    const decide = (jobRunId: number, now: string) => decideAll(db, { currentPolicy: POLICY, minPriority: 'P2', jobRunId, now });

    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-01T00:00:00.000Z',
      finishedAt: '2026-11-01T00:10:00.000Z',
    });
    // The failed refresh scanned the finding in and decided it (digest: P1 with triage pending), then failed.
    const failed = insertJob(db, {
      type: 'refresh-all',
      status: 'failed',
      startedAt: '2026-11-03T00:00:00.000Z',
      finishedAt: '2026-11-03T00:10:00.000Z',
    });
    insertEvent(db, f.id, 'created', '2026-11-03T00:01:00.000Z', { jobRunId: insertJob(db, { type: 'scan', parentId: failed }) });
    expect(decide(insertJob(db, { type: 'decide', parentId: failed }), '2026-11-03T00:05:00.000Z')).toMatchObject({ firstDecisions: 1 });
    // The next refresh succeeds and decides the same: no new event for the finding.
    const latest = insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    expect(decide(insertJob(db, { type: 'decide', parentId: latest }), '2026-11-05T00:05:00.000Z')).toMatchObject({
      firstDecisions: 0,
      changed: 0,
    });
    const eventTimes = db
      .select({ at: events.at })
      .from(events)
      .where(eq(events.findingId, f.id))
      .all()
      .map((e) => e.at);
    // The old anchor (the latest refresh's start) saw nothing for this finding.
    expect(eventTimes.every((at) => at < '2026-11-05T00:00:00.000Z')).toBe(true);

    const since = getInbox(db, 'since');
    expect(since.sinceAt).toBe('2026-11-01T00:10:00.000Z');
    expect(since.digest.flatMap((g) => g.items.map((i) => i.findingId))).toEqual([f.id]);

    // Once a further refresh succeeds, the failed run is behind the anchor and the unchanged finding drops out.
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-07T00:00:00.000Z',
      finishedAt: '2026-11-07T00:10:00.000Z',
    });
    expect(getInbox(db, 'since').digest).toEqual([]);
  });

  it('shows a finding whose first decision a standalone Re-evaluate made after the latest refresh', () => {
    const db = openDb(':memory:');
    const { scanId } = insertProject(db, 'web');
    insertConfig(db, 'cfg-a', true);
    const f = insertFinding(db, scanId, { packageName: 'qs' });
    const first = insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-01T00:00:00.000Z',
      finishedAt: '2026-11-01T00:10:00.000Z',
    });
    insertEvent(db, f.id, 'created', '2026-11-01T00:01:00.000Z', { jobRunId: insertJob(db, { type: 'scan', parentId: first }) });
    insertJob(db, {
      type: 'refresh-all',
      status: 'succeeded',
      startedAt: '2026-11-05T00:00:00.000Z',
      finishedAt: '2026-11-05T00:10:00.000Z',
    });
    // Both refreshes left it undecided (enrich had not scored it), and its 'created' is behind the anchor.
    expect(getInbox(db, 'all').counts).toMatchObject({ undecided: 1, unenriched: 1 });
    expect(getInbox(db, 'since').counts).toMatchObject({ undecided: 0, digestFindings: 0 });
    // A manual Enrich, then Re-evaluate policy: the first decision is an event, so the finding shows up.
    db.update(findings).set({ epss: 0.6, enrichedAt: '2026-11-06T00:00:00.000Z' }).where(eq(findings.id, f.id)).run();
    decideAll(db, {
      currentPolicy: POLICY,
      minPriority: 'P2',
      jobRunId: insertJob(db, { type: 'decide' }),
      now: '2026-11-06T00:01:00.000Z',
    });
    expect(getInbox(db, 'since').digest.flatMap((g) => g.items.map((i) => i.findingId))).toEqual([f.id]);
  });
});
