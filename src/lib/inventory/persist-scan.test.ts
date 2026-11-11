import { asc, eq } from 'drizzle-orm';
import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { advisories, events, findings, inventory, projects, scans } from '../db/schema';
import type { AdvisoryInsert } from '../osv/output';
import type { ProjectProfile } from '../types';
import type { InventoryItem, ObservedFinding, ScanObservation } from './observe';
import { applyScanResult } from './persist-scan';

const PROJECT = 'demo';
const LOCK = 'package-lock.json';

const profile: ProjectProfile = {
  id: PROJECT,
  name: 'Demo',
  enabled: true,
  repo_path: '/nowhere',
  ref: 'origin/main',
  fetch_before_scan: false,
  exclude: [],
  owners: [],
  criticality: 'medium',
  exposure: 'internal',
  data_classes: [],
  runtime: {},
  deployments: [],
  third_party_services: [],
  mitigations: '',
  notes: '',
};

/** A package@version installed in the lockfile, with the advisories (id → modified) that match it. */
interface Pkg {
  name: string;
  version: string;
  advisories?: Record<string, string>;
  /** The instance is marked dev in the lockfile */
  dev?: boolean;
  /** Uncapped import-site count for findings of this package */
  importSiteCount?: number;
}

function observation(pkgs: Pkg[]): ScanObservation {
  const inv: InventoryItem[] = pkgs.map((p) => ({
    lockfile: LOCK,
    ecosystem: 'npm',
    name: p.name,
    version: p.version,
    direct: true,
    devOnly: false,
  }));
  const byKey = new Map<string, ObservedFinding>();
  const advs = new Map<string, AdvisoryInsert>();
  for (const p of pkgs) {
    for (const [osvId, modified] of Object.entries(p.advisories ?? {})) {
      const key = `${p.name}|${osvId}`;
      const f = byKey.get(key) ?? {
        lockfile: LOCK,
        ecosystem: 'npm',
        packageName: p.name,
        osvId,
        installedVersions: [],
        fixedVersions: ['9.9.9'],
        direct: true,
        devOnly: true,
        paths: [[p.name]],
        instances: [],
        importSites: [],
        importSiteCount: p.importSiteCount ?? 0,
        advisoryModified: modified,
      };
      f.installedVersions.push(p.version);
      f.instances.push({ version: p.version, direct: true, devOnly: p.dev ?? false, paths: [[p.name]] });
      f.devOnly = f.instances.every((i) => i.devOnly);
      byKey.set(key, f);
      advs.set(osvId, { osvId, modified, raw: { id: osvId, modified }, cvssScore: 7.5 });
    }
  }
  const findingsList = [...byKey.values()];
  return {
    inventory: inv,
    findings: findingsList,
    advisories: [...advs.values()],
    packages: inv.length,
    vulnerablePackages: new Set(findingsList.flatMap((f) => f.installedVersions.map((v) => `${f.packageName}@${v}`))).size,
  };
}

let db: Db;
let jobRunId = 100;

function runScan(pkgs: Pkg[], opts: { fail?: boolean; skipped?: string[]; coverageGaps?: string[] } = {}) {
  const scanId = db
    .insert(scans)
    .values({ projectId: PROJECT, ref: 'origin/main', status: 'running' })
    .returning({ id: scans.id })
    .get().id;
  jobRunId++;
  if (opts.fail) {
    db.update(scans).set({ status: 'failed', error: 'boom' }).where(eq(scans.id, scanId)).run();
    return { scanId, stats: null };
  }
  const stats = applyScanResult(db, {
    projectId: PROJECT,
    scanId,
    jobRunId,
    observation: observation(pkgs),
    lockfiles: [LOCK],
    skippedLockfiles: opts.skipped,
    coverageGaps: opts.coverageGaps,
    osvDbDate: '2026-11-10T00:00:00.000Z',
    now: `2026-11-10T00:00:${String(scanId).padStart(2, '0')}.000Z`,
  });
  return { scanId, stats };
}

const row = (name: string, osvId: string) =>
  db
    .select()
    .from(findings)
    .where(eq(findings.packageName, name))
    .all()
    .find((f) => f.osvId === osvId)!;

const eventsOf = (findingId: number) =>
  db
    .select()
    .from(events)
    .where(eq(events.findingId, findingId))
    .orderBy(asc(events.id))
    .all()
    .map((e) => e.type);

const eventsFor = (scanJobRunId: number) => db.select().from(events).where(eq(events.jobRunId, scanJobRunId)).all();

beforeEach(() => {
  db = openDb(':memory:');
  db.insert(projects).values({ id: PROJECT, name: 'Demo', repoPath: '/nowhere', ref: 'origin/main', profile, profileHash: 'h' }).run();
});

describe('applyScanResult (§7.5 diff)', () => {
  const baseline: Pkg[] = [
    { name: 'a', version: '1.0.0', advisories: { 'GHSA-a1': 'm1' } },
    { name: 'b', version: '2.0.0', advisories: { 'GHSA-b1': 'm1' } },
    { name: 'c', version: '3.0.0' },
  ];

  it('first successful scan creates baseline findings with created events', () => {
    const { scanId, stats } = runScan(baseline);
    expect(stats).toMatchObject({ lockfiles: 1, packages: 3, vulnerablePackages: 2, created: 2, findingsTotalOpen: 2, fixed: 0 });
    const a = row('a', 'GHSA-a1');
    expect(a).toMatchObject({
      status: 'open',
      origin: 'baseline',
      firstSeenScanId: scanId,
      lastSeenScanId: scanId,
      installedVersions: ['1.0.0'],
      advisoryModified: 'm1',
      paths: [['a']],
    });
    const created = eventsFor(jobRunId);
    expect(created).toHaveLength(2);
    expect(created[0]).toMatchObject({ type: 'created', data: { origin: 'baseline', scanId } });

    const scan = db.select().from(scans).where(eq(scans.id, scanId)).get()!;
    expect(scan).toMatchObject({ status: 'succeeded', osvDbDate: '2026-11-10T00:00:00.000Z' });
    expect(scan.stats).toMatchObject({ created: 2, findingsTotalOpen: 2 });
    expect(db.select().from(projects).get()!.lastScanId).toBe(scanId);
    expect(db.select().from(inventory).where(eq(inventory.scanId, scanId)).all()).toHaveLength(3);
    expect(
      db
        .select()
        .from(advisories)
        .all()
        .map((r) => r.osvId)
        .sort(),
    ).toEqual(['GHSA-a1', 'GHSA-b1']);
  });

  it('an identical rescan writes no events and creates no duplicates', () => {
    runScan(baseline);
    const before = db.select().from(findings).all();
    const { stats } = runScan(baseline);
    expect(stats).toMatchObject({
      created: 0,
      updated: 2,
      factsChanged: 0,
      fixed: 0,
      reopened: 0,
      advisoryChanged: 0,
      findingsTotalOpen: 2,
    });
    expect(eventsFor(jobRunId)).toEqual([]);
    const after = db.select().from(findings).all();
    expect(after).toHaveLength(2);
    expect(after.map((f) => f.updatedAt)).toEqual(before.map((f) => f.updatedAt));
  });

  it('classifies new findings as new_dependency or new_advisory against the previous succeeded scan', () => {
    runScan(baseline);
    runScan([], { fail: true }); // a failed scan in between is not "previous"
    runScan([
      { name: 'a', version: '1.0.0', advisories: { 'GHSA-a1': 'm1', 'GHSA-a2': 'm1' } }, // new advisory on an installed version
      { name: 'b', version: '2.0.0', advisories: { 'GHSA-b1': 'm1' } },
      { name: 'c', version: '3.1.0', advisories: { 'GHSA-c1': 'm1' } }, // upgraded into a vulnerable version
      { name: 'd', version: '1.0.0', advisories: { 'GHSA-d1': 'm1' } }, // brand-new package
    ]);
    expect(row('a', 'GHSA-a2').origin).toBe('new_advisory');
    expect(row('c', 'GHSA-c1').origin).toBe('new_dependency');
    expect(row('d', 'GHSA-d1').origin).toBe('new_dependency');
    expect(eventsFor(jobRunId).map((e) => [e.type, (e.data as { origin?: string }).origin])).toEqual([
      ['created', 'new_advisory'],
      ['created', 'new_dependency'],
      ['created', 'new_dependency'],
    ]);
  });

  it('upgrading past the fix marks the finding fixed', () => {
    runScan(baseline);
    const { stats } = runScan([baseline[0]!, { name: 'b', version: '2.0.1' }, baseline[2]!]);
    expect(stats).toMatchObject({ fixed: 1, noLongerMatches: 0, findingsTotalOpen: 1 });
    const b = row('b', 'GHSA-b1');
    expect(b.status).toBe('fixed');
    expect(b.resolvedAt).not.toBeNull();
    expect(eventsOf(b.id)).toEqual(['created', 'fixed']);
  });

  it('removing the package entirely also marks it fixed', () => {
    runScan(baseline);
    runScan([baseline[0]!, baseline[2]!]);
    expect(row('b', 'GHSA-b1').status).toBe('fixed');
  });

  it('an advisory that stops matching while the version stays is no_longer_matches', () => {
    runScan(baseline);
    const { stats } = runScan([baseline[0]!, { name: 'b', version: '2.0.0' }, baseline[2]!]);
    expect(stats).toMatchObject({ fixed: 0, noLongerMatches: 1 });
    const b = row('b', 'GHSA-b1');
    expect(b.status).toBe('no_longer_matches');
    const ev = db.select().from(events).where(eq(events.findingId, b.id)).all().at(-1)!;
    expect(ev).toMatchObject({ type: 'no_longer_matches', data: { stillInstalled: ['2.0.0'] }, jobRunId });
  });

  it('a changed advisory modified date writes advisory_changed and stores the new date', () => {
    runScan(baseline);
    const { stats } = runScan([{ name: 'a', version: '1.0.0', advisories: { 'GHSA-a1': 'm2' } }, baseline[1]!, baseline[2]!]);
    expect(stats).toMatchObject({ advisoryChanged: 1, factsChanged: 1, created: 0 });
    const a = row('a', 'GHSA-a1');
    expect(a.advisoryModified).toBe('m2');
    const ev = db.select().from(events).where(eq(events.findingId, a.id)).all().at(-1)!;
    expect(ev).toMatchObject({ type: 'advisory_changed', data: { from: 'm1', to: 'm2' } });
    expect(db.select().from(advisories).where(eq(advisories.osvId, 'GHSA-a1')).get()!.modified).toBe('m2');
  });

  it('updates facts on still-present findings without an event', () => {
    runScan(baseline);
    const { stats } = runScan([baseline[0]!, { name: 'a', version: '1.5.0', advisories: { 'GHSA-a1': 'm1' } }, baseline[1]!, baseline[2]!]);
    expect(stats).toMatchObject({ updated: 2, factsChanged: 1 });
    expect(row('a', 'GHSA-a1').installedVersions).toEqual(['1.0.0', '1.5.0']);
    expect(eventsFor(jobRunId)).toEqual([]);
  });

  it('stores per-version instances and the uncapped import-site count (review #31/#32)', () => {
    runScan([
      { name: 'a', version: '1.0.0', dev: true, importSiteCount: 37, advisories: { 'GHSA-a1': 'm1' } },
      { name: 'a', version: '1.5.0', advisories: { 'GHSA-a1': 'm1' } },
    ]);
    expect(row('a', 'GHSA-a1')).toMatchObject({
      devOnly: false,
      importSiteCount: 37,
      instances: [
        { version: '1.0.0', direct: true, devOnly: true, paths: [['a']] },
        { version: '1.5.0', direct: true, devOnly: false, paths: [['a']] },
      ],
    });
  });

  it('treats a change in one instance as a facts change even when the merged view is the same', () => {
    runScan([
      { name: 'a', version: '1.0.0', dev: true, advisories: { 'GHSA-a1': 'm1' } },
      { name: 'a', version: '1.5.0', advisories: { 'GHSA-a1': 'm1' } },
    ]);
    const { stats } = runScan([
      { name: 'a', version: '1.0.0', advisories: { 'GHSA-a1': 'm1' } },
      { name: 'a', version: '1.5.0', dev: true, advisories: { 'GHSA-a1': 'm1' } },
    ]);
    expect(stats).toMatchObject({ updated: 1, factsChanged: 1 });
    const a = row('a', 'GHSA-a1');
    expect(a.devOnly).toBe(false);
    expect(a.instances.map((i) => [i.version, i.devOnly])).toEqual([
      ['1.0.0', false],
      ['1.5.0', true],
    ]);
  });

  it('fills in instances and the site count on findings stored before those columns existed', () => {
    runScan(baseline);
    db.update(findings).set({ instances: [], importSiteCount: 0 }).run();
    const { stats } = runScan(baseline.map((p) => ({ ...p, importSiteCount: 3 })));
    expect(stats).toMatchObject({ updated: 2, factsChanged: 2 });
    expect(row('a', 'GHSA-a1')).toMatchObject({
      importSiteCount: 3,
      instances: [{ version: '1.0.0', direct: true, devOnly: false, paths: [['a']] }],
    });
  });

  it('a resolved finding that reappears is reopened, keeping its origin', () => {
    runScan(baseline);
    runScan([baseline[0]!, { name: 'b', version: '2.0.1' }, baseline[2]!]); // fixed
    const { stats } = runScan(baseline); // downgraded again
    expect(stats).toMatchObject({ reopened: 1, created: 0, findingsTotalOpen: 2 });
    const b = row('b', 'GHSA-b1');
    expect(b).toMatchObject({ status: 'open', resolvedAt: null, origin: 'baseline' });
    expect(eventsOf(b.id)).toEqual(['created', 'fixed', 'reopened']);
    const ev = db.select().from(events).where(eq(events.findingId, b.id)).all().at(-1)!;
    expect(ev.data).toMatchObject({ from: 'fixed' });
    expect(db.select().from(findings).all()).toHaveLength(2);
  });

  it('does not touch findings of other projects or already-resolved ones', () => {
    db.insert(projects)
      .values({ id: 'other', name: 'Other', repoPath: '/x', ref: 'main', profile: { ...profile, id: 'other' }, profileHash: 'h' })
      .run();
    const other = db
      .insert(findings)
      .values({
        projectId: 'other',
        lockfile: LOCK,
        ecosystem: 'npm',
        packageName: 'a',
        osvId: 'GHSA-a1',
        origin: 'baseline',
        firstSeenScanId: 999,
        lastSeenScanId: 999,
      })
      .returning({ id: findings.id })
      .get();
    runScan(baseline);
    runScan([baseline[2]!]); // a and b fixed
    const { stats } = runScan([baseline[2]!]);
    expect(stats).toMatchObject({ fixed: 0, noLongerMatches: 0, findingsTotalOpen: 0 });
    expect(eventsFor(jobRunId)).toEqual([]);
    expect(db.select().from(findings).where(eq(findings.id, other.id)).get()!.status).toBe('open');
    expect(eventsOf(other.id)).toEqual([]);
  });

  it('rewrites an advisory row only when the record or score changed', () => {
    runScan(baseline);
    const first = db.select().from(advisories).where(eq(advisories.osvId, 'GHSA-b1')).get()!;
    runScan(baseline);
    expect(db.select().from(advisories).where(eq(advisories.osvId, 'GHSA-b1')).get()!.updatedAt).toBe(first.updatedAt);
  });

  it('leaves the findings of a lockfile that could not be matched this scan untouched', () => {
    runScan(baseline);
    const before = row('b', 'GHSA-b1');
    // The lockfile was found but not matched (e.g. no osv-scanner extractor): no packages observed.
    const { scanId, stats } = runScan([], { skipped: [LOCK], coverageGaps: [LOCK] });
    expect(stats).toMatchObject({ fixed: 0, noLongerMatches: 0, findingsTotalOpen: 2 });
    expect(row('b', 'GHSA-b1')).toEqual(before);
    expect(eventsFor(jobRunId)).toEqual([]);
    expect(db.select().from(scans).where(eq(scans.id, scanId)).get()!.coverageGaps).toEqual([LOCK]);
    // Matched again later: the findings are simply still present.
    expect(runScan(baseline).stats).toMatchObject({ created: 0, updated: 2, fixed: 0, reopened: 0 });
  });

  it('marks the scan succeeded and points the project at it only when the diff commits', () => {
    runScan(baseline);
    const first = db.select().from(projects).get()!.lastScanId;
    const scanId = db
      .insert(scans)
      .values({ projectId: PROJECT, ref: 'origin/main', status: 'running' })
      .returning({ id: scans.id })
      .get().id;
    const broken = observation(baseline);
    // A duplicate finding key violates the unique index part-way through the transaction.
    broken.findings.push({ ...broken.findings[0]!, osvId: 'GHSA-new' }, { ...broken.findings[0]!, osvId: 'GHSA-new' });
    expect(() =>
      applyScanResult(db, { projectId: PROJECT, scanId, jobRunId: 1, observation: broken, lockfiles: [LOCK], osvDbDate: null }),
    ).toThrow();
    expect(db.select().from(scans).where(eq(scans.id, scanId)).get()!.status).toBe('running');
    expect(db.select().from(inventory).where(eq(inventory.scanId, scanId)).all()).toEqual([]);
    expect(db.select().from(findings).all()).toHaveLength(2);
    expect(db.select().from(projects).get()!.lastScanId).toBe(first);
  });
});
