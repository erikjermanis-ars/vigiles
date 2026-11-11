/**
 * Writes one scan's observation and diffs it against the project's findings (spec §7.5), in one
 * transaction: inventory rows, advisory upserts, finding create/update/resolve/reopen, events,
 * and the scan row's final status.
 */
import { and, desc, eq, inArray, ne, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, events, findings, inventory, projects, scans } from '../db/schema';
import type { EventType, FindingOrigin, FindingStatus } from '../types';
import { findingKey, type ObservedFinding, type ScanObservation } from './observe';

export interface ApplyScanInput {
  projectId: string;
  scanId: number;
  jobRunId: number | null;
  observation: ScanObservation;
  lockfiles: string[];
  /**
   * Lockfiles found but not matched this scan (osv-scanner has no extractor for them, OSV has no
   * database for their ecosystem, or the file is unsafe to read). Nothing is known about them, so
   * their findings are left as they are instead of being resolved as fixed.
   */
  skippedLockfiles?: string[];
  /** Replaces scans.coverage_gaps when given */
  coverageGaps?: string[];
  osvDbDate: string | null;
  /** Extra keys merged into scans.stats (timings, warnings, ...) */
  extraStats?: Record<string, unknown>;
  now?: string;
}

export interface ScanDiffStats {
  lockfiles: number;
  packages: number;
  vulnerablePackages: number;
  findingsTotalOpen: number;
  created: number;
  /** Still-present findings refreshed by this scan */
  updated: number;
  /** Still-present findings whose dependency facts or advisory changed */
  factsChanged: number;
  fixed: number;
  noLongerMatches: number;
  reopened: number;
  advisoryChanged: number;
}

type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];
type FindingRow = typeof findings.$inferSelect;
type AdvisoryRow = typeof advisories.$inferInsert;

const CHUNK = 400;

function chunks<T>(items: T[], size = CHUNK): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

const packageKey = (lockfile: string, name: string, version: string) => `${lockfile}\0${name}\0${version}`;

function previousSucceededScan(tx: Tx, projectId: string, scanId: number) {
  return tx
    .select({ id: scans.id })
    .from(scans)
    .where(and(eq(scans.projectId, projectId), eq(scans.status, 'succeeded'), ne(scans.id, scanId)))
    .orderBy(desc(scans.id))
    .limit(1)
    .get();
}

function inventoryKeys(tx: Tx, scanId: number): Set<string> {
  const rows = tx
    .select({ lockfile: inventory.lockfile, name: inventory.name, version: inventory.version })
    .from(inventory)
    .where(eq(inventory.scanId, scanId))
    .all();
  return new Set(rows.map((r) => packageKey(r.lockfile, r.name, r.version)));
}

function upsertAdvisories(tx: Tx, rows: AdvisoryRow[], now: string): void {
  const existing = new Map<string, { raw: unknown; cvssScore: number | null }>();
  for (const ids of chunks(rows.map((r) => r.osvId))) {
    const found = tx
      .select({ osvId: advisories.osvId, raw: advisories.raw, cvssScore: advisories.cvssScore })
      .from(advisories)
      .where(inArray(advisories.osvId, ids))
      .all();
    for (const r of found) existing.set(r.osvId, r);
  }
  for (const row of rows) {
    const prev = existing.get(row.osvId);
    if (prev && prev.cvssScore === (row.cvssScore ?? null) && JSON.stringify(prev.raw) === JSON.stringify(row.raw)) continue;
    const values = { ...row, updatedAt: now };
    tx.insert(advisories).values(values).onConflictDoUpdate({ target: advisories.osvId, set: values }).run();
  }
}

type Facts = Pick<
  ObservedFinding,
  'installedVersions' | 'fixedVersions' | 'direct' | 'devOnly' | 'paths' | 'instances' | 'importSites' | 'importSiteCount'
>;

/** The facts a scan refreshes on a still-present finding (fixed key order, so JSON compares). */
function factsOf(f: Facts): Facts {
  return {
    installedVersions: f.installedVersions,
    fixedVersions: f.fixedVersions,
    direct: f.direct,
    devOnly: f.devOnly,
    paths: f.paths,
    instances: f.instances.map((i) => ({ version: i.version, direct: i.direct, devOnly: i.devOnly, paths: i.paths })),
    importSites: f.importSites,
    importSiteCount: f.importSiteCount,
  };
}

function factsChanged(row: FindingRow, f: ObservedFinding): boolean {
  return JSON.stringify(factsOf(row)) !== JSON.stringify(factsOf(f));
}

export function applyScanResult(db: Db, input: ApplyScanInput): ScanDiffStats {
  const now = input.now ?? new Date().toISOString();
  const { observation: obs, projectId, scanId } = input;
  const stats: ScanDiffStats = {
    lockfiles: input.lockfiles.length,
    packages: obs.packages,
    vulnerablePackages: obs.vulnerablePackages,
    findingsTotalOpen: 0,
    created: 0,
    updated: 0,
    factsChanged: 0,
    fixed: 0,
    noLongerMatches: 0,
    reopened: 0,
    advisoryChanged: 0,
  };

  db.transaction((tx) => {
    const addEvent = (findingId: number, type: EventType, data: Record<string, unknown>) =>
      tx
        .insert(events)
        .values({ findingId, type, jobRunId: input.jobRunId, data: { scanId, ...data }, at: now })
        .run();

    const previous = previousSucceededScan(tx, projectId, scanId);
    const previousInventory = previous ? inventoryKeys(tx, previous.id) : new Set<string>();

    for (const batch of chunks(obs.inventory)) {
      tx.insert(inventory)
        .values(batch.map((i) => ({ scanId, ...i })))
        .run();
    }
    const currentInventory = new Set(obs.inventory.map((i) => packageKey(i.lockfile, i.name, i.version)));

    upsertAdvisories(tx, obs.advisories, now);

    const existing = new Map(
      tx
        .select()
        .from(findings)
        .where(eq(findings.projectId, projectId))
        .all()
        .map((row) => [findingKey(row), row]),
    );

    const originOf = (f: ObservedFinding): FindingOrigin => {
      if (!previous) return 'baseline';
      const wasInstalled = f.installedVersions.some((v) => previousInventory.has(packageKey(f.lockfile, f.packageName, v)));
      return wasInstalled ? 'new_advisory' : 'new_dependency';
    };

    const seen = new Set<string>();
    for (const f of obs.findings) {
      const key = findingKey(f);
      seen.add(key);
      const row = existing.get(key);

      if (!row) {
        const origin = originOf(f);
        const inserted = tx
          .insert(findings)
          .values({
            projectId,
            lockfile: f.lockfile,
            ecosystem: f.ecosystem,
            packageName: f.packageName,
            osvId: f.osvId,
            ...factsOf(f),
            status: 'open',
            origin,
            firstSeenScanId: scanId,
            lastSeenScanId: scanId,
            firstSeenAt: now,
            advisoryModified: f.advisoryModified,
            createdAt: now,
            updatedAt: now,
          })
          .returning({ id: findings.id })
          .get();
        addEvent(inserted.id, 'created', { origin });
        stats.created++;
        continue;
      }

      const advisoryChanged = row.advisoryModified !== f.advisoryModified;
      const changed = advisoryChanged || factsChanged(row, f);
      const reopening = row.status !== 'open';
      tx.update(findings)
        .set({
          ...factsOf(f),
          lastSeenScanId: scanId,
          advisoryModified: f.advisoryModified,
          ...(reopening ? { status: 'open' as const, resolvedAt: null } : {}),
          ...(changed || reopening ? { updatedAt: now } : {}),
        })
        .where(eq(findings.id, row.id))
        .run();
      if (reopening) {
        addEvent(row.id, 'reopened', { from: row.status });
        stats.reopened++;
      } else {
        stats.updated++;
        if (changed) stats.factsChanged++;
      }
      if (advisoryChanged) {
        addEvent(row.id, 'advisory_changed', { from: row.advisoryModified, to: f.advisoryModified });
        stats.advisoryChanged++;
      }
    }

    const skipped = new Set(input.skippedLockfiles ?? []);
    for (const [key, row] of existing) {
      if (seen.has(key) || row.status !== 'open' || skipped.has(row.lockfile)) continue;
      const stillInstalled = row.installedVersions.filter((v) => currentInventory.has(packageKey(row.lockfile, row.packageName, v)));
      const status: FindingStatus = stillInstalled.length ? 'no_longer_matches' : 'fixed';
      tx.update(findings).set({ status, resolvedAt: now, updatedAt: now }).where(eq(findings.id, row.id)).run();
      if (status === 'fixed') {
        addEvent(row.id, 'fixed', { installedVersions: row.installedVersions });
        stats.fixed++;
      } else {
        addEvent(row.id, 'no_longer_matches', { stillInstalled });
        stats.noLongerMatches++;
      }
    }

    stats.findingsTotalOpen =
      tx
        .select({ n: sql<number>`count(*)` })
        .from(findings)
        .where(and(eq(findings.projectId, projectId), eq(findings.status, 'open')))
        .get()?.n ?? 0;

    tx.update(scans)
      .set({
        status: 'succeeded',
        stats: { ...stats, ...input.extraStats },
        osvDbDate: input.osvDbDate,
        ...(input.coverageGaps ? { coverageGaps: input.coverageGaps } : {}),
        finishedAt: now,
        error: null,
      })
      .where(eq(scans.id, scanId))
      .run();
    tx.update(projects).set({ lastScanId: scanId }).where(eq(projects.id, projectId)).run();
  });

  return stats;
}
