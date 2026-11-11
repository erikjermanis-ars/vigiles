/** Synthetic fixtures and stubs shared by the signals and job tests. Not used at runtime. */
import { loadVigilesConfig, repoRoot } from '../config/load';
import type { Db } from '../db/client';
import { advisories, findings, jobRuns, projects } from '../db/schema';
import { CancelledError, type JobContext } from '../jobs/types';
import { ProjectProfileSchema, type Criticality, type Exposure, type JobType } from '../types';
import type { FetchFn } from './http';
import type { PriorityThresholds } from './priority';

export const THRESHOLDS: PriorityThresholds = { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9.0, cvss_high: 7.0 };

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

export interface RecordedCall {
  url: string;
  init?: RequestInit;
}

/** A fetch stub that records calls and answers through `respond`. */
export function stubFetch(
  respond: (url: string, init?: RequestInit) => Response | Promise<Response>,
): FetchFn & { calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fn = async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return respond(url, init);
  };
  return Object.assign(fn, { calls });
}

/** Serves EPSS scores from a table, the way api.first.org does (unknown CVEs are simply absent). */
export function epssApiStub(table: Record<string, number>, date = '2026-11-09') {
  return stubFetch((url) => {
    const cves = new URL(url).searchParams.get('cve')?.split(',') ?? [];
    const data = cves
      .filter((c) => c in table)
      .map((cve) => ({ cve, epss: table[cve]!.toFixed(9), percentile: Math.min(1, table[cve]! + 0.3).toFixed(9), date }));
    return jsonResponse({ status: 'OK', 'status-code': 200, total: data.length, data });
  });
}

export function kevFeed(entries: { cveID: string; dateAdded: string }[]) {
  return {
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    catalogVersion: '2026.11.10',
    dateReleased: '2026-11-10T15:00:00.000Z',
    count: entries.length,
    vulnerabilities: entries.map((e) => ({
      ...e,
      vendorProject: 'Vendor',
      product: 'Product',
      vulnerabilityName: `Vuln ${e.cveID}`,
      shortDescription: 'A synthetic entry.',
      requiredAction: 'Apply updates.',
      dueDate: '2027-01-01',
      knownRansomwareCampaignUse: 'Unknown',
      notes: '',
      cwes: ['CWE-20'],
    })),
  };
}

export function seedProject(db: Db, id: string, exposure: Exposure, criticality: Criticality): void {
  const profile = ProjectProfileSchema.parse({ id, name: id, repo_path: `/nonexistent/${id}`, exposure, criticality });
  db.insert(projects).values({ id, name: id, repoPath: profile.repo_path, ref: profile.ref, profile, profileHash: 'test' }).run();
}

export function seedAdvisory(
  db: Db,
  osvId: string,
  fields: { cves?: string[]; cvssScore?: number | null; severityLabel?: string | null; malicious?: boolean } = {},
): void {
  db.insert(advisories)
    .values({
      osvId,
      cves: fields.cves ?? [],
      aliases: fields.cves ?? [],
      cvssScore: fields.cvssScore ?? null,
      severityLabel: fields.severityLabel ?? null,
      malicious: fields.malicious ?? false,
      raw: { id: osvId },
    })
    .run();
}

export function seedFinding(
  db: Db,
  projectId: string,
  osvId: string,
  extra: Partial<typeof findings.$inferInsert> = {},
): number {
  return db
    .insert(findings)
    .values({
      projectId,
      lockfile: 'package-lock.json',
      ecosystem: 'npm',
      packageName: `pkg-${osvId.toLowerCase()}`,
      osvId,
      origin: 'baseline',
      firstSeenScanId: 1,
      lastSeenScanId: 1,
      ...extra,
    })
    .returning({ id: findings.id })
    .get().id;
}

/** A JobContext over an in-memory DB, without the runner: logs are collected, runChild is unsupported. */
export function fakeJobContext(db: Db, type: JobType): JobContext & { logs: string[]; controller: AbortController } {
  const root = repoRoot();
  const logs: string[] = [];
  const controller = new AbortController();
  const jobId = db.insert(jobRuns).values({ type, status: 'running' }).returning({ id: jobRuns.id }).get().id;
  const scratch = '/nonexistent/vigiles-test';
  return {
    db,
    jobId,
    type,
    params: {},
    config: loadVigilesConfig(root),
    paths: { root: scratch, db: ':memory:', osvDb: scratch, snapshots: scratch, logs: scratch, scratch },
    root,
    signal: controller.signal,
    log: (m) => logs.push(m),
    progress: () => {},
    throwIfCancelled: () => {
      if (controller.signal.aborted) throw new CancelledError();
    },
    runChild: async () => {
      throw new Error('runChild is not available in tests');
    },
    logs,
    controller,
  };
}
