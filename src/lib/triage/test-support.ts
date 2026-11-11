/** Test fixtures for the triage module (in-memory DB rows). Not used at runtime. */
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, findings, labels, projects, scans, triageConfigs, triageRuns } from '../db/schema';
import type { Priority, ProjectProfile, TriageRunStatus } from '../types';

export const PROFILE: ProjectProfile = {
  id: 'demo',
  name: 'Demo',
  enabled: true,
  repo_path: '/nonexistent/demo',
  ref: 'origin/main',
  fetch_before_scan: false,
  exclude: [],
  owners: [],
  criticality: 'high',
  exposure: 'internet-facing',
  data_classes: [],
  runtime: { language: 'typescript' },
  deployments: [{ env: 'production', hosting: 'Linux container' }],
  third_party_services: [],
  mitigations: '',
  notes: '',
};

export function seedProject(db: Db, opts: { id?: string; repoPath?: string; commitSha?: string | null; enabled?: boolean } = {}) {
  const id = opts.id ?? 'demo';
  const profile = { ...PROFILE, id, repo_path: opts.repoPath ?? PROFILE.repo_path };
  db.insert(projects)
    .values({
      id,
      name: id,
      enabled: opts.enabled ?? true,
      repoPath: profile.repo_path,
      ref: 'origin/main',
      profile,
      profileHash: `hash-${id}`,
    })
    .run();
  const scan = db
    .insert(scans)
    .values({ projectId: id, ref: 'origin/main', commitSha: opts.commitSha === undefined ? 'abc123' : opts.commitSha, status: 'succeeded' })
    .returning({ id: scans.id })
    .get();
  return { projectId: id, scanId: scan.id };
}

export function seedConfig(db: Db, name = 'cfg', opts: { codeAccess?: boolean; model?: string } = {}) {
  return db
    .insert(triageConfigs)
    .values({
      name,
      promptVersion: 'v1',
      model: opts.model ?? 'sonnet',
      effort: 'high',
      codeAccess: opts.codeAccess ?? false,
      active: true,
    })
    .returning()
    .get();
}

export interface FindingSeed {
  projectId?: string;
  scanId: number;
  osvId?: string;
  packageName?: string;
  priority?: Priority | null;
  epss?: number | null;
  cvss?: number | null;
  status?: 'open' | 'fixed';
  malicious?: boolean;
  /** Goes into the advisory details, i.e. into the prompt (used to steer the fake claude) */
  details?: string;
  modified?: string;
}

let seq = 0;
export function seedFinding(db: Db, f: FindingSeed) {
  const osvId = f.osvId ?? `GHSA-test-${++seq}`;
  const packageName = f.packageName ?? 'zod';
  db.insert(advisories)
    .values({
      osvId,
      summary: `Test advisory ${osvId}`,
      details: f.details ?? 'Details.',
      modified: f.modified ?? '2026-10-01T00:00:00Z',
      malicious: f.malicious ?? false,
      cvssScore: f.cvss ?? null,
      raw: {
        id: osvId,
        affected: [
          {
            package: { name: packageName, ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }],
          },
        ],
      },
    })
    .onConflictDoNothing()
    .run();
  return db
    .insert(findings)
    .values({
      projectId: f.projectId ?? 'demo',
      lockfile: 'package-lock.json',
      ecosystem: 'npm',
      packageName,
      osvId,
      installedVersions: ['1.0.0'],
      fixedVersions: ['9.9.9'],
      direct: true,
      devOnly: false,
      paths: [[packageName]],
      importSites: [],
      status: f.status ?? 'open',
      origin: 'baseline',
      firstSeenScanId: f.scanId,
      lastSeenScanId: f.scanId,
      priority: f.priority === undefined ? 'P2' : f.priority,
      epss: f.epss ?? null,
      cvssScore: f.cvss ?? null,
    })
    .returning()
    .get();
}

export function seedRun(db: Db, findingId: number, configName: string, inputHash: string, status: TriageRunStatus) {
  db.insert(triageRuns).values({ findingId, configName, inputHash, status, prompt: 'p' }).run();
}

export function seedLabel(db: Db, findingId: number) {
  db.insert(labels).values({ findingId, expectedAction: 'digest' }).run();
}

export function setAdvisoryModified(db: Db, osvId: string, modified: string) {
  db.update(advisories).set({ modified }).where(eq(advisories.osvId, osvId)).run();
}
