/**
 * Resolves a finding's triage state under one triage config (spec §9.1, §10):
 *   skipped  – malicious package, or priority below triage.min_priority (never sent to the LLM)
 *   ok       – a successful run exists for the current input hash  → its output is used
 *   failed   – the latest run for the current input hash failed     → policy treats it as no verdict
 *   pending  – no run for the current input hash yet (inputs changed, or never triaged)
 * Shared by the triage job (what to run), the decide job (which verdict counts) and the UI.
 */
import { and, desc, eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, findings, projects, triageConfigs, triageRuns } from '../db/schema';
import { PRIORITIES, type Priority, type TriageStatus } from '../types';
import { computeInputHash, promptFingerprint } from './input-hash';
import { triageProfileHash } from './profile';

type FindingRow = typeof findings.$inferSelect;
type TriageRunRow = typeof triageRuns.$inferSelect;
type TriageConfigRow = typeof triageConfigs.$inferSelect;

export interface TriageState {
  status: TriageStatus;
  inputHash: string;
  /** The ok run (status=ok) or the latest failed run (status=failed) for the current hash */
  run: TriageRunRow | null;
  /** Why it was skipped, when status=skipped */
  reason?: string;
}

export function priorityAtLeast(p: Priority | null, min: Priority): boolean {
  if (!p) return false;
  return PRIORITIES.indexOf(p) <= PRIORITIES.indexOf(min);
}

/**
 * projects.triage_profile_hash, or the same hash computed from the stored profile while the column is
 * still empty (rows written before the column existed, until the next config sync).
 */
function projectTriageHash(db: Db, projectId: string): string {
  const stored = db.select({ h: projects.triageProfileHash }).from(projects).where(eq(projects.id, projectId)).get();
  if (!stored) return '';
  if (stored.h) return stored.h;
  // Only parse the profile JSON in the rare case the column is empty (this runs once per finding on list pages).
  const row = db.select({ profile: projects.profile }).from(projects).where(eq(projects.id, projectId)).get();
  return row ? triageProfileHash(row.profile) : '';
}

export function findingInputHash(db: Db, finding: FindingRow, config: TriageConfigRow): string {
  const adv = db.select({ m: advisories.modified }).from(advisories).where(eq(advisories.osvId, finding.osvId)).get();
  return computeInputHash({
    advisoryModified: adv?.m ?? finding.advisoryModified ?? null,
    installedVersions: finding.installedVersions,
    fixedVersions: finding.fixedVersions,
    direct: finding.direct,
    devOnly: finding.devOnly,
    paths: finding.paths,
    instances: finding.instances,
    importSites: finding.importSites,
    importSiteCount: finding.importSiteCount,
    // Only what the prompt shows: scanner-only profile keys (enabled, exclude, ...) never invalidate a verdict.
    projectProfileHash: projectTriageHash(db, finding.projectId),
    // Version plus a hash of the prompt files, so editing prompts/triage/<v>.* in place invalidates cached runs.
    promptVersion: promptFingerprint(config.promptVersion),
    model: config.model,
    effort: config.effort,
    codeAccess: config.codeAccess,
  });
}

export function resolveTriageState(
  db: Db,
  finding: FindingRow,
  config: TriageConfigRow,
  minPriority: Priority,
  opts: { ignoreMinPriority?: boolean } = {},
): TriageState {
  const inputHash = findingInputHash(db, finding, config);
  const adv = db.select({ malicious: advisories.malicious }).from(advisories).where(eq(advisories.osvId, finding.osvId)).get();
  if (adv?.malicious) return { status: 'skipped', inputHash, run: null, reason: 'malicious package (no LLM needed)' };

  const runs = db
    .select()
    .from(triageRuns)
    .where(and(eq(triageRuns.findingId, finding.id), eq(triageRuns.configName, config.name), eq(triageRuns.inputHash, inputHash)))
    .orderBy(desc(triageRuns.id))
    .all();
  const ok = runs.find((r) => r.status === 'ok');
  if (ok) return { status: 'ok', inputHash, run: ok };
  if (!opts.ignoreMinPriority && !priorityAtLeast(finding.priority, minPriority)) {
    return { status: 'skipped', inputHash, run: null, reason: `priority ${finding.priority ?? 'none'} below ${minPriority}` };
  }
  const latest = runs[0];
  if (latest && latest.status !== 'cancelled') return { status: 'failed', inputHash, run: latest };
  return { status: 'pending', inputHash, run: null };
}
