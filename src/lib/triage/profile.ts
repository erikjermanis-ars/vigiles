/**
 * The part of a project profile that triage sees (spec §9.1, §9.2). The prompt renders exactly
 * `triageVisibleProfile(profile)`, and the triage input hash covers exactly that object, so editing a
 * scanner-only setting (repo path, fetch, excludes, lockfiles, enabled) never invalidates a verdict.
 * Kept free of other Vigiles imports so config loading and prompt rendering can both use it.
 */
import { createHash } from 'node:crypto';
import type { ProjectProfile } from '../types';

/** Scanner settings in the profile that say nothing about how the project runs; never shown to the model. */
export const HIDDEN_PROFILE_KEYS = ['repo_path', 'enabled', 'fetch_before_scan', 'exclude', 'lockfiles'] as const;

/** The profile minus HIDDEN_PROFILE_KEYS, in the profile's own key order (what renderProfile serialises). */
export function triageVisibleProfile(profile: ProjectProfile): Record<string, unknown> {
  const visible: Record<string, unknown> = { ...profile };
  for (const key of HIDDEN_PROFILE_KEYS) delete visible[key];
  return visible;
}

/** sha256 of the JSON of the triage-visible profile, first 12 hex chars (projects.triage_profile_hash). */
export function triageProfileHash(profile: ProjectProfile): string {
  return createHash('sha256').update(JSON.stringify(triageVisibleProfile(profile))).digest('hex').slice(0, 12);
}
