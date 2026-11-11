/**
 * Triage input hash (spec §9.1). A finding needs (re-)triage under a config when no successful run
 * exists for its current hash. Shared by the triage job (selection) and the decide job (which run counts).
 */
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { repoRoot, sha256 } from '../config/load';
import type { FindingInstance } from '../types';

const PROMPT_FILES = ['system.md', 'user.md', 'schema.json'];
const fingerprintCache = new Map<string, { key: string; value: string }>();

/**
 * `<version>@<hash of the version's prompt files>`. Cached per process and refreshed when a file's
 * mtime or size changes. Missing files hash as empty (the triage job reports them separately).
 */
export function promptFingerprint(version: string, root = repoRoot()): string {
  const files = PROMPT_FILES.map((f) => path.join(root, 'prompts/triage', `${version}.${f}`));
  const statKey = files
    .map((f) => {
      const st = statSync(f, { throwIfNoEntry: false });
      return st ? `${st.mtimeMs}:${st.size}` : 'missing';
    })
    .join('|');
  const cacheKey = `${root}\0${version}`;
  const cached = fingerprintCache.get(cacheKey);
  if (cached && cached.key === statKey) return cached.value;
  const content = files
    .map((f) => {
      try {
        return readFileSync(f, 'utf8');
      } catch {
        return '';
      }
    })
    .join('\0');
  const value = `${version}@${sha256(content).slice(0, 8)}`;
  fingerprintCache.set(cacheKey, { key: statKey, value });
  return value;
}

export interface TriageHashInputs {
  advisoryModified: string | null;
  installedVersions: string[];
  fixedVersions: string[];
  direct: boolean | null;
  devOnly: boolean;
  paths: string[][];
  /** Per installed version facts (what the prompt renders, one line per instance) */
  instances: FindingInstance[];
  importSites: { file: string; line: number }[];
  /** Uncapped import-site count (the prompt shows "showing N of <count>") */
  importSiteCount: number;
  /** projects.triage_profile_hash: only the profile fields the prompt shows */
  projectProfileHash: string;
  promptVersion: string;
  model: string;
  effort: string;
  codeAccess: boolean;
}

/** Order-independent form of the instances: sorted by version, each instance's paths sorted. */
function canonicalInstances(instances: FindingInstance[]): unknown[] {
  return instances
    .map((i) => [i.version, i.direct, i.devOnly, i.paths.map((p) => p.join('>')).sort()] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

export function computeInputHash(i: TriageHashInputs): string {
  const canonical = JSON.stringify([
    i.advisoryModified ?? '',
    [...i.installedVersions].sort(),
    [...i.fixedVersions].sort(),
    i.direct,
    i.devOnly,
    i.paths.map((p) => p.join('>')).sort(),
    canonicalInstances(i.instances),
    i.importSites.map((s) => `${s.file}:${s.line}`).sort(),
    i.importSiteCount,
    i.projectProfileHash,
    i.promptVersion,
    i.model,
    i.effort,
    i.codeAccess,
  ]);
  return sha256(canonical).slice(0, 16);
}
