/**
 * Loads the three config sources (spec §14): config/vigiles.yaml, config/policy.yaml, projects/*.yaml.
 * Files are re-read on every call (they're tiny), so edits apply without restarting anything.
 */
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { ProjectProfileSchema, type ProjectProfile } from '../types';
import { validatePolicyFields } from '../policy/engine';
import { triageProfileHash } from '../triage/profile';
import { PolicySchema, VigilesConfigSchema, type Policy, type VigilesConfig } from './schema';

export function repoRoot(): string {
  return process.env.VIGILES_ROOT ?? process.cwd();
}

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return path.join(homedir(), p.slice(2));
  return p;
}

function readYaml(file: string): unknown {
  return parseYaml(readFileSync(file, 'utf8'));
}

function formatZodError(file: string, err: { issues: { path: PropertyKey[]; message: string }[] }): Error {
  const lines = err.issues.map((i) => `  ${i.path.map(String).join('.') || '(root)'}: ${i.message}`);
  return new Error(`Invalid ${file}:\n${lines.join('\n')}`);
}

export function loadVigilesConfig(root = repoRoot()): VigilesConfig {
  const file = path.join(root, 'config/vigiles.yaml');
  const parsed = VigilesConfigSchema.safeParse(readYaml(file));
  if (!parsed.success) throw formatZodError(file, parsed.error);
  return parsed.data;
}

export interface LoadedPolicy {
  policy: Policy;
  /** Raw file text (stored in policy_versions) */
  content: string;
  /** sha256 of the raw text, first 12 hex chars */
  hash: string;
}

export function loadPolicy(root = repoRoot()): LoadedPolicy {
  const file = path.join(root, 'config/policy.yaml');
  const content = readFileSync(file, 'utf8');
  return parsePolicy(content, file);
}

export function parsePolicy(content: string, file = 'policy.yaml'): LoadedPolicy {
  const parsed = PolicySchema.safeParse(parseYaml(content));
  if (!parsed.success) throw formatZodError(file, parsed.error);
  // Catch typos (unknown fields, impossible enum values, missing catch-all) at load time, not at decide time.
  try {
    validatePolicyFields(parsed.data);
  } catch (err) {
    throw new Error(`Invalid ${file}: ${(err as Error).message}`);
  }
  return { policy: parsed.data, content, hash: sha256(content).slice(0, 12) };
}

export interface LoadedProject {
  profile: ProjectProfile;
  /** sha256 of the canonical JSON of the whole profile, first 12 hex chars (display and change detection) */
  hash: string;
  /** sha256 of only what the triage prompt shows (triageVisibleProfile), first 12 hex chars; part of the triage input hash */
  triageHash: string;
  file: string;
}

export function loadProjects(root = repoRoot()): LoadedProject[] {
  const dir = path.join(root, 'projects');
  if (!existsSync(dir)) return [];
  const out: LoadedProject[] = [];
  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith('.yaml') && !name.endsWith('.yml')) continue;
    const file = path.join(dir, name);
    const parsed = ProjectProfileSchema.safeParse(readYaml(file));
    if (!parsed.success) throw formatZodError(file, parsed.error);
    const profile = { ...parsed.data, repo_path: expandHome(parsed.data.repo_path) };
    const base = path.basename(name, path.extname(name));
    if (profile.id !== base) throw new Error(`${file}: id "${profile.id}" must match the file name "${base}"`);
    out.push({ profile, hash: sha256(JSON.stringify(profile)).slice(0, 12), triageHash: triageProfileHash(profile), file });
  }
  return out;
}

export interface DataPaths {
  root: string;
  db: string;
  osvDb: string;
  snapshots: string;
  logs: string;
  scratch: string;
}

/** Resolves (and creates, mode 700) the runtime data directory. VIGILES_DATA_DIR overrides config. */
export function dataPaths(config?: VigilesConfig): DataPaths {
  const root = expandHome(process.env.VIGILES_DATA_DIR ?? config?.data_dir ?? '~/.vigiles');
  const p: DataPaths = {
    root,
    db: path.join(root, 'vigiles.db'),
    osvDb: path.join(root, 'osv-db'),
    snapshots: path.join(root, 'snapshots'),
    logs: path.join(root, 'logs'),
    scratch: path.join(root, 'scratch'),
  };
  for (const dir of [p.root, p.osvDb, p.snapshots, p.logs, p.scratch]) {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  try {
    chmodSync(p.root, 0o700);
  } catch {
    // best effort
  }
  return p;
}
