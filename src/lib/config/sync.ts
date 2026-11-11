/**
 * Mirrors the YAML config into the DB (YAML stays the source of truth):
 * projects/*.yaml → projects, vigiles.yaml triage.configs → triage_configs, policy.yaml → policy_versions.
 * Called by the worker before every job and on startup.
 */
import { eq, notInArray } from 'drizzle-orm';
import type { Db } from '../db/client';
import { policyVersions, projects, triageConfigs } from '../db/schema';
import { loadPolicy, loadProjects, loadVigilesConfig, repoRoot, type LoadedPolicy, type LoadedProject } from './load';
import type { VigilesConfig } from './schema';

export interface SyncedConfig {
  config: VigilesConfig;
  policy: LoadedPolicy;
  projects: LoadedProject[];
}

export function syncConfigToDb(db: Db, root = repoRoot()): SyncedConfig {
  const config = loadVigilesConfig(root);
  const policy = loadPolicy(root);
  const loaded = loadProjects(root);
  const now = new Date().toISOString();

  db.transaction((tx) => {
    for (const { profile, hash, triageHash } of loaded) {
      const values = {
        name: profile.name,
        enabled: profile.enabled,
        repoPath: profile.repo_path,
        ref: profile.ref,
        profile,
        profileHash: hash,
        triageProfileHash: triageHash,
        updatedAt: now,
      };
      tx.insert(projects)
        .values({ id: profile.id, ...values })
        .onConflictDoUpdate({ target: projects.id, set: values })
        .run();
    }
    // Projects whose YAML was deleted are disabled, never deleted (their findings stay viewable).
    const ids = loaded.map((p) => p.profile.id);
    if (ids.length) tx.update(projects).set({ enabled: false }).where(notInArray(projects.id, ids)).run();

    for (const c of config.triage.configs) {
      const values = {
        name: c.name,
        promptVersion: c.prompt_version,
        model: c.model,
        effort: c.effort,
        codeAccess: c.code_access,
        active: c.name === config.triage.active_config,
      };
      tx.insert(triageConfigs)
        .values(values)
        .onConflictDoUpdate({ target: triageConfigs.name, set: values })
        .run();
    }
    tx.update(triageConfigs)
      .set({ active: false })
      .where(notInArray(triageConfigs.name, [config.triage.active_config]))
      .run();

    const existing = tx.select().from(policyVersions).where(eq(policyVersions.hash, policy.hash)).get();
    if (!existing) tx.insert(policyVersions).values({ hash: policy.hash, content: policy.content }).run();
  });

  return { config, policy, projects: loaded };
}
