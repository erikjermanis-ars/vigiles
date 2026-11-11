import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, describe, expect, it } from 'vitest';
import { openDb } from '../db/client';
import { projects } from '../db/schema';
import { triageProfileHash } from '../triage/profile';
import { loadProjects } from './load';
import { syncConfigToDb } from './sync';

const REPO = path.join(import.meta.dirname, '../../..');
const root = mkdtempSync(path.join(tmpdir(), 'vigiles-sync-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));
mkdirSync(path.join(root, 'projects'));
cpSync(path.join(REPO, 'config/vigiles.yaml'), path.join(root, 'config/vigiles.yaml'));
cpSync(path.join(REPO, 'config/policy.yaml'), path.join(root, 'config/policy.yaml'));

function writeProject(fields: Record<string, string>) {
  const yaml = {
    id: 'demo',
    name: 'Demo',
    enabled: 'true',
    repo_path: '/nowhere/demo',
    ref: 'origin/main',
    fetch_before_scan: 'true',
    exclude: '[]',
    criticality: 'high',
    exposure: 'internet-facing',
    notes: "'Linux only.'",
    ...fields,
  };
  writeFileSync(
    path.join(root, 'projects/demo.yaml'),
    Object.entries(yaml)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n'),
  );
}

describe('syncConfigToDb: projects.triage_profile_hash (review #2/#7/#12)', () => {
  const db = openDb(':memory:');
  const synced = () => {
    syncConfigToDb(db, root);
    return db.select().from(projects).where(eq(projects.id, 'demo')).get()!;
  };

  writeProject({});
  const first = synced();

  it('stores the triage hash of the visible profile next to the full profile hash', () => {
    const [loaded] = loadProjects(root);
    expect(loaded!.triageHash).toBe(triageProfileHash(loaded!.profile));
    expect(first.triageProfileHash).toBe(loaded!.triageHash);
    expect(first.profileHash).toBe(loaded!.hash);
    expect(first.triageProfileHash).not.toBe(first.profileHash);
  });

  it('keeps the triage hash when only scanner settings change, while the full hash changes', () => {
    writeProject({
      enabled: 'false',
      fetch_before_scan: 'false',
      exclude: '[vendor/**]',
      lockfiles: '[package-lock.json]',
      repo_path: '/elsewhere/demo',
    });
    const row = synced();
    expect(row.enabled).toBe(false);
    expect(row.profileHash).not.toBe(first.profileHash);
    expect(row.triageProfileHash).toBe(first.triageProfileHash);
  });

  it('changes the triage hash when a field the prompt shows changes', () => {
    writeProject({ exposure: 'internal' });
    const row = synced();
    expect(row.triageProfileHash).not.toBe(first.triageProfileHash);
  });
});
