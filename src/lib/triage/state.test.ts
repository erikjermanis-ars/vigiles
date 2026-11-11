import { eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { openDb } from '../db/client';
import { findings, projects } from '../db/schema';
import type { ProjectProfile } from '../types';
import { triageProfileHash } from './profile';
import { findingInputHash } from './state';
import { PROFILE, seedConfig, seedFinding, seedProject } from './test-support';

function setup() {
  const db = openDb(':memory:');
  const { scanId } = seedProject(db);
  const config = seedConfig(db);
  const id = seedFinding(db, { scanId }).id;
  const finding = () => db.select().from(findings).where(eq(findings.id, id)).get()!;
  const setProfile = (profile: ProjectProfile, opts: { storeHash?: boolean } = {}) =>
    db
      .update(projects)
      .set({ profile, profileHash: `full-${Math.random()}`, triageProfileHash: opts.storeHash === false ? '' : triageProfileHash(profile) })
      .where(eq(projects.id, 'demo'))
      .run();
  return { db, config, finding, setProfile };
}

describe('findingInputHash', () => {
  it('does not change when only scanner settings of the profile change (review #2/#7/#12)', () => {
    const { db, config, finding, setProfile } = setup();
    setProfile(PROFILE);
    const before = findingInputHash(db, finding(), config);
    setProfile({ ...PROFILE, enabled: false, fetch_before_scan: true, exclude: ['x/**'], lockfiles: ['a/package-lock.json'], repo_path: '/x' });
    expect(findingInputHash(db, finding(), config)).toBe(before);
    setProfile({ ...PROFILE, exposure: 'internal' });
    expect(findingInputHash(db, finding(), config)).not.toBe(before);
  });

  it('computes the triage profile hash from the stored profile until sync has written the column', () => {
    const { db, config, finding, setProfile } = setup();
    setProfile(PROFILE);
    const synced = findingInputHash(db, finding(), config);
    setProfile(PROFILE, { storeHash: false });
    expect(findingInputHash(db, finding(), config)).toBe(synced);
  });

  it('covers per-version instances (order-independent) and the uncapped import-site count (review #31/#32)', () => {
    const { db, config, finding } = setup();
    const a = { version: '1.0.0', direct: true, devOnly: false, paths: [['zod'], ['x', 'zod']] };
    const b = { version: '3.0.0', direct: false, devOnly: true, paths: [['cli', 'zod']] };
    const set = (values: Partial<typeof findings.$inferInsert>) => db.update(findings).set(values).run();

    set({ instances: [a, b] });
    const base = findingInputHash(db, finding(), config);
    set({ instances: [b, { ...a, paths: [['x', 'zod'], ['zod']] }] });
    expect(findingInputHash(db, finding(), config)).toBe(base);

    set({ instances: [a, { ...b, devOnly: false }] });
    expect(findingInputHash(db, finding(), config)).not.toBe(base);
    set({ instances: [a, { ...b, paths: [['other', 'zod']] }] });
    expect(findingInputHash(db, finding(), config)).not.toBe(base);

    set({ instances: [a, b], importSiteCount: 42 });
    expect(findingInputHash(db, finding(), config)).not.toBe(base);
  });
});
