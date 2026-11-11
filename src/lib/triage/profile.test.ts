import { describe, expect, it } from 'vitest';
import type { ProjectProfile } from '../types';
import { HIDDEN_PROFILE_KEYS, triageProfileHash, triageVisibleProfile } from './profile';
import { PROFILE } from './test-support';

describe('triageVisibleProfile', () => {
  it('drops exactly the scanner-only keys and keeps the rest in order', () => {
    const visible = triageVisibleProfile({ ...PROFILE, lockfiles: ['package-lock.json'] });
    for (const key of HIDDEN_PROFILE_KEYS) expect(visible).not.toHaveProperty(key);
    expect(Object.keys(visible)).toEqual(Object.keys(PROFILE).filter((k) => !(HIDDEN_PROFILE_KEYS as readonly string[]).includes(k)));
  });
});

describe('triageProfileHash', () => {
  const base = triageProfileHash(PROFILE);

  it.each<[string, Partial<ProjectProfile>]>([
    ['enabled', { enabled: false }],
    ['fetch_before_scan', { fetch_before_scan: !PROFILE.fetch_before_scan }],
    ['exclude', { exclude: ['vendor/**'] }],
    ['lockfiles', { lockfiles: ['backend/package-lock.json'] }],
    ['repo_path', { repo_path: '/somewhere/else' }],
  ])('ignores %s (the prompt never shows it)', (_, change) => {
    expect(triageProfileHash({ ...PROFILE, ...change })).toBe(base);
  });

  it.each<[string, Partial<ProjectProfile>]>([
    ['exposure', { exposure: 'internal' }],
    ['mitigations', { mitigations: 'WAF in front' }],
    ['owners', { owners: ['someone'] }],
    ['deployments', { deployments: [{ env: 'production', hosting: 'Windows' }] }],
    ['ref', { ref: 'origin/release' }],
  ])('changes with %s (rendered in the prompt)', (_, change) => {
    expect(triageProfileHash({ ...PROFILE, ...change })).not.toBe(base);
  });

  it('is 12 hex characters', () => {
    expect(base).toMatch(/^[0-9a-f]{12}$/);
  });
});
