import { describe, expect, it } from 'vitest';
import { discoverLockfiles, findCoverageGaps, LockfileDiscoveryError, lockfileCoverageDir, lockfileEcosystem } from './lockfiles';

const files = [
  'package.json',
  'package-lock.json',
  'apps/admin/package.json', // covered by the root lockfile
  'supabase/functions/request-access/deno.json',
  'supabase/functions/request-access/index.ts',
  'supabase/functions/sync-due/deno.json',
  'legacy/package.json',
  'legacy/yarn.lock',
  'vendor/node_modules/x/package-lock.json',
  'ios/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved',
  'ios/LocalKit/Package.swift', // covered: Xcode's Package.resolved pins the directory holding the .xcodeproj
  'py/requirements-dev.txt',
  'py/pyproject.toml',
  'rust/Cargo.toml',
  'go/go.mod',
  'deno-app/deno.jsonc',
  'deno-app/deno.lock',
  'README.md',
];

describe('lockfileEcosystem', () => {
  it.each([
    ['package-lock.json', 'npm'],
    ['a/pnpm-lock.yaml', 'npm'],
    ['yarn.lock', 'npm'],
    ['bun.lock', 'npm'],
    ['deno.lock', 'npm'],
    ['x/Package.resolved', 'SwiftURL'],
    ['Podfile.lock', 'CocoaPods'],
    ['requirements.txt', 'PyPI'],
    ['requirements-dev.txt', 'PyPI'],
    ['poetry.lock', 'PyPI'],
    ['uv.lock', 'PyPI'],
    ['Pipfile.lock', 'PyPI'],
    ['go.mod', 'Go'],
    ['Cargo.lock', 'crates.io'],
    ['Gemfile.lock', 'RubyGems'],
    ['composer.lock', 'Packagist'],
    ['pubspec.lock', 'Pub'],
    ['gradle.lockfile', 'Maven'],
  ])('%s → %s', (file, eco) => {
    expect(lockfileEcosystem(file)).toBe(eco);
  });

  it('ignores other files', () => {
    for (const f of ['package.json', 'requirements.in', 'go.sum', 'Gemfile', 'my-package-lock.json'])
      expect(lockfileEcosystem(f)).toBeNull();
  });
});

describe('lockfileCoverageDir', () => {
  it('is the lockfile directory, or the directory holding an Xcode bundle', () => {
    expect(lockfileCoverageDir('package-lock.json')).toBe('');
    expect(lockfileCoverageDir('backend/package-lock.json')).toBe('backend');
    expect(lockfileCoverageDir('held.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved')).toBe('');
    expect(lockfileCoverageDir('ios/App.xcworkspace/xcshareddata/swiftpm/Package.resolved')).toBe('ios');
  });
});

describe('discoverLockfiles', () => {
  it('matches known names, skips node_modules and applies exclude globs', () => {
    const r = discoverLockfiles(files, { exclude: ['legacy/**'], lockfiles: undefined });
    expect(r.lockfiles).toEqual([
      'deno-app/deno.lock',
      'go/go.mod',
      'ios/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved',
      'package-lock.json',
      'py/requirements-dev.txt',
    ]);
    expect(r.coverageGaps).toEqual([
      'rust/Cargo.toml',
      'supabase/functions/request-access/deno.json',
      'supabase/functions/sync-due/deno.json',
    ]);
  });

  it('matches dotfile paths with exclude globs', () => {
    const r = discoverLockfiles(['.claude/worktrees/x/package-lock.json', 'package-lock.json'], { exclude: ['.claude/**'] });
    expect(r.lockfiles).toEqual(['package-lock.json']);
  });

  it('reports a manifest whose only lockfile is excluded', () => {
    const r = discoverLockfiles(['package-lock.json', 'tools/Cargo.toml', 'tools/Cargo.lock'], { exclude: ['tools/Cargo.lock'] });
    expect(r.coverageGaps).toEqual(['tools/Cargo.toml']);
  });

  it('uses an explicit lockfile list as is', () => {
    const r = discoverLockfiles(files, { exclude: ['legacy/**'], lockfiles: ['legacy/yarn.lock', 'package-lock.json'] });
    expect(r.lockfiles).toEqual(['legacy/yarn.lock', 'package-lock.json']);
    // Gaps are relative to the lockfiles actually scanned.
    expect(r.coverageGaps).toEqual([
      'deno-app/deno.jsonc',
      'ios/LocalKit/Package.swift',
      'py/pyproject.toml',
      'rust/Cargo.toml',
      'supabase/functions/request-access/deno.json',
      'supabase/functions/sync-due/deno.json',
    ]);
  });

  it('fails clearly when an explicit lockfile is missing at the commit', () => {
    expect(() => discoverLockfiles(files, { exclude: [], lockfiles: ['backend/package-lock.json'] })).toThrow(LockfileDiscoveryError);
    expect(() => discoverLockfiles(files, { exclude: [], lockfiles: ['backend/package-lock.json'] })).toThrow(
      /backend\/package-lock\.json/,
    );
  });

  it('rejects an explicit file that is not a lockfile', () => {
    expect(() => discoverLockfiles(files, { exclude: [], lockfiles: ['package.json'] })).toThrow(/not a supported lockfile/);
  });
});

describe('findCoverageGaps', () => {
  it('needs a lockfile of the matching kind in the same or an ancestor directory', () => {
    const gaps = findCoverageGaps(
      ['package.json', 'web/package.json', 'web/deno.json', 'api/Gemfile', 'api/Gemfile.lock', 'svc/Gemfile'],
      ['package-lock.json', 'api/Gemfile.lock'],
    );
    expect(gaps).toEqual(['svc/Gemfile', 'web/deno.json']);
  });

  it('does not treat a sibling directory as an ancestor', () => {
    expect(findCoverageGaps(['web-admin/package.json'], ['web/package-lock.json'])).toEqual(['web-admin/package.json']);
  });
});
