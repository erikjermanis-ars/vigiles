import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { instancesOf, isDevOnly, isDirect, NpmLockfileError, parsePackageLock, shortestPaths } from './npm-lock';

const fixture = readFileSync(path.join(process.cwd(), 'test/fixtures/scan/package-lock.json'), 'utf8');
const graph = parsePackageLock(fixture);

describe('parsePackageLock', () => {
  it('rejects lockfile v1 with a clear message', () => {
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0' } } });
    expect(() => parsePackageLock(v1, 'web/package-lock.json')).toThrow(NpmLockfileError);
    expect(() => parsePackageLock(v1, 'web/package-lock.json')).toThrow(/web\/package-lock\.json: lockfileVersion 1 .*v2\/v3/);
  });

  it('rejects invalid JSON', () => {
    expect(() => parsePackageLock('{', 'x/package-lock.json')).toThrow(/invalid JSON/);
  });

  it('lists every installed instance, including nested and aliased ones', () => {
    expect(instancesOf(graph, 'vuln-pkg').map((i) => [i.key, i.version])).toEqual([
      ['node_modules/vuln-pkg', '1.0.0'],
      ['node_modules/web-framework/node_modules/vuln-pkg', '0.9.0'],
    ]);
    expect(instancesOf(graph, 'real-pkg').map((i) => i.key)).toEqual(['node_modules/aliased']);
    expect(instancesOf(graph, 'my-ws').map((i) => i.key)).toEqual(['packages/my-ws']);
    expect(instancesOf(graph, 'vuln-pkg', ['0.9.0'])).toHaveLength(1);
  });
});

describe('isDirect', () => {
  it('is true for root dependencies, devDependencies and optionalDependencies', () => {
    for (const name of ['cli-tool', 'test-runner', 'opt-native', 'util-a']) expect(isDirect(graph, name)).toBe(true);
  });
  it('covers npm aliases by both the alias and the real name', () => {
    expect(isDirect(graph, 'aliased')).toBe(true);
    expect(isDirect(graph, 'real-pkg')).toBe(true);
  });
  it('is false for transitive packages', () => {
    for (const name of ['vuln-pkg', 'server-lib', 'peer-core', 'ws-dep']) expect(isDirect(graph, name)).toBe(false);
  });
  it('with versions, asks whether one of them is the instance the root resolves to', () => {
    expect(isDirect(graph, 'util-a', ['1.0.0'])).toBe(true);
    expect(isDirect(graph, 'util-a', ['2.0.0'])).toBe(false); // cli-tool's nested copy
    expect(isDirect(graph, 'util-a', ['1.0.0', '2.0.0'])).toBe(true);
    expect(isDirect(graph, 'shared-dep', ['1.0.0'])).toBe(false);
    expect(isDirect(graph, 'real-pkg', ['1.0.0'])).toBe(true);
    expect(isDirect(graph, 'cli-tool', ['9.9.9'])).toBe(true); // unknown version: falls back to the name
  });
});

describe('isDevOnly', () => {
  it('is true when every instance is dev or devOptional', () => {
    expect(isDevOnly(graph, 'test-runner')).toBe(true);
    expect(isDevOnly(graph, 'glob-ish')).toBe(true);
    expect(isDevOnly(graph, 'fs-watch')).toBe(true); // devOptional
  });
  it('is false when any matching instance ships in production', () => {
    expect(isDevOnly(graph, 'shared-dep')).toBe(false);
    expect(isDevOnly(graph, 'opt-native')).toBe(false); // optional, not dev
    expect(isDevOnly(graph, 'vuln-pkg')).toBe(false);
  });
  it('looks only at the vulnerable versions', () => {
    expect(isDevOnly(graph, 'shared-dep', ['1.0.0'])).toBe(true);
    expect(isDevOnly(graph, 'shared-dep', ['2.0.0'])).toBe(false);
  });
  it('returns null when nothing matches', () => {
    expect(isDevOnly(graph, 'nope')).toBeNull();
    expect(isDevOnly(graph, 'vuln-pkg', ['9.9.9'])).toBeNull();
  });
});

describe('shortestPaths', () => {
  it('returns up to 3 shortest chains, resolving nested node_modules first', () => {
    // cli-tool's util-a@2 (nested) depends on vuln-pkg; the root util-a@1 does not.
    expect(shortestPaths(graph, 'vuln-pkg', ['1.0.0'])).toEqual([
      ['cli-tool', 'server-lib', 'vuln-pkg'],
      ['cli-tool', 'util-a', 'vuln-pkg'],
      ['cli-tool', 'server-lib', 'addr', 'vuln-pkg'],
    ]);
  });

  it('restricts targets to the given versions', () => {
    expect(shortestPaths(graph, 'vuln-pkg', ['0.9.0'])).toEqual([['web-framework', 'vuln-pkg']]);
    expect(shortestPaths(graph, 'vuln-pkg')[0]).toEqual(['web-framework', 'vuln-pkg']);
  });

  it('gives a direct dependency a one-element path', () => {
    expect(shortestPaths(graph, 'cli-tool')).toEqual([['cli-tool']]);
  });

  it('follows optional and peer dependencies', () => {
    expect(shortestPaths(graph, 'native-img')).toEqual([['web-framework', 'native-img']]);
    expect(shortestPaths(graph, 'peer-core')).toEqual([['plugin-x', 'peer-core']]);
    expect(shortestPaths(graph, 'fs-watch')).toEqual([['test-runner', 'fs-watch']]);
  });

  it('follows workspace links', () => {
    expect(shortestPaths(graph, 'ws-dep')).toEqual([['my-ws', 'ws-dep']]);
  });

  it('respects the limit and returns [] for unknown packages', () => {
    expect(shortestPaths(graph, 'vuln-pkg', ['1.0.0'], 1)).toHaveLength(1);
    expect(shortestPaths(graph, 'missing-pkg')).toEqual([]);
  });

  it('terminates on dependency cycles', () => {
    const cyclic = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { a: '1' } },
          'node_modules/a': { version: '1.0.0', dependencies: { b: '1' } },
          'node_modules/b': { version: '1.0.0', dependencies: { a: '1', c: '1' } },
          'node_modules/c': { version: '1.0.0' },
        },
      }),
    );
    expect(shortestPaths(cyclic, 'c')).toEqual([['a', 'b', 'c']]);
  });
});
