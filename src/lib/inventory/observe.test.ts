import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseOsvOutput } from '../osv/output';
import { MAX_IMPORT_SITES, type ImportIndex } from './import-sites';
import { parsePackageLock } from './npm-lock';
import { observeScan, type LockfileScan } from './observe';

const read = (f: string) => readFileSync(path.join(process.cwd(), 'test/fixtures/scan', f), 'utf8');
const results = parseOsvOutput(JSON.parse(read('osv-output.json')));
const graph = parsePackageLock(read('package-lock.json'));
const IOS_LOCKFILE = 'ios/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved';

const scans: LockfileScan[] = [
  { lockfile: 'package-lock.json', packages: results[0]!.packages, npmGraph: graph },
  { lockfile: IOS_LOCKFILE, packages: results[1]!.packages, npmGraph: null },
];

const index: ImportIndex = {
  filesScanned: 2,
  byPackage: new Map([
    ['web-framework', [{ file: 'src/server.ts', line: 3, specifier: 'web-framework/server' }]],
    ['test-runner', [{ file: 'scripts/check.ts', line: 1, specifier: 'test-runner' }]],
    ['vuln-pkg', [{ file: 'src/direct-use.ts', line: 9, specifier: 'vuln-pkg' }]],
  ]),
};

describe('observeScan', () => {
  let indexBuilds = 0;
  const obs = observeScan(scans, {
    importIndex: () => {
      indexBuilds++;
      return index;
    },
  });
  const finding = (name: string, osvId: string) => obs.findings.find((f) => f.packageName === name && f.osvId === osvId);

  it('builds one inventory row per lockfile+name+version with direct/dev facts', () => {
    expect(obs.packages).toBe(8);
    const row = (name: string, version: string) => obs.inventory.find((i) => i.name === name && i.version === version);
    expect(row('cli-tool', '1.0.0')).toMatchObject({ lockfile: 'package-lock.json', ecosystem: 'npm', direct: true, devOnly: false });
    expect(row('test-runner', '3.0.0')).toMatchObject({ direct: true, devOnly: true });
    expect(row('glob-ish', '1.0.0')).toMatchObject({ direct: false, devOnly: true });
    expect(row('vuln-pkg', '0.9.0')).toMatchObject({ direct: false, devOnly: false });
    expect(row('github.com/example/clean-lib', '2.0.0')).toMatchObject({
      lockfile: IOS_LOCKFILE,
      ecosystem: 'SwiftURL',
      direct: null,
      devOnly: false,
    });
  });

  it('counts vulnerable package versions, ignoring withdrawn advisories', () => {
    expect(obs.vulnerablePackages).toBe(4);
  });

  it('keys findings per lockfile, package and representative id, merging installed versions', () => {
    expect(obs.findings.map((f) => `${f.lockfile}|${f.packageName}|${f.osvId}`)).toEqual([
      `${IOS_LOCKFILE}|github.com/example/swift-lib|GHSA-swft-swft-swft`,
      'package-lock.json|glob-ish|GHSA-dev0-dev0-dev0',
      'package-lock.json|vuln-pkg|GHSA-aaaa-bbbb-cccc',
      'package-lock.json|vuln-pkg|GHSA-zzzz-yyyy-xxxx',
    ]);
    expect(finding('vuln-pkg', 'GHSA-aaaa-bbbb-cccc')).toMatchObject({
      installedVersions: ['0.9.0', '1.0.0'],
      fixedVersions: ['0.9.5', '1.0.10'],
      direct: false,
      devOnly: false,
      advisoryModified: '2026-10-01T00:00:00Z',
      paths: [
        ['web-framework', 'vuln-pkg'],
        ['cli-tool', 'server-lib', 'vuln-pkg'],
        ['cli-tool', 'util-a', 'vuln-pkg'],
      ],
    });
  });

  it('unions fixed versions across an alias group and uses the representative record date', () => {
    expect(finding('vuln-pkg', 'GHSA-zzzz-yyyy-xxxx')).toMatchObject({
      installedVersions: ['1.0.0'],
      fixedVersions: ['1.0.2', '1.0.3'],
      advisoryModified: '2026-08-01T00:00:00Z',
      paths: [
        ['cli-tool', 'server-lib', 'vuln-pkg'],
        ['cli-tool', 'util-a', 'vuln-pkg'],
        ['cli-tool', 'server-lib', 'addr', 'vuln-pkg'],
      ],
    });
  });

  it('records facts per installed version next to the merged view (review #31)', () => {
    expect(finding('vuln-pkg', 'GHSA-aaaa-bbbb-cccc')!.instances).toEqual([
      { version: '0.9.0', direct: false, devOnly: false, paths: [['web-framework', 'vuln-pkg']] },
      {
        version: '1.0.0',
        direct: false,
        devOnly: false,
        paths: [
          ['cli-tool', 'server-lib', 'vuln-pkg'],
          ['cli-tool', 'util-a', 'vuln-pkg'],
          ['cli-tool', 'server-lib', 'addr', 'vuln-pkg'],
        ],
      },
    ]);
  });

  it('searches import sites of the direct dependencies a transitive package comes through', () => {
    expect(finding('vuln-pkg', 'GHSA-aaaa-bbbb-cccc')!.importSites).toEqual([
      { file: 'src/server.ts', line: 3, specifier: 'web-framework/server', via: 'web-framework' },
    ]);
    expect(finding('vuln-pkg', 'GHSA-aaaa-bbbb-cccc')!.importSiteCount).toBe(1);
    expect(finding('glob-ish', 'GHSA-dev0-dev0-dev0')).toMatchObject({
      devOnly: true,
      direct: false,
      paths: [['test-runner', 'glob-ish']],
      importSites: [{ file: 'scripts/check.ts', line: 1, specifier: 'test-runner', via: 'test-runner' }],
    });
    expect(indexBuilds).toBe(1);
  });

  it('leaves flat ecosystems without graph facts', () => {
    expect(finding('github.com/example/swift-lib', 'GHSA-swft-swft-swft')).toMatchObject({
      ecosystem: 'SwiftURL',
      direct: null,
      devOnly: false,
      paths: [],
      importSites: [],
      importSiteCount: 0,
      fixedVersions: ['1.2.1'],
    });
    const swift = finding('github.com/example/swift-lib', 'GHSA-swft-swft-swft')!;
    expect(swift.instances).toEqual(swift.installedVersions.map((version) => ({ version, direct: null, devOnly: false, paths: [] })));
  });

  it('keeps a direct dev instance and a transitive production instance apart, and searches for both (review #31)', () => {
    // shared-dep@2.0.0 is a direct production dependency; shared-dep@1.0.0 only comes in through the
    // dev-only test-runner. The merged view says "direct, not dev-only", which neither instance is alone.
    const obs2 = observeScan(
      [
        {
          lockfile: 'package-lock.json',
          npmGraph: graph,
          packages: [
            { name: 'shared-dep', version: '1.0.0', ecosystem: 'npm', dev: true, groups: [group('GHSA-shrd-shrd-shrd')] },
            { name: 'shared-dep', version: '2.0.0', ecosystem: 'npm', dev: false, groups: [group('GHSA-shrd-shrd-shrd')] },
          ],
        },
      ],
      {
        importIndex: () => ({
          filesScanned: 2,
          byPackage: new Map([
            ['shared-dep', [{ file: 'src/use.ts', line: 1, specifier: 'shared-dep' }]],
            ['test-runner', [{ file: 'scripts/check.ts', line: 1, specifier: 'test-runner' }]],
          ]),
        }),
      },
    );
    expect(obs2.findings[0]).toMatchObject({
      installedVersions: ['1.0.0', '2.0.0'],
      direct: true,
      devOnly: false,
      instances: [
        { version: '1.0.0', direct: false, devOnly: true, paths: [['test-runner', 'shared-dep']] },
        { version: '2.0.0', direct: true, devOnly: false, paths: [['shared-dep']] },
      ],
      importSites: [
        { file: 'scripts/check.ts', line: 1, specifier: 'test-runner', via: 'test-runner' },
        { file: 'src/use.ts', line: 1, specifier: 'shared-dep', via: 'shared-dep' },
      ],
      importSiteCount: 2,
    });
  });

  it('stores at most MAX_IMPORT_SITES sites but the uncapped count (review #32)', () => {
    const many = Array.from({ length: 27 }, (_, i) => ({ file: `src/f${String(i).padStart(2, '0')}.ts`, line: 1, specifier: 'cli-tool' }));
    const capped = observeScan(
      [
        {
          lockfile: 'package-lock.json',
          npmGraph: graph,
          packages: [{ name: 'cli-tool', version: '1.0.0', ecosystem: 'npm', dev: false, groups: [group('GHSA-cli0-cli0-cli0')] }],
        },
      ],
      { importIndex: () => ({ filesScanned: 27, byPackage: new Map([['cli-tool', many]]) }) },
    );
    expect(capped.findings[0]!.importSites).toHaveLength(MAX_IMPORT_SITES);
    expect(capped.findings[0]!.importSiteCount).toBe(27);
  });

  it('stores one advisory row per record, withdrawn ones included', () => {
    const byId = new Map(obs.advisories.map((a) => [a.osvId, a]));
    expect([...byId.keys()].sort()).toEqual([
      'GHSA-aaaa-bbbb-cccc',
      'GHSA-dev0-dev0-dev0',
      'GHSA-swft-swft-swft',
      'GHSA-wdrn-wdrn-wdrn',
      'GHSA-zzzz-yyyy-xxxx',
      'MAL-2026-1',
      'OSV-2026-7',
    ]);
    expect(byId.get('GHSA-dev0-dev0-dev0')).toMatchObject({ cvssScore: null, severityLabel: 'HIGH' });
    expect(byId.get('MAL-2026-1')).toMatchObject({ cvssScore: 5.3, malicious: true });
    expect(byId.get('GHSA-wdrn-wdrn-wdrn')!.withdrawn).toBe('2026-06-01T00:00:00Z');
  });

  it('searches the package itself when it is a direct dependency', () => {
    const direct = observeScan(
      [
        {
          lockfile: 'package-lock.json',
          npmGraph: graph,
          packages: [{ name: 'cli-tool', version: '1.0.0', ecosystem: 'npm', dev: false, groups: [group('GHSA-cli0-cli0-cli0')] }],
        },
      ],
      {
        importIndex: () => ({
          filesScanned: 1,
          byPackage: new Map([['cli-tool', [{ file: 'bin/run.ts', line: 2, specifier: 'cli-tool' }]]]),
        }),
      },
    );
    expect(direct.findings[0]).toMatchObject({
      direct: true,
      paths: [['cli-tool']],
      importSites: [{ file: 'bin/run.ts', line: 2, specifier: 'cli-tool', via: 'cli-tool' }],
    });
  });

  it('treats a vulnerable nested copy of a direct dependency as transitive', () => {
    const nested = observeScan(
      [
        {
          lockfile: 'package-lock.json',
          npmGraph: graph,
          packages: [{ name: 'util-a', version: '2.0.0', ecosystem: 'npm', dev: false, groups: [group('GHSA-util-util-util')] }],
        },
      ],
      {
        importIndex: () => ({
          filesScanned: 1,
          byPackage: new Map([['cli-tool', [{ file: 'bin/run.ts', line: 2, specifier: 'cli-tool' }]]]),
        }),
      },
    );
    expect(nested.findings[0]).toMatchObject({
      direct: false,
      paths: [['cli-tool', 'util-a']],
      importSites: [{ file: 'bin/run.ts', line: 2, specifier: 'cli-tool', via: 'cli-tool' }],
    });
    expect(nested.inventory[0]).toMatchObject({ name: 'util-a', version: '2.0.0', direct: false });
  });

  it('does not build the import index when no npm graph is involved', () => {
    let builds = 0;
    observeScan([scans[1]!], {
      importIndex: () => {
        builds++;
        return index;
      },
    });
    expect(builds).toBe(0);
  });
});

function group(id: string) {
  return { osvId: id, ids: [id], aliases: [id], maxSeverity: 7, records: [{ id, modified: '2026-01-01T00:00:00Z' }] };
}
