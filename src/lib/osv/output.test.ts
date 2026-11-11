import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  advisoryFromRecord,
  cvssVectorOf,
  fixedVersionsFor,
  parseOsvOutput,
  parseSeverityScore,
  representativeId,
  type OsvRecord,
} from './output';

const fixture = JSON.parse(readFileSync(path.join(process.cwd(), 'test/fixtures/scan/osv-output.json'), 'utf8')) as unknown;

describe('representativeId', () => {
  it('prefers GHSA, then MAL, then the lexicographically first id', () => {
    expect(representativeId(['OSV-2026-7', 'GHSA-zzzz-yyyy-xxxx', 'MAL-2026-1'])).toBe('GHSA-zzzz-yyyy-xxxx');
    expect(representativeId(['GHSA-bbbb', 'GHSA-aaaa'])).toBe('GHSA-aaaa');
    expect(representativeId(['PYSEC-2026-1', 'MAL-2026-9'])).toBe('MAL-2026-9');
    expect(representativeId(['PYSEC-2026-1', 'OSV-2026-2'])).toBe('OSV-2026-2');
    expect(() => representativeId([])).toThrow();
  });
});

describe('parseSeverityScore', () => {
  it('parses scores in 0..10 and rejects everything else', () => {
    expect(parseSeverityScore('9.8')).toBe(9.8);
    expect(parseSeverityScore('0')).toBe(0);
    expect(parseSeverityScore('')).toBeNull();
    expect(parseSeverityScore(undefined)).toBeNull();
    expect(parseSeverityScore('HIGH')).toBeNull();
    expect(parseSeverityScore('11')).toBeNull();
  });
});

describe('parseOsvOutput', () => {
  const results = parseOsvOutput(fixture);

  it('keeps sources and every package (--all-packages)', () => {
    expect(results.map((r) => [r.path, r.packages.length])).toEqual([
      ['/snapshot/package-lock.json', 6],
      ['/snapshot/ios/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved', 2],
    ]);
  });

  it('turns groups into representative ids with their records and score', () => {
    const vuln = results[0]!.packages.find((p) => p.name === 'vuln-pkg' && p.version === '1.0.0')!;
    expect(vuln.groups.map((g) => [g.osvId, g.maxSeverity, g.records.map((r) => r.id)])).toEqual([
      ['GHSA-aaaa-bbbb-cccc', 9.8, ['GHSA-aaaa-bbbb-cccc']],
      ['GHSA-zzzz-yyyy-xxxx', 5.3, ['GHSA-zzzz-yyyy-xxxx', 'MAL-2026-1', 'OSV-2026-7']],
    ]);
  });

  it('reads the dev dependency group', () => {
    const byName = new Map(results[0]!.packages.map((p) => [p.name, p]));
    expect(byName.get('glob-ish')!.dev).toBe(true);
    expect(byName.get('cli-tool')!.dev).toBe(false);
    expect(byName.get('glob-ish')!.groups[0]!.maxSeverity).toBeNull();
  });

  it('picks the representative among ids whose record is present', () => {
    const [r] = parseOsvOutput({
      results: [
        {
          source: { path: '/s/package-lock.json' },
          packages: [
            {
              package: { name: 'p', version: '1.0.0', ecosystem: 'npm' },
              groups: [{ ids: ['GHSA-gone-gone-gone', 'MAL-2026-5'], max_severity: '' }],
              vulnerabilities: [{ id: 'MAL-2026-5', modified: '2026-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    expect(r!.packages[0]!.groups[0]).toMatchObject({ osvId: 'MAL-2026-5', ids: ['GHSA-gone-gone-gone', 'MAL-2026-5'] });
    expect(r!.packages[0]!.groups[0]!.records.map((x) => x.id)).toEqual(['MAL-2026-5']);
  });

  it('accepts output with no results', () => {
    expect(parseOsvOutput({ results: [] })).toEqual([]);
    expect(parseOsvOutput({})).toEqual([]);
  });

  it('fails clearly on an unexpected shape', () => {
    expect(() => parseOsvOutput({ results: [{ source: {} }] })).toThrow(/unexpected osv-scanner output at results\.0\.source\.path/);
  });
});

describe('advisory mapping', () => {
  const results = parseOsvOutput(fixture);
  const vuln = results[0]!.packages.find((p) => p.name === 'vuln-pkg' && p.version === '1.0.0')!;
  const ghsa = vuln.groups[0]!.records[0]!;

  it('maps an OSV record to an advisories row', () => {
    const row = advisoryFromRecord(ghsa, 9.8);
    expect(row).toMatchObject({
      osvId: 'GHSA-aaaa-bbbb-cccc',
      aliases: ['CVE-2026-1000'],
      cves: ['CVE-2026-1000'],
      summary: 'Prototype pollution in vuln-pkg',
      cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      cvssScore: 9.8,
      severityLabel: 'CRITICAL',
      cwes: ['CWE-1321'],
      references: ['https://github.com/advisories/GHSA-aaaa-bbbb-cccc', 'https://example.com/fix'],
      published: '2026-09-01T00:00:00Z',
      modified: '2026-10-01T00:00:00Z',
      withdrawn: null,
      malicious: false,
    });
    expect(row.raw).toBe(ghsa);
  });

  it('flags MAL- records (and records aliased to one) as malicious', () => {
    const mal = vuln.groups[1]!.records.find((r) => r.id === 'MAL-2026-1')!;
    expect(advisoryFromRecord(mal, null).malicious).toBe(true);
    const aliased = { id: 'GHSA-mmmm', aliases: ['MAL-2026-3'] } as OsvRecord;
    expect(advisoryFromRecord(aliased, null).malicious).toBe(true);
  });

  it('includes a CVE id itself in cves and tolerates sparse records', () => {
    const row = advisoryFromRecord({ id: 'CVE-2026-5' } as OsvRecord, null);
    expect(row).toMatchObject({ cves: ['CVE-2026-5'], aliases: [], cwes: [], references: [], cvssVector: null, severityLabel: null });
  });

  it('falls back to the CVSS v3 vector', () => {
    expect(cvssVectorOf({ id: 'x', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }] } as OsvRecord)).toBe('CVSS:3.1/AV:N');
    expect(cvssVectorOf({ id: 'x', severity: [{ type: 'CVSS_V2', score: 'AV:N' }] } as OsvRecord)).toBeNull();
  });

  it('collects fixed versions for the matching package only, deduped and version-sorted', () => {
    expect(fixedVersionsFor([ghsa], 'vuln-pkg', 'npm')).toEqual(['0.9.5', '1.0.10']);
    expect(fixedVersionsFor(vuln.groups[1]!.records, 'vuln-pkg', 'npm')).toEqual(['1.0.2', '1.0.3']);
    expect(fixedVersionsFor([ghsa], 'vuln-pkg', 'PyPI')).toEqual([]);
    const globIsh = results[0]!.packages.find((p) => p.name === 'glob-ish')!.groups[0]!.records;
    expect(fixedVersionsFor(globIsh, 'glob-ish', 'npm')).toEqual(['1.10.0', '2.0.1']);
  });
});

describe('group alias CVEs', () => {
  it('adds CVEs known only through other records of the group to the representative advisory', () => {
    const record = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-0001'], modified: '2026-01-01T00:00:00Z' };
    const row = advisoryFromRecord(record as Parameters<typeof advisoryFromRecord>[0], 7.5, [
      'GHSA-aaaa-bbbb-cccc',
      'CVE-2026-0002',
      'PYSEC-2026-1',
    ]);
    expect(row.cves).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
  });
});
