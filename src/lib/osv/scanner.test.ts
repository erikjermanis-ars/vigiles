import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { osvScannerArgs, runOsvScanner, unsupportedLockfile } from './scanner';

const dir = mkdtempSync(path.join(tmpdir(), 'vigiles-osv-scanner-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const output = {
  results: [
    {
      source: { path: '/snap/package-lock.json', type: 'lockfile' },
      packages: [{ package: { name: 'a', version: '1.0.0', ecosystem: 'npm' } }],
    },
  ],
};

/**
 * A stand-in for osv-scanner: writes `json` to --output-file (unless null) and exits with `code`.
 * Like osv-scanner 2.7.1, it aborts with exit 127 when any -L file is a deno.lock (no extractor),
 * naming the unprefixed path.
 */
function fakeScanner(name: string, code: number, json: unknown): string {
  const file = path.join(dir, name);
  writeFileSync(
    file,
    `#!/usr/bin/env node
const args = process.argv.slice(2);
const out = args[args.indexOf('--output-file') + 1];
const calls = require('node:path').join(${JSON.stringify(dir)}, ${JSON.stringify(name)} + '.calls');
require('node:fs').appendFileSync(calls, JSON.stringify(args) + '\\n');
if (process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY !== ${JSON.stringify(dir)}) { console.error('no db dir'); process.exit(127); }
if (process.env.VIGILES_TEST_SECRET) { console.error('secret leaked'); process.exit(127); }
// -L takes "<parse-as>:<path>": text before the first ':' is a parse-as type (osv-scanner then
// fails to stat the rest); an empty prefix means "detect".
const lockfiles = args.filter((a, i) => args[i - 1] === '-L').map((l) => {
  const c = l.indexOf(':');
  if (c === -1) return l;
  if (c > 0) { console.error('failed to resolve path: stat ' + l.slice(c + 1) + ': no such file or directory'); process.exit(127); }
  return l.slice(c + 1);
});
const deno = lockfiles.find((l) => l.endsWith('deno.lock'));
if (deno) { console.error('could not determine extractor suitable to this file: "' + deno + '"'); process.exit(127); }
const json = ${JSON.stringify(json)};
if (json !== null) require('node:fs').writeFileSync(out, JSON.stringify(json));
console.error('warn: something');
process.exit(${code});
`,
  );
  chmodSync(file, 0o755);
  return file;
}

const opts = (bin: string) => ({ bin, osvDbDir: dir, lockfiles: ['/snap/package-lock.json'], scratchDir: dir });
const callsOf = (name: string) =>
  readFileSync(path.join(dir, `${name}.calls`), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as string[]);

describe('osvScannerArgs', () => {
  it('runs offline, without transitive resolution or call analysis, with every lockfile', () => {
    const args = osvScannerArgs(['/s/a/package-lock.json', '/s/b/Package.resolved'], '/tmp/out.json');
    expect(args.slice(0, 2)).toEqual(['scan', 'source']);
    for (const flag of ['--offline', '--offline-vulnerabilities', '--no-resolve', '--no-call-analysis=all', '--all-packages']) {
      expect(args).toContain(flag);
    }
    expect(args).not.toContain('--download-offline-databases');
    expect(args[args.indexOf('--format') + 1]).toBe('json');
    expect(args[args.indexOf('--output-file') + 1]).toBe('/tmp/out.json');
    expect(args.slice(-4)).toEqual(['-L', ':/s/a/package-lock.json', '-L', ':/s/b/Package.resolved']);
  });

  it('prefixes every lockfile with ":" so a colon in its path is not read as a parse-as type', () => {
    const args = osvScannerArgs(['/s/a:b/package-lock.json'], '/tmp/out.json');
    expect(args.slice(-2)).toEqual(['-L', ':/s/a:b/package-lock.json']);
  });
});

describe('runOsvScanner', () => {
  beforeAll(() => {
    process.env.VIGILES_TEST_SECRET = 'x';
  });
  afterAll(() => {
    delete process.env.VIGILES_TEST_SECRET;
  });

  it('treats exit 1 (vulnerabilities found) as success and removes its temp file', async () => {
    const r = await runOsvScanner(opts(fakeScanner('found.cjs', 1, output)));
    expect(r.exitCode).toBe(1);
    expect(r.results[0]!.packages[0]!.name).toBe('a');
    expect(r.warnings).toBe('warn: something');
    expect(readdirSync(dir).filter((f) => f.endsWith('.json'))).toEqual([]);
  });

  it('accepts exit 0', async () => {
    const r = await runOsvScanner(opts(fakeScanner('clean.cjs', 0, output)));
    expect(r.results).toHaveLength(1);
  });

  it('treats exit 128 without output as "no packages"', async () => {
    const r = await runOsvScanner(opts(fakeScanner('empty.cjs', 128, null)));
    expect(r.results).toEqual([]);
  });

  it('fails on other exit codes with stderr in the message', async () => {
    await expect(runOsvScanner(opts(fakeScanner('broken.cjs', 127, output)))).rejects.toThrow(/osv-scanner exited 127: warn: something/);
  });

  it('fails when exit 1 comes without an output file', async () => {
    await expect(runOsvScanner(opts(fakeScanner('noout.cjs', 1, null)))).rejects.toThrow(/without writing/);
  });

  it('drops a lockfile osv-scanner has no extractor for and scans the rest', async () => {
    const bin = fakeScanner('nodeno.cjs', 1, output);
    const r = await runOsvScanner({ ...opts(bin), lockfiles: ['/snap/fn/deno.lock', '/snap/package-lock.json'] });
    expect(r.unsupported).toEqual(['/snap/fn/deno.lock']);
    expect(r.results).toHaveLength(1);
    const calls = callsOf('nodeno.cjs').map((args) => args.filter((a, i) => args[i - 1] === '-L'));
    expect(calls).toEqual([[':/snap/fn/deno.lock', ':/snap/package-lock.json'], [':/snap/package-lock.json']]);
  });

  it('scans lockfiles under a directory whose name contains ":" and maps them back unprefixed', async () => {
    const bin = fakeScanner('colon.cjs', 1, output);
    const r = await runOsvScanner({ ...opts(bin), lockfiles: ['/snap/a:b/deno.lock', '/snap/a:b/package-lock.json'] });
    expect(r.unsupported).toEqual(['/snap/a:b/deno.lock']);
    expect(r.results).toHaveLength(1);
    const calls = callsOf('colon.cjs').map((args) => args.filter((a, i) => args[i - 1] === '-L'));
    expect(calls).toEqual([[':/snap/a:b/deno.lock', ':/snap/a:b/package-lock.json'], [':/snap/a:b/package-lock.json']]);
  });

  it('returns no results when every lockfile is unsupported', async () => {
    const r = await runOsvScanner({ ...opts(fakeScanner('alldeno.cjs', 1, output)), lockfiles: ['/a/deno.lock', '/b/deno.lock'] });
    expect(r).toMatchObject({ results: [], unsupported: ['/a/deno.lock', '/b/deno.lock'] });
  });

  it('skips the run when there are no lockfiles', async () => {
    const r = await runOsvScanner({ ...opts('/does/not/exist'), lockfiles: [] });
    expect(r).toMatchObject({ results: [], exitCode: 0 });
  });
});

describe('unsupportedLockfile', () => {
  it('names the rejected lockfile only for the no-extractor error', () => {
    const stderr = 'could not determine extractor suitable to this file: "/snap/x/deno.lock"';
    expect(unsupportedLockfile(stderr, ['/snap/package-lock.json', '/snap/x/deno.lock'])).toBe('/snap/x/deno.lock');
    expect(unsupportedLockfile(stderr, ['/snap/package-lock.json'])).toBeNull();
    expect(unsupportedLockfile('extraction failed on specified lockfile', ['/snap/x/deno.lock'])).toBeNull();
  });
});

const REAL_OSV_SCANNER = ['/opt/homebrew/bin/osv-scanner', '/usr/local/bin/osv-scanner'].find((p) => existsSync(p));

describe.skipIf(!REAL_OSV_SCANNER)('runOsvScanner with the real osv-scanner', () => {
  // A deno.lock is rejected before any database loads, so this needs no OSV database or network.
  it('accepts a lockfile under a directory named "a:b" and reports it by its plain path', async () => {
    const root = mkdtempSync(path.join(tmpdir(), 'vigiles-osv-real-'));
    try {
      const lockfile = path.join(root, 'snap', 'a:b', 'deno.lock');
      mkdirSync(path.dirname(lockfile), { recursive: true });
      writeFileSync(lockfile, '{"version":"4"}');
      mkdirSync(path.join(root, 'db'));
      const r = await runOsvScanner({ bin: REAL_OSV_SCANNER!, osvDbDir: path.join(root, 'db'), lockfiles: [lockfile], scratchDir: root });
      expect(r.unsupported).toEqual([lockfile]);
      expect(r.results).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  // An empty npm database (a zip with no entries) keeps this offline and hermetic.
  it('scans a package-lock.json under "a:b" and reports its packages under the plain path', async () => {
    const root = mkdtempSync(path.join(tmpdir(), 'vigiles-osv-real-'));
    try {
      const lockfile = path.join(root, 'snap', 'a:b', 'package-lock.json');
      mkdirSync(path.dirname(lockfile), { recursive: true });
      writeFileSync(
        lockfile,
        JSON.stringify({
          name: 't',
          version: '1.0.0',
          lockfileVersion: 3,
          requires: true,
          packages: {
            '': { name: 't', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } },
            'node_modules/left-pad': { version: '1.3.0' },
          },
        }),
      );
      const dbDir = path.join(root, 'db');
      mkdirSync(path.join(dbDir, 'osv-scalibr', 'npm'), { recursive: true });
      // End-of-central-directory record only: a valid, empty zip.
      writeFileSync(path.join(dbDir, 'osv-scalibr', 'npm', 'all.zip'), Buffer.concat([Buffer.from('PK\x05\x06'), Buffer.alloc(18)]));
      const r = await runOsvScanner({ bin: REAL_OSV_SCANNER!, osvDbDir: dbDir, lockfiles: [lockfile], scratchDir: root });
      expect(r.unsupported).toEqual([]);
      expect(r.exitCode).toBe(0);
      expect(r.results.map((s) => s.path)).toEqual([lockfile]);
      expect(r.results[0]!.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['left-pad@1.3.0']);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
