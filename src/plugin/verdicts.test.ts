import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { makeFinding, makeVerdict } from './report-fixtures';
import { loadFailures, loadVerdicts, saveFailures, VerdictStore } from './verdicts';

const tmp = mkdtempSync(path.join(os.tmpdir(), 'vigiles-verdicts-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
let n = 0;
const file = (name = 'verdicts.json') => path.join(tmp, `${++n}-${name}`);

const zod = makeFinding({ osvId: 'GHSA-b', packageName: 'zod' });
const next = makeFinding({ osvId: 'GHSA-a', packageName: 'next' });
const nextApps = makeFinding({ osvId: 'GHSA-a', packageName: 'next', lockfile: 'apps/web/package-lock.json' });

describe('VerdictStore', () => {
  it('finds a verdict by (osvId, ecosystem, package, lockfile) and counts it as current only for the same input hash', () => {
    const store = new VerdictStore([makeVerdict(next)]);
    expect(store.get(next)?.packageName).toBe('next');
    expect(store.get(nextApps)).toBeNull();
    expect(store.current(next)).not.toBeNull();
    const changed = { ...next, inputHash: 'changed' };
    expect(store.get(changed)).not.toBeNull();
    expect(store.current(changed)).toBeNull();
  });

  it('upsert replaces the verdict of the same finding and validates it', () => {
    const store = new VerdictStore([makeVerdict(next)]);
    store.upsert(makeVerdict(next, { verdict: 'affected' }, { inputHash: 'h2' }));
    expect(store.size).toBe(1);
    expect(store.get(next)?.output.verdict).toBe('affected');
    expect(() => store.upsert({ ...makeVerdict(zod), inputHash: 42 } as never)).toThrow();
  });

  it('saves sorted, 2-space JSON with a trailing newline that loads back unchanged', () => {
    const store = new VerdictStore([makeVerdict(zod), makeVerdict(nextApps), makeVerdict(next)]);
    const f = file();
    store.save(f);
    const text = readFileSync(f, 'utf8');
    expect(text.endsWith('}\n')).toBe(true);
    expect(text).toContain('\n  "verdicts": [\n    {\n      "osvId": "GHSA-a"');
    const json = JSON.parse(text);
    expect(json.format).toBe(1);
    expect(json.verdicts.map((v: { osvId: string; lockfile: string }) => `${v.osvId} ${v.lockfile}`)).toEqual([
      'GHSA-a apps/web/package-lock.json',
      'GHSA-a package-lock.json',
      'GHSA-b package-lock.json',
    ]);
    const { store: again, warnings } = loadVerdicts(f);
    expect(warnings).toEqual([]);
    expect(again.toFile()).toEqual(store.toFile());
    // Saving what was loaded writes the same bytes (no churn in git).
    const f2 = file();
    again.save(f2);
    expect(readFileSync(f2, 'utf8')).toBe(text);
  });

  it('writes keys in schema order whatever order the verdict object had', () => {
    const v = makeVerdict(zod);
    const reversed = Object.fromEntries(Object.entries(v).reverse()) as typeof v;
    const store = new VerdictStore([reversed]);
    expect(Object.keys(store.all()[0]!)[0]).toBe('osvId');
  });
});

describe('loadVerdicts', () => {
  it('treats a missing file as empty', () => {
    const { store, warnings } = loadVerdicts(path.join(tmp, 'nope.json'));
    expect(store.size).toBe(0);
    expect(warnings).toEqual([]);
  });

  it('skips invalid entries with a warning and keeps the rest', () => {
    const f = file();
    const bad = { ...makeVerdict(zod), output: { verdict: 'maybe' } };
    writeFileSync(f, JSON.stringify({ format: 1, verdicts: [makeVerdict(next), bad, 'junk'] }));
    const { store, warnings } = loadVerdicts(f);
    expect(store.size).toBe(1);
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toMatch(/entry 2 \(GHSA-b zod\) is invalid and was ignored \(output\.verdict: .*\); it will be triaged again/);
    expect(warnings[1]).toMatch(/^verdicts\.json entry 3 is invalid/);
  });

  it('keeps the newer of two entries for the same finding', () => {
    const f = file();
    const older = makeVerdict(next, { verdict: 'affected' }, { triagedAt: '2026-11-01T00:00:00Z' });
    const newer = makeVerdict(next, { verdict: 'not_affected' }, { triagedAt: '2026-11-02T00:00:00Z' });
    writeFileSync(f, JSON.stringify({ format: 1, verdicts: [newer, older] }));
    const { store, warnings } = loadVerdicts(f);
    expect(store.get(next)?.output.verdict).toBe('not_affected');
    expect(warnings[0]).toMatch(/duplicates another entry/);
  });

  it('refuses files that are not a verdict file', () => {
    const cases: [string, RegExp][] = [
      ['{ not json', /is not valid JSON/],
      ['[]', /expected an object/],
      [JSON.stringify({ format: 2, verdicts: [] }), /newer Vigiles/],
      [JSON.stringify({ format: 'x', verdicts: [] }), /unknown format/],
      [JSON.stringify({ format: 1 }), /"verdicts" must be an array/],
      ['{\n<<<<<<< HEAD\n  "format": 1\n=======\n  "format": 1\n>>>>>>> other\n}\n', /merge conflict/],
    ];
    for (const [text, error] of cases) {
      const f = file();
      writeFileSync(f, text);
      expect(() => loadVerdicts(f)).toThrow(error);
    }
  });

  it('names where the JSON broke without quoting the file', () => {
    const f = file();
    writeFileSync(f, 'STRIPE_SECRET_KEY=sk_test_FAKE123\n');
    expect(() => loadVerdicts(f)).toThrow(/is not valid JSON$/);
    let message = '';
    try {
      loadVerdicts(f);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).not.toMatch(/STRIPE|sk_test/);
    const g = file();
    writeFileSync(g, '{\n  "format": 1,\n  "verdicts": [] SECRET\n}\n');
    expect(() => loadVerdicts(g)).toThrow(/is not valid JSON \(line 3, column \d+\)$/);
  });

  it('refuses a symlinked verdicts.json or .vigiles/, and never writes through them', () => {
    const secret = path.join(tmp, 'dot-env');
    writeFileSync(secret, 'STRIPE_SECRET_KEY=sk_test_FAKE123\n');
    const dir = path.join(tmp, 'linked-file');
    mkdirSync(dir);
    const f = path.join(dir, 'verdicts.json');
    symlinkSync(secret, f);
    expect(() => loadVerdicts(f)).toThrow(/verdicts\.json is a symlink/);
    // Saving replaces the link itself; the target keeps its content.
    new VerdictStore([makeVerdict(next)]).save(f);
    expect(lstatSync(f).isSymbolicLink()).toBe(false);
    expect(readFileSync(secret, 'utf8')).toBe('STRIPE_SECRET_KEY=sk_test_FAKE123\n');

    const real = path.join(tmp, 'real-vigiles');
    mkdirSync(real);
    const repo = path.join(tmp, 'linked-dir');
    mkdirSync(repo);
    symlinkSync(real, path.join(repo, '.vigiles'));
    const g = path.join(repo, '.vigiles', 'verdicts.json');
    expect(() => loadVerdicts(g)).toThrow(/\.vigiles is a symlink/);
    expect(() => new VerdictStore().save(g)).toThrow(/\.vigiles is a symlink/);
    expect(existsSync(path.join(real, 'verdicts.json'))).toBe(false);
  });
});

describe('failures', () => {
  it('round-trips sorted by finding id; missing or broken files are empty', () => {
    const f = file('failures.json');
    expect(loadFailures(f)).toEqual({});
    saveFailures(f, {
      [zod.id]: { inputHash: 'h1', error: 'claude error_max_budget_usd', at: '2026-11-12T10:00:00Z' },
      [next.id]: { inputHash: 'h2', error: 'timed out', at: '2026-11-12T10:01:00Z' },
    });
    expect(existsSync(f)).toBe(true);
    const loaded = loadFailures(f);
    expect(Object.keys(loaded)).toEqual([next.id, zod.id]);
    expect(loaded[zod.id]?.error).toBe('claude error_max_budget_usd');

    writeFileSync(f, JSON.stringify({ ok: { inputHash: 'h', error: 'e', at: 't' }, bad: { inputHash: 1 } }));
    expect(Object.keys(loadFailures(f))).toEqual(['ok']);
    writeFileSync(f, 'garbage');
    expect(loadFailures(f)).toEqual({});
  });
});
