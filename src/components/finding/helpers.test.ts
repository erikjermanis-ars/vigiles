import { describe, expect, it } from 'vitest';
import {
  formatChain,
  formatCvss,
  formatEpss,
  humanize,
  importSitesShownNote,
  isFileCitation,
  isHttpUrl,
  sourceHref,
  summarizeEventData,
  truncate,
} from './helpers';
import { isTextEntryTarget, reviewKeyCommand, type ReviewKeyInput } from './review-keys';

describe('helpers', () => {
  it('builds source viewer links with an anchor for the line', () => {
    expect(sourceHref(7, 'src/app/a b.ts', 12)).toBe('/findings/7/source?file=src%2Fapp%2Fa+b.ts&line=12#L12');
    expect(sourceHref(7, 'package.json', null)).toBe('/findings/7/source?file=package.json');
  });

  it('carries the triage run of an evidence link (the viewer opens the commit that run read)', () => {
    expect(sourceHref(7, 'src/a.ts', 3, 42)).toBe('/findings/7/source?file=src%2Fa.ts&line=3&run=42#L3');
    expect(sourceHref(7, 'src/a.ts', null, 42)).toBe('/findings/7/source?file=src%2Fa.ts&run=42');
    expect(sourceHref(7, 'src/a.ts', 3, null)).toBe('/findings/7/source?file=src%2Fa.ts&line=3#L3');
  });

  it('notes a capped import-site list', () => {
    expect(importSitesShownNote(20, 57)).toBe('showing 20 of 57');
    expect(importSitesShownNote(3, 3)).toBe('');
    expect(importSitesShownNote(3, 0)).toBe(''); // findings from older scans store no count
  });

  it('links only path-like evidence citations (real outputs cite "(dependency facts)" etc.)', () => {
    for (const f of ['package.json', 'src/app/api/users/invite/route.ts', 'src/app/(marketing)/page.tsx', '(group)/page.tsx']) {
      expect(isFileCitation(f)).toBe(true);
    }
    // '.' and '**/*' are what real runs cite for a repo-wide grep with no matches.
    for (const f of ['(dependency facts)', '(repo source, excluding package-lock.json)', '(project profile)', '[advisory]', '<advisory>', '  ', '', '.', './', '**/*', 'src/**/*.ts']) {
      expect(isFileCitation(f)).toBe(false);
    }
  });

  it('formats values', () => {
    expect(truncate('  a   b  ', 10)).toBe('a b');
    expect(truncate('abcdefghij', 5)).toBe('abcd…');
    expect(truncate(null, 5)).toBe('');
    expect(humanize('build_or_tooling_only')).toBe('build or tooling only');
    expect(formatChain(['shadcn', 'express', 'proxy-addr'])).toBe('shadcn › express › proxy-addr');
    expect(formatEpss(0.1234, 0.97)).toBe('12.3% (p97)');
    expect(formatEpss(0.0004)).toBe('0.040%');
    expect(formatEpss(null)).toBe('—');
    expect(formatCvss(9.75)).toBe('9.8');
    expect(isHttpUrl('https://x.test')).toBe(true);
    expect(isHttpUrl('javascript:alert(1)')).toBe(false);
  });

  it('summarizes event data on one line', () => {
    expect(summarizeEventData({ from: 'P2', to: 'P1', n: 3, ok: true, x: null })).toBe('from: P2 · to: P1 · n: 3 · ok: true · x: —');
    expect(summarizeEventData({ nested: { a: [1, 2] } })).toBe('nested: {"a":[1,2]}');
    expect(summarizeEventData(null)).toBe('');
  });
});

describe('review shortcuts', () => {
  const key = (k: string, over: Partial<ReviewKeyInput> = {}) =>
    reviewKeyCommand({ key: k, metaKey: false, ctrlKey: false, altKey: false, targetTag: 'BODY', ...over });

  it('maps the documented keys', () => {
    expect(key('1')).toEqual({ kind: 'expected', value: 'ping' });
    expect(key('2')).toEqual({ kind: 'expected', value: 'digest' });
    expect(key('3')).toEqual({ kind: 'expected', value: 'log' });
    expect(key('y')).toEqual({ kind: 'affected', value: 'yes' });
    expect(key('N')).toEqual({ kind: 'affected', value: 'no' });
    expect(key('u')).toEqual({ kind: 'affected', value: 'unsure' });
    expect(key('Enter')).toEqual({ kind: 'save' });
    expect(key('j')).toEqual({ kind: 'next' });
    expect(key('k')).toEqual({ kind: 'prev' });
    expect(key('x')).toBeNull();
  });

  it('works while a radio button has focus', () => {
    expect(key('2', { targetTag: 'INPUT', targetType: 'radio' })).toEqual({ kind: 'expected', value: 'digest' });
  });

  it('never fires while typing in the note or another text field', () => {
    for (const k of ['1', 'y', 'j', 'k', 'Enter']) {
      expect(key(k, { targetTag: 'TEXTAREA' })).toBeNull();
      expect(key(k, { targetTag: 'INPUT', targetType: 'text' })).toBeNull();
      expect(key(k, { targetTag: 'DIV', targetEditable: true })).toBeNull();
    }
    expect(isTextEntryTarget({ targetTag: 'INPUT', targetType: null })).toBe(true);
    expect(isTextEntryTarget({ targetTag: 'SELECT' })).toBe(true);
  });

  it('leaves modified keys, IME composition and Enter on buttons/links alone', () => {
    expect(key('1', { metaKey: true })).toBeNull();
    expect(key('k', { ctrlKey: true })).toBeNull();
    expect(key('j', { altKey: true })).toBeNull();
    expect(key('y', { isComposing: true })).toBeNull();
    expect(key('Enter', { targetTag: 'BUTTON' })).toBeNull();
    expect(key('Enter', { targetTag: 'A' })).toBeNull();
    expect(key('Enter', { targetTag: 'SUMMARY' })).toBeNull(); // toggles the references <details>
    expect(key('Enter', { targetTag: null })).toEqual({ kind: 'save' });
  });

  it('fires once for a held key (auto-repeat would save, then skip past the reveal)', () => {
    expect(key('Enter', { repeat: true })).toBeNull();
    expect(key('j', { repeat: true })).toBeNull();
    expect(key('1', { repeat: true })).toBeNull();
  });
});
