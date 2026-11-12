import { describe, expect, it } from 'vitest';
import {
  PROJECT_PALETTE,
  UNKNOWN_PROJECT_COLOR,
  colorFor,
  isScopedPath,
  parseScopeValue,
  projectColors,
  resolveProjectScope,
  scopeIncludes,
  scopeLabel,
  scopeParam,
  scopeReturnPath,
  scopedProjects,
  withScope,
  type ScopeContext,
} from './project-scope';

const KNOWN = ['how-clutch-web', 'held-api', 'held-ios'];

describe('parseScopeValue', () => {
  it('reads one or several known ids, deduplicated, in the order given', () => {
    expect(parseScopeValue('held-api', KNOWN)).toEqual(['held-api']);
    expect(parseScopeValue('held-ios, held-api,held-ios', KNOWN)).toEqual(['held-ios', 'held-api']);
    expect(parseScopeValue(['held-api', 'held-ios'], KNOWN)).toEqual(['held-api', 'held-ios']);
  });

  it('reads "all" and an empty value as every project', () => {
    expect(parseScopeValue('all', KNOWN)).toBeNull();
    expect(parseScopeValue('', KNOWN)).toBeNull();
    expect(parseScopeValue(' , ', KNOWN)).toBeNull();
    expect(parseScopeValue('held-api,all', KNOWN)).toBeNull();
  });

  it('ignores unknown ids, and a value naming no known project is no value at all', () => {
    expect(parseScopeValue('held-api,ghost', KNOWN)).toEqual(['held-api']);
    expect(parseScopeValue('ghost', KNOWN)).toBeUndefined();
    expect(parseScopeValue(undefined, KNOWN)).toBeUndefined();
    expect(parseScopeValue(null, KNOWN)).toBeUndefined();
    expect(parseScopeValue(42, KNOWN)).toBeUndefined();
    expect(parseScopeValue('held-api', [])).toBeUndefined();
  });
});

describe('resolveProjectScope', () => {
  it('defaults to every project', () => {
    expect(resolveProjectScope({ knownIds: KNOWN })).toEqual({ ids: null, source: 'default' });
  });

  it('uses a valid cookie, and ignores a stale or tampered one', () => {
    expect(resolveProjectScope({ cookie: 'held-ios', knownIds: KNOWN })).toEqual({ ids: ['held-ios'], source: 'cookie' });
    expect(resolveProjectScope({ cookie: 'removed-project', knownIds: KNOWN })).toEqual({ ids: null, source: 'default' });
    expect(resolveProjectScope({ cookie: 'all', knownIds: KNOWN })).toEqual({ ids: null, source: 'default' });
  });

  it('lets ?project= override the cookie, including back to every project', () => {
    expect(resolveProjectScope({ query: 'held-api', cookie: 'held-ios', knownIds: KNOWN })).toEqual({ ids: ['held-api'], source: 'query' });
    expect(resolveProjectScope({ query: 'all', cookie: 'held-ios', knownIds: KNOWN })).toEqual({ ids: null, source: 'query' });
    expect(resolveProjectScope({ query: '', cookie: 'held-ios', knownIds: KNOWN })).toEqual({ ids: null, source: 'query' });
  });

  it('falls back to the cookie when ?project= names no known project', () => {
    expect(resolveProjectScope({ query: 'ghost', cookie: 'held-ios', knownIds: KNOWN })).toEqual({ ids: ['held-ios'], source: 'cookie' });
  });
});

describe('scope helpers', () => {
  const projects = [
    { id: 'how-clutch-web', name: 'HowClutch Web', enabled: true },
    { id: 'held-api', name: 'Held API', enabled: true },
    { id: 'held-ios', name: 'Held iOS', enabled: false },
  ];
  const ctx = (ids: string[] | null, source: ScopeContext['source'] = 'cookie'): ScopeContext => ({ ids, source, projects, cookieIds: null });

  it('names the scope in words', () => {
    expect(scopeLabel(ctx(null, 'default'))).toBe('All projects');
    expect(scopeLabel(ctx(['held-api']))).toBe('Held API');
    expect(scopeLabel(ctx(['held-api', 'held-ios', 'how-clutch-web'], 'query'))).toBe('Held API, Held iOS and HowClutch Web');
    expect(scopeLabel(ctx(['gone']))).toBe('gone');
  });

  it('lists the projects in scope and checks membership', () => {
    expect(scopedProjects(ctx(null)).map((p) => p.id)).toEqual(['how-clutch-web', 'held-api', 'held-ios']);
    expect(scopedProjects(ctx(['held-ios', 'held-api'])).map((p) => p.id)).toEqual(['held-api', 'held-ios']);
    expect(scopeIncludes({ ids: null }, 'x')).toBe(true);
    expect(scopeIncludes({ ids: ['held-api'] }, 'held-api')).toBe(true);
    expect(scopeIncludes({ ids: ['held-api'] }, 'held-ios')).toBe(false);
  });

  it('carries only a URL override on in-page links', () => {
    expect(scopeParam({ ids: ['held-api'], source: 'cookie' })).toBeNull();
    expect(scopeParam({ ids: null, source: 'default' })).toBeNull();
    expect(scopeParam({ ids: ['held-api', 'held-ios'], source: 'query' })).toBe('held-api,held-ios');
    expect(scopeParam({ ids: null, source: 'query' })).toBe('all');

    expect(withScope('/review?id=3', { ids: ['held-api'], source: 'cookie' })).toBe('/review?id=3');
    expect(withScope('/review?id=3', { ids: ['held-api'], source: 'query' })).toBe('/review?id=3&project=held-api');
    expect(withScope('/?view=all', { ids: null, source: 'query' })).toBe('/?view=all&project=all');
    expect(withScope('/eval#cell', { ids: ['a', 'b'], source: 'query' })).toBe('/eval?project=a,b#cell');
  });
});

describe('isScopedPath', () => {
  it('is true only on the list pages the scope filters', () => {
    for (const p of ['/', '/findings', '/findings/', '/review', '/eval', null, undefined]) expect(isScopedPath(p)).toBe(true);
    for (const p of ['/projects', '/projects/held-api', '/jobs', '/jobs/9', '/findings/12', '/decide']) expect(isScopedPath(p)).toBe(false);
  });
});

describe('scopeReturnPath', () => {
  it('returns to the same page without its project override', () => {
    expect(scopeReturnPath('/findings?project=held-api&action=ping&sort=epss')).toBe('/findings?action=ping&sort=epss');
    expect(scopeReturnPath('/?view=all&project=all')).toBe('/?view=all');
    expect(scopeReturnPath('/eval')).toBe('/eval');
    expect(scopeReturnPath('/findings/12')).toBe('/findings/12');
  });

  it('restarts the Review queue in the new scope', () => {
    expect(scopeReturnPath('/review?id=12&project=held-api')).toBe('/review');
  });

  it('only accepts same-origin paths', () => {
    for (const bad of ['https://evil.example/', '//evil.example/x', '/\\evil.example', 'javascript:alert(1)', '', 'findings', null, 3]) {
      expect(scopeReturnPath(bad)).toBe('/');
    }
  });
});

describe('projectColors', () => {
  it('gives every project its own colour, the same whatever order the ids come in', () => {
    const a = projectColors(['how-clutch-web', 'held-api', 'held-ios']);
    const b = projectColors(['held-ios', 'how-clutch-web', 'held-api', 'held-api']);
    expect(new Set([...a.values()]).size).toBe(3);
    for (const id of ['how-clutch-web', 'held-api', 'held-ios']) expect(b.get(id)).toBe(a.get(id));
  });

  it('keeps colours distinct up to the palette size, then reuses them', () => {
    const ids = Array.from({ length: PROJECT_PALETTE.length }, (_, i) => `p-${i}`);
    expect(new Set([...projectColors(ids).values()]).size).toBe(PROJECT_PALETTE.length);
    const more = projectColors([...ids, 'one-more']);
    expect(more.size).toBe(PROJECT_PALETTE.length + 1);
    expect(PROJECT_PALETTE).toContain(more.get('one-more'));
  });

  it('greys out a project id it does not know', () => {
    expect(colorFor(projectColors(['a']), 'gone')).toBe(UNKNOWN_PROJECT_COLOR);
  });
});
