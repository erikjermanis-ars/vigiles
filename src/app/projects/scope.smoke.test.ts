/**
 * Smoke test of the project scope: renders the Inbox, Findings, Review, Eval and Projects pages (and the header
 * switcher) against a seeded in-memory DB with three projects, under the scope cookie and `?project=` overrides.
 * Next's router modules are stubbed; the cookie jar stands in for the request's cookies.
 */
import { createElement, type AnchorHTMLAttributes, type FormHTMLAttributes, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadVigilesConfig } from '@/lib/config/load';
import { openDb, type Db } from '@/lib/db/client';
import { eq } from 'drizzle-orm';
import { ownerCases, projects, scans } from '@/lib/db/schema';
import { insertConfig, insertFinding, insertLabel, insertProject } from '@/lib/eval/test-fixtures';
import { PROJECT_COOKIE, projectColors } from '@/lib/project-scope';

const cookieJar = vi.hoisted(() => new Map<string, string>());
vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name)! } : undefined),
    set: (name: string, value: string) => void cookieJar.set(name, value),
    delete: (name: string) => void cookieJar.delete(name),
  }),
}));
const nav = vi.hoisted(() => ({ search: '', pathname: '/' }));
vi.mock('next/navigation', () => ({
  unstable_rethrow: () => {},
  useRouter: () => ({ push: () => {}, refresh: () => {} }),
  usePathname: () => nav.pathname,
  useSearchParams: () => new URLSearchParams(nav.search),
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND');
  },
  redirect: (to: string) => {
    throw new Error(`NEXT_REDIRECT ${to}`);
  },
}));
vi.mock('next/link', () => ({
  default: ({ href, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) => createElement('a', { href, ...rest }),
}));
vi.mock('next/form', () => ({
  default: ({ action, ...rest }: FormHTMLAttributes<HTMLFormElement> & { action: string }) => createElement('form', { action, ...rest }),
}));
vi.mock('next/cache', () => ({ revalidatePath: () => {} }));

let tmp: string;
let db: Db;

const brief = {
  title: 'qs: denial of service',
  whatItIs: 'w',
  attackerCouldDo: 'a',
  whatItTakes: 'w',
  yourApp: 'y',
  exploitableToday: 'no' as const,
  fix: 'f',
  similarTo: null,
};

beforeAll(() => {
  tmp = mkdtempSync(path.join(tmpdir(), 'vigiles-scope-smoke-'));
  process.env.VIGILES_DATA_DIR = tmp;
  db = openDb(':memory:');
  (globalThis as unknown as { __vigilesDb?: Db }).__vigilesDb = db;
  insertConfig(db, loadVigilesConfig().triage.active_config, true);

  const web = insertProject(db, 'how-clutch-web', { name: 'HowClutch Web' });
  const api = insertProject(db, 'held-api', { name: 'Held API', exposure: 'internal' });
  const ios = insertProject(db, 'held-ios', { name: 'Held iOS', enabled: false });
  db.insert(scans)
    .values({ projectId: 'held-api', ref: 'origin/main', status: 'failed', error: 'could not read lockfile' })
    .run();

  insertFinding(db, web.scanId, { projectId: 'how-clutch-web', packageName: 'next-web', action: 'ping', priority: 'P1' });
  insertFinding(db, web.scanId, { projectId: 'how-clutch-web', packageName: 'lodash-web', action: 'log', priority: 'P3' });
  const qs = insertFinding(db, api.scanId, { projectId: 'held-api', packageName: 'qs-api', action: 'digest', priority: 'P2' });
  insertFinding(db, ios.scanId, { projectId: 'held-ios', packageName: 'alamofire-ios', action: 'ping', priority: 'P1' });
  const quiet = insertProject(db, 'quiet-tool', { name: 'Quiet Tool' });
  insertFinding(db, quiet.scanId, { projectId: 'quiet-tool', packageName: 'minimist-quiet', action: 'log', priority: 'P3' });
  insertLabel(db, qs.id, 'digest');
  db.insert(ownerCases).values({ findingId: qs.id, brief, reason: 'taste' }).run();
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
beforeEach(() => {
  cookieJar.clear();
  nav.search = '';
  nav.pathname = '/';
});

type Page = (props: { params?: Promise<Record<string, string>>; searchParams: Promise<Record<string, string>> }) => Promise<ReactElement> | ReactElement;
async function renderRaw(load: () => Promise<{ default: unknown }>, searchParams: Record<string, string> = {}) {
  const page = (await load()).default as Page;
  return renderToStaticMarkup(await page({ params: Promise.resolve({}), searchParams: Promise.resolve(searchParams) }));
}
const text = (html: string) =>
  html
    .replace(/<script[\s\S]*?<\/script>/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ');
const render = async (load: () => Promise<{ default: unknown }>, sp: Record<string, string> = {}) => text(await renderRaw(load, sp));

const inbox = () => import('../page');
const findingsPage = () => import('../findings/page');

describe('Inbox in a project scope', () => {
  it('shows a card per enabled project with its numbers and open owner cases', async () => {
    const html = await render(inbox, { view: 'all' });
    expect(html).toContain('All projects');
    expect(html).toContain('Ping now');
    expect(html).toContain("This week's digest");
    expect(html).toContain('Needs your call: 1 case');
    expect(html).toContain('The latest scan failed'); // held-api's newer scan failed
    expect(html).toContain('could not read lockfile');
    expect(html).toContain('next-web');
    expect(html).toContain('qs-api');
    expect(html).not.toContain('alamofire-ios'); // disabled project: no message
    // Cards in name order: Held API, then HowClutch Web; the disabled Held iOS has none.
    expect(html.indexOf('Held API')).toBeLessThan(html.indexOf('HowClutch Web'));
    expect(html).not.toContain('Not monitored');
  });

  it('narrows to the cookie’s project and lets ?project= override it', async () => {
    cookieJar.set(PROJECT_COOKIE, 'held-api');
    const api = await render(inbox, { view: 'all' });
    expect(api).toContain('qs-api');
    expect(api).not.toContain('next-web');
    expect(api).not.toContain('HowClutch Web');

    const all = await render(inbox, { view: 'all', project: 'all' });
    expect(all).toContain('next-web');
    expect(all).toContain('HowClutch Web');
    // The override is carried on the view toggle, so switching views keeps the scope.
    const raw = await renderRaw(inbox, { view: 'all', project: 'how-clutch-web' });
    expect(raw).toContain('href="/?project=how-clutch-web"');
  });

  it('ignores a cookie naming a project that no longer exists', async () => {
    cookieJar.set(PROJECT_COOKIE, 'removed-project');
    const html = await render(inbox, { view: 'all' });
    expect(html).toContain('All projects');
    expect(html).toContain('next-web');
  });

  it('says plainly when nothing needs attention', async () => {
    const html = await render(inbox, { project: 'quiet-tool' });
    expect(html).toContain('Quiet Tool');
    expect(html).toContain('Nothing to act on');
    expect(html).toContain('Nothing needs attention');
    expect(html).toContain('1 finding logged');
  });

  it('marks a disabled project as not monitored instead of sending its findings', async () => {
    const html = await render(inbox, { view: 'all', project: 'held-ios' });
    expect(html).toContain('Not monitored');
    expect(html).toContain('Held iOS (disabled)');
    expect(html).toContain('Held iOS is not monitored');
    expect(html).not.toContain('Nothing needs attention');
    expect(html).not.toContain('alamofire-ios');
  });
});

describe('Findings, Review and Eval in a project scope', () => {
  it('filters the findings list by the cookie, shows project names, and keeps an "all" override on links', async () => {
    cookieJar.set(PROJECT_COOKIE, 'held-api');
    const api = await render(findingsPage);
    expect(api).toContain('qs-api');
    expect(api).not.toContain('next-web');
    expect(api).toContain('Held API');

    const raw = await renderRaw(findingsPage, { project: 'all' });
    const all = text(raw);
    for (const pkg of ['qs-api', 'next-web', 'lodash-web', 'alamofire-ios']) expect(all).toContain(pkg);
    // Sort links keep "all projects", or the next request would fall back to the cookie's project.
    expect(raw).toMatch(/href="\/findings\?project=all&amp;sort=epss"/);
    const colors = projectColors(['how-clutch-web', 'held-api', 'held-ios', 'quiet-tool']);
    expect(raw).toContain(colors.get('held-api')!.soft);
    expect(raw).toContain(colors.get('how-clutch-web')!.soft);
  });

  it('limits the review queue and the eval labeled set to the scope', async () => {
    cookieJar.set(PROJECT_COOKIE, 'how-clutch-web');
    const review = await render(() => import('../review/page'));
    expect(review).toContain('labeled 0 of 1 open P0–P2 findings');
    expect(review).toContain('next-web');

    const evalWeb = await render(() => import('../eval/page'));
    expect(evalWeb).toContain('No labels from me on HowClutch Web yet');
    const evalApi = await render(() => import('../eval/page'), { project: 'held-api' });
    expect(evalApi).toContain('1 finding labeled by me');
    expect(evalApi).toContain('Held API');
  });
});

describe('Projects page', () => {
  it('shows each project’s state in plain words', async () => {
    const html = await render(() => import('./page'));
    expect(html).toContain('3 of 4 projects monitored');
    expect(html).toContain('Not monitored');
    expect(html).toContain('Last scan failed');
    expect(html).toContain('Monitored');
    expect(html).toContain('need your call');
  });
});

describe('header switcher', () => {
  async function switcher(cookieIds: string[] | null) {
    const { ProjectSwitcher } = await import('@/components/project-switcher');
    const colors = projectColors(['how-clutch-web', 'held-api', 'held-ios']);
    const projects = [
      { id: 'held-api', name: 'Held API', enabled: true, color: colors.get('held-api')! },
      { id: 'how-clutch-web', name: 'HowClutch Web', enabled: true, color: colors.get('how-clutch-web')! },
      { id: 'held-ios', name: 'Held iOS', enabled: false, color: colors.get('held-ios')! },
    ];
    return renderToStaticMarkup(createElement(ProjectSwitcher, { projects, cookieIds }));
  }
  const pressed = (html: string) => [...html.matchAll(/aria-pressed="true"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*aria-pressed="true"/g)].map((m) => m[1] ?? m[2]);

  it('highlights the cookie’s scope, or the URL override when there is one', async () => {
    expect(pressed(await switcher(null))).toEqual(['all']);
    expect(pressed(await switcher(['held-api']))).toEqual(['held-api']);
    nav.search = 'project=how-clutch-web&action=ping';
    nav.pathname = '/findings';
    const html = await switcher(['held-api']);
    expect(pressed(html)).toEqual(['how-clutch-web']);
    expect(html).toContain('value="/findings?project=how-clutch-web&amp;action=ping"');
    expect(html).toContain('(off)'); // the disabled project is listed, greyed
  });

  it('stores the picked project and returns to the page without its override', async () => {
    const { setProjectScopeAction } = await import('./actions');
    const submit = (project: string, returnTo: string) => {
      const fd = new FormData();
      fd.set('project', project);
      fd.set('returnTo', returnTo);
      return setProjectScopeAction(fd);
    };
    await expect(submit('held-api', '/findings?project=all&sort=epss')).rejects.toThrow('NEXT_REDIRECT /findings?sort=epss');
    expect(cookieJar.get(PROJECT_COOKIE)).toBe('held-api');
    await expect(submit('nope', '/')).rejects.toThrow('NEXT_REDIRECT /');
    expect(cookieJar.get(PROJECT_COOKIE)).toBe('held-api'); // an unknown id changes nothing
    await expect(submit('all', 'https://evil.example/')).rejects.toThrow('NEXT_REDIRECT /');
    expect(cookieJar.has(PROJECT_COOKIE)).toBe(false);
  });
});

describe('Inbox for a project that is new or clean', () => {
  beforeAll(() => {
    // fresh-app: its only scan failed, so nothing is known yet. clean-app: scanned, and nothing matches.
    const fresh = insertProject(db, 'fresh-app', { name: 'Fresh App' });
    db.update(projects).set({ lastScanId: null }).where(eq(projects.id, 'fresh-app')).run();
    db.update(scans).set({ status: 'failed', error: 'git fetch failed: could not read Username\nmore' }).where(eq(scans.id, fresh.scanId)).run();
    insertProject(db, 'clean-app', { name: 'Clean App' });
  });

  it('says once, plainly, that a project was never scanned, and shows dashes rather than reassuring zeros', async () => {
    const html = await render(inbox, { project: 'fresh-app' });
    expect(html).toContain('Never scanned successfully: the scan');
    expect(html).toContain('git fetch failed: could not read Username');
    expect(html).not.toContain('Username more'); // only the error's first line
    expect(html).not.toContain('from the scan before'); // there is no scan before
    expect(html).toContain('not scanned');
    expect(html).toContain('Nothing to show yet: no project here has been scanned successfully.');
    expect(html).not.toContain('Nothing needs attention');
    expect(html).not.toContain('Nothing to act on');
  });

  it('is reassuring for a scanned project with no finding at all', async () => {
    const html = await render(inbox, { project: 'clean-app' });
    expect(html).toContain('Nothing needs attention');
    expect(html).toContain('No known vulnerability matches the dependencies of');
    expect(html).toContain('Nothing to act on');
    expect(html).not.toContain('Go to Jobs');
  });
});

describe('header switcher on pages the scope does not filter', () => {
  it('is dimmed and says it filters the lists, not this page', async () => {
    const { ProjectSwitcher } = await import('@/components/project-switcher');
    const colors = projectColors(['held-api']);
    const projects = [{ id: 'held-api', name: 'Held API', enabled: true, color: colors.get('held-api')! }];
    const at = (pathname: string) => {
      nav.pathname = pathname;
      return renderToStaticMarkup(createElement(ProjectSwitcher, { projects, cookieIds: ['held-api'] }));
    };
    for (const p of ['/projects', '/jobs', '/findings/12']) {
      const html = at(p);
      expect(html).toContain('Filter for lists');
      expect(html).toContain('This page always shows every project');
    }
    for (const p of ['/', '/findings', '/review', '/eval']) {
      const html = at(p);
      expect(html).toContain('Showing');
      expect(html).not.toContain('Filter for lists');
    }
  });
});

describe('header', () => {
  async function renderLayout() {
    const { default: RootLayout } = await import('../layout');
    return renderToStaticMarkup(await RootLayout({ children: createElement('p', null, 'page body') }));
  }

  it('lists the pages in order, with Your call between Review and Eval, and the project switcher', async () => {
    cookieJar.set(PROJECT_COOKIE, 'held-api');
    const html = await renderLayout();
    const order = ['Inbox', 'Findings', 'Review', 'Your call', 'Eval', 'Projects', 'Jobs'].map((label) => html.indexOf(`>${label}<`));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).toMatch(/aria-pressed="true"[^>]*value="held-api"|value="held-api"[^>]*aria-pressed="true"/);
    expect(html).toContain('page body');
  });

  it('still renders the nav when the database cannot be read', async () => {
    const g = globalThis as unknown as { __vigilesDb?: Db };
    const real = g.__vigilesDb;
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    g.__vigilesDb = new Proxy({} as Db, {
      get() {
        throw new Error('database is locked');
      },
    });
    try {
      const html = await renderLayout();
      expect(html).toContain('>Inbox<');
      expect(html).toContain('page body');
      expect(html).not.toContain('All projects'); // no switcher without the project list
    } finally {
      g.__vigilesDb = real;
      errors.mockRestore();
    }
  });
});
