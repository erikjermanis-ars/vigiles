/**
 * Smoke test of the "Your call" page, its server action and the nav link: renders them to HTML against a
 * seeded in-memory DB (Next's router modules are stubbed). Checks the one-case-at-a-time flow and that the
 * answers to compare with (system, agents, reason) stay hidden until the owner has answered.
 */
import { and, eq } from 'drizzle-orm';
import { createElement, type AnchorHTMLAttributes, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { answeredWhen } from '@/components/decide/case-view';
import { DecideNavLink, openCaseCount } from '@/components/decide/nav-link';
import { openDb, type Db } from '@/lib/db/client';
import { findings, labels, ownerCases, projects } from '@/lib/db/schema';
import { LABELER_COOKIE } from '@/lib/queries/findings';
import type { OwnerBrief, ProjectProfile } from '@/lib/types';

const cookieJar = vi.hoisted(() => new Map<string, string>());
const revalidated = vi.hoisted(() => [] as string[]);
vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name)! } : undefined),
  }),
}));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: () => {}, refresh: () => {} }),
  redirect: (to: string) => {
    throw new Error(`NEXT_REDIRECT ${to}`);
  },
}));
vi.mock('next/link', () => ({
  default: ({ href, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) => createElement('a', { href, ...rest }),
}));
vi.mock('next/cache', () => ({ revalidatePath: (p: string, type?: string) => void revalidated.push(`${p}|${type ?? ''}`) }));

const brief = (title: string, extra: Partial<OwnerBrief> = {}): OwnerBrief => ({
  title,
  whatItIs: 'A bug in the image resizer.',
  attackerCouldDo: 'Crash the server for every user.',
  whatItTakes: 'The resize endpoint must be reachable from the internet.',
  yourApp: 'The endpoint is switched off in production.',
  exploitableToday: 'no',
  fix: 'Minor version bump of sharp.',
  similarTo: null,
  ...extra,
});

let db: Db;

beforeAll(() => {
  db = openDb(':memory:');
  (globalThis as unknown as { __vigilesDb?: Db }).__vigilesDb = db;
  const profile = { id: 'held-api', name: 'Held API' } as unknown as ProjectProfile;
  db.insert(projects).values({ id: 'held-api', name: 'Held API', repoPath: '/x', ref: 'origin/main', profile, profileHash: 'h' }).run();
  for (const id of [1, 2, 3]) {
    db.insert(findings)
      .values({
        id,
        projectId: 'held-api',
        lockfile: 'package-lock.json',
        ecosystem: 'npm',
        packageName: `pkg-${id}`,
        osvId: `GHSA-${id}`,
        origin: 'baseline',
        firstSeenScanId: 1,
        lastSeenScanId: 1,
      })
      .run();
  }
});
afterAll(() => {
  delete (globalThis as unknown as { __vigilesDb?: Db }).__vigilesDb;
});
beforeEach(() => {
  db.delete(ownerCases).run();
  db.delete(labels).run();
  cookieJar.clear();
  revalidated.length = 0;
});

type Page = (props: { searchParams: Promise<Record<string, string>> }) => Promise<ReactElement>;
async function render(searchParams: Record<string, string> = {}) {
  const page = (await import('./page')).default as unknown as Page;
  return renderToStaticMarkup(await page({ searchParams: Promise.resolve(searchParams) }));
}

function addCase(findingId: number, title: string, extra: Partial<typeof ownerCases.$inferInsert> = {}) {
  return db
    .insert(ownerCases)
    .values({ findingId, brief: brief(title), reason: `REASON-${findingId}`, systemAction: 'log', agentAction: 'digest', ...extra })
    .returning({ id: ownerCases.id })
    .get().id;
}

function form(fields: Record<string, string>) {
  const fd = new FormData();
  for (const [k, v] of Object.entries(fields)) fd.set(k, v);
  return fd;
}

describe('decide page', () => {
  it('shows the empty state', async () => {
    const html = await render();
    expect(html).toContain('Nothing needs your call right now.');
    expect(html).not.toContain('decided');
  });

  it('shows the first open case with the brief and hides the answers to compare with', async () => {
    addCase(1, 'Image resizer: server crash');
    addCase(2, 'Second case', {
      brief: brief('Second case', { exploitableToday: 'yes', similarTo: 'Like the sharp case: you chose Digest.' }),
    });
    const html = await render();
    for (const s of [
      '0 of 2</strong> decided',
      'Held API',
      'Image resizer: server crash',
      'What it is',
      'What an attacker could do',
      'Crash the server for every user.',
      'What it takes',
      'Your app',
      'Exploitable today: <strong class="font-semibold">No</strong>',
      'Fix',
      'Ping',
      'Digest',
      'Log',
      'interrupt someone now',
      'href="/findings/1"',
      'See full technical details',
      'Skip for now',
    ]) {
      expect(html).toContain(s);
    }
    expect(html).not.toContain('Similar earlier case');
    expect(html).not.toContain('REASON-1');
    expect(html).not.toContain('Second case');

    const second = await render({ case: '2' });
    expect(second).toContain('Similar earlier case');
    expect(second).toContain('Exploitable today: <strong class="font-semibold">Yes</strong>');

    // Neutral until answered: no ping / digest / log (or red / green) colour anywhere, not even on "Yes".
    for (const page of [html, second]) expect(page).not.toMatch(/\b(?:bg|text|border)-(?:ping|digest|log|ok)(?:-bg)?\b/);
  });

  it('answers through the action, reveals the comparison, and lists the case as decided', async () => {
    const a = addCase(1, 'First case');
    const b = addCase(2, 'Second case', { systemAction: 'digest', agentAction: null });
    cookieJar.set(LABELER_COOKIE, 'Ana');
    const { answerCaseAction } = await import('./actions');

    await expect(answerCaseAction({ error: null }, form({ caseId: String(b), answer: 'digest', note: 'fine for monday' }))).rejects.toThrow(
      `NEXT_REDIRECT /decide?case=${b}`,
    );
    expect(revalidated).toContain('/|layout');
    const label = db
      .select()
      .from(labels)
      .where(and(eq(labels.findingId, 2), eq(labels.labeler, 'ana')))
      .get();
    expect(label).toMatchObject({ expectedAction: 'digest', note: '[decide] fine for monday' });

    const reveal = await render({ case: String(b) });
    for (const s of [
      'You chose',
      'What the system does now',
      'Matches',
      'What the agent reviewers said',
      'Not recorded',
      'REASON-2',
      'Your note: “fine for monday”',
      'just now',
      'Saved. Where these differ, your answer is the one that counts.',
      `href="/decide?case=${a}"`,
      'Next case →',
      'Change your answer',
    ]) {
      expect(reveal).toContain(s);
    }
    expect(reveal).toContain('1 of 2</strong> decided');
    expect(reveal).toContain(`href="/decide?case=${b}&amp;change=1"`); // the decided list

    // The default view moves on to the open case; the decided one is listed below.
    const next = await render();
    expect(next).toContain('First case');
    expect(next).toContain('Decided (1)');
    expect(next).not.toContain('REASON-2');

    // Changing the answer updates the case and the label.
    await expect(answerCaseAction({ error: null }, form({ caseId: String(b), answer: 'ping' }))).rejects.toThrow('NEXT_REDIRECT');
    expect(db.select().from(labels).where(eq(labels.findingId, 2)).get()?.expectedAction).toBe('ping');
    const changed = await render({ case: String(b), change: '1' });
    expect(changed).toContain('Differs');
    expect(changed).toContain('<details open=""');

    // The last open case: Finish goes back to the overview, which says everything is decided.
    await expect(answerCaseAction({ error: null }, form({ caseId: String(a), answer: 'log' }))).rejects.toThrow('NEXT_REDIRECT');
    const last = await render({ case: String(a) });
    expect(last).toContain('Finish');
    expect(last).toContain('href="/decide"');
    const done = await render();
    expect(done).toContain('All 2 decided.');
    expect(done).toContain('Decided (2)');
  });

  it('returns readable errors instead of throwing', async () => {
    const w = addCase(1, 'Withdrawn case', { status: 'withdrawn' });
    const { answerCaseAction } = await import('./actions');
    expect(await answerCaseAction({ error: null }, form({ caseId: String(w), answer: 'ping' }))).toEqual({
      error: 'This case was withdrawn, so there is nothing to decide. Reload the page to see the next one.',
    });
    expect(await answerCaseAction({ error: null }, form({ caseId: String(w) }))).toEqual({ error: 'Choose Ping, Digest or Log.' });
    expect(db.select().from(labels).all()).toHaveLength(0);
    expect(revalidated).toHaveLength(0);
  });

  it('says when a requested case is no longer open', async () => {
    const w = addCase(1, 'Withdrawn case', { status: 'withdrawn' });
    addCase(2, 'Open case');
    const html = await render({ case: String(w) });
    expect(html).toContain('That case is no longer open. Here is the next one.');
    expect(html).toContain('Open case');
    expect(html).not.toContain('Withdrawn case');
  });

  it('still renders a case whose brief is unreadable', async () => {
    addCase(3, 'x', { brief: { title: 'only a title' } as unknown as OwnerBrief });
    const html = await render();
    expect(html).toContain('pkg-3 (GHSA-3)');
    expect(html).toContain('The plain-language summary for this case is missing.');
  });
});

it('says "just now" for the first minute after answering', () => {
  const now = new Date('2026-11-11T10:00:00Z');
  expect(answeredWhen('2026-11-11T09:59:30Z', now)).toBe('just now');
  expect(answeredWhen('2026-11-11T09:55:00Z', now)).toBe('5 minutes ago');
});

describe('nav link', () => {
  it('shows the open-case count', () => {
    addCase(1, 'a');
    addCase(2, 'b');
    addCase(3, 'c', { status: 'answered', answer: 'log' });
    const html = renderToStaticMarkup(createElement(DecideNavLink));
    expect(html).toContain('href="/decide"');
    expect(html).toContain('Your call');
    expect(html).toContain('aria-label="Your call (2 open)"');
    expect(html).toMatch(/>2<\/span>/);
  });

  it('shows no badge without open cases, and never throws', () => {
    const html = renderToStaticMarkup(createElement(DecideNavLink));
    expect(html).toContain('Your call');
    expect(html).not.toContain('rounded-full'); // the badge
    expect(html).not.toContain('aria-label');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(
      openCaseCount(() => {
        throw new Error('no such table: owner_cases');
      }),
    ).toBe(0);
    spy.mockRestore();
    expect(renderToStaticMarkup(createElement(DecideNavLink, { count: 120 }))).toContain('99+');
    for (const count of [-1, Number.NaN, 0])
      expect(renderToStaticMarkup(createElement(DecideNavLink, { count }))).not.toContain('rounded-full');
  });
});
