/**
 * Smoke test: renders the Inbox and Eval pages to HTML against a seeded in-memory DB (Next's router modules
 * are stubbed). Covers the 'since' anchor text, the malicious remediation, the disabled-project note, the
 * logged link, the policy-action consistency column and the per-refresh volume table.
 */
import { loadVigilesConfig } from '@/lib/config/load';
import { MALICIOUS_REMEDIATION } from '@/lib/types';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createElement, type AnchorHTMLAttributes, type FormHTMLAttributes, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { loadPolicy } from '@/lib/config/load';
import { openDb, type Db } from '@/lib/db/client';
import { triageConfigs } from '@/lib/db/schema';
import {
  insertConfig,
  insertEvent,
  insertFinding,
  insertJob,
  insertLabel,
  insertProject,
  insertTriageRun,
  triageOutput,
} from '@/lib/eval/test-fixtures';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: () => {}, refresh: () => {} }),
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND');
  },
}));
vi.mock('next/link', () => ({
  default: ({ href, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) => createElement('a', { href, ...rest }),
}));
vi.mock('next/form', () => ({
  default: ({ action, ...rest }: FormHTMLAttributes<HTMLFormElement> & { action: string }) => createElement('form', { action, ...rest }),
}));
vi.mock('next/cache', () => ({ revalidatePath: () => {} }));
// Eval defaults its labeler to the Review page's cookie; no cookie → 'me'.
vi.mock('next/headers', () => ({ cookies: async () => ({ get: () => undefined }) }));

let tmp: string;
let db: Db;
/** The real config's active triage config (the page reads config/vigiles.yaml). */
const ACTIVE = loadVigilesConfig().triage.active_config;

let ids: { mal: number; logged: number; latest: number; previous: number };

beforeAll(() => {
  tmp = mkdtempSync(path.join(tmpdir(), 'vigiles-eval-smoke-'));
  process.env.VIGILES_DATA_DIR = tmp;
  db = openDb(':memory:');
  (globalThis as unknown as { __vigilesDb?: Db }).__vigilesDb = db;

  const { scanId } = insertProject(db, 'web');
  const legacy = insertProject(db, 'legacy', { enabled: false });
  insertConfig(db, ACTIVE, true);
  const config = db.select().from(triageConfigs).get()!;

  const mal = insertFinding(db, scanId, { packageName: 'evil-pkg', osvId: 'MAL-2026-7', action: 'ping', malicious: true, priority: 'P0' });
  const next = insertFinding(db, scanId, { packageName: 'next', action: 'ping', fixedVersions: ['1.0.5'] });
  const logged = insertFinding(db, scanId, { packageName: 'lodash', action: 'log' });
  insertFinding(db, scanId, { packageName: 'qs', action: null, priority: null });
  insertFinding(db, legacy.scanId, { projectId: 'legacy', packageName: 'next', action: 'ping' });

  const previous = insertJob(db, {
    type: 'refresh-all',
    status: 'succeeded',
    startedAt: '2026-11-01T00:00:00.000Z',
    finishedAt: '2026-11-01T00:10:00.000Z',
  });
  const latest = insertJob(db, {
    type: 'refresh-all',
    status: 'succeeded',
    startedAt: '2026-11-05T00:00:00.000Z',
    finishedAt: '2026-11-05T00:10:00.000Z',
  });
  const decide = insertJob(db, { type: 'decide', parentId: latest });
  for (const f of [mal, next]) {
    insertEvent(db, f.id, 'decision_changed', '2026-11-05T00:05:00.000Z', {
      jobRunId: decide,
      data: { from: null, to: 'ping', ruleId: 'r' },
    });
  }
  insertEvent(db, logged.id, 'decision_changed', '2026-11-05T00:05:00.000Z', { jobRunId: decide, data: { from: 'digest', to: 'log' } });

  // Two runs that differ in suggested action only: identical policy action, not identical suggested action.
  // (P1 affected → the p1-floor rule digests both, whatever the LLM suggested.)
  insertTriageRun(db, next.id, config, { output: triageOutput({ verdict: 'affected', suggested_action: 'digest' }) });
  insertTriageRun(db, next.id, config, { output: triageOutput({ verdict: 'affected', suggested_action: 'log' }) });
  insertLabel(db, next.id, 'ping');

  ids = { mal: mal.id, logged: logged.id, latest, previous };
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Page = (props: { searchParams: Promise<Record<string, string>> }) => Promise<ReactElement>;
async function render(load: () => Promise<{ default: unknown }>, searchParams: Record<string, string> = {}) {
  const page = (await load()).default as Page;
  const html = renderToStaticMarkup(await page({ searchParams: Promise.resolve(searchParams) }));
  // Plain text with entities decoded, so assertions read like the page.
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ');
}

describe('Inbox page', () => {
  it('anchors "since last refresh" at the previous refresh and shows the malicious remediation', async () => {
    const html = await render(() => import('../page'));
    expect(html).toContain(`Refresh all #${ids.previous} , finished`);
    expect(html).toContain(`malicious package: ${MALICIOUS_REMEDIATION}`);
    expect(html).not.toMatch(/evil-pkg[^→]*→\s*no fix yet/);
    expect(html).toContain('1 open finding of disabled project legacy is not shown');
    expect(html).toContain('1 finding logged');
    const raw = renderToStaticMarkup(await ((await import('../page')).default as Page)({ searchParams: Promise.resolve({}) }));
    expect(raw).toContain(`href="/findings?action=log&amp;ids=${ids.logged}"`);
  });

  it('points undecided findings at Refresh all in the all-open view', async () => {
    const html = await render(() => import('../page'), { view: 'all' });
    expect(html).toContain('1 open finding has no decision yet (1 not enriched yet): run Refresh all');
    expect(html).toContain('of disabled project legacy is not shown');
    expect(html).not.toContain('Project legacy'); // no message group for the disabled project
  });
});

describe('Eval page', () => {
  it('reports policy-action consistency and the per-refresh volume', async () => {
    const html = await render(() => import('./page'), { policy: loadPolicy().hash });
    expect(html).toContain('identical policy action');
    expect(html).toMatch(/Identical policy action.*Identical verdict.*Identical suggested action/);
    expect(html).toContain(`${ACTIVE} 1 2 100% (1/1) 100% (1/1) 0% (0/1)`);
    expect(html).toContain('Baseline-origin findings, current decisions');
    expect(html).toContain('Volume per refresh');
    expect(html).toMatch(new RegExp(`#${ids.latest} \\d+ \\w+ ago 2 \\(2 findings\\) 0 \\(0 findings\\) 1 web 2 / 0`));
  });
});
