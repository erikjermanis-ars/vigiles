/** Renders Inbox message cards (review #27): a malicious package shows the fixed remediation, never an upgrade or 'no fix yet'. */
import { createElement, type AnchorHTMLAttributes } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import { groupInboxItems, MALICIOUS_REMEDIATION, type InboxItem } from '@/lib/queries/inbox';
import { InboxGroupCard } from './inbox-group';

vi.mock('next/link', () => ({
  default: ({ href, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) => createElement('a', { href, ...rest }),
}));

function item(o: Partial<InboxItem>): InboxItem {
  return {
    findingId: 1,
    projectId: 'web',
    projectName: 'Web',
    packageName: 'evil',
    lockfile: 'package-lock.json',
    osvId: 'GHSA-x',
    vulnId: 'GHSA-x',
    action: 'ping',
    priority: 'P0',
    priorityReasons: [],
    verdict: null,
    confidence: null,
    summary: null,
    ruleId: 'malicious',
    fixedVersions: [],
    installedVersions: ['1.0.0'],
    devOnly: false,
    direct: true,
    malicious: false,
    ...o,
  };
}

function text(items: InboxItem[]): { header: string; body: string } {
  const [group] = groupInboxItems(items);
  const html = renderToStaticMarkup(createElement(InboxGroupCard, { group: group! }));
  const plain = (s: string) =>
    s
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  const header = /<h3[^>]*>([\s\S]*?)<\/h3>/.exec(html)![1]!;
  const body = /<ul[^>]*>([\s\S]*?)<\/ul>/.exec(html)![1]!;
  return { header: plain(header), body: plain(body) };
}

describe('InboxGroupCard', () => {
  it('shows the fixed remediation for a malicious package instead of "no fix yet"', () => {
    const { header, body } = text([item({ osvId: 'MAL-2026-1', vulnId: 'MAL-2026-1', malicious: true })]);
    expect(header).toContain(`→ malicious package: ${MALICIOUS_REMEDIATION}`);
    expect(header).not.toContain('no fix yet');
    expect(header).not.toContain('upgrade to');
    expect(body).toContain(`malicious: ${MALICIOUS_REMEDIATION}`);
    expect(body).not.toContain('no fix yet');
  });

  it('shows the remediation and the other advisories’ upgrade target in a mixed group', () => {
    const { header, body } = text([
      item({ findingId: 1, osvId: 'MAL-2026-2', vulnId: 'MAL-2026-2', malicious: true }),
      item({ findingId: 2, osvId: 'GHSA-a', vulnId: 'CVE-A', priority: 'P1', fixedVersions: ['1.2.0'] }),
    ]);
    expect(header).toContain(`malicious package: ${MALICIOUS_REMEDIATION} · other advisory: upgrade to 1.2.0`);
    expect(body).toContain('fixed in 1.2.0');
    expect(body.match(/no fix yet/g)).toBeNull();
  });

  it('keeps the upgrade target and "no fix yet" for ordinary advisories', () => {
    expect(text([item({ fixedVersions: ['1.0.3'] })]).header).toMatch(/→ upgrade to 1\.0\.3$/);
    const none = text([item({})]);
    expect(none.header).toMatch(/→ no fix yet$/);
    expect(none.body).toContain('no fix yet');
    expect(none.header).not.toContain('malicious');
  });
});
