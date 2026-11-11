/** Inbox (spec §12): what Slack would have received, one message per (project, package). */
import Link from 'next/link';
import { InboxGroupCard } from '@/components/inbox/inbox-group';
import { ButtonLink, cx, Empty, PageHeader } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { relativeTime } from '@/lib/format';
import { getInbox, loggedFindingsHref, parseInboxView, type InboxData, type InboxGroup, type InboxView } from '@/lib/queries/inbox';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function ViewToggle({ view }: { view: InboxView }) {
  const options: { value: InboxView; label: string }[] = [
    { value: 'since', label: 'Since last refresh' },
    { value: 'all', label: 'All open' },
  ];
  return (
    <div className="inline-flex rounded-md border border-border bg-panel p-0.5">
      {options.map((o) => (
        <Link
          key={o.value}
          href={o.value === 'since' ? '/' : '/?view=all'}
          aria-current={view === o.value ? 'page' : undefined}
          className={cx(
            'rounded px-2.5 py-1 text-sm no-underline',
            view === o.value ? 'bg-panel-2 font-medium text-text' : 'text-muted hover:text-text',
          )}
        >
          {o.label}
        </Link>
      ))}
    </div>
  );
}

function Scope({ inbox }: { inbox: InboxData }) {
  if (inbox.view === 'all') return <>All open findings.</>;
  if (inbox.sinceFallback) {
    return inbox.lastRefresh ? (
      <>
        Only one Refresh all (<Link href={`/jobs/${inbox.lastRefresh.id}`}>#{inbox.lastRefresh.id}</Link>) has succeeded, so there is no
        previous refresh to compare with and every open finding is shown.
      </>
    ) : (
      <>No Refresh all has succeeded yet, so every open finding is shown.</>
    );
  }
  const prev = inbox.previousRefresh!;
  const latest = inbox.lastRefresh!;
  return (
    <>
      Findings created, reopened, escalated, or with a changed advisory or decision since the previous refresh,{' '}
      <Link href={`/jobs/${prev.id}`}>Refresh all #{prev.id}</Link>, finished {relativeTime(inbox.sinceAt)} (the latest is{' '}
      <Link href={`/jobs/${latest.id}`}>#{latest.id}</Link>; failed runs and single jobs in between count too).
    </>
  );
}

function Summary({ inbox }: { inbox: InboxData }) {
  const c = inbox.counts;
  const loggedHref = loggedFindingsHref(inbox);
  const logged = `${plural(c.logged, 'finding')} logged`;
  return (
    <div className="mb-5 space-y-1 text-sm">
      <p>
        Would send <strong>{plural(c.pingMessages, 'ping message')}</strong> ({plural(c.pingFindings, 'finding')}) and{' '}
        <strong>{plural(c.digestMessages, 'digest message')}</strong> ({plural(c.digestFindings, 'finding')});{' '}
        {loggedHref ? <Link href={loggedHref}>{logged}</Link> : logged}.
      </p>
      {c.undecided ? (
        <p className="text-digest">
          {plural(c.undecided, 'open finding has', 'open findings have')} no decision yet
          {c.unenriched ? <> ({c.unenriched} not enriched yet)</> : null}: run <Link href="/jobs">Refresh all</Link> (or Enrich, then
          Re-evaluate policy, on the <Link href="/jobs">Jobs</Link> page).
        </p>
      ) : null}
      {inbox.disabled.open ? (
        <p className="text-xs text-muted">
          {plural(inbox.disabled.open, 'open finding')} of disabled project{inbox.disabled.projectIds.length === 1 ? '' : 's'}{' '}
          {inbox.disabled.projectIds.join(', ')} {inbox.disabled.open === 1 ? 'is' : 'are'} not shown (scan and triage skip them).
        </p>
      ) : null}
    </div>
  );
}

function Section({ title, groups, tone }: { title: string; groups: InboxGroup[]; tone: 'ping' | 'digest' }) {
  if (!groups.length) return null;
  return (
    <section className="mb-8">
      <h2 className={cx('mb-3 text-sm font-semibold tracking-wide uppercase', tone === 'ping' ? 'text-ping' : 'text-digest')}>
        {title} · {plural(groups.length, 'message')}
      </h2>
      <div className="space-y-3">
        {groups.map((g) => (
          <InboxGroupCard key={g.key} group={g} />
        ))}
      </div>
    </section>
  );
}

export default async function InboxPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const view = parseInboxView((await searchParams).view);
  const inbox = getInbox(getDb(), view);
  const nothingToSend = !inbox.ping.length && !inbox.digest.length;

  return (
    <>
      <PageHeader
        title="Inbox"
        subtitle={
          <>
            What Slack would have received. <Scope inbox={inbox} />
          </>
        }
        actions={<ViewToggle view={view} />}
      />
      {inbox.totals.findings === 0 ? (
        <Empty>
          <p className="mb-3">
            {inbox.disabled.open
              ? `Every open finding belongs to a disabled project (${inbox.disabled.projectIds.join(', ')}), and the Inbox leaves those out.`
              : inbox.lastRefresh
                ? 'No findings: no advisory matches any scanned lockfile. Check the Projects page for lockfiles and coverage gaps.'
                : 'No findings yet. Run the pipeline to scan your projects.'}
          </p>
          <ButtonLink href="/jobs" variant="primary">
            Go to Jobs → Refresh all
          </ButtonLink>
        </Empty>
      ) : (
        <>
          <Summary inbox={inbox} />
          {nothingToSend ? (
            <Empty>
              {inbox.sinceAt ? (
                <>
                  Nothing would have been sent since the previous refresh. <Link href="/?view=all">Show all open findings</Link>.
                </>
              ) : inbox.totals.open === 0 ? (
                <>No open findings.</>
              ) : (
                <>
                  No open finding would ping or go into a digest. <Link href="/findings">Browse findings</Link>.
                </>
              )}
            </Empty>
          ) : null}
          <Section title="Ping" groups={inbox.ping} tone="ping" />
          <Section title="Digest" groups={inbox.digest} tone="digest" />
        </>
      )}
    </>
  );
}
