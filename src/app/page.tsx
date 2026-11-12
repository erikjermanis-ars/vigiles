/**
 * Inbox (spec §12): what Slack would have received, one message per (project, package), limited to the
 * header's project scope. One card per project says what is open right now; the message groups below follow
 * the view toggle (since the previous refresh, or all open).
 */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { InboxGroupCard } from '@/components/inbox/inbox-group';
import { ProjectTag, ScopePill } from '@/components/inbox/project-tag';
import { Badge, ButtonLink, Card, cx, Empty, Mono, PageHeader } from '@/components/ui';
import { currentProjectScope } from '@/app/projects/scope';
import { getDb } from '@/lib/db/client';
import { relativeTime } from '@/lib/format';
import { colorFor, projectColors, scopeLabel, withScope, type ProjectColor, type ProjectScope } from '@/lib/project-scope';
import {
  getInbox,
  loggedFindingsHref,
  parseInboxView,
  projectFindingsHref,
  type InboxData,
  type InboxGroup,
  type InboxProjectCard,
  type InboxView,
} from '@/lib/queries/inbox';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function ViewToggle({ view, scope }: { view: InboxView; scope: ProjectScope }) {
  const options: { value: InboxView; label: string }[] = [
    { value: 'since', label: 'Since last refresh' },
    { value: 'all', label: 'All open' },
  ];
  return (
    <div className="inline-flex rounded-md border border-border bg-panel p-0.5">
      {options.map((o) => (
        <Link
          key={o.value}
          href={withScope(o.value === 'since' ? '/' : '/?view=all', scope)}
          aria-current={view === o.value ? 'page' : undefined}
          className={cx('group rounded px-2.5 py-1 text-sm no-underline', view === o.value && 'bg-panel-2 font-medium')}
        >
          {/* The colour sits on a span: globals.css colours <a> outside Tailwind's layers, which beats text-* on the <a>. */}
          <span className={view === o.value ? 'text-text' : 'text-muted group-hover:text-text'}>{o.label}</span>
        </Link>
      ))}
    </div>
  );
}

function Scope({ inbox }: { inbox: InboxData }) {
  if (inbox.view === 'all') return <>Every open finding.</>;
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

/** One big number on a project card, linking to the findings behind it. */
function BigNumber({
  value,
  label,
  sub,
  href,
  tone,
  muted = false,
}: {
  /** null: not known yet (never scanned), shown as a dash rather than a reassuring 0 */
  value: number | null;
  label: string;
  sub: string;
  href: string;
  tone: 'ping' | 'digest' | 'log';
  /** A disabled project's numbers: kept for reference, but nothing is sent */
  muted?: boolean;
}) {
  const color = !value || muted ? 'text-muted' : tone === 'ping' ? 'text-ping' : tone === 'digest' ? 'text-digest' : 'text-text';
  return (
    <Link href={href} className="group block rounded-md px-2 py-1.5 no-underline hover:bg-panel-2">
      <div className={cx('text-3xl leading-none font-semibold tabular-nums', color)}>{value ?? '–'}</div>
      <div className="mt-1.5 text-xs font-medium text-text sm:text-sm">{label}</div>
      <div className="text-xs text-muted">{sub}</div>
    </Link>
  );
}

function ProjectCard({ card, color }: { card: InboxProjectCard; color: ProjectColor }) {
  const n = card.now;
  const scanned = card.lastScan !== null;
  // "Nothing to act on" only for a project that was actually scanned and whose findings all have a decision.
  const clear = n.pingMessages === 0 && n.digestMessages === 0 && n.undecided === 0 && scanned;
  const problem = card.scanProblem;
  const scanError = problem?.error ? `: ${problem.error.split('\n')[0]}` : '';
  const notes: ReactNode[] = [];
  if (!card.enabled) {
    notes.push(
      <span key="off" className="text-muted">
        Not monitored: disabled in <Mono>projects/{card.id}.yaml</Mono>, so it is not scanned and nothing is sent.
      </span>,
    );
  } else if (!scanned) {
    // One plain sentence for a project with no successful scan yet; its numbers are dashes, not zeros.
    notes.push(
      problem?.status === 'failed' ? (
        <span key="unscanned" className="text-ping">
          Never scanned successfully: the scan {relativeTime(problem.at)} failed{scanError}. Fix that, then run Refresh all on the{' '}
          <Link href="/jobs">Jobs</Link> page.
        </span>
      ) : problem?.status === 'running' ? (
        <span key="unscanned" className="text-muted">
          The first scan is running now.
        </span>
      ) : (
        <span key="unscanned" className="text-digest">
          Not scanned yet. Run Refresh all on the <Link href="/jobs">Jobs</Link> page.
        </span>
      ),
    );
  } else if (problem?.status === 'failed') {
    notes.push(
      <span key="failed" className="text-ping">
        The latest scan failed {relativeTime(problem.at)}
        {scanError}. These numbers are from the scan before.
      </span>,
    );
  } else if (problem?.status === 'running') {
    notes.push(
      <span key="running" className="text-muted">
        A scan is running now.
      </span>,
    );
  }
  if (n.undecided) {
    notes.push(
      <span key="undecided" className="text-digest">
        {plural(n.undecided, 'open finding has', 'open findings have')} no decision yet (run Refresh all on the{' '}
        <Link href="/jobs">Jobs</Link> page).
      </span>,
    );
  }
  return (
    <Card className={cx('border-l-4', color.border, !card.enabled && 'opacity-75')}>
      <div className="flex flex-wrap items-start justify-between gap-2 px-4 pt-3">
        <div className="min-w-0">
          <h2 className="flex flex-wrap items-center gap-2 text-base font-semibold">
            <ProjectTag name={card.name} color={color} enabled={card.enabled} className="text-sm" />
          </h2>
          <p className="mt-1 text-xs text-muted">
            {card.lastScan ? (
              <>
                Last scan {relativeTime(card.lastScan.at)} · commit <Mono>{card.lastScan.commitSha?.slice(0, 7) ?? '?'}</Mono> on{' '}
                <Mono>{card.lastScan.ref}</Mono>
              </>
            ) : (
              'Not scanned yet'
            )}
          </p>
        </div>
        {card.exposure ? (
          <Badge title="Exposure, from the project profile">{card.exposure}</Badge>
        ) : null}
      </div>
      <div className="grid grid-cols-3 gap-1 px-2 py-3">
        <BigNumber
          value={scanned ? n.pingMessages : null}
          label="Ping now"
          sub={!scanned ? 'not scanned' : n.pingMessages ? plural(n.pingFindings, 'finding') : 'none'}
          href={projectFindingsHref(card.id, 'ping')}
          tone="ping"
          muted={!card.enabled}
        />
        <BigNumber
          value={scanned ? n.digestMessages : null}
          label="This week's digest"
          sub={!scanned ? 'not scanned' : n.digestMessages ? plural(n.digestFindings, 'finding') : 'none'}
          href={projectFindingsHref(card.id, 'digest')}
          tone="digest"
          muted={!card.enabled}
        />
        <BigNumber
          value={scanned ? n.logged : null}
          label="Logged"
          sub={scanned ? 'no message' : 'not scanned'}
          href={projectFindingsHref(card.id, 'log')}
          tone="log"
          muted={!card.enabled}
        />
      </div>
      {card.needsYourCall || notes.length || (clear && card.enabled) ? (
        <div className="space-y-1.5 border-t border-border px-4 py-2.5 text-sm">
          {card.needsYourCall ? (
            <Link
              href="/decide"
              className="flex items-center justify-between rounded-md bg-digest-bg px-3 py-2 font-medium no-underline hover:opacity-90"
            >
              {/* Colours on spans: globals.css colours <a> outside Tailwind's layers, which beats text-* on the <a>. */}
              <span className="text-digest">
                Needs your call: {card.needsYourCall} {card.needsYourCall === 1 ? 'case' : 'cases'}
              </span>
              <span aria-hidden className="text-digest">
                →
              </span>
            </Link>
          ) : clear && card.enabled ? (
            <p className="font-medium text-ok">✓ Nothing to act on</p>
          ) : null}
          {notes.map((note, i) => (
            <p key={i} className="text-xs">
              {note}
            </p>
          ))}
        </div>
      ) : null}
    </Card>
  );
}

function ProjectCards({ inbox, colors }: { inbox: InboxData; colors: Map<string, ProjectColor> }) {
  if (!inbox.projects.length) return null;
  return (
    <div
      className={cx(
        'mb-8 grid gap-4',
        inbox.projects.length === 1 ? 'max-w-xl' : inbox.projects.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 xl:grid-cols-3',
      )}
    >
      {inbox.projects.map((card) => (
        <ProjectCard key={card.id} card={card} color={colorFor(colors, card.id)} />
      ))}
    </div>
  );
}

function Summary({ inbox, scope }: { inbox: InboxData; scope: ProjectScope }) {
  const c = inbox.counts;
  const loggedHref = loggedFindingsHref(inbox, scope);
  const logged = `${plural(c.logged, 'finding')} logged`;
  return (
    <div className="mb-5 space-y-1 text-sm">
      <p>
        {inbox.view === 'all' ? 'Open now' : 'In this view'}: would send <strong>{plural(c.pingMessages, 'ping message')}</strong> (
        {plural(c.pingFindings, 'finding')}) and <strong>{plural(c.digestMessages, 'digest message')}</strong> (
        {plural(c.digestFindings, 'finding')}); {loggedHref ? <Link href={loggedHref}>{logged}</Link> : logged}.
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

/** Groups of one section split by project, in the order of the project cards (most urgent first inside each). */
function byProject(groups: InboxGroup[], order: readonly string[]): { projectId: string; projectName: string; groups: InboxGroup[] }[] {
  const out = new Map<string, { projectId: string; projectName: string; groups: InboxGroup[] }>();
  for (const g of groups) {
    const entry = out.get(g.projectId) ?? { projectId: g.projectId, projectName: g.projectName, groups: [] };
    entry.groups.push(g);
    out.set(g.projectId, entry);
  }
  const rank = (id: string) => (order.includes(id) ? order.indexOf(id) : order.length);
  return [...out.values()].sort((a, b) => rank(a.projectId) - rank(b.projectId) || a.projectName.localeCompare(b.projectName));
}

function Section({
  title,
  hint,
  groups,
  tone,
  order,
  colors,
}: {
  title: string;
  hint: string;
  groups: InboxGroup[];
  tone: 'ping' | 'digest';
  order: readonly string[];
  colors: Map<string, ProjectColor>;
}) {
  if (!groups.length) return null;
  const parts = byProject(groups, order);
  return (
    <section className="mb-10">
      <h2 className={cx('text-sm font-semibold tracking-wide uppercase', tone === 'ping' ? 'text-ping' : 'text-digest')}>
        {title} · {plural(groups.length, 'message')}
      </h2>
      <p className="mb-3 text-xs text-muted">{hint}</p>
      <div className="space-y-6">
        {parts.map((part) => (
          <div key={part.projectId} className="space-y-3">
            {parts.length > 1 ? (
              <h3 className="flex items-center gap-2 text-sm font-semibold">
                <ProjectTag name={part.projectName} color={colorFor(colors, part.projectId)} className="text-sm" />
                <span className="font-normal text-muted">{plural(part.groups.length, 'message')}</span>
              </h3>
            ) : null}
            {part.groups.map((g) => (
              <InboxGroupCard key={g.key} group={g} color={colorFor(colors, g.projectId)} />
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

/** The reassuring or explanatory panel when this view has no message to show. */
function NothingToSend({ inbox, scope, scopeName }: { inbox: InboxData; scope: ProjectScope; scopeName: ReactNode }) {
  // Disabled projects send nothing, so their stale decisions do not count as open messages.
  const live = inbox.projects.filter((p) => p.enabled);
  const openPing = live.reduce((n, p) => n + p.now.pingMessages, 0);
  const openDigest = live.reduce((n, p) => n + p.now.digestMessages, 0);
  if (inbox.view === 'since' && inbox.sinceAt && openPing + openDigest > 0) {
    return (
      <Empty>
        <p className="text-base font-medium text-text">Nothing new since the previous refresh.</p>
        <p className="mt-1">
          {plural(openPing, 'ping message')} and {plural(openDigest, 'digest message')} from before are still open.{' '}
          <Link href={withScope('/?view=all', scope)}>Show all open</Link>
        </p>
      </Empty>
    );
  }
  return (
    <div className="rounded-lg border border-ok/30 bg-ok-bg px-6 py-10 text-center">
      <p className="text-lg font-semibold text-ok">✓ Nothing needs attention</p>
      <p className="mt-1 text-sm text-text">
        {inbox.view === 'since' && inbox.sinceAt ? 'Nothing changed since the previous refresh, and no' : 'No'} open finding in {scopeName}{' '}
        would ping or go into a digest.
        {inbox.totals.open ? <> The {plural(inbox.totals.open, 'open finding')} left are logged or undecided (see above).</> : null}
      </p>
    </div>
  );
}

/** The scope has no finding at all: clean (scanned, nothing matches), not scanned yet, or only disabled projects' findings. */
function NoFindings({ inbox, scopeName }: { inbox: InboxData; scopeName: ReactNode }) {
  const live = inbox.projects.filter((p) => p.enabled);
  const scanned = live.filter((p) => p.lastScan);
  if (!inbox.disabled.open && scanned.length) {
    return (
      <div className="rounded-lg border border-ok/30 bg-ok-bg px-6 py-10 text-center">
        <p className="text-lg font-semibold text-ok">✓ Nothing needs attention</p>
        <p className="mt-1 text-sm text-text">
          No known vulnerability matches the dependencies of {scopeName}
          {scanned.length < live.length ? ' (the projects scanned so far)' : ''}. Coverage gaps are listed on the{' '}
          <Link href="/projects">Projects</Link> page.
        </p>
      </div>
    );
  }
  return (
    <Empty>
      <p className="mb-3">
        {inbox.disabled.open
          ? `Every open finding belongs to a disabled project (${inbox.disabled.projectIds.join(', ')}), and the Inbox leaves those out.`
          : live.length
            ? 'Nothing to show yet: no project here has been scanned successfully.'
            : 'No findings yet. Run the pipeline to scan your projects.'}
      </p>
      <ButtonLink href="/jobs" variant="primary">
        {/* The colour sits on a span: globals.css colours <a> outside Tailwind's layers, which beats text-white on the <a>. */}
        <span className="text-white">Go to Jobs → Refresh all</span>
      </ButtonLink>
    </Empty>
  );
}

export default async function InboxPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const view = parseInboxView(sp.view);
  const scope = await currentProjectScope(sp);
  const inbox = getInbox(getDb(), view, { projectIds: scope.ids });
  const colors = projectColors(scope.projects.map((p) => p.id));
  const nothingToSend = !inbox.ping.length && !inbox.digest.length;
  const order = inbox.projects.map((p) => p.id);
  const scopeName = <ScopePill scope={scope} className="align-middle" />;

  return (
    <>
      <PageHeader
        title="Inbox"
        subtitle={
          <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
            {scopeName}
            <span>What Slack would have sent.</span>
          </span>
        }
        actions={<ViewToggle view={view} scope={scope} />}
      />
      <ProjectCards inbox={inbox} colors={colors} />
      {!inbox.enabledProjectIds.length && inbox.disabled.projectIds.length ? (
        <Empty>
          {scopeLabel(scope)} {inbox.disabled.projectIds.length === 1 ? 'is' : 'are'} not monitored (disabled in{' '}
          <Mono>projects/*.yaml</Mono>), so nothing is scanned or sent. Pick another project in the header.
        </Empty>
      ) : inbox.totals.findings === 0 ? (
        <NoFindings inbox={inbox} scopeName={scopeName} />
      ) : (
        <>
          <h2 className="mb-1 text-lg font-semibold">{view === 'all' ? 'All open messages' : 'Messages since the last refresh'}</h2>
          <p className="mb-3 text-sm text-muted">
            <Scope inbox={inbox} />
          </p>
          <Summary inbox={inbox} scope={scope} />
          {nothingToSend ? <NothingToSend inbox={inbox} scope={scope} scopeName={scopeName} /> : null}
          <Section
            title="Ping"
            hint="Sent right away to the project's owners."
            groups={inbox.ping}
            tone="ping"
            order={order}
            colors={colors}
          />
          <Section
            title="Digest"
            hint="Collected into the weekly summary message."
            groups={inbox.digest}
            tone="digest"
            order={order}
            colors={colors}
          />
        </>
      )}
    </>
  );
}
