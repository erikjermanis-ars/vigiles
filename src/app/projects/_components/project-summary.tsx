/** Scan state, coverage and open-finding counts of one project (shared by /projects and /projects/[id]). */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { ProjectTag } from '@/components/inbox/project-tag';
import { ActionBadge, Badge, Card, Kv, Mono, PriorityBadge, cx } from '@/components/ui';
import { relativeTime, shortDate } from '@/lib/format';
import type { ProjectColor } from '@/lib/project-scope';
import { summarizeStats } from '@/lib/queries/jobs';
import { projectHealth, type ProjectHealthTone, type ProjectOverview } from '@/lib/queries/projects';
import { ACTIONS, PRIORITIES } from '@/lib/types';

const healthTone: Record<ProjectHealthTone, string> = {
  ok: 'bg-ok-bg text-ok',
  warn: 'bg-digest-bg text-digest',
  bad: 'bg-ping-bg text-ping',
  off: 'bg-panel-2 text-muted',
};
const healthIcon: Record<ProjectHealthTone, string> = { ok: '✓', warn: '!', bad: '✕', off: '–' };

/** "✓ Monitored", "✕ Last scan failed", "– Not monitored": the project's state in two words. */
export function HealthPill({ overview }: { overview: Pick<ProjectOverview, 'project' | 'lastScan' | 'newerAttempt'> }) {
  const h = projectHealth(overview);
  return (
    <span
      title={h.detail}
      className={cx('inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold whitespace-nowrap', healthTone[h.tone])}
    >
      <span aria-hidden>{healthIcon[h.tone]}</span>
      {h.label}
    </span>
  );
}

function Stat({ value, label, href, tone }: { value: number; label: string; href?: string; tone?: 'ping' | 'digest' | 'warn' }) {
  const color =
    value === 0 ? 'text-muted' : tone === 'ping' ? 'text-ping' : tone === 'digest' || tone === 'warn' ? 'text-digest' : 'text-text';
  const body = (
    <>
      <div className={cx('text-2xl leading-none font-semibold tabular-nums', color)}>{value}</div>
      <div className="mt-1 text-xs text-muted">{label}</div>
    </>
  );
  return href ? (
    <Link href={href} className="block rounded-md px-2 py-1.5 no-underline hover:bg-panel-2">
      {body}
    </Link>
  ) : (
    <div className="px-2 py-1.5">{body}</div>
  );
}

/**
 * One project on the Projects page: its state at a glance (monitored or not, last scan, coverage gaps) and its
 * open findings by current action. The full detail is on /projects/[id].
 */
export function ProjectStateCard({ overview, color }: { overview: ProjectOverview; color: ProjectColor }) {
  const { project, lastScan, newerAttempt, counts, openOwnerCases } = overview;
  const health = projectHealth(overview);
  const findingsHref = (action?: string) =>
    `/findings?project=${encodeURIComponent(project.id)}${action ? `&action=${action}` : ''}`;
  const gaps = lastScan?.coverageGaps ?? [];
  return (
    <Card className={cx('border-l-4', color.border, !project.enabled && 'opacity-80')}>
      <div className="flex flex-wrap items-center gap-2 px-4 pt-3">
        <Link href={`/projects/${encodeURIComponent(project.id)}`} className="no-underline">
          <ProjectTag name={project.name} color={color} enabled={project.enabled} className="text-sm" />
        </Link>
        <HealthPill overview={overview} />
        {/* Profile facts stay neutral: the state pill is the one coloured thing to read here. */}
        <Badge title="Exposure, from the project profile">{project.profile.exposure}</Badge>
        <Badge title="Criticality, from the project profile">criticality {project.profile.criticality}</Badge>
        <Link href={`/projects/${encodeURIComponent(project.id)}`} className="ml-auto text-sm">
          Details →
        </Link>
      </div>
      <p className="px-4 pt-1.5 text-sm text-muted">{health.detail}</p>
      <div className="grid grid-cols-3 gap-1 px-2 py-3 sm:grid-cols-6">
        <Stat value={counts.open} label="open findings" href={findingsHref()} />
        <Stat value={counts.byAction.ping} label="ping" href={findingsHref('ping')} tone="ping" />
        <Stat value={counts.byAction.digest} label="digest" href={findingsHref('digest')} tone="digest" />
        <Stat value={counts.byAction.log} label="logged" href={findingsHref('log')} />
        <Stat value={counts.byAction.undecided} label="no decision yet" href={findingsHref('none')} tone="warn" />
        <Stat value={openOwnerCases} label="need your call" href={openOwnerCases ? '/decide' : undefined} tone="digest" />
      </div>
      <div className="space-y-2 border-t border-border px-4 py-3 text-sm">
        <p>
          {lastScan ? (
            <>
              <span className="font-medium">Last scan</span> {relativeTime(lastScan.finishedAt ?? lastScan.startedAt)}{' '}
              <span className="text-muted">
                · commit <Mono>{lastScan.commitSha?.slice(0, 7) ?? '?'}</Mono> from {shortDate(lastScan.commitDate)} on{' '}
                <Mono>{lastScan.ref}</Mono> · {lastScan.lockfiles.length} lockfile{lastScan.lockfiles.length === 1 ? '' : 's'} checked
              </span>
            </>
          ) : (
            <span className="text-muted">Never scanned.</span>
          )}
        </p>
        {newerAttempt ? (
          <p className={newerAttempt.status === 'failed' ? 'text-ping' : 'text-muted'}>
            {lastScan ? 'Newer scan' : 'Scan'} #{newerAttempt.id} {newerAttempt.status === 'running' ? 'started' : 'failed'}{' '}
            {relativeTime(newerAttempt.startedAt)}
            {newerAttempt.error ? `: ${newerAttempt.error.split('\n')[0]}` : ''}
          </p>
        ) : null}
        {lastScan?.fetchError ? <p className="text-digest">Could not fetch the latest commits: {lastScan.fetchError}</p> : null}
        {gaps.length ? (
          <div className="rounded-md bg-digest-bg px-3 py-2 text-digest">
            <p className="font-medium">
              Not checked: {gaps.length} manifest{gaps.length === 1 ? ' has' : 's have'} no lockfile
            </p>
            <ul className="mt-1 space-y-0.5 text-xs">
              {gaps.map((g) => (
                <li key={g}>
                  <Mono>{g}</Mono>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {lastScan?.lockfiles.length ? (
          <details className="text-xs text-muted">
            <summary className="cursor-pointer select-none">Lockfiles checked</summary>
            <ul className="mt-1 space-y-0.5">
              {lastScan.lockfiles.map((l) => (
                <li key={l}>
                  <Mono>{l}</Mono>
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </div>
    </Card>
  );
}

export function ProjectBadges({ project }: { project: ProjectOverview['project'] }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {project.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>}
      <Badge title="Exposure, from the project profile">{project.profile.exposure}</Badge>
      <Badge title="Criticality, from the project profile">criticality {project.profile.criticality}</Badge>
    </span>
  );
}

function ScanLine({ overview }: { overview: ProjectOverview }) {
  const { project, lastScan } = overview;
  if (!lastScan) {
    return (
      <span>
        <Mono>{project.ref}</Mono> <span className="text-muted">→ not scanned yet</span>
      </span>
    );
  }
  return (
    <span>
      <Mono>{lastScan.ref}</Mono> → <Mono>{lastScan.commitSha?.slice(0, 8) ?? '?'}</Mono>{' '}
      <span className="text-muted">
        committed {shortDate(lastScan.commitDate)} · scanned{' '}
        <span title={lastScan.finishedAt ?? lastScan.startedAt}>{relativeTime(lastScan.finishedAt ?? lastScan.startedAt)}</span>
        {lastScan.ref !== project.ref ? ` · profile ref is now ${project.ref}` : ''}
      </span>
    </span>
  );
}

function CountList<K extends string>({
  keys,
  counts,
  render,
}: {
  keys: readonly K[];
  counts: Record<K, number>;
  render: (k: K) => ReactNode;
}) {
  const shown = keys.filter((k) => counts[k] > 0);
  if (!shown.length) return <span className="text-muted">none</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
      {shown.map((k) => (
        <span key={k} className="inline-flex items-center gap-1">
          {render(k)} <span className="tabular-nums">{counts[k]}</span>
        </span>
      ))}
    </span>
  );
}

export function ProjectSummary({ overview }: { overview: ProjectOverview }) {
  const { project, lastScan, newerAttempt, counts } = overview;
  const items: [ReactNode, ReactNode][] = [
    [
      'State',
      <span key="state" className="inline-flex flex-wrap items-center gap-2">
        <HealthPill overview={overview} />
        <span className="text-muted">{projectHealth(overview).detail}</span>
      </span>,
    ],
    ['Ref', <ScanLine key="ref" overview={overview} />],
  ];
  if (lastScan?.fetchError)
    items.push([
      'Fetch',
      <span key="fetch" className="text-digest">
        {lastScan.fetchError}
      </span>,
    ]);
  if (newerAttempt) {
    items.push([
      'Latest attempt',
      <span key="attempt" className={newerAttempt.status === 'failed' ? 'text-ping' : undefined}>
        scan #{newerAttempt.id} {newerAttempt.status} {relativeTime(newerAttempt.startedAt)}
        {newerAttempt.error ? `: ${newerAttempt.error.split('\n')[0]}` : ''}
      </span>,
    ]);
  }
  items.push([
    'Lockfiles',
    lastScan?.lockfiles.length ? (
      <ul key="lockfiles" className="space-y-0.5">
        {lastScan.lockfiles.map((l) => (
          <li key={l}>
            <Mono>{l}</Mono>
          </li>
        ))}
      </ul>
    ) : (
      <span key="lockfiles" className="text-muted">
        {lastScan ? 'none found' : '—'}
      </span>
    ),
  ]);
  if (lastScan?.coverageGaps.length) {
    items.push([
      <span key="gaps-k" className="text-digest">
        Coverage gaps
      </span>,
      <div key="gaps" className="rounded-md bg-digest-bg px-2 py-1.5 text-digest">
        <p className="text-xs">Manifests without a lockfile; their dependencies are not matched:</p>
        <ul className="mt-1 space-y-0.5">
          {lastScan.coverageGaps.map((g) => (
            <li key={g}>
              <Mono>{g}</Mono>
            </li>
          ))}
        </ul>
      </div>,
    ]);
  }
  items.push([
    'Open by priority',
    <CountList
      key="priority"
      keys={[...PRIORITIES, 'none'] as const}
      counts={counts.byPriority}
      render={(k) => (k === 'none' ? <span className="text-xs text-muted">unscored</span> : <PriorityBadge priority={k} />)}
    />,
  ]);
  items.push([
    'Open by action',
    <CountList
      key="action"
      keys={[...ACTIONS, 'undecided'] as const}
      counts={counts.byAction}
      render={(k) => <ActionBadge action={k === 'undecided' ? null : k} />}
    />,
  ]);
  items.push([
    'Findings',
    <span key="findings">
      <Link href={`/findings?project=${encodeURIComponent(project.id)}`}>{counts.open} open</Link>
      <span className="text-muted"> · {counts.total} total</span>
    </span>,
  ]);
  if (overview.openOwnerCases) {
    items.push([
      'Your call',
      <Link key="decide" href="/decide">
        {overview.openOwnerCases} case{overview.openOwnerCases === 1 ? '' : 's'} waiting
      </Link>,
    ]);
  }
  if (lastScan?.stats)
    items.push([
      'Last scan',
      <span key="stats" className="text-xs text-muted">
        {summarizeStats(lastScan.stats, 6)}
      </span>,
    ]);
  if (lastScan?.osvDbDate)
    items.push([
      'OSV DB',
      <span key="osv" className="text-xs text-muted">
        {lastScan.osvDbDate}
      </span>,
    ]);
  return <Kv items={items} />;
}
