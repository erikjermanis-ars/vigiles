/** Scan state, coverage and open-finding counts of one project (shared by /projects and /projects/[id]). */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { ActionBadge, Badge, Kv, Mono, PriorityBadge } from '@/components/ui';
import { relativeTime, shortDate } from '@/lib/format';
import { summarizeStats } from '@/lib/queries/jobs';
import type { ProjectOverview } from '@/lib/queries/projects';
import { ACTIONS, PRIORITIES } from '@/lib/types';

export function ProjectBadges({ project }: { project: ProjectOverview['project'] }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {project.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>}
      <Badge tone={project.profile.exposure === 'internet-facing' ? 'ping' : 'neutral'} title="exposure">
        {project.profile.exposure}
      </Badge>
      <Badge tone={project.profile.criticality === 'high' ? 'digest' : 'neutral'} title="criticality">
        criticality {project.profile.criticality}
      </Badge>
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
  const items: [ReactNode, ReactNode][] = [['Ref', <ScanLine key="ref" overview={overview} />]];
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
