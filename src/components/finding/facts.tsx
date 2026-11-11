/** Signals and dependency facts of a finding (spec §7.3, §8). Server-component safe. */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { Badge, Kv, Mono, PriorityBadge } from '@/components/ui';
import { shortDate } from '@/lib/format';
import type { FindingInstance, ImportSite, Priority } from '@/lib/types';
import { formatChain, formatCvss, formatEpss, importSitesShownNote, MALICIOUS_REMEDIATION, sourceHref } from './helpers';

export interface SignalFields {
  priority: Priority | null;
  priorityReasons: string[];
  inKev: boolean;
  kevDateAdded: string | null;
  /** From the KEV catalog: 'Known' | 'Unknown' */
  kevRansomware?: string | null;
  epss: number | null;
  epssPercentile: number | null;
  cvssScore: number | null;
  cvssVector: string | null;
  severityLabel: string | null;
  malicious: boolean;
}

export function PriorityReasons({ reasons }: { reasons: string[] }) {
  if (!reasons.length) return null;
  return <span className="text-sm text-muted">{reasons.join(' · ')}</span>;
}

export function SignalsList({ s }: { s: SignalFields }) {
  const malicious: [ReactNode, ReactNode][] = s.malicious ? [['Malicious', <Badge key="m" tone="ping">malicious package (OpenSSF)</Badge>]] : [];
  return (
    <Kv
      items={[
        ...malicious,
        [
          'Base priority',
          <span key="p" className="inline-flex flex-wrap items-center gap-2">
            <PriorityBadge priority={s.priority} />
            <PriorityReasons reasons={s.priorityReasons} />
          </span>,
        ],
        [
          'KEV',
          s.inKev ? (
            <span key="k" className="inline-flex flex-wrap items-center gap-2">
              <Badge tone="ping">known exploited</Badge>
              <span className="text-sm">added {shortDate(s.kevDateAdded)}</span>
              {s.kevRansomware === 'Known' ? <Badge tone="ping">ransomware use</Badge> : null}
            </span>
          ) : (
            'no'
          ),
        ],
        ['EPSS', formatEpss(s.epss, s.epssPercentile)],
        [
          'CVSS',
          <span key="c">
            {formatCvss(s.cvssScore)}
            {s.cvssVector ? (
              <span className="ml-2 break-all text-muted">
                <Mono>{s.cvssVector}</Mono>
              </span>
            ) : null}
          </span>,
        ],
        ['Severity', s.severityLabel ?? '—'],
      ]}
    />
  );
}

export interface DependencyFields {
  findingId: number;
  projectId: string;
  lockfile: string;
  ecosystem: string;
  packageName: string;
  installedVersions: string[];
  fixedVersions: string[];
  /** Merged across installed versions; shown only when `instances` is empty (findings from older scans) */
  direct: boolean | null;
  devOnly: boolean;
  paths: string[][];
  /** One entry per installed version (spec §7.3 facts per instance) */
  instances?: FindingInstance[];
  importSites: ImportSite[];
  /** Uncapped number of import sites; importSites holds the first ones only */
  importSiteCount?: number;
  /** A MAL-* advisory: the remediation is fixed (spec §9.1), there is no fix version */
  malicious?: boolean;
}

export function DependencyPaths({ paths }: { paths: string[][] }) {
  if (!paths.length) return <span className="text-muted">unknown (flat ecosystem or not computed)</span>;
  return (
    <ul className="space-y-1">
      {paths.map((p, i) => (
        <li key={i} className="font-mono text-[0.85em] break-words">
          {formatChain(p.slice(0, -1))}
          {p.length > 1 ? ' › ' : ''}
          <strong>{p.at(-1)}</strong>
        </li>
      ))}
    </ul>
  );
}

export function ImportSites({
  findingId,
  packageName,
  sites,
  total,
  newTab = false,
}: {
  findingId: number;
  packageName: string;
  sites: ImportSite[];
  /** Uncapped count; findings from older scans store 0 here, so the list length is the floor */
  total?: number;
  newTab?: boolean;
}) {
  if (!sites.length && !total) {
    return <span className="text-muted">none found (no file imports the package or the direct dependency that brings it in)</span>;
  }
  const shown = importSitesShownNote(sites.length, Math.max(total ?? 0, sites.length));
  return (
    <ul className="space-y-1">
      {shown ? <li className="text-xs text-muted">{shown} (the stored list is capped)</li> : null}
      {sites.map((s) => (
        <li key={`${s.file}:${s.line}:${s.specifier}:${s.via}`} className="break-words">
          <Link href={sourceHref(findingId, s.file, s.line)} className="font-mono text-[0.85em]" target={newTab ? '_blank' : undefined}>
            {s.file}:{s.line}
          </Link>{' '}
          <Mono>{s.specifier}</Mono>
          {s.via !== packageName ? <span className="text-muted"> via {s.via}</span> : null}
        </li>
      ))}
    </ul>
  );
}

const directLabel = (direct: boolean | null) => (direct === null ? 'direct?' : direct ? 'direct' : 'transitive');

/** One block per installed version: its own direct/dev facts and paths, never merged across versions. */
export function InstalledInstances({ instances }: { instances: FindingInstance[] }) {
  return (
    <ul className="space-y-2">
      {instances.map((inst) => (
        <li key={inst.version}>
          <div className="flex flex-wrap items-center gap-1.5">
            <Mono>{inst.version}</Mono>
            <Badge title={inst.direct === null ? 'Not known for this ecosystem' : undefined}>{directLabel(inst.direct)}</Badge>
            {/* Flat ecosystems (direct unknown) report devOnly false without knowing, so no "production" claim there. */}
            {inst.devOnly ? <Badge tone="log">dev only</Badge> : inst.direct !== null ? <Badge>production</Badge> : null}
          </div>
          {inst.paths.length ? (
            <div className="mt-1 ml-3">
              <DependencyPaths paths={inst.paths} />
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function DependencyFacts({ d, newTab = false }: { d: DependencyFields; newTab?: boolean }) {
  const instances = d.instances ?? [];
  const perVersion: [ReactNode, ReactNode][] = instances.length
    ? [[instances.length === 1 ? 'Installed' : `Installed (${instances.length} versions)`, <InstalledInstances key="iv" instances={instances} />]]
    : [
        ['Installed', <Mono key="i">{d.installedVersions.join(', ') || '—'}</Mono>],
        ['Direct', d.direct === null ? 'unknown' : d.direct ? 'yes' : 'no (transitive)'],
        ['Dev only', d.devOnly ? 'yes' : 'no'],
        ['Paths', <DependencyPaths key="p" paths={d.paths} />],
      ];
  const fix: [ReactNode, ReactNode] = d.malicious
    ? ['Remediation', <span key="r" className="text-ping">{MALICIOUS_REMEDIATION}</span>]
    : ['Fixed in', <Mono key="f">{d.fixedVersions.join(', ') || 'no fix yet'}</Mono>];
  return (
    <Kv
      items={[
        ['Lockfile', <Mono key="l">{`${d.projectId} · ${d.lockfile}`}</Mono>],
        ['Ecosystem', d.ecosystem],
        ...perVersion,
        fix,
        [
          'Import sites',
          <ImportSites key="s" findingId={d.findingId} packageName={d.packageName} sites={d.importSites} total={d.importSiteCount} newTab={newTab} />,
        ],
      ]}
    />
  );
}
