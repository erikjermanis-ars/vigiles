/** One project: summary, full profile and scan history. */
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { stringify } from 'yaml';
import { Badge, ButtonLink, Card, CardBody, CardHeader, Empty, Mono, PageHeader, Table, Td, Th } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { formatDuration, relativeTime, shortDate } from '@/lib/format';
import { summarizeStats } from '@/lib/queries/jobs';
import { ProjectTag } from '@/components/inbox/project-tag';
import { colorFor, projectColors } from '@/lib/project-scope';
import { getProjectDetail, listScopeProjects, type ScanRow } from '@/lib/queries/projects';
import { ProjectBadges, ProjectSummary } from '../_components/project-summary';

const scanTone = { running: 'accent', succeeded: 'ok', failed: 'ping' } as const;

function scanDuration(s: ScanRow): number | null {
  return s.finishedAt ? Date.parse(s.finishedAt) - Date.parse(s.startedAt) : null;
}

function ScanHistory({ scans }: { scans: ScanRow[] }) {
  if (!scans.length) return <Empty>No scans yet.</Empty>;
  return (
    <Table>
      <thead>
        <tr>
          <Th>Scan</Th>
          <Th>Status</Th>
          <Th>Started</Th>
          <Th>Duration</Th>
          <Th>Ref → commit</Th>
          <Th>Commit date</Th>
          <Th>Lockfiles</Th>
          <Th>OSV DB</Th>
          <Th>Stats / error</Th>
        </tr>
      </thead>
      <tbody>
        {scans.map((s) => (
          <tr key={s.id}>
            <Td>{s.jobRunId ? <Link href={`/jobs/${s.jobRunId}`}>#{s.id}</Link> : `#${s.id}`}</Td>
            <Td>
              <Badge tone={scanTone[s.status]}>{s.status}</Badge>
            </Td>
            <Td className="text-xs whitespace-nowrap" title={s.startedAt}>
              {relativeTime(s.startedAt)}
            </Td>
            <Td className="text-xs whitespace-nowrap">{formatDuration(scanDuration(s))}</Td>
            <Td className="text-xs whitespace-nowrap">
              <Mono>{s.ref}</Mono> → <Mono>{s.commitSha?.slice(0, 8) ?? '—'}</Mono>
            </Td>
            <Td className="text-xs whitespace-nowrap">{shortDate(s.commitDate)}</Td>
            <Td className="text-xs" title={s.lockfiles.join('\n')}>
              {s.lockfiles.length}
              {s.coverageGaps.length ? <span className="text-digest"> · {s.coverageGaps.length} gaps</span> : null}
            </Td>
            <Td className="text-xs whitespace-nowrap">{s.osvDbDate ? shortDate(s.osvDbDate) : '—'}</Td>
            <Td className="text-xs">
              {s.error ? (
                <span className="text-ping">{s.error.split('\n')[0]}</span>
              ) : (
                <span className="text-muted">{summarizeStats(s.stats, 5)}</span>
              )}
              {s.fetchError ? <div className="text-digest">fetch: {s.fetchError}</div> : null}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export default async function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const db = getDb();
  const detail = getProjectDetail(db, id);
  if (!detail) notFound();
  const { project } = detail;
  // The same colour as on every other page (colours are assigned over all project ids).
  const color = colorFor(projectColors(listScopeProjects(db).map((p) => p.id)), project.id);

  return (
    <>
      <PageHeader
        title={project.name}
        subtitle={
          <span className="inline-flex flex-wrap items-center gap-2">
            <ProjectTag name={project.name} color={color} enabled={project.enabled} />
            <Mono>{project.id}</Mono> <ProjectBadges project={project} />
          </span>
        }
        actions={
          <>
            <ButtonLink href={`/findings?project=${encodeURIComponent(project.id)}`}>Findings</ButtonLink>
            <ButtonLink href="/projects">All projects</ButtonLink>
          </>
        }
      />
      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Scan state" />
          <CardBody>
            <ProjectSummary overview={detail} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader
            title={
              <>
                Profile{' '}
                <span className="font-normal text-muted">
                  projects/{project.id}.yaml · hash {project.profileHash}
                </span>
              </>
            }
          />
          <CardBody>
            <pre className="overflow-x-auto rounded-md bg-panel-2 p-3 font-mono text-xs whitespace-pre-wrap">
              {stringify(project.profile, { lineWidth: 100 })}
            </pre>
          </CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Scan history" actions={<span className="text-xs text-muted">latest 20</span>} />
        <ScanHistory scans={detail.scans} />
      </Card>
    </>
  );
}
