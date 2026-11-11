/** One job run: params, stats, error, full log and child jobs. */
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AutoRefresh } from '@/components/auto-refresh';
import { CancelJobButton } from '@/components/jobs/cancel-job-button';
import { JobStatusBadge } from '@/components/jobs/job-status-badge';
import { JobTable } from '@/components/jobs/job-table';
import { ButtonLink, Card, CardBody, CardHeader, Kv, Mono, PageHeader } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { formatDuration, relativeTime } from '@/lib/format';
import { getJobDetail, jobDurationMs } from '@/lib/queries/jobs';

function Json({ value }: { value: unknown }) {
  return <pre className="overflow-x-auto rounded-md bg-panel-2 p-3 font-mono text-xs">{JSON.stringify(value, null, 2)}</pre>;
}

function When({ iso }: { iso: string | null }) {
  if (!iso) return <span className="text-muted">—</span>;
  return (
    <span title={iso}>
      {relativeTime(iso)} <span className="text-xs text-muted">({iso})</span>
    </span>
  );
}

export default async function JobPage({ params }: { params: Promise<{ id: string }> }) {
  const id = Number((await params).id);
  if (!Number.isInteger(id) || id <= 0) notFound();
  const detail = getJobDetail(getDb(), id);
  if (!detail) notFound();
  const { job, parent, children } = detail;
  const active = job.status === 'queued' || job.status === 'running';

  return (
    <>
      <AutoRefresh active={active} />
      <PageHeader
        title={`Job #${job.id} · ${job.type}`}
        subtitle={
          <span className="inline-flex items-center gap-2">
            <JobStatusBadge status={job.status} cancelRequested={job.cancelRequested} />
            {job.progress ? <span>{job.progress}</span> : null}
          </span>
        }
        actions={
          <>
            {active && !job.parentId ? <CancelJobButton id={job.id} /> : null}
            <ButtonLink href="/jobs">All jobs</ButtonLink>
          </>
        }
      />

      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Run" />
          <CardBody>
            <Kv
              items={[
                ['Type', <Mono key="type">{job.type}</Mono>],
                [
                  'Parent',
                  parent ? (
                    <Link key="parent" href={`/jobs/${parent.id}`}>
                      #{parent.id} {parent.type}
                    </Link>
                  ) : (
                    '—'
                  ),
                ],
                ['Created', <When key="created" iso={job.createdAt} />],
                ['Started', <When key="started" iso={job.startedAt} />],
                ['Finished', <When key="finished" iso={job.finishedAt} />],
                ['Duration', formatDuration(jobDurationMs(job))],
                ['Cancel requested', job.cancelRequested ? 'yes' : 'no'],
              ]}
            />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Params" />
          <CardBody>
            <Json value={job.params ?? {}} />
          </CardBody>
        </Card>
      </div>

      {job.error ? (
        <Card className="mb-5">
          <CardHeader title="Error" />
          <CardBody>
            <pre className="overflow-x-auto rounded-md bg-ping-bg p-3 font-mono text-xs whitespace-pre-wrap text-ping">{job.error}</pre>
          </CardBody>
        </Card>
      ) : null}

      {job.stats ? (
        <Card className="mb-5">
          <CardHeader title="Stats" />
          <CardBody>
            <Json value={job.stats} />
          </CardBody>
        </Card>
      ) : null}

      {children.length ? (
        <Card className="mb-5">
          <CardHeader title={`Child jobs (${children.length})`} />
          <JobTable jobs={children} />
        </Card>
      ) : null}

      <Card>
        <CardHeader title="Log" />
        <CardBody>
          {job.log ? (
            <pre className="max-h-[70vh] overflow-auto rounded-md bg-panel-2 p-3 font-mono text-xs whitespace-pre-wrap">{job.log}</pre>
          ) : (
            <p className="text-sm text-muted">No log output{active ? ' yet' : ''}.</p>
          )}
        </CardBody>
      </Card>
    </>
  );
}
