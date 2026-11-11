/** Job run history as a table; child jobs are indented under their parent. */
import Link from 'next/link';
import { CancelJobButton } from '@/components/jobs/cancel-job-button';
import { JobStatusBadge } from '@/components/jobs/job-status-badge';
import { Mono, Table, Td, Th } from '@/components/ui';
import { formatDuration, relativeTime } from '@/lib/format';
import { formatParams, jobDurationMs, summarizeStats, type JobNode } from '@/lib/queries/jobs';

function JobRows({ job, depth, now }: { job: JobNode; depth: number; now: Date }) {
  const active = job.status === 'queued' || job.status === 'running';
  return (
    <>
      <tr className={depth ? 'bg-panel-2/40' : undefined}>
        <Td className="whitespace-nowrap">
          <Link href={`/jobs/${job.id}`}>#{job.id}</Link>
        </Td>
        <Td className="whitespace-nowrap">
          <span style={{ paddingLeft: `${depth * 1.25}rem` }}>
            {depth ? <span className="text-muted">↳ </span> : null}
            <Mono>{job.type}</Mono>
          </span>
        </Td>
        <Td>
          <JobStatusBadge status={job.status} cancelRequested={job.cancelRequested} />
        </Td>
        <Td className="text-xs text-muted">{formatParams(job.params)}</Td>
        <Td className="text-xs">{job.progress ?? ''}</Td>
        <Td className="text-xs whitespace-nowrap text-muted" title={job.createdAt}>
          {relativeTime(job.createdAt, now)}
        </Td>
        <Td className="text-xs whitespace-nowrap">{formatDuration(jobDurationMs(job, now))}</Td>
        <Td className="text-xs">
          {job.status === 'failed' && job.error ? (
            <span className="text-ping">{job.error.split('\n')[0]?.slice(0, 160)}</span>
          ) : (
            <span className="text-muted">{summarizeStats(job.stats)}</span>
          )}
        </Td>
        {/* Only top-level jobs can be cancelled; the worker aborts their children with them. */}
        <Td>{active && job.parentId === null ? <CancelJobButton id={job.id} /> : null}</Td>
      </tr>
      {job.children.map((c) => (
        <JobRows key={c.id} job={c} depth={depth + 1} now={now} />
      ))}
    </>
  );
}

export function JobTable({ jobs }: { jobs: JobNode[] }) {
  const now = new Date();
  return (
    <Table>
      <thead>
        <tr>
          <Th>Id</Th>
          <Th>Type</Th>
          <Th>Status</Th>
          <Th>Params</Th>
          <Th>Progress</Th>
          <Th>Created</Th>
          <Th>Duration</Th>
          <Th>Stats / error</Th>
          <Th />
        </tr>
      </thead>
      <tbody>
        {jobs.map((j) => (
          <JobRows key={j.id} job={j} depth={0} now={now} />
        ))}
      </tbody>
    </Table>
  );
}
