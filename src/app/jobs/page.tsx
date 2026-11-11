/** Jobs (spec §6, §12): run buttons, feed freshness, and run history with live progress. */
import { AutoRefresh } from '@/components/auto-refresh';
import { JobStatusBadge } from '@/components/jobs/job-status-badge';
import { JobTable } from '@/components/jobs/job-table';
import { RunJobForm } from '@/components/jobs/run-job-form';
import { Card, CardBody, CardHeader, Empty, Mono, PageHeader, Table, Td, Th } from '@/components/ui';
import { loadVigilesConfig } from '@/lib/config/load';
import { getDb } from '@/lib/db/client';
import { JOB_DESCRIPTIONS } from '@/lib/jobs/descriptions';
import { relativeTime } from '@/lib/format';
import {
  getJobFormOptions,
  latestRunByType,
  listActiveJobs,
  listFeeds,
  listJobHistory,
  workerSeemsDown,
  type FeedRow,
} from '@/lib/queries/jobs';
import type { JobType } from '@/lib/types';

const JOB_CARDS: { type: JobType; label: string }[] = [
  { type: 'sync-osv', label: 'Sync OSV' },
  { type: 'sync-kev', label: 'Sync KEV' },
  { type: 'scan', label: 'Scan' },
  { type: 'enrich', label: 'Enrich' },
  { type: 'triage', label: 'Triage' },
  { type: 'decide', label: 'Re-evaluate policy' },
  { type: 'noop', label: 'Noop' },
];

function maxPerRun(): number | undefined {
  try {
    return loadVigilesConfig().triage.max_per_run;
  } catch {
    return undefined;
  }
}

function FeedTable({ feeds }: { feeds: FeedRow[] }) {
  if (!feeds.length) return <p className="text-sm text-muted">No feed has been synced yet.</p>;
  return (
    <Table>
      <thead>
        <tr>
          <Th>Feed</Th>
          <Th>Last success</Th>
          <Th>Last attempt</Th>
          <Th>Last error</Th>
        </tr>
      </thead>
      <tbody>
        {feeds.map((f) => (
          <tr key={f.feed}>
            <Td>
              <Mono>{f.feed}</Mono>
            </Td>
            <Td title={f.lastSuccessAt ?? undefined} className={f.lastSuccessAt ? undefined : 'text-digest'}>
              {relativeTime(f.lastSuccessAt)}
            </Td>
            <Td title={f.lastAttemptAt ?? undefined} className="text-muted">
              {relativeTime(f.lastAttemptAt)}
            </Td>
            <Td className="text-xs text-ping">{f.lastError ?? ''}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export default function JobsPage() {
  const db = getDb();
  const history = listJobHistory(db, 50);
  const active = listActiveJobs(db);
  const latest = latestRunByType(db);
  const options = getJobFormOptions(db);
  const feeds = listFeeds(db);
  const refreshAll = latest.get('refresh-all');

  return (
    <>
      <AutoRefresh active={active.length > 0} />
      <PageHeader
        title="Jobs"
        subtitle="Jobs run one at a time in the worker process, which npm run dev starts next to the dashboard."
        actions={<RunJobForm type="refresh-all" label="Refresh all" primary />}
      />

      {workerSeemsDown(active) ? (
        <div className="mb-5 rounded-lg border border-border bg-digest-bg px-4 py-3 text-sm text-digest">
          A job has been queued for more than 10 seconds and nothing is running. The worker is probably not started: run{' '}
          <Mono>npm run dev</Mono> (or <Mono>npm run worker</Mono>).
        </div>
      ) : null}

      <Card className="mb-5">
        <CardHeader
          title="Refresh all"
          actions={
            refreshAll ? (
              <span className="inline-flex items-center gap-2 text-xs text-muted">
                last run {relativeTime(refreshAll.createdAt)}{' '}
                <JobStatusBadge status={refreshAll.status} cancelRequested={refreshAll.cancelRequested} />
              </span>
            ) : null
          }
        />
        <CardBody className="text-sm text-muted">{JOB_DESCRIPTIONS['refresh-all']}</CardBody>
      </Card>

      <div className="mb-6 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {JOB_CARDS.map(({ type, label }) => {
          const last = latest.get(type);
          return (
            <Card key={type} className="flex flex-col">
              <CardHeader
                title={
                  <>
                    {label} {label.toLowerCase() !== type ? <span className="font-normal text-muted">({type})</span> : null}
                  </>
                }
                actions={last ? <JobStatusBadge status={last.status} cancelRequested={last.cancelRequested} /> : null}
              />
              <CardBody className="flex flex-1 flex-col gap-3">
                <p className="text-sm text-muted">{JOB_DESCRIPTIONS[type]}</p>
                {last ? <p className="text-xs text-muted">Last run {relativeTime(last.createdAt)}</p> : null}
                <div className="mt-auto">
                  <RunJobForm
                    type={type}
                    label={type === 'decide' ? 'Re-evaluate' : 'Run'}
                    projects={type === 'scan' ? options.projects : undefined}
                    configs={type === 'triage' ? options.configs : undefined}
                    defaultLimit={type === 'triage' ? maxPerRun() : undefined}
                  />
                </div>
              </CardBody>
            </Card>
          );
        })}
      </div>

      <Card className="mb-6">
        <CardHeader title="Feed freshness" />
        <CardBody>
          <FeedTable feeds={feeds} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Run history"
          actions={<span className="text-xs text-muted">latest 50 · refreshes every 2 s while a job is active</span>}
        />
        {history.length ? (
          <JobTable jobs={history} />
        ) : (
          <CardBody>
            <Empty>No jobs yet. Start with Refresh all.</Empty>
          </CardBody>
        )}
      </Card>
    </>
  );
}
