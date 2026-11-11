/**
 * Run or enqueue a job from the terminal.
 *
 *   npm run job -- <type> [--project how-clutch-web] [--config v1-sonnet-high-code] [--limit 5]
 *                         [--findings 12,13] [--force] [--tag consistency] [--sample 20]
 *                         [--enqueue]   # hand it to a running worker instead of running inline
 *   npm run job -- list
 */
import { getDb, type Db } from '../lib/db/client';
import { jobRuns } from '../lib/db/schema';
import { describeLiveJob, enqueueJob, getJob, isJobType, liveRunningJobs, recentJobs } from '../lib/jobs/queue';
import { onStopSignals, runJob, SIGNAL_ECHO_MS } from '../lib/jobs/runner';
import { JOB_TYPES, type JobType } from '../lib/types';

function parseArgs(argv: string[]) {
  const params: Record<string, unknown> = {};
  let enqueue = false;
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const key = a.slice(2);
    if (key === 'enqueue') {
      enqueue = true;
      continue;
    }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      params[key] = true;
      continue;
    }
    i++;
    if (key === 'findings') params[key] = next.split(',').map(Number);
    else if (/^-?\d+(\.\d+)?$/.test(next)) params[key] = Number(next);
    else params[key] = next;
  }
  return { positional, params, enqueue };
}

/**
 * Runs `type` inline as a top-level job row owned by this process. SIGINT/SIGTERM cancel it (children are
 * killed, the row is recorded `cancelled`) instead of leaving the row `running`. The echoes of one Ctrl-C
 * (npm and tsx forward it again) are ignored; a signal a few seconds later exits at once.
 */
async function runInline(db: Db, type: JobType, params: Record<string, unknown>) {
  // A top-level job of the same type that a live process (the worker or another CLI) is running. A row with
  // our own pid was left by an earlier process that had this pid: we have not started anything yet.
  const busy = liveRunningJobs(db, { type, topLevelOnly: true }).find((j) => j.pid !== process.pid);
  if (busy) {
    console.error(`${describeLiveJob(busy)} is already running; wait for it to finish, or add --enqueue to queue this run for the worker`);
    process.exitCode = 1;
    return;
  }
  // Inserted as running (with our pid) so a concurrently running worker neither picks it up nor reclaims it.
  const id = db
    .insert(jobRuns)
    .values({ type, params, status: 'running', pid: process.pid, startedAt: new Date().toISOString() })
    .returning({ id: jobRuns.id })
    .get().id;

  const stop = new AbortController();
  // Left installed until the process exits: an echo arriving after the job finished must not kill the output.
  onStopSignals({
    stop(signal) {
      console.error(`\n${signal}: cancelling ${type}#${id} (a signal more than ${SIGNAL_ECHO_MS / 1000} s from now exits at once)`);
      stop.abort(`interrupted by ${signal}`);
    },
    force: () => process.exit(130),
  });
  const status = await runJob(db, id, { signal: stop.signal });

  const row = getJob(db, id);
  console.log(`\n${type}#${id} ${status}`);
  if (row?.stats) console.log(JSON.stringify(row.stats, null, 2));
  if (status === 'failed') {
    console.error(row?.error);
    process.exitCode = 1;
  }
  if (stop.signal.aborted) process.exitCode = 130;
}

async function main() {
  const { positional, params, enqueue } = parseArgs(process.argv.slice(2));
  const type = positional[0];
  const db = getDb();

  if (!type || type === 'help') {
    console.log(`usage: npm run job -- <${JOB_TYPES.join('|')}|list> [--flags] [--enqueue]`);
    return;
  }
  if (type === 'list') {
    for (const j of recentJobs(db, 20)) console.log(`#${j.id} ${j.type} ${j.status} ${j.createdAt} ${j.progress ?? ''}`);
    return;
  }
  if (!isJobType(type)) throw new Error(`unknown job type "${type}"`);

  if (enqueue) {
    const id = enqueueJob(db, type, params);
    console.log(`enqueued ${type}#${id}; the worker will pick it up`);
    return;
  }
  await runInline(db, type, params);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
