/**
 * Vigiles worker: polls job_runs for queued jobs and runs them one at a time.
 * Started by `npm run dev` / `npm start` next to the dashboard, or alone with `npm run worker`.
 *
 * SIGINT/SIGTERM cancel the job in progress (its child processes are killed and the row is recorded as
 * `cancelled`) before the worker exits. The echoes of one Ctrl-C (npm, tsx and concurrently forward it again)
 * are ignored; a signal a few seconds later exits at once.
 */
import { syncConfigToDb } from '../lib/config/sync';
import { getDb } from '../lib/db/client';
import { failInterruptedJobs, onStopSignals, runWorkerLoop, SIGNAL_ECHO_MS } from '../lib/jobs/runner';

async function main() {
  const db = getDb();
  const interrupted = failInterruptedJobs(db);
  if (interrupted) console.log(`[worker] marked ${interrupted} interrupted job(s) as failed`);
  try {
    syncConfigToDb(db);
  } catch (err) {
    console.error(`[worker] config error: ${(err as Error).message}`);
  }
  console.log('[worker] ready, polling for jobs');

  const stop = new AbortController();
  onStopSignals({
    stop(signal) {
      console.log(
        `[worker] ${signal}: stopping (cancelling the job in progress, if any; ` +
          `a signal more than ${SIGNAL_ECHO_MS / 1000} s from now exits at once)`,
      );
      stop.abort(`worker received ${signal}`);
    },
    force(signal) {
      console.log(`[worker] ${signal} again, exiting without waiting`);
      process.exit(130);
    },
  });

  await runWorkerLoop(db, { signal: stop.signal });
  console.log('[worker] stopped');
  process.exit(0);
}

main().catch((err) => {
  console.error('[worker] fatal', err);
  process.exit(1);
});
