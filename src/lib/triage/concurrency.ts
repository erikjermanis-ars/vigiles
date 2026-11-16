/** Concurrency helpers for triage runs, without the DB. triage/runner.ts re-exports forEachConcurrent. */

/**
 * Findings in a row whose every claude attempt failed at the CLI level (is_error, bad exit, no JSON).
 * That pattern means claude itself is unavailable (usage limit, auth, outage), not that the findings are
 * hard; carrying on would only spend time on runs that fail the same way. Used by the triage job
 * (src/jobs/triage.ts) and the plugin (src/plugin/triage.ts).
 */
export const MAX_CONSECUTIVE_CLI_FAILURES = 3;

/**
 * Runs `fn` over `items` with at most `concurrency` in flight. Stops starting new items once `signal`
 * aborts or an item throws; in-flight items always finish (so no claude process outlives the job),
 * then the first error is rethrown. Returns how many items were started.
 */
export async function forEachConcurrent<T>(
  items: readonly T[],
  concurrency: number,
  signal: AbortSignal,
  fn: (item: T, index: number) => Promise<void>,
): Promise<number> {
  let next = 0;
  const errors: unknown[] = [];
  const worker = async () => {
    while (!signal.aborted && errors.length === 0 && next < items.length) {
      const index = next++;
      try {
        await fn(items[index]!, index);
      } catch (error) {
        errors.push(error);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, worker));
  if (errors.length) throw errors[0];
  return next;
}
