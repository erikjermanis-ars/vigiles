import type { JobContext, JobHandler } from '../lib/jobs/types';
import { recordFeedFailure } from '../lib/signals/feed-state';
import { errorMessage, type FetchFn } from '../lib/signals/http';
import { fetchKevFeed, replaceKevCatalog } from '../lib/signals/kev';

/** Downloads the CISA KEV catalog and replaces the `kev` table (spec §6). */
export const run: JobHandler = (ctx) => runSyncKev(ctx);

export async function runSyncKev(ctx: JobContext, deps: { fetchFn?: FetchFn } = {}) {
  ctx.progress('downloading KEV catalog');
  try {
    const feed = await fetchKevFeed({ fetchFn: deps.fetchFn, signal: ctx.signal });
    ctx.throwIfCancelled();
    if (feed.count !== feed.vulnerabilities.length) {
      ctx.log(`warning: catalog says count=${feed.count} but lists ${feed.vulnerabilities.length} entries`);
    }
    // Rolls back on error, so the previous catalog survives a failed write as well as a failed download.
    const { count } = replaceKevCatalog(ctx.db, feed);
    ctx.log(`KEV catalog ${feed.catalogVersion} (released ${feed.dateReleased}): ${count} CVEs`);
    return { catalogVersion: feed.catalogVersion, dateReleased: feed.dateReleased, count };
  } catch (err) {
    // A user cancel is not a feed failure.
    if (!ctx.signal.aborted) recordFeedFailure(ctx.db, 'kev', errorMessage(err));
    throw err;
  }
}
