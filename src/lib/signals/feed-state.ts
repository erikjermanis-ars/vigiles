/** feed_state bookkeeping for the KEV and EPSS feeds (spec §4.4: staleness is always visible). */
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { feedState } from '../db/schema';

export type SignalFeed = 'kev' | 'epss';

/** Drizzle's transaction handle shares the query API we use here. */
type DbLike = Pick<Db, 'insert' | 'select'>;

export function recordFeedSuccess(db: DbLike, feed: SignalFeed, meta: Record<string, unknown>, at = new Date().toISOString()): void {
  const values = { lastAttemptAt: at, lastSuccessAt: at, lastError: null, meta };
  db.insert(feedState)
    .values({ feed, ...values })
    .onConflictDoUpdate({ target: feedState.feed, set: values })
    .run();
}

/** Keeps lastSuccessAt and meta from the last good sync, so the UI can show how stale the data is. */
export function recordFeedFailure(db: DbLike, feed: SignalFeed, error: string, at = new Date().toISOString()): void {
  const values = { lastAttemptAt: at, lastError: error };
  db.insert(feedState)
    .values({ feed, ...values })
    .onConflictDoUpdate({ target: feedState.feed, set: values })
    .run();
}

export function getFeedState(db: DbLike, feed: SignalFeed) {
  return db.select().from(feedState).where(eq(feedState.feed, feed)).get();
}
