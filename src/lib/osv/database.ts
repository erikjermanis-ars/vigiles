/**
 * osv-scanner's offline databases: one `all.zip` per ecosystem under
 * <osvDb>/osv-scalibr/<Ecosystem>/all.zip. osv-scanner never refreshes an existing zip, so we
 * download them ourselves with conditional requests and swap them in atomically (spec §4.3, §6).
 */
import { existsSync } from 'node:fs';
import { and, eq, isNull, like } from 'drizzle-orm';
import type { Db } from '../db/client';
import { feedState } from '../db/schema';
import {
  assertEcosystemName,
  errorText,
  fetchOsvZip,
  OsvDatabaseUnavailableError,
  osvZipPath,
  type OsvRefreshResult,
  type OsvZipMeta,
  type RefreshOptions,
} from './zip';

// The DB-free half lives in ./zip; re-exported so existing imports keep working.
export {
  assertEcosystemName,
  DOWNLOAD_TIMEOUT_MS,
  errorText,
  fetchOsvZip,
  OsvDatabaseUnavailableError,
  osvDbDate,
  osvZipPath,
  startsWithZipMagic,
  USER_AGENT,
  type FetchFn,
  type OsvRefreshResult,
  type OsvZipMeta,
  type RefreshOptions,
} from './zip';

const FEED_PREFIX = 'osv:';

export function osvFeedName(ecosystem: string): string {
  return `${FEED_PREFIX}${ecosystem}`;
}

/**
 * Ecosystems with an `osv:*` feed_state row: every database that was ever downloaded (or attempted). The
 * staleness banner checks all of them, so `sync-osv` keeps them fresh too, even when no enabled project uses
 * them any more. Names that are not valid ecosystems are ignored.
 */
export function ecosystemsWithFeedState(db: Db): string[] {
  return db
    .select({ feed: feedState.feed })
    .from(feedState)
    .where(like(feedState.feed, `${FEED_PREFIX}%`))
    .all()
    .map((r) => r.feed.slice(FEED_PREFIX.length))
    .filter((eco) => {
      try {
        assertEcosystemName(eco);
        return true;
      } catch {
        return false;
      }
    });
}

function readMeta(db: Db, ecosystem: string): Partial<OsvZipMeta> {
  const row = db
    .select({ meta: feedState.meta })
    .from(feedState)
    .where(eq(feedState.feed, osvFeedName(ecosystem)))
    .get();
  return (row?.meta ?? {}) as Partial<OsvZipMeta>;
}

function recordSuccess(db: Db, ecosystem: string, meta: OsvZipMeta, at: string): void {
  const values = { lastAttemptAt: at, lastSuccessAt: at, lastError: null, meta: { ...meta } };
  db.insert(feedState)
    .values({ feed: osvFeedName(ecosystem), ...values })
    .onConflictDoUpdate({ target: feedState.feed, set: values })
    .run();
}

function recordFailure(db: Db, ecosystem: string, error: string, at: string): void {
  const values = { lastAttemptAt: at, lastError: error };
  db.insert(feedState)
    .values({ feed: osvFeedName(ecosystem), ...values })
    .onConflictDoUpdate({ target: feedState.feed, set: values })
    .run();
}

/**
 * Refreshes one ecosystem's zip with fetchOsvZip, using the ETag stored in feed_state 'osv:<eco>' for the
 * conditional request, and records the outcome there.
 */
export async function refreshOsvZip(db: Db, ecosystem: string, opts: RefreshOptions): Promise<OsvRefreshResult> {
  const now = () => (opts.now ? opts.now() : new Date()).toISOString();
  // An invalid name throws as is, before anything is recorded.
  assertEcosystemName(ecosystem);
  try {
    const result = await fetchOsvZip(ecosystem, opts, readMeta(db, ecosystem));
    recordSuccess(db, ecosystem, { etag: result.etag, lastModified: result.lastModified, bytes: result.bytes, path: result.path }, now());
    return result;
  } catch (err) {
    // No feed_state row for an ecosystem OSV doesn't cover: it would read as a feed that is always stale, and
    // sync-osv (which refreshes every osv:* row) could never clear it. A row left by an earlier failure (a
    // network error before the 404) goes too; one that once synced stays, so its old zip still shows as stale.
    if (err instanceof OsvDatabaseUnavailableError) {
      db.delete(feedState)
        .where(and(eq(feedState.feed, osvFeedName(ecosystem)), isNull(feedState.lastSuccessAt)))
        .run();
      throw err;
    }
    const message = errorText(err);
    // A cancelled job is not a feed failure; the old zip (if any) is untouched.
    if (!opts.signal?.aborted) recordFailure(db, ecosystem, message, now());
    throw new Error(`OSV ${ecosystem} database: ${message}`, { cause: err });
  }
}

export interface EnsureResult {
  downloaded: OsvRefreshResult[];
  /** Ecosystems OSV has no database for: their lockfiles cannot be matched */
  unavailable: string[];
}

/**
 * Downloads the zips that are missing (a scan needs every ecosystem it matches against). Any
 * failure other than "OSV has no such database" throws: scanning without the data would turn
 * every open finding of that ecosystem into a false "fixed".
 */
export async function ensureOsvZips(db: Db, ecosystems: string[], opts: RefreshOptions): Promise<EnsureResult> {
  const out: EnsureResult = { downloaded: [], unavailable: [] };
  for (const eco of ecosystems) {
    if (existsSync(osvZipPath(opts.osvDbDir, eco))) continue;
    try {
      out.downloaded.push(await refreshOsvZip(db, eco, opts));
    } catch (err) {
      if (!(err instanceof OsvDatabaseUnavailableError)) throw err;
      out.unavailable.push(eco);
    }
  }
  return out;
}

/**
 * Ecosystems `sync-osv` keeps fresh: configured ∪ found in projects' lockfiles ∪ already synced (feed_state),
 * or npm when all are empty.
 */
export function selectSyncEcosystems(configured: string[], fromLockfiles: string[], alreadySynced: string[] = []): string[] {
  const all = [...new Set([...configured, ...fromLockfiles, ...alreadySynced])].sort();
  return all.length ? all : ['npm'];
}
