/**
 * osv-scanner's offline databases: one `all.zip` per ecosystem under
 * <osvDb>/osv-scalibr/<Ecosystem>/all.zip. osv-scanner never refreshes an existing zip, so we
 * download them ourselves with conditional requests and swap them in atomically (spec §4.3, §6).
 */
import { createWriteStream, existsSync, mkdirSync, openSync, readSync, closeSync, renameSync, rmSync, statSync, utimesSync } from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { and, eq, isNull, like } from 'drizzle-orm';
import type { Db } from '../db/client';
import { feedState } from '../db/schema';

export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

const DOWNLOAD_TIMEOUT_MS = 15 * 60_000;
const USER_AGENT = 'vigiles-poc';

/**
 * OSV ecosystem names are plain words, optionally with a version or vendor suffix ("crates.io",
 * "Alpine:v3.20", "Red Hat"). Anything with a path separator or a dot segment would let a config
 * value escape the database directory, so it is rejected.
 */
export function assertEcosystemName(ecosystem: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9.:_ +-]*$/.test(ecosystem) || ecosystem.split('.').some((p) => p === '')) {
    throw new Error(`invalid OSV ecosystem name "${ecosystem}"`);
  }
}

export function osvZipPath(osvDbDir: string, ecosystem: string): string {
  assertEcosystemName(ecosystem);
  return path.join(osvDbDir, 'osv-scalibr', ecosystem, 'all.zip');
}

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

/** OSV publishes no offline database for this ecosystem (HTTP 404), e.g. CocoaPods. */
export class OsvDatabaseUnavailableError extends Error {
  constructor(public ecosystem: string) {
    super(`OSV has no offline database for ecosystem "${ecosystem}"`);
  }
}

export interface OsvZipMeta {
  etag: string | null;
  lastModified: string | null;
  bytes: number;
  path: string;
}

export interface OsvRefreshResult extends OsvZipMeta {
  ecosystem: string;
  status: 'downloaded' | 'not_modified';
  durationMs: number;
}

export interface RefreshOptions {
  baseUrl: string;
  osvDbDir: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  fetchFn?: FetchFn;
  now?: () => Date;
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

function errorText(err: unknown): string {
  if (err instanceof Error) {
    if (err.name === 'TimeoutError') return `timed out: ${err.message}`;
    const cause = (err as { cause?: unknown }).cause;
    return cause instanceof Error ? `${err.message} (${cause.message})` : err.message;
  }
  return String(err);
}

function startsWithZipMagic(file: string): boolean {
  const fd = openSync(file, 'r');
  try {
    const buf = Buffer.alloc(2);
    return readSync(fd, buf, 0, 2, 0) === 2 && buf.toString('latin1') === 'PK';
  } finally {
    closeSync(fd);
  }
}

/**
 * Refreshes one ecosystem's zip: conditional GET (If-None-Match from the stored ETag,
 * If-Modified-Since from the local file's mtime). 304 keeps the file; 200 streams to a temp file
 * in the same directory, then renames it over the old one. The file's mtime is set to the
 * server's Last-Modified, so it doubles as the database date. Records feed_state 'osv:<eco>'.
 */
export async function refreshOsvZip(db: Db, ecosystem: string, opts: RefreshOptions): Promise<OsvRefreshResult> {
  const started = Date.now();
  const now = () => (opts.now ? opts.now() : new Date()).toISOString();
  const target = osvZipPath(opts.osvDbDir, ecosystem);
  const url = `${opts.baseUrl.replace(/\/+$/, '')}/${encodeURIComponent(ecosystem)}/all.zip`;
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  try {
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const existing = statSync(target, { throwIfNoEntry: false });
    const stored = readMeta(db, ecosystem);
    const headers: Record<string, string> = { 'User-Agent': USER_AGENT };
    if (existing) {
      if (stored.etag) headers['If-None-Match'] = stored.etag;
      headers['If-Modified-Since'] = existing.mtime.toUTCString();
    }

    const timeout = AbortSignal.timeout(opts.timeoutMs ?? DOWNLOAD_TIMEOUT_MS);
    const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
    const res = await (opts.fetchFn ?? fetch)(url, { headers, signal });

    let meta: OsvZipMeta;
    let status: OsvRefreshResult['status'];
    if (res.status === 304 && existing) {
      await res.body?.cancel();
      status = 'not_modified';
      meta = {
        etag: res.headers.get('etag') ?? stored.etag ?? null,
        lastModified: stored.lastModified ?? existing.mtime.toUTCString(),
        bytes: existing.size,
        path: target,
      };
    } else if (res.ok && res.body) {
      await pipeline(Readable.fromWeb(res.body as unknown as WebReadableStream), createWriteStream(tmp, { mode: 0o600 }));
      const bytes = statSync(tmp).size;
      // fetch decodes a Content-Encoding body, so Content-Length then counts the encoded bytes.
      const expected = res.headers.has('content-encoding') ? NaN : Number(res.headers.get('content-length') ?? NaN);
      if (Number.isFinite(expected) && expected !== bytes) throw new Error(`truncated download: ${bytes} of ${expected} bytes`);
      if (!startsWithZipMagic(tmp)) throw new Error('downloaded file is not a zip');
      const lastModified = res.headers.get('last-modified');
      const mtime = lastModified ? new Date(lastModified) : null;
      if (mtime && !Number.isNaN(mtime.getTime())) utimesSync(tmp, mtime, mtime);
      renameSync(tmp, target);
      status = 'downloaded';
      meta = { etag: res.headers.get('etag'), lastModified, bytes, path: target };
    } else {
      await res.body?.cancel();
      if (res.status === 404) throw new OsvDatabaseUnavailableError(ecosystem);
      throw new Error(`GET ${url} → HTTP ${res.status} ${res.statusText}`.trim());
    }
    recordSuccess(db, ecosystem, meta, now());
    return { ecosystem, status, durationMs: Date.now() - started, ...meta };
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
  } finally {
    rmSync(tmp, { force: true });
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

/** The oldest mtime among the ecosystems' zips (ISO), i.e. the date of the stalest data used. */
export function osvDbDate(osvDbDir: string, ecosystems: string[]): string | null {
  let oldest: number | null = null;
  for (const eco of ecosystems) {
    const st = statSync(osvZipPath(osvDbDir, eco), { throwIfNoEntry: false });
    if (st && (oldest === null || st.mtimeMs < oldest)) oldest = st.mtimeMs;
  }
  return oldest === null ? null : new Date(oldest).toISOString();
}

/**
 * Ecosystems `sync-osv` keeps fresh: configured ∪ found in projects' lockfiles ∪ already synced (feed_state),
 * or npm when all are empty.
 */
export function selectSyncEcosystems(configured: string[], fromLockfiles: string[], alreadySynced: string[] = []): string[] {
  const all = [...new Set([...configured, ...fromLockfiles, ...alreadySynced])].sort();
  return all.length ? all : ['npm'];
}
