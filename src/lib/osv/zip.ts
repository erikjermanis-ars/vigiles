/**
 * osv-scanner's offline databases without the DB: one `all.zip` per ecosystem under
 * <osvDb>/osv-scalibr/<Ecosystem>/all.zip, downloaded with conditional requests and swapped in atomically
 * (spec §4.3, §6). Where the HTTP validators (ETag, Last-Modified) are stored is the caller's business:
 * osv/database.ts keeps them in feed_state, the plugin in a sidecar file.
 */
import { closeSync, createWriteStream, mkdirSync, openSync, readSync, renameSync, rmSync, statSync, utimesSync } from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';

export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

export const DOWNLOAD_TIMEOUT_MS = 15 * 60_000;
export const USER_AGENT = 'vigiles-poc';

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

/** A readable one-line description of a download failure (timeouts and fetch's wrapped causes spelled out). */
export function errorText(err: unknown): string {
  if (err instanceof Error) {
    if (err.name === 'TimeoutError') return `timed out: ${err.message}`;
    const cause = (err as { cause?: unknown }).cause;
    return cause instanceof Error ? `${err.message} (${cause.message})` : err.message;
  }
  return String(err);
}

export function startsWithZipMagic(file: string): boolean {
  const fd = openSync(file, 'r');
  try {
    const buf = Buffer.alloc(2);
    return readSync(fd, buf, 0, 2, 0) === 2 && buf.toString('latin1') === 'PK';
  } finally {
    closeSync(fd);
  }
}

/**
 * Fetches one ecosystem's zip: conditional GET (If-None-Match from `stored.etag`, If-Modified-Since from
 * the local file's mtime). 304 keeps the file; 200 streams to a temp file in the same directory, checks it,
 * then renames it over the old one. The file's mtime is set to the server's Last-Modified, so it doubles
 * as the database date. The returned meta is what the caller should store for the next conditional request.
 *
 * Throws OsvDatabaseUnavailableError on HTTP 404 (OSV has no database for the ecosystem). Any other failure
 * (network, timeout, abort, HTTP error, truncated or non-zip body) is thrown as is, leaving the existing zip
 * untouched; describe it with errorText.
 */
export async function fetchOsvZip(ecosystem: string, opts: RefreshOptions, stored: Partial<OsvZipMeta>): Promise<OsvRefreshResult> {
  const started = Date.now();
  const target = osvZipPath(opts.osvDbDir, ecosystem);
  const url = `${opts.baseUrl.replace(/\/+$/, '')}/${encodeURIComponent(ecosystem)}/all.zip`;
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  try {
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const existing = statSync(target, { throwIfNoEntry: false });
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
    return { ecosystem, status, durationMs: Date.now() - started, ...meta };
  } finally {
    rmSync(tmp, { force: true });
  }
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
