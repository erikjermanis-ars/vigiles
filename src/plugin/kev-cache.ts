/**
 * The CISA KEV catalog without the POC's DB: the validated feed is cached in <cache>/kev.json with the time it was
 * fetched, refreshed once older than maxAgeHours, and served as a cve → { dateAdded, ransomware } index.
 * Fetching, validation and row mapping are src/lib/signals/kev-feed.ts.
 *
 * KEV flags drive P0/P1, so a missing catalog is loud: a failed refresh falls back to the cached copy with a
 * warning, and with no copy at all `available` is false and the warning says priorities may be too low.
 */
import { readFileSync } from 'node:fs';
import { errorMessage, type FetchFn } from '../lib/signals/http';
import { fetchKevFeed, kevRowsFromFeed, parseKevFeed, type KevFeed } from '../lib/signals/kev-feed';
import { writeFileAtomic } from './paths';

export const KEV_MAX_AGE_HOURS = 24;
const CACHE_FORMAT = 1;

export interface KevIndexEntry {
  /** YYYY-MM-DD the CVE was added to the catalog */
  dateAdded: string | null;
  /** knownRansomwareCampaignUse: 'Known' | 'Unknown' */
  ransomware: string | null;
}

export type KevIndex = Map<string, KevIndexEntry>;

export interface LoadKevOptions {
  kevFile: string;
  maxAgeHours?: number;
  /** Fetch now, however recent the cached copy */
  force?: boolean;
  signal?: AbortSignal;
  fetchFn?: FetchFn;
  now?: () => Date;
}

export interface KevLoadResult {
  index: KevIndex;
  /** The catalog's dateReleased, ISO */
  catalogDate: string | null;
  warnings: string[];
  /** false when no catalog could be loaded at all: no finding is flagged as known exploited */
  available: boolean;
  /** true when this call downloaded the catalog */
  fetched: boolean;
}

interface KevCacheFile {
  format: typeof CACHE_FORMAT;
  fetchedAt: string;
  feed: KevFeed;
}

function readCache(file: string): { cache: KevCacheFile | null; problem: string | null } {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { cache: null, problem: null };
    return { cache: null, problem: errorMessage(err) };
  }
  try {
    const raw = JSON.parse(text) as Partial<KevCacheFile>;
    if (raw.format !== CACHE_FORMAT || typeof raw.fetchedAt !== 'string') throw new Error('unknown format');
    return { cache: { format: CACHE_FORMAT, fetchedAt: raw.fetchedAt, feed: parseKevFeed(raw.feed) }, problem: null };
  } catch (err) {
    return { cache: null, problem: errorMessage(err).split('\n')[0]! };
  }
}

export function kevIndexFromFeed(feed: KevFeed): KevIndex {
  return new Map(kevRowsFromFeed(feed).map((r) => [r.cve, { dateAdded: r.dateAdded ?? null, ransomware: r.ransomware ?? null }]));
}

/** cve → dateAdded, the shape computeFindingSignals (src/lib/signals/compute.ts) takes. */
export function kevDateIndex(index: KevIndex): Map<string, string | null> {
  return new Map([...index].map(([cve, e]) => [cve, e.dateAdded]));
}

/**
 * knownRansomwareCampaignUse for a finding's CVEs: the entry of the first matching CVE in sorted order (the POC
 * reads the first kev row among the advisory's CVEs). null when none is in KEV.
 */
export function kevRansomwareFor(cves: readonly string[], index: KevIndex): string | null {
  for (const cve of [...cves].sort()) {
    const entry = index.get(cve);
    if (entry) return entry.ransomware;
  }
  return null;
}

function result(cache: KevCacheFile, warnings: string[], fetched: boolean): KevLoadResult {
  return { index: kevIndexFromFeed(cache.feed), catalogDate: cache.feed.dateReleased, warnings, available: true, fetched };
}

export async function loadKev(opts: LoadKevOptions): Promise<KevLoadResult> {
  const now = opts.now ?? (() => new Date());
  const maxAgeMs = (opts.maxAgeHours ?? KEV_MAX_AGE_HOURS) * 3_600_000;
  const warnings: string[] = [];
  const { cache, problem } = readCache(opts.kevFile);
  if (problem) warnings.push(`ignoring the cached KEV catalog ${opts.kevFile} (${problem})`);

  const fetchedAt = cache ? Date.parse(cache.fetchedAt) : NaN;
  if (cache && !opts.force && Number.isFinite(fetchedAt) && now().getTime() - fetchedAt < maxAgeMs) {
    return result(cache, warnings, false);
  }

  try {
    const feed = await fetchKevFeed({ fetchFn: opts.fetchFn, signal: opts.signal });
    const fresh: KevCacheFile = { format: CACHE_FORMAT, fetchedAt: now().toISOString(), feed };
    writeFileAtomic(opts.kevFile, `${JSON.stringify(fresh)}\n`);
    return result(fresh, warnings, true);
  } catch (err) {
    if (opts.signal?.aborted) throw err;
    const message = errorMessage(err).split('\n')[0]!;
    if (cache) {
      warnings.push(
        `CISA KEV catalog could not be refreshed (${message}); using the copy released ${cache.feed.dateReleased.slice(0, 10)}`,
      );
      return result(cache, warnings, false);
    }
    warnings.push(
      `CISA KEV catalog unavailable (${message}): no finding could be checked against known-exploited vulnerabilities, ` +
        'so findings that belong in P0/P1 may be ranked lower. Re-run when the network is back.',
    );
    return { index: new Map(), catalogDate: null, warnings, available: false, fetched: false };
  }
}
