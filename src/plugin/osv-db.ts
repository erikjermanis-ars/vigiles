/**
 * The offline OSV databases osv-scanner matches against (one all.zip per ecosystem under
 * <cache>/osv-db/osv-scalibr/<Ecosystem>/), kept fresh without the POC's DB: the HTTP validators and the time of the
 * last successful check live in a sidecar `<zip>.meta.json`. Downloading and the atomic swap are src/lib/osv/zip.ts.
 *
 * A missing database is downloaded, and failing to get it fails the scan (matching without the data would report a
 * vulnerable lockfile as clean). A present one is re-checked once it is older than maxAgeHours; when that check
 * fails the old copy is used with a warning naming its date.
 */
import { existsSync, readFileSync } from 'node:fs';
import {
  assertEcosystemName,
  errorText,
  fetchOsvZip,
  OsvDatabaseUnavailableError,
  osvDbDate,
  osvZipPath,
  type FetchFn,
  type OsvZipMeta,
} from '../lib/osv/zip';
import { writeFileAtomic } from './paths';

export const OSV_BASE_URL = 'https://osv-vulnerabilities.storage.googleapis.com';
export const OSV_MAX_AGE_HOURS = 24;

export interface OsvSidecar extends OsvZipMeta {
  /** When the zip was last confirmed current (downloaded or answered 304), ISO */
  checkedAt: string;
}

export interface EnsureOsvOptions {
  osvDbDir: string;
  baseUrl?: string;
  maxAgeHours?: number;
  /** Re-check every database now, however recent the last check */
  force?: boolean;
  signal?: AbortSignal;
  fetchFn?: FetchFn;
  now?: () => Date;
  /** One line per download or refresh */
  log?: (message: string) => void;
}

export interface EnsureOsvResult {
  /** Ecosystems OSV publishes no database for: their lockfiles cannot be matched */
  unavailable: string[];
  /** Ecosystems whose zip was (re)downloaded by this call */
  downloaded: string[];
  warnings: string[];
  /** The oldest database date (zip mtime = the server's Last-Modified) among the available ecosystems, ISO */
  dbDate: string | null;
}

export function sidecarPath(osvDbDir: string, ecosystem: string): string {
  return `${osvZipPath(osvDbDir, ecosystem)}.meta.json`;
}

export function readSidecar(osvDbDir: string, ecosystem: string): Partial<OsvSidecar> {
  try {
    const value = JSON.parse(readFileSync(sidecarPath(osvDbDir, ecosystem), 'utf8')) as unknown;
    return value && typeof value === 'object' ? (value as Partial<OsvSidecar>) : {};
  } catch {
    return {};
  }
}

function writeSidecar(osvDbDir: string, ecosystem: string, meta: OsvSidecar): void {
  writeFileAtomic(sidecarPath(osvDbDir, ecosystem), `${JSON.stringify(meta, null, 2)}\n`);
}

function isFresh(sidecar: Partial<OsvSidecar>, now: Date, maxAgeHours: number): boolean {
  const checked = sidecar.checkedAt ? Date.parse(sidecar.checkedAt) : NaN;
  return Number.isFinite(checked) && now.getTime() - checked < maxAgeHours * 3_600_000;
}

function mb(bytes: number): string {
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

/** Makes sure every ecosystem's database is present and recent enough (see the module comment). */
export async function ensureOsvDatabases(ecosystems: string[], opts: EnsureOsvOptions): Promise<EnsureOsvResult> {
  const now = opts.now ?? (() => new Date());
  const maxAgeHours = opts.maxAgeHours ?? OSV_MAX_AGE_HOURS;
  const log = opts.log ?? (() => {});
  const refresh = { baseUrl: opts.baseUrl ?? OSV_BASE_URL, osvDbDir: opts.osvDbDir, signal: opts.signal, fetchFn: opts.fetchFn, now };
  const out: EnsureOsvResult = { unavailable: [], downloaded: [], warnings: [], dbDate: null };

  for (const eco of [...new Set(ecosystems)].sort()) {
    assertEcosystemName(eco);
    const zip = osvZipPath(opts.osvDbDir, eco);
    const present = existsSync(zip);
    const sidecar = present ? readSidecar(opts.osvDbDir, eco) : {};
    if (present && !opts.force && isFresh(sidecar, now(), maxAgeHours)) continue;
    if (!present) log(`downloading the OSV ${eco} database (first use; a large ecosystem like npm is about 200 MB)`);

    try {
      const r = await fetchOsvZip(eco, refresh, sidecar);
      writeSidecar(opts.osvDbDir, eco, {
        etag: r.etag,
        lastModified: r.lastModified,
        bytes: r.bytes,
        path: r.path,
        checkedAt: now().toISOString(),
      });
      if (r.status === 'downloaded') {
        out.downloaded.push(eco);
        log(`OSV ${eco} database ${present ? 'updated' : 'downloaded'} (${mb(r.bytes)})`);
      }
    } catch (err) {
      if (opts.signal?.aborted) throw err;
      if (err instanceof OsvDatabaseUnavailableError) {
        if (!present) {
          out.unavailable.push(eco);
          continue;
        }
        // OSV stopped publishing it: keep matching against the last copy.
        out.warnings.push(
          `OSV no longer publishes a ${eco} database; using the copy from ${osvDbDate(opts.osvDbDir, [eco])?.slice(0, 10) ?? 'an unknown date'}`,
        );
        continue;
      }
      if (!present) throw new Error(`OSV ${eco} database could not be downloaded: ${errorText(err)}`, { cause: err });
      out.warnings.push(
        `OSV ${eco} database could not be refreshed (${errorText(err)}); matched against the copy from ${
          osvDbDate(opts.osvDbDir, [eco])?.slice(0, 10) ?? 'an unknown date'
        }`,
      );
    }
  }

  out.dbDate = osvDbDate(
    opts.osvDbDir,
    ecosystems.filter((e) => !out.unavailable.includes(e)),
  );
  return out;
}
