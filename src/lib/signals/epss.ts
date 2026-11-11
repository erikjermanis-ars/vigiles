/**
 * FIRST EPSS scores (spec §4.3, §8): today's score for every CVE among open findings, in batches of 100.
 * Fail-soft per batch: a failed batch leaves its CVEs unscored so callers keep the previous values.
 */
import { z } from 'zod';
import { normalizeCves } from './cve';
import { errorMessage, fetchJson, type FetchFn } from './http';

export const EPSS_API_URL = 'https://api.first.org/data/v1/epss';
export const EPSS_BATCH_SIZE = 100;
const EPSS_TIMEOUT_MS = 30_000;

/** The API returns scores as decimal strings ("0.944240000"). */
const Probability = z
  .union([z.string().trim().min(1), z.number()])
  .transform((v) => (typeof v === 'string' ? Number(v) : v))
  .pipe(z.number().min(0).max(1));

export const EpssEntrySchema = z.object({
  cve: z.string().trim().toUpperCase(),
  epss: Probability,
  percentile: Probability,
  date: z.string().nullish(),
});

export const EpssResponseSchema = z.object({
  data: z.array(EpssEntrySchema),
});

export interface EpssScore {
  epss: number;
  percentile: number;
  date: string | null;
}

export function parseEpssResponse(json: unknown): Map<string, EpssScore> {
  const parsed = EpssResponseSchema.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues.slice(0, 5).map((i) => `${i.path.map(String).join('.') || '(root)'}: ${i.message}`);
    throw new Error(`EPSS response failed validation: ${issues.join('; ')}`);
  }
  return new Map(parsed.data.data.map((d) => [d.cve, { epss: d.epss, percentile: d.percentile, date: d.date ?? null }]));
}

export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export function epssUrl(cves: readonly string[]): string {
  // CVE IDs are validated, so a literal comma list is safe and matches the API's documented form.
  return `${EPSS_API_URL}?cve=${cves.join(',')}`;
}

export interface EpssFetchResult {
  scores: Map<string, EpssScore>;
  /** CVEs whose batch failed: callers keep previous values for findings that include them */
  failedCves: Set<string>;
  errors: string[];
  /** Latest score date seen (the EPSS model date) */
  date: string | null;
}

export interface EpssFetchOptions {
  fetchFn?: FetchFn;
  signal?: AbortSignal;
  batchSize?: number;
  /** Per-request timeout; tests shorten it */
  timeoutMs?: number;
  /** Called before each batch, e.g. for progress and cancellation checks */
  onBatch?: (index: number, total: number) => void;
}

export async function fetchEpssScores(cves: readonly string[], opts: EpssFetchOptions = {}): Promise<EpssFetchResult> {
  const result: EpssFetchResult = { scores: new Map(), failedCves: new Set(), errors: [], date: null };
  const batches = chunk(normalizeCves(cves), opts.batchSize ?? EPSS_BATCH_SIZE);
  for (const [i, batch] of batches.entries()) {
    opts.onBatch?.(i, batches.length);
    try {
      const json = await fetchJson(epssUrl(batch), { fetchFn: opts.fetchFn, signal: opts.signal, timeoutMs: opts.timeoutMs ?? EPSS_TIMEOUT_MS });
      for (const [cve, score] of parseEpssResponse(json)) {
        result.scores.set(cve, score);
        if (score.date && (result.date === null || score.date > result.date)) result.date = score.date;
      }
    } catch (err) {
      // A user cancel is not a feed failure; let it end the job.
      if (opts.signal?.aborted) throw err;
      for (const cve of batch) result.failedCves.add(cve);
      result.errors.push(`batch ${i + 1}/${batches.length}: ${errorMessage(err)}`);
    }
  }
  return result;
}

/** Highest EPSS over a finding's CVEs, with that CVE's percentile; null when none is scored. */
export function maxEpss(cves: readonly string[], scores: ReadonlyMap<string, EpssScore>): { epss: number; percentile: number } | null {
  let best: EpssScore | null = null;
  for (const cve of cves) {
    const s = scores.get(cve);
    if (s && (best === null || s.epss > best.epss)) best = s;
  }
  return best ? { epss: best.epss, percentile: best.percentile } : null;
}
