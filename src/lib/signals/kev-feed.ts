/**
 * CISA Known Exploited Vulnerabilities catalog without the DB (spec §4.3, §8): the feed's schema, fetching
 * and parsing it, the rows it maps to, and matching CVEs against a cve → dateAdded index.
 * signals/kev.ts stores the catalog in the `kev` table.
 */
import { z } from 'zod';
import { CVE_ID_RE } from './cve';
import { fetchJson, type FetchFn } from './http';

export const KEV_FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEV_TIMEOUT_MS = 60_000;

const optionalText = z.string().nullish();

export const KevEntrySchema = z.object({
  cveID: z.string().trim().toUpperCase().regex(CVE_ID_RE),
  vendorProject: optionalText,
  product: optionalText,
  vulnerabilityName: optionalText,
  dateAdded: z.string().regex(/^\d{4}-\d{2}-\d{2}/),
  shortDescription: optionalText,
  requiredAction: optionalText,
  dueDate: optionalText,
  knownRansomwareCampaignUse: optionalText,
});
export type KevEntry = z.infer<typeof KevEntrySchema>;

export const KevFeedSchema = z.object({
  catalogVersion: z.string(),
  dateReleased: z.string(),
  count: z.number().int().nonnegative(),
  // An empty catalog would wipe every KEV flag on the next enrich; treat it as a broken download.
  vulnerabilities: z.array(KevEntrySchema).min(1),
});
export type KevFeed = z.infer<typeof KevFeedSchema>;

export function parseKevFeed(json: unknown): KevFeed {
  const parsed = KevFeedSchema.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues.slice(0, 5).map((i) => `${i.path.map(String).join('.') || '(root)'}: ${i.message}`);
    throw new Error(`KEV feed failed validation:\n  ${issues.join('\n  ')}`);
  }
  return parsed.data;
}

/** One catalog entry as stored: the `kev` table's insert shape (signals/kev.ts checks they stay equal). */
export interface KevRow {
  cve: string;
  dateAdded?: string | null;
  dueDate?: string | null;
  /** knownRansomwareCampaignUse: 'Known' | 'Unknown' */
  ransomware?: string | null;
  vendor?: string | null;
  product?: string | null;
  name?: string | null;
  shortDescription?: string | null;
}

/** Feed entries → table rows, one per CVE (the earliest dateAdded wins if CISA ever lists a CVE twice). */
export function kevRowsFromFeed(feed: KevFeed): KevRow[] {
  const byCve = new Map<string, KevRow>();
  for (const v of feed.vulnerabilities) {
    const row: KevRow = {
      cve: v.cveID,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate ?? null,
      ransomware: v.knownRansomwareCampaignUse ?? null,
      vendor: v.vendorProject ?? null,
      product: v.product ?? null,
      name: v.vulnerabilityName ?? null,
      shortDescription: v.shortDescription ?? null,
    };
    const existing = byCve.get(row.cve);
    if (!existing || (row.dateAdded ?? '') < (existing.dateAdded ?? '')) byCve.set(row.cve, row);
  }
  return [...byCve.values()];
}

export async function fetchKevFeed(opts: { fetchFn?: FetchFn; signal?: AbortSignal } = {}): Promise<KevFeed> {
  const json = await fetchJson(KEV_FEED_URL, { ...opts, timeoutMs: KEV_TIMEOUT_MS });
  return parseKevFeed(json);
}

export interface KevMatch {
  inKev: boolean;
  /** Earliest dateAdded among the matching CVEs */
  dateAdded: string | null;
}

export function matchKev(cves: readonly string[], index: ReadonlyMap<string, string | null>): KevMatch {
  let inKev = false;
  let dateAdded: string | null = null;
  for (const cve of cves) {
    if (!index.has(cve)) continue;
    inKev = true;
    const d = index.get(cve) ?? null;
    if (d && (dateAdded === null || d < dateAdded)) dateAdded = d;
  }
  return { inKev, dateAdded };
}
