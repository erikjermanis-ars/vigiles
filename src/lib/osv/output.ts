/**
 * Parses osv-scanner's `--format json --all-packages` output (spec §7.4) and maps OSV records to
 * `advisories` rows. Only the fields we use are validated; full records are kept as `raw`.
 */
import { z } from 'zod';
import type { advisories } from '../db/schema';

const OsvSeveritySchema = z.looseObject({ type: z.string(), score: z.string() });

const OsvAffectedSchema = z.looseObject({
  package: z.looseObject({ ecosystem: z.string().optional(), name: z.string().optional() }).optional(),
  ranges: z
    .array(z.looseObject({ type: z.string().optional(), events: z.array(z.record(z.string(), z.unknown())).default([]) }))
    .optional(),
  versions: z.array(z.string()).optional(),
});

export const OsvRecordSchema = z.looseObject({
  id: z.string(),
  aliases: z.array(z.string()).nullish(),
  summary: z.string().nullish(),
  details: z.string().nullish(),
  modified: z.string().nullish(),
  published: z.string().nullish(),
  withdrawn: z.string().nullish(),
  severity: z.array(OsvSeveritySchema).nullish(),
  database_specific: z.record(z.string(), z.unknown()).nullish(),
  affected: z.array(OsvAffectedSchema).nullish(),
  references: z.array(z.looseObject({ type: z.string().optional(), url: z.string() })).nullish(),
});
export type OsvRecord = z.infer<typeof OsvRecordSchema>;

const OsvGroupSchema = z.looseObject({
  ids: z.array(z.string()),
  aliases: z.array(z.string()).nullish(),
  max_severity: z.string().nullish(),
});

const OsvPackageSchema = z.looseObject({
  package: z.looseObject({ name: z.string(), version: z.string(), ecosystem: z.string() }),
  dependency_groups: z.array(z.string()).nullish(),
  groups: z.array(OsvGroupSchema).nullish(),
  vulnerabilities: z.array(OsvRecordSchema).nullish(),
});

export const OsvOutputSchema = z.looseObject({
  results: z
    .array(
      z.looseObject({
        source: z.looseObject({ path: z.string(), type: z.string().optional() }),
        packages: z.array(OsvPackageSchema).nullish(),
      }),
    )
    .nullish(),
});

export interface OsvGroup {
  /** Representative id: the finding's osv_id (§7.5) */
  osvId: string;
  ids: string[];
  /** Every id and alias osv-scanner reported for the group (CVE, GHSA, MAL, ...) */
  aliases: string[];
  /** osv-scanner's numeric score from the CVSS vectors; null when absent or unparseable */
  maxSeverity: number | null;
  /** The group's records that are present in the output (representative first) */
  records: OsvRecord[];
}

export interface OsvPackage {
  name: string;
  version: string;
  ecosystem: string;
  /** osv-scanner put the package in the `dev` dependency group */
  dev: boolean;
  groups: OsvGroup[];
}

export interface OsvSourceResult {
  /** Path as osv-scanner reports it (absolute, as passed with -L) */
  path: string;
  packages: OsvPackage[];
}

const ID_PREFERENCE = ['GHSA-', 'MAL-'];

/** Prefers GHSA-, then MAL-, then anything else; ties break lexicographically. */
export function representativeId(ids: string[]): string {
  if (ids.length === 0) throw new Error('empty OSV group');
  const rank = (id: string) => {
    const i = ID_PREFERENCE.findIndex((p) => id.startsWith(p));
    return i === -1 ? ID_PREFERENCE.length : i;
  };
  return [...ids].sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0))[0]!;
}

export function parseSeverityScore(value: string | null | undefined): number | null {
  if (value === null || value === undefined || value.trim() === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 && n <= 10 ? n : null;
}

function toPackage(p: z.infer<typeof OsvPackageSchema>): OsvPackage {
  const records = new Map((p.vulnerabilities ?? []).map((r) => [r.id, r]));
  const groups: OsvGroup[] = [];
  for (const g of p.groups ?? []) {
    if (g.ids.length === 0) continue;
    // The finding needs the representative's record (advisory row, modified date), so prefer ids
    // whose record is in the output; otherwise the whole group would silently drop out.
    const withRecords = g.ids.filter((id) => records.has(id));
    const osvId = representativeId(withRecords.length ? withRecords : g.ids);
    const ordered = [osvId, ...g.ids.filter((id) => id !== osvId).sort()];
    groups.push({
      osvId,
      ids: [...g.ids].sort(),
      aliases: [...new Set([...g.ids, ...(g.aliases ?? [])])].sort(),
      maxSeverity: parseSeverityScore(g.max_severity),
      records: ordered.map((id) => records.get(id)).filter((r): r is OsvRecord => r !== undefined),
    });
  }
  return {
    name: p.package.name,
    version: p.package.version,
    ecosystem: p.package.ecosystem,
    dev: (p.dependency_groups ?? []).includes('dev'),
    groups,
  };
}

export function parseOsvOutput(json: unknown): OsvSourceResult[] {
  const parsed = OsvOutputSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`unexpected osv-scanner output at ${issue?.path.map(String).join('.') ?? '?'}: ${issue?.message ?? ''}`);
  }
  return (parsed.data.results ?? []).map((r) => ({ path: r.source.path, packages: (r.packages ?? []).map(toPackage) }));
}

/** All `fixed` versions from the records' affected entries for this package (deduped, version-sorted). */
export function fixedVersionsFor(records: OsvRecord[], name: string, ecosystem: string): string[] {
  const out = new Set<string>();
  for (const record of records) {
    for (const affected of record.affected ?? []) {
      if (affected.package?.name !== name || affected.package?.ecosystem !== ecosystem) continue;
      for (const range of affected.ranges ?? []) {
        for (const event of range.events) {
          if (typeof event.fixed === 'string' && event.fixed) out.add(event.fixed);
        }
      }
    }
  }
  return [...out].sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
}

export type AdvisoryInsert = typeof advisories.$inferInsert;

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** First CVSS v4 vector, else first CVSS v3 vector. */
export function cvssVectorOf(record: OsvRecord): string | null {
  const severity = record.severity ?? [];
  return severity.find((s) => s.type === 'CVSS_V4')?.score ?? severity.find((s) => s.type === 'CVSS_V3')?.score ?? null;
}

/** GitHub's malware advisories (GHSA ids) carry CWE-506 "Embedded Malicious Code" and summaries like these. */
const MALWARE_SUMMARY = /^(malicious package\b|malware in\b)|\b(is|contains) malware\b/i;

/**
 * A malicious package (spec §8: always P0, always ping). OSV/OpenSSF use MAL- ids; GitHub publishes the same kind of
 * advisory under a GHSA id with CWE-506 (e.g. the 2018 event-stream/flatmap-stream backdoor, the 2025 chalk/debug and
 * color-string account-takeover releases), so both are recognised.
 */
export function isMalicious(record: OsvRecord): boolean {
  if (record.id.startsWith('MAL-') || (record.aliases ?? []).some((a) => a.startsWith('MAL-'))) return true;
  const cwes = record.database_specific?.cwe_ids;
  if (Array.isArray(cwes) && cwes.includes('CWE-506')) return true;
  return MALWARE_SUMMARY.test(record.summary ?? '');
}

/**
 * One `advisories` row per OSV record. `maxSeverity` is the score of the group the record is in.
 * `groupAliases` (for the group's representative record) adds CVEs known only through other records
 * of the same group, so the KEV/EPSS joins in enrich see every CVE of the finding.
 */
export function advisoryFromRecord(record: OsvRecord, maxSeverity: number | null, groupAliases: string[] = []): AdvisoryInsert {
  const aliases = record.aliases ?? [];
  const label = record.database_specific?.severity;
  return {
    osvId: record.id,
    aliases,
    cves: [...new Set([record.id, ...aliases, ...groupAliases].filter((id) => id.startsWith('CVE-')))].sort(),
    summary: record.summary ?? null,
    details: record.details ?? null,
    cvssVector: cvssVectorOf(record),
    cvssScore: maxSeverity,
    severityLabel: typeof label === 'string' ? label : null,
    cwes: stringArray(record.database_specific?.cwe_ids),
    references: [...new Set((record.references ?? []).map((r) => r.url))],
    published: record.published ?? null,
    modified: record.modified ?? null,
    withdrawn: record.withdrawn ?? null,
    malicious: isMalicious(record),
    raw: record as Record<string, unknown>,
  };
}
