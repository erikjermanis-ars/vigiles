/**
 * One finding's signals (spec §8) computed from the feeds without the DB: CVEs, malicious flag, KEV match,
 * EPSS, CVSS score, base priority and escalation triggers. signals/enrich.ts loads the rows and writes the result.
 */
import type { Criticality, Exposure, Priority } from '../types';
import { normalizeCves } from './cve';
import { resolveCvssScore } from './cvss';
import { maxEpss, type EpssFetchResult } from './epss';
import { detectEscalation } from './escalation';
import { matchKev } from './kev-feed';
import { computeBasePriority, type PriorityThresholds } from './priority';

/** An open finding with what enrich needs from its advisory and project. */
export interface EnrichRow {
  id: number;
  projectId: string;
  osvId: string;
  priority: Priority | null;
  inKev: boolean;
  epss: number | null;
  epssPercentile: number | null;
  enrichedAt: string | null;
  advisory: { cves: string[]; cvssScore: number | null; severityLabel: string | null; malicious: boolean } | null;
  exposure: Exposure;
  criticality: Criticality;
}

export interface FindingSignals {
  cves: string[];
  malicious: boolean;
  inKev: boolean;
  kevDateAdded: string | null;
  epss: number | null;
  epssPercentile: number | null;
  cvssScore: number | null;
  priority: Priority;
  priorityReasons: string[];
  /** Escalation triggers versus the previous enrichment; empty on the first one or when nothing moved up */
  escalation: string[];
}

export interface SignalSources {
  kevIndex: ReadonlyMap<string, string | null>;
  epss: Pick<EpssFetchResult, 'scores' | 'failedCves'>;
  thresholds: PriorityThresholds;
}

/**
 * EPSS for one finding. When some of its CVEs were in a failed batch, the stored max may belong to one
 * of them, so it is kept unless a CVE that did get scored now beats it (a real rise is never hidden).
 */
export function resolveFindingEpss(
  cves: readonly string[],
  stored: { epss: number | null; epssPercentile: number | null },
  epss: SignalSources['epss'],
): { epss: number | null; epssPercentile: number | null } {
  const scored = cves.filter((c) => !epss.failedCves.has(c));
  const fresh = maxEpss(scored, epss.scores);
  if (scored.length === cves.length) return { epss: fresh?.epss ?? null, epssPercentile: fresh?.percentile ?? null };
  if (fresh && (stored.epss === null || fresh.epss > stored.epss)) return { epss: fresh.epss, epssPercentile: fresh.percentile };
  return { epss: stored.epss, epssPercentile: stored.epssPercentile };
}

/** Pure: one finding's fresh signals from the feeds, falling back to stored EPSS when its batch failed. */
export function computeFindingSignals(row: EnrichRow, src: SignalSources): FindingSignals {
  const cves = normalizeCves(row.advisory?.cves ?? []);
  // The advisory flag is authoritative; the MAL- prefix covers a finding whose advisory row is missing.
  const malicious = (row.advisory?.malicious ?? false) || row.osvId.startsWith('MAL-');
  const kevMatch = matchKev(cves, src.kevIndex);
  const { epss, epssPercentile } = resolveFindingEpss(cves, row, src.epss);

  const cvssScore = resolveCvssScore(row.advisory);
  const { priority, reasons } = computeBasePriority(
    {
      osvId: row.osvId,
      malicious,
      inKev: kevMatch.inKev,
      kevDateAdded: kevMatch.dateAdded,
      epss,
      cvss: cvssScore,
      exposure: row.exposure,
      criticality: row.criticality,
    },
    src.thresholds,
  );

  const escalation =
    row.enrichedAt === null
      ? []
      : detectEscalation(
          { priority: row.priority, inKev: row.inKev, epss: row.epss },
          { priority, inKev: kevMatch.inKev, epss },
          src.thresholds,
        );

  return {
    cves,
    malicious,
    inKev: kevMatch.inKev,
    kevDateAdded: kevMatch.dateAdded,
    epss,
    epssPercentile,
    cvssScore,
    priority,
    priorityReasons: reasons,
    escalation,
  };
}
