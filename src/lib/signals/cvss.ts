/** Numeric severity for base priority (spec §8). */

/** GHSA `database_specific.severity` label → representative score, used when no CVSS vector score exists. */
const LABEL_SCORES: Record<string, number> = {
  CRITICAL: 9.0,
  HIGH: 7.0,
  MODERATE: 4.0,
  MEDIUM: 4.0,
  LOW: 2.0,
};

export function severityLabelScore(label: string | null | undefined): number | null {
  if (!label) return null;
  return LABEL_SCORES[label.trim().toUpperCase()] ?? null;
}

/** advisories.cvss_score when present, else the severity label mapping, else null. */
export function resolveCvssScore(advisory: { cvssScore: number | null; severityLabel: string | null } | null): number | null {
  if (!advisory) return null;
  if (advisory.cvssScore !== null && Number.isFinite(advisory.cvssScore)) return advisory.cvssScore;
  return severityLabelScore(advisory.severityLabel);
}
