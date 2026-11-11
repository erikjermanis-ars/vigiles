/** Builds the facts a policy rule can look at (spec §10) from a finding, its project and its triage state. */
import type { Policy } from '../config/schema';
import type { advisories, findings } from '../db/schema';
import { computeBasePriority } from '../signals/priority';
import type { TriageState } from '../triage/state';
import type { DecisionInputs, Priority, ProjectProfile } from '../types';

type FindingRow = typeof findings.$inferSelect;
type AdvisoryRow = typeof advisories.$inferSelect;

export type DecisionFinding = Pick<
  FindingRow,
  'osvId' | 'priority' | 'inKev' | 'epss' | 'cvssScore' | 'direct' | 'devOnly' | 'fixedVersions'
>;

export type PrioritySignals = Pick<FindingRow, 'osvId' | 'priority' | 'enrichedAt' | 'inKev' | 'kevDateAdded' | 'epss' | 'cvssScore'>;

/** `advisory` may be missing (not synced yet); the MAL- prefix then still marks a malicious package (§8). */
export function isMalicious(finding: Pick<FindingRow, 'osvId'>, advisory: Pick<AdvisoryRow, 'malicious'> | null | undefined): boolean {
  return Boolean(advisory?.malicious) || finding.osvId.startsWith('MAL-');
}

/**
 * A finding enrich has not scored yet has no base priority, so the rules (which mostly key on priority) would
 * send it to `default`. decide leaves it undecided instead. A malicious package needs no signals (rule
 * `malicious` pings it either way).
 */
export function awaitingEnrichment(
  finding: Pick<FindingRow, 'osvId' | 'enrichedAt'>,
  advisory: Pick<AdvisoryRow, 'malicious'> | null | undefined,
): boolean {
  return finding.enrichedAt === null && !isMalicious(finding, advisory);
}

/**
 * Base priority under the evaluated policy's own thresholds (§8: they live in policy.yaml), recomputed from
 * the signals `enrich` stored. Without this, editing a threshold and re-evaluating would change nothing until
 * the next enrich, and the Eval page would compare policy versions using another version's thresholds.
 * A finding enrich has not scored yet keeps its stored priority (null): no signals means no tier
 * (decideAll only evaluates such a finding when it is malicious; see awaitingEnrichment).
 */
export function priorityUnderPolicy(
  finding: PrioritySignals,
  profile: Pick<ProjectProfile, 'exposure' | 'criticality'>,
  malicious: boolean,
  thresholds: Policy['thresholds'],
): Priority | null {
  if (finding.enrichedAt === null) return finding.priority;
  return computeBasePriority(
    {
      osvId: finding.osvId,
      malicious,
      inKev: finding.inKev,
      kevDateAdded: finding.kevDateAdded,
      epss: finding.epss,
      cvss: finding.cvssScore,
      exposure: profile.exposure,
      criticality: profile.criticality,
    },
    thresholds,
  ).priority;
}

/**
 * `finding.priority` is used as given: pass the priority under the evaluated policy (priorityUnderPolicy).
 * Triage fields are null unless the triage status is ok, so a failed or stale run can never lend its verdict.
 */
export function buildDecisionInputs(
  finding: DecisionFinding,
  profile: Pick<ProjectProfile, 'exposure' | 'criticality'>,
  advisory: Pick<AdvisoryRow, 'malicious'> | null | undefined,
  triage: Pick<TriageState, 'status' | 'run'>,
): DecisionInputs {
  const output = triage.status === 'ok' ? (triage.run?.output ?? null) : null;
  // An ok run without stored output is unusable; report it as failed so P0/P1 still fail loud.
  const triageStatus = triage.status === 'ok' && !output ? 'failed' : triage.status;
  return {
    priority: finding.priority,
    malicious: isMalicious(finding, advisory),
    in_kev: finding.inKev,
    epss: finding.epss,
    cvss: finding.cvssScore,
    exposure: profile.exposure,
    criticality: profile.criticality,
    direct: finding.direct,
    dev_only: finding.devOnly,
    fix_available: finding.fixedVersions.length > 0,
    triage_status: triageStatus,
    verdict: output?.verdict ?? null,
    confidence: output?.confidence ?? null,
    runtime_usage: output?.runtime_usage ?? null,
    vulnerable_code_used: output?.vulnerable_code_used ?? null,
    attacker_reachable: output?.attacker_reachable ?? null,
    deployment_conditions_met: output?.deployment_conditions_met ?? null,
    suggested_action: output?.suggested_action ?? null,
  };
}
