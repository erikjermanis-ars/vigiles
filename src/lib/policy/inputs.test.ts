import { describe, expect, it } from 'vitest';
import type { triageRuns } from '../db/schema';
import type { TriageOutput } from '../types';
import {
  awaitingEnrichment,
  buildDecisionInputs,
  isMalicious,
  priorityUnderPolicy,
  type DecisionFinding,
  type PrioritySignals,
} from './inputs';

type TriageRunRow = typeof triageRuns.$inferSelect;

const finding: DecisionFinding = {
  osvId: 'GHSA-aaaa-bbbb-cccc',
  priority: 'P1',
  inKev: true,
  epss: 0.42,
  cvssScore: 9.8,
  direct: null,
  devOnly: true,
  fixedVersions: ['1.2.3'],
};
const profile = { exposure: 'internet-facing', criticality: 'high' } as const;

const output: TriageOutput = {
  verdict: 'likely_not_affected',
  confidence: 'medium',
  runtime_usage: 'browser',
  vulnerable_code_used: 'no',
  attacker_reachable: 'unknown',
  deployment_conditions_met: 'yes',
  summary: 's',
  evidence: [],
  exploit_conditions: 'e',
  remediation: 'r',
  workaround: null,
  suggested_action: 'digest',
  suggested_action_reason: 'why',
};

function run(over: Partial<TriageRunRow> = {}): TriageRunRow {
  return { id: 7, status: 'ok', output, ...over } as TriageRunRow;
}

describe('buildDecisionInputs', () => {
  it('copies signals and the project profile', () => {
    const i = buildDecisionInputs(finding, profile, { malicious: false }, { status: 'pending', run: null });
    expect(i).toMatchObject({
      priority: 'P1',
      malicious: false,
      in_kev: true,
      epss: 0.42,
      cvss: 9.8,
      exposure: 'internet-facing',
      criticality: 'high',
      direct: null,
      dev_only: true,
      fix_available: true,
      triage_status: 'pending',
    });
  });

  it('fix_available is false without fixed versions', () => {
    const i = buildDecisionInputs({ ...finding, fixedVersions: [] }, profile, null, { status: 'pending', run: null });
    expect(i.fix_available).toBe(false);
  });

  it('uses the triage output only when the status is ok', () => {
    const ok = buildDecisionInputs(finding, profile, null, { status: 'ok', run: run() });
    expect(ok).toMatchObject({
      triage_status: 'ok',
      verdict: 'likely_not_affected',
      confidence: 'medium',
      runtime_usage: 'browser',
      vulnerable_code_used: 'no',
      attacker_reachable: 'unknown',
      deployment_conditions_met: 'yes',
      suggested_action: 'digest',
    });

    const failed = buildDecisionInputs(finding, profile, null, { status: 'failed', run: run({ status: 'invalid' }) });
    expect(failed.triage_status).toBe('failed');
    for (const k of [
      'verdict',
      'confidence',
      'runtime_usage',
      'vulnerable_code_used',
      'attacker_reachable',
      'deployment_conditions_met',
      'suggested_action',
    ] as const) {
      expect(failed[k]).toBeNull();
    }
  });

  it('treats an ok run without stored output as failed', () => {
    const i = buildDecisionInputs(finding, profile, null, { status: 'ok', run: run({ output: null }) });
    expect(i.triage_status).toBe('failed');
    expect(i.verdict).toBeNull();
  });

  it('marks malicious from the advisory flag or the MAL- prefix', () => {
    const skipped = { status: 'skipped', run: null } as const;
    expect(buildDecisionInputs(finding, profile, { malicious: true }, skipped).malicious).toBe(true);
    expect(buildDecisionInputs({ ...finding, osvId: 'MAL-2025-1234' }, profile, undefined, skipped).malicious).toBe(true);
    expect(buildDecisionInputs(finding, profile, undefined, skipped).malicious).toBe(false);
  });

  it('isMalicious: advisory flag or MAL- prefix', () => {
    expect(isMalicious({ osvId: 'GHSA-x' }, { malicious: true })).toBe(true);
    expect(isMalicious({ osvId: 'MAL-2025-1' }, null)).toBe(true);
    expect(isMalicious({ osvId: 'GHSA-x' }, { malicious: false })).toBe(false);
  });

  it('produces inputs the schema accepts', async () => {
    const { DecisionInputsSchema } = await import('../types');
    expect(() => DecisionInputsSchema.parse(buildDecisionInputs(finding, profile, null, { status: 'ok', run: run() }))).not.toThrow();
  });
});

describe('priorityUnderPolicy', () => {
  const thresholds = { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9, cvss_high: 7 };
  const internal = { exposure: 'internal', criticality: 'low' } as const;
  const enriched: PrioritySignals = {
    osvId: 'GHSA-aaaa-bbbb-cccc',
    priority: 'P2',
    enrichedAt: '2026-11-01T00:00:00.000Z',
    inKev: false,
    kevDateAdded: null,
    epss: 0.3,
    cvssScore: 5,
  };

  it('matches what enrich stored when the thresholds are the same', () => {
    expect(priorityUnderPolicy(enriched, internal, false, thresholds)).toBe('P2');
  });

  it("follows the evaluated policy's thresholds, not the ones enrich used", () => {
    expect(priorityUnderPolicy(enriched, internal, false, { ...thresholds, epss_high: 0.25 })).toBe('P1');
    expect(priorityUnderPolicy(enriched, internal, false, { ...thresholds, epss_medium: 0.4 })).toBe('P3');
  });

  it('uses the current project profile (KEV on an internet-facing asset is P0)', () => {
    const kev = { ...enriched, inKev: true, priority: 'P1' as const };
    expect(priorityUnderPolicy(kev, internal, false, thresholds)).toBe('P1');
    expect(priorityUnderPolicy(kev, { exposure: 'internet-facing', criticality: 'low' }, false, thresholds)).toBe('P0');
  });

  it('a malicious package is P0 whatever its signals', () => {
    expect(priorityUnderPolicy({ ...enriched, epss: null, cvssScore: null }, internal, true, thresholds)).toBe('P0');
  });

  it('keeps the stored priority of a finding enrich has not scored yet', () => {
    expect(priorityUnderPolicy({ ...enriched, enrichedAt: null, priority: null }, internal, false, thresholds)).toBeNull();
  });
});

describe('awaitingEnrichment', () => {
  it('is true only for a finding enrich has not scored that is not a malicious package', () => {
    const at = '2026-11-10T10:00:00.000Z';
    expect(awaitingEnrichment({ osvId: 'GHSA-1', enrichedAt: null }, { malicious: false })).toBe(true);
    expect(awaitingEnrichment({ osvId: 'GHSA-1', enrichedAt: null }, undefined)).toBe(true);
    expect(awaitingEnrichment({ osvId: 'GHSA-1', enrichedAt: at }, { malicious: false })).toBe(false);
    expect(awaitingEnrichment({ osvId: 'GHSA-1', enrichedAt: null }, { malicious: true })).toBe(false);
    expect(awaitingEnrichment({ osvId: 'MAL-2026-1', enrichedAt: null }, undefined)).toBe(false);
  });
});
