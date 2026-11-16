/**
 * Applies the decision policy to the last scan (src/lib/policy/decide.ts decideAll, without the DB): the same
 * base priority under the policy's thresholds, the same decision inputs, the same rule engine and the same
 * `same_advisory: max` step. Verdicts come from `.vigiles/verdicts.json` instead of triage_runs.
 */
import type { LoadedPolicy } from '../lib/config/load';
import { evaluatePolicy } from '../lib/policy/engine';
import { buildDecisionInputs } from '../lib/policy/inputs';
import { raiseToSameAdvisoryMax } from '../lib/policy/same-advisory';
import { computeBasePriority } from '../lib/signals/priority';
import type { Action, TriageStatus } from '../lib/types';
import { isMaliciousFinding } from './triage';
import type { DecidedFinding, Decisions, PluginProfile, ScanFinding, ScanResult, StoredVerdict, TriageFailures } from './types';
import type { VerdictStore } from './verdicts';

interface Triage {
  status: TriageStatus;
  verdict: StoredVerdict | null;
  failure: string | null;
}

/**
 * The POC's triage state (src/lib/triage/state.ts resolveTriageState) from files: malicious → skipped (never
 * triaged); a verdict for the current inputs → ok; the last triage of these inputs failed → failed; else pending.
 */
export function triageStateOf(f: ScanFinding, malicious: boolean, verdicts: VerdictStore, failures: TriageFailures): Triage {
  if (malicious) return { status: 'skipped', verdict: null, failure: null };
  const verdict = verdicts.current(f);
  if (verdict) return { status: 'ok', verdict, failure: null };
  const failure = failures[f.id];
  if (failure && failure.inputHash === f.inputHash) return { status: 'failed', verdict: null, failure: failure.error };
  return { status: 'pending', verdict: null, failure: null };
}

export function decide(
  scan: ScanResult,
  verdicts: VerdictStore,
  failures: TriageFailures,
  policy: LoadedPolicy,
  profile: PluginProfile,
): Decisions {
  const decided: DecidedFinding[] = [];
  for (const stored of scan.findings) {
    const advisory = scan.advisories[stored.osvId] ?? null;
    const malicious = isMaliciousFinding(stored, advisory);
    // Base priority under the evaluated policy's thresholds and the current profile (policy/inputs.ts
    // priorityUnderPolicy); the same as the scan's unless the policy or the profile changed since.
    const base = computeBasePriority(
      {
        osvId: stored.osvId,
        malicious,
        inKev: stored.inKev,
        kevDateAdded: stored.kevDateAdded,
        epss: stored.epss,
        cvss: stored.cvssScore,
        exposure: profile.exposure,
        criticality: profile.criticality,
      },
      policy.policy.thresholds,
    );
    const finding: ScanFinding =
      base.priority === stored.priority ? stored : { ...stored, priority: base.priority, priorityReasons: base.reasons };
    const triage = triageStateOf(finding, malicious, verdicts, failures);
    const inputs = buildDecisionInputs(
      finding,
      profile,
      { malicious },
      {
        status: triage.status,
        run: triage.verdict ? { output: triage.verdict.output } : null,
      },
    );
    const { action, ruleId } = evaluatePolicy(policy.policy, inputs);
    decided.push({
      finding,
      advisory,
      triageStatus: triage.status,
      verdict: triage.verdict,
      failure: triage.failure,
      action,
      ruleId,
      inputs,
    });
  }

  if (policy.policy.same_advisory === 'max') {
    const rows = decided.map((d) => ({
      finding: { projectId: profile.id, lockfile: d.finding.lockfile, osvId: d.finding.osvId },
      action: d.action,
      ruleId: d.ruleId,
      decided: d,
    }));
    raiseToSameAdvisoryMax(rows);
    for (const r of rows) {
      r.decided.action = r.action;
      r.decided.ruleId = r.ruleId;
    }
  }

  const counts: Record<Action, number> & { untriaged: number } = { ping: 0, digest: 0, log: 0, untriaged: 0 };
  for (const d of decided) {
    counts[d.action]++;
    if (d.triageStatus === 'pending' || d.triageStatus === 'failed') counts.untriaged++;
  }
  return { policyHash: policy.hash, findings: decided, counts };
}
