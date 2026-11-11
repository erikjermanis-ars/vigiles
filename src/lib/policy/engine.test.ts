import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { parsePolicy } from '../config/load';
import { PolicySchema } from '../config/schema';
import type { Policy } from '../config/schema';
import type { DecisionInputs } from '../types';
import { evaluatePolicy, matchesCondition, traceRules, validatePolicyFields } from './engine';

/** A P3 finding on an internal asset with no triage: every field set, overridden per scenario. */
function inputs(overrides: Partial<DecisionInputs> = {}): DecisionInputs {
  return {
    priority: 'P3',
    malicious: false,
    in_kev: false,
    epss: null,
    cvss: null,
    exposure: 'internal',
    criticality: 'medium',
    direct: false,
    dev_only: false,
    fix_available: true,
    triage_status: 'skipped',
    verdict: null,
    confidence: null,
    runtime_usage: null,
    vulnerable_code_used: null,
    attacker_reachable: null,
    deployment_conditions_met: null,
    suggested_action: null,
    ...overrides,
  };
}

/** Inputs for a successfully triaged finding. */
function triaged(overrides: Partial<DecisionInputs>): DecisionInputs {
  return inputs({
    triage_status: 'ok',
    verdict: 'affected',
    confidence: 'high',
    runtime_usage: 'server',
    vulnerable_code_used: 'yes',
    attacker_reachable: 'unknown',
    deployment_conditions_met: 'unknown',
    suggested_action: 'digest',
    ...overrides,
  });
}

/** Schema-parsed only (no validatePolicyFields), so engine-level checks can be tested directly. */
function policyOf(yamlRules: string): Policy {
  const yaml = `thresholds: { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9, cvss_high: 7 }\nrules:\n${yamlRules}`;
  return PolicySchema.parse(parseYaml(yaml));
}

describe('config/policy.yaml (the real file)', () => {
  const file = fileURLToPath(new URL('../../../config/policy.yaml', import.meta.url));
  const { policy } = parsePolicy(readFileSync(file, 'utf8'), file);
  const decide = (i: DecisionInputs) => evaluatePolicy(policy, i);

  it('passes validation', () => {
    expect(() => validatePolicyFields(policy)).not.toThrow();
  });

  it('pings a malicious package', () => {
    expect(decide(inputs({ priority: 'P0', malicious: true }))).toEqual({ action: 'ping', ruleId: 'malicious' });
  });

  it('pings a P0 whose triage is pending (fail loud)', () => {
    expect(decide(inputs({ priority: 'P0', in_kev: true, triage_status: 'pending' }))).toEqual({
      action: 'ping',
      ruleId: 'no-verdict-urgent',
    });
  });

  it('pings a P1 whose triage failed', () => {
    expect(decide(inputs({ priority: 'P1', triage_status: 'failed' }))).toEqual({ action: 'ping', ruleId: 'no-verdict-urgent' });
  });

  it('digests a P0 the LLM is highly confident is not affected', () => {
    expect(decide(triaged({ priority: 'P0', verdict: 'not_affected', confidence: 'high' }))).toEqual({
      action: 'digest',
      ruleId: 'p0-not-affected',
    });
  });

  it('still pings a P0 judged not affected with only medium confidence', () => {
    expect(decide(triaged({ priority: 'P0', verdict: 'not_affected', confidence: 'medium' }))).toEqual({
      action: 'ping',
      ruleId: 'p0-unless-clearly-not',
    });
  });

  // Scenarios from the 2026-11-11 labeling round (policy v2 + the owner's rubric).
  it('logs a P1 that is verifiably not affected when the LLM also suggests log (Next.js Windows-only RCE on Linux)', () => {
    const nextWindowsRce = triaged({
      priority: 'P1',
      cvss: 9.8,
      exposure: 'internet-facing',
      criticality: 'high',
      direct: true,
      verdict: 'not_affected',
      confidence: 'high',
      deployment_conditions_met: 'no',
      suggested_action: 'log',
    });
    expect(decide(nextWindowsRce)).toEqual({ action: 'log', ruleId: 'p1-clearly-not-affected' });
  });

  it('keeps a not-affected P1 in the digest when confidence is only medium, or the LLM suggests digest', () => {
    expect(decide(triaged({ priority: 'P1', verdict: 'not_affected', confidence: 'medium', suggested_action: 'log' }))).toEqual({
      action: 'digest',
      ruleId: 'p1-floor',
    });
    // Storybook dev-server flaw: production unaffected, developer machines at risk (rubric ruling 1).
    const storybook = triaged({
      priority: 'P1',
      runtime_usage: 'build_or_tooling_only',
      verdict: 'not_affected',
      confidence: 'high',
      suggested_action: 'digest',
    });
    expect(decide(storybook)).toEqual({ action: 'digest', ruleId: 'p1-floor' });
  });

  it('keeps an affected P1 the LLM rates digest (e.g. a reachable DoS) in the digest, never lower', () => {
    expect(decide(triaged({ priority: 'P1', verdict: 'likely_affected', confidence: 'medium', suggested_action: 'digest' }))).toEqual({
      action: 'digest',
      ruleId: 'p1-floor',
    });
    expect(decide(triaged({ priority: 'P1', verdict: 'affected', suggested_action: 'log' }))).toEqual({ action: 'digest', ruleId: 'p1-floor' });
  });

  it('pings when the LLM suggests ping and the verdict backs it, at any priority', () => {
    for (const priority of ['P1', 'P2'] as const) {
      expect(decide(triaged({ priority, verdict: 'likely_affected', confidence: 'medium', suggested_action: 'ping' }))).toEqual({
        action: 'ping',
        ruleId: 'llm-ping',
      });
    }
  });

  it('does not ping on a ping suggestion the verdict does not back', () => {
    const i = triaged({ priority: 'P2', verdict: 'likely_not_affected', confidence: 'medium', suggested_action: 'ping' });
    expect(decide(i)).toEqual({ action: 'log', ruleId: 'default' });
  });

  it('parsePolicy rejects typos at load time', () => {
    const bad = `thresholds: { epss_high: 0.5, epss_medium: 0.1, cvss_critical: 9, cvss_high: 7 }
rules:
  - { id: a, when: { verdict: afected }, then: ping }
  - { id: default, when: {}, then: log }`;
    expect(() => parsePolicy(bad)).toThrow(/afected/);
  });

  it('digests a reachable P2 the LLM rates digest (e.g. an authenticated DoS)', () => {
    const zod = triaged({ priority: 'P2', verdict: 'likely_affected', confidence: 'medium', attacker_reachable: 'yes', suggested_action: 'digest' });
    expect(decide(zod)).toEqual({ action: 'digest', ruleId: 'llm-digest' });
  });

  it('digests a tooling-only P2 when the LLM flags developer-machine risk (rubric ruling 1)', () => {
    const viteDevServer = triaged({ priority: 'P2', runtime_usage: 'build_or_tooling_only', verdict: 'not_affected', suggested_action: 'digest' });
    expect(decide(viteDevServer)).toEqual({ action: 'digest', ruleId: 'llm-digest' });
  });

  it('logs a P2 used only by build tooling, not affected, with no developer-machine risk', () => {
    const i = triaged({ priority: 'P2', runtime_usage: 'build_or_tooling_only', verdict: 'not_affected', dev_only: true, suggested_action: 'log' });
    expect(decide(i)).toEqual({ action: 'log', ruleId: 'tooling-only' });
  });

  it('keeps an affected P2 in the digest even if the LLM suggests log', () => {
    expect(decide(triaged({ priority: 'P2', verdict: 'affected', suggested_action: 'log' }))).toEqual({ action: 'digest', ruleId: 'p2-affected' });
  });

  it('logs a P2 whose triage was skipped', () => {
    expect(decide(inputs({ priority: 'P2', triage_status: 'skipped' }))).toEqual({ action: 'log', ruleId: 'default' });
  });

  it('digests a P2 whose triage is still pending or failed (never silently logged)', () => {
    expect(decide(inputs({ priority: 'P2', triage_status: 'pending' }))).toEqual({ action: 'digest', ruleId: 'no-verdict-p2' });
    expect(decide(inputs({ priority: 'P2', triage_status: 'failed' }))).toEqual({ action: 'digest', ruleId: 'no-verdict-p2' });
  });

  it('logs a P3', () => {
    expect(decide(inputs({ priority: 'P3' }))).toEqual({ action: 'log', ruleId: 'default' });
  });

  it('logs a finding that has not been enriched yet (no priority)', () => {
    expect(decide(inputs({ priority: null, triage_status: 'pending' }))).toEqual({ action: 'log', ruleId: 'default' });
  });
});

describe('condition semantics', () => {
  it('{} always matches', () => {
    expect(matchesCondition({}, inputs())).toBe(true);
  });

  it('scalar equality is strict: the string "yes" never equals true', () => {
    expect(matchesCondition({ attacker_reachable: 'yes' }, inputs({ attacker_reachable: 'yes' }))).toBe(true);
    expect(matchesCondition({ attacker_reachable: true }, inputs({ attacker_reachable: 'yes' }))).toBe(false);
    expect(matchesCondition({ malicious: 'true' }, inputs({ malicious: true }))).toBe(false);
    expect(matchesCondition({ cvss: 9.8 }, inputs({ cvss: 9.8 }))).toBe(true);
  });

  it('null equality matches only null', () => {
    expect(matchesCondition({ verdict: null }, inputs())).toBe(true);
    expect(matchesCondition({ verdict: null }, triaged({}))).toBe(false);
    expect(matchesCondition({ direct: false }, inputs({ direct: null }))).toBe(false);
  });

  it('a list matches any of its values, including booleans and null', () => {
    const cond = { direct: [true, null] };
    expect(matchesCondition(cond, inputs({ direct: true }))).toBe(true);
    expect(matchesCondition(cond, inputs({ direct: null }))).toBe(true);
    expect(matchesCondition(cond, inputs({ direct: false }))).toBe(false);
  });

  it('every key must match (AND)', () => {
    const cond = { priority: 'P1', in_kev: true };
    expect(matchesCondition(cond, inputs({ priority: 'P1', in_kev: true }))).toBe(true);
    expect(matchesCondition(cond, inputs({ priority: 'P1', in_kev: false }))).toBe(false);
  });

  it('ranges are inclusive (gte/lte) or exclusive (gt/lt) and never match null', () => {
    expect(matchesCondition({ epss: { gte: 0.5 } }, inputs({ epss: 0.5 }))).toBe(true);
    expect(matchesCondition({ epss: { gt: 0.5 } }, inputs({ epss: 0.5 }))).toBe(false);
    expect(matchesCondition({ epss: { gte: 0.1, lt: 0.5 } }, inputs({ epss: 0.3 }))).toBe(true);
    expect(matchesCondition({ epss: { gte: 0.1, lt: 0.5 } }, inputs({ epss: 0.5 }))).toBe(false);
    expect(matchesCondition({ cvss: { lte: 4 } }, inputs({ cvss: 4 }))).toBe(true);
    expect(matchesCondition({ cvss: { lte: 4 } }, inputs({ cvss: null }))).toBe(false);
    expect(matchesCondition({ cvss: { gte: 0 } }, inputs({ cvss: null }))).toBe(false);
  });

  it('not negates a nested condition (all of its keys)', () => {
    const cond = { priority: 'P0', not: { verdict: 'not_affected', confidence: 'high' } };
    expect(matchesCondition(cond, triaged({ priority: 'P0', verdict: 'not_affected', confidence: 'high' }))).toBe(false);
    expect(matchesCondition(cond, triaged({ priority: 'P0', verdict: 'not_affected', confidence: 'low' }))).toBe(true);
    expect(matchesCondition(cond, inputs({ priority: 'P0' }))).toBe(true);
  });

  it('a range inside not matches null inputs (null is "not in range")', () => {
    expect(matchesCondition({ not: { epss: { gte: 0.1 } } }, inputs({ epss: null }))).toBe(true);
    expect(matchesCondition({ not: { epss: { gte: 0.1 } } }, inputs({ epss: 0.2 }))).toBe(false);
  });

  it('nested not', () => {
    expect(matchesCondition({ not: { not: { in_kev: true } } }, inputs({ in_kev: true }))).toBe(true);
    expect(matchesCondition({ not: { not: { in_kev: true } } }, inputs({ in_kev: false }))).toBe(false);
  });

  it('throws on an unknown field instead of silently not matching', () => {
    expect(() => matchesCondition({ verdcit: 'affected' }, inputs())).toThrow(/unknown field "verdcit"/);
  });
});

describe('evaluatePolicy', () => {
  it('returns the first matching rule', () => {
    const policy = policyOf(`
  - { id: kev, when: { in_kev: true }, then: ping }
  - { id: kev-again, when: { in_kev: true }, then: digest }
  - { id: default, when: {}, then: log }`);
    expect(evaluatePolicy(policy, inputs({ in_kev: true }))).toEqual({ action: 'ping', ruleId: 'kev' });
    expect(evaluatePolicy(policy, inputs())).toEqual({ action: 'log', ruleId: 'default' });
  });

  it('throws when no rule matches', () => {
    const policy = policyOf(`
  - { id: kev, when: { in_kev: true }, then: ping }`);
    expect(() => evaluatePolicy(policy, inputs())).toThrow(/no policy rule matched/);
  });

  it('traceRules lists the rules tried up to the winner', () => {
    const policy = policyOf(`
  - { id: kev, when: { in_kev: true }, then: ping }
  - { id: p3, when: { priority: P3 }, then: log }
  - { id: default, when: {}, then: digest }`);
    expect(traceRules(policy, inputs())).toEqual([
      { ruleId: 'kev', action: 'ping', matched: false },
      { ruleId: 'p3', action: 'log', matched: true },
    ]);
  });
});

describe('validatePolicyFields', () => {
  const valid = (rules: string) => () => validatePolicyFields(policyOf(rules));
  const catchAll = `\n  - { id: default, when: {}, then: log }`;

  it('accepts every condition form on the right field types', () => {
    expect(
      valid(`
  - { id: a, when: { priority: [P0, P1], malicious: true, epss: { gte: 0.5 }, cvss: 9.8 }, then: ping }
  - { id: b, when: { direct: [true, null], not: { verdict: not_affected, confidence: high } }, then: digest }
  - { id: c, when: { attacker_reachable: 'yes', triage_status: [pending, failed], suggested_action: ping }, then: ping }${catchAll}`),
    ).not.toThrow();
  });

  it('accepts the spec’s unquoted `attacker_reachable: yes` (YAML 1.2 reads it as the string)', () => {
    const policy = policyOf(`\n  - { id: a, when: { attacker_reachable: yes, vulnerable_code_used: no }, then: ping }${catchAll}`);
    expect(() => validatePolicyFields(policy)).not.toThrow();
    expect(evaluatePolicy(policy, triaged({ attacker_reachable: 'yes', vulnerable_code_used: 'no' })).ruleId).toBe('a');
  });

  it('rejects an unknown field', () => {
    expect(valid(`\n  - { id: a, when: { verdcit: affected }, then: ping }${catchAll}`)).toThrow(
      /rules\[0\] \(a\)\.when\.verdcit: unknown field/,
    );
  });

  it('rejects an unknown field inside not', () => {
    expect(valid(`\n  - { id: a, when: { not: { confidance: high } }, then: ping }${catchAll}`)).toThrow(
      /when\.not\.confidance: unknown field/,
    );
  });

  it('rejects a value impossible for an enum field', () => {
    expect(valid(`\n  - { id: a, when: { verdict: afected }, then: ping }${catchAll}`)).toThrow(
      /when\.verdict: "afected" is not a possible value/,
    );
  });

  it('rejects an impossible value inside a list', () => {
    expect(valid(`\n  - { id: a, when: { priority: [P0, P4] }, then: ping }${catchAll}`)).toThrow(/when\.priority\[1\]: "P4"/);
  });

  it('rejects a boolean on a yes/no/unknown field (YAML `true` is not the string "yes")', () => {
    expect(valid(`\n  - { id: a, when: { attacker_reachable: true }, then: ping }${catchAll}`)).toThrow(
      /attacker_reachable: true is not a possible value/,
    );
  });

  it('rejects a string on a boolean field', () => {
    expect(valid(`\n  - { id: a, when: { in_kev: 'yes' }, then: ping }${catchAll}`)).toThrow(/in_kev: "yes" is not a possible value/);
  });

  it('rejects null on a non-nullable field', () => {
    expect(valid(`\n  - { id: a, when: { malicious: null }, then: ping }${catchAll}`)).toThrow(/malicious: null/);
  });

  it('rejects a range on a non-numeric field and a malformed range', () => {
    expect(valid(`\n  - { id: a, when: { priority: { gte: 1 } }, then: ping }${catchAll}`)).toThrow(/only valid on a numeric field/);
    expect(valid(`\n  - { id: a, when: { epss: { gte: high } }, then: ping }${catchAll}`)).toThrow(/must be a numeric range/);
    expect(valid(`\n  - { id: a, when: { epss: {} }, then: ping }${catchAll}`)).toThrow(/must be a numeric range/);
  });

  it('rejects a range no number can satisfy (e.g. swapped bounds)', () => {
    expect(valid(`\n  - { id: a, when: { epss: { gte: 0.5, lte: 0.1 } }, then: ping }${catchAll}`)).toThrow(/contains no number/);
    expect(valid(`\n  - { id: a, when: { cvss: { gt: 7, lte: 7 } }, then: ping }${catchAll}`)).toThrow(/contains no number/);
    expect(valid(`\n  - { id: a, when: { cvss: { gte: 7, lt: 7 } }, then: ping }${catchAll}`)).toThrow(/contains no number/);
    expect(valid(`\n  - { id: a, when: { cvss: { gte: 7, lte: 7 } }, then: ping }${catchAll}`)).not.toThrow();
    expect(valid(`\n  - { id: a, when: { epss: { gt: 0.1, gte: 0.2, lt: 0.5 } }, then: ping }${catchAll}`)).not.toThrow();
  });

  it('rejects not: {} (it never matches, so the rule is dead)', () => {
    expect(valid(`\n  - { id: a, when: { in_kev: true, not: {} }, then: ping }${catchAll}`)).toThrow(/not \{\} never matches/);
  });

  it('rejects an empty any-of list', () => {
    expect(valid(`\n  - { id: a, when: { verdict: [] }, then: ping }${catchAll}`)).toThrow(/empty list never matches/);
  });

  it('requires a final catch-all', () => {
    expect(valid(`\n  - { id: a, when: { in_kev: true }, then: ping }`)).toThrow(/last rule must be a catch-all/);
  });

  it('rejects a catch-all before the end (unreachable rules)', () => {
    expect(valid(`\n  - { id: early, when: {}, then: ping }\n  - { id: a, when: { in_kev: true }, then: ping }${catchAll}`)).toThrow(
      /rules\[0\] \(early\): matches everything, so the 2 rule\(s\) after it are unreachable/,
    );
  });

  it('rejects duplicate rule ids', () => {
    expect(
      valid(`\n  - { id: a, when: { in_kev: true }, then: ping }\n  - { id: a, when: { malicious: true }, then: ping }${catchAll}`),
    ).toThrow(/duplicate rule id "a"/);
  });

  it('reports every problem at once', () => {
    try {
      validatePolicyFields(policyOf(`\n  - { id: a, when: { verdict: afected, foo: 1 }, then: ping }`));
      expect.unreachable();
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toMatch(/afected/);
      expect(msg).toMatch(/unknown field "foo"/);
      expect(msg).toMatch(/catch-all/);
    }
  });
});
