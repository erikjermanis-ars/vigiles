/**
 * Decision policy engine (spec §10): an ordered rule list where the first matching rule wins.
 *
 * Condition semantics (see ConditionSchema in ../config/schema.ts): every key must match.
 *   field: scalar        strict equality, exactly as typed ('yes' never equals true)
 *   field: [a, b]        any of (strict equality per element)
 *   field: {gte,gt,lte,lt}  numeric range; a null input never matches
 *   not: {...}           negation of a nested condition
 *   {}                   always matches
 *
 * Evaluation is pure and fast. Call validatePolicyFields once per policy (at load time) so typos
 * fail loudly instead of silently never matching.
 */
import type { Condition, Policy, PolicyRule } from '../config/schema';
import { DecisionInputsSchema, type Action, type DecisionInputs } from '../types';

export interface PolicyDecision {
  action: Action;
  ruleId: string;
}

type Field = keyof DecisionInputs;
const FIELD_SCHEMAS = DecisionInputsSchema.shape;
const RANGE_KEYS = ['gte', 'gt', 'lte', 'lt'] as const;
type RangeKey = (typeof RANGE_KEYS)[number];
type Range = Partial<Record<RangeKey, number>>;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isField(key: string): key is Field {
  return Object.hasOwn(FIELD_SCHEMAS, key);
}

function isRange(v: Record<string, unknown>): v is Range {
  const keys = Object.keys(v);
  return keys.length > 0 && keys.every((k) => (RANGE_KEYS as readonly string[]).includes(k) && typeof v[k] === 'number');
}

function inRange(value: unknown, range: Range): boolean {
  if (typeof value !== 'number' || Number.isNaN(value)) return false;
  if (range.gte !== undefined && !(value >= range.gte)) return false;
  if (range.gt !== undefined && !(value > range.gt)) return false;
  if (range.lte !== undefined && !(value <= range.lte)) return false;
  if (range.lt !== undefined && !(value < range.lt)) return false;
  return true;
}

function matchesField(field: string, expected: unknown, inputs: DecisionInputs): boolean {
  // An unknown field would otherwise silently never match; validatePolicyFields reports it with context.
  if (!isField(field)) throw new Error(`policy references unknown field "${field}"`);
  const actual = inputs[field];
  if (Array.isArray(expected)) return expected.some((e) => e === actual);
  if (isPlainObject(expected)) {
    if (!isRange(expected)) throw new Error(`policy field "${field}" has an invalid range ${JSON.stringify(expected)}`);
    return inRange(actual, expected);
  }
  return expected === actual;
}

export function matchesCondition(condition: Condition, inputs: DecisionInputs): boolean {
  for (const [key, expected] of Object.entries(condition)) {
    if (key === 'not') {
      if (matchesCondition(expected as Condition, inputs)) return false;
    } else if (!matchesField(key, expected, inputs)) {
      return false;
    }
  }
  return true;
}

/** First matching rule wins. Throws when nothing matches (a valid policy ends with a `when: {}` catch-all). */
export function evaluatePolicy(policy: Policy, inputs: DecisionInputs): PolicyDecision {
  for (const rule of policy.rules) {
    if (matchesCondition(rule.when, inputs)) return { action: rule.then, ruleId: rule.id };
  }
  throw new Error('no policy rule matched; the policy must end with a catch-all rule (when: {})');
}

export interface RuleTrace {
  ruleId: string;
  action: Action;
  matched: boolean;
}

/** Every rule up to and including the winning one, with whether it matched (for the decision trace UI). */
export function traceRules(policy: Policy, inputs: DecisionInputs): RuleTrace[] {
  const out: RuleTrace[] = [];
  for (const rule of policy.rules) {
    const matched = matchesCondition(rule.when, inputs);
    out.push({ ruleId: rule.id, action: rule.then, matched });
    if (matched) break;
  }
  return out;
}

// ---------- validation ----------

function describe(v: unknown): string {
  return JSON.stringify(v);
}

function fieldValueProblem(field: Field, value: unknown): string | null {
  const parsed = FIELD_SCHEMAS[field].safeParse(value);
  if (parsed.success) return null;
  return `${describe(value)} is not a possible value (${parsed.error.issues[0]?.message ?? 'invalid'})`;
}

/** True when no number satisfies every bound, e.g. { gte: 0.5, lte: 0.1 } (swapped bounds). */
function isEmptyRange(r: Range): boolean {
  const lo = Math.max(r.gte ?? -Infinity, r.gt ?? -Infinity);
  const hi = Math.min(r.lte ?? Infinity, r.lt ?? Infinity);
  const loOpen = r.gt !== undefined && r.gt === lo;
  const hiOpen = r.lt !== undefined && r.lt === hi;
  return lo > hi || (lo === hi && (loOpen || hiOpen));
}

function conditionProblems(condition: Condition, at: string): string[] {
  const problems: string[] = [];
  for (const [key, expected] of Object.entries(condition)) {
    const here = `${at}.${key}`;
    if (key === 'not') {
      if (!isPlainObject(expected)) problems.push(`${here}: must be a condition object`);
      else if (Object.keys(expected).length === 0) problems.push(`${here}: not {} never matches, so the rule is unreachable`);
      else problems.push(...conditionProblems(expected as Condition, here));
      continue;
    }
    if (!isField(key)) {
      problems.push(`${here}: unknown field "${key}" (fields: ${Object.keys(FIELD_SCHEMAS).join(', ')})`);
      continue;
    }
    if (Array.isArray(expected)) {
      if (expected.length === 0) problems.push(`${here}: an empty list never matches`);
      expected.forEach((e, i) => {
        const p = fieldValueProblem(key, e);
        if (p) problems.push(`${here}[${i}]: ${p}`);
      });
    } else if (isPlainObject(expected)) {
      if (!isRange(expected)) {
        problems.push(`${here}: an object value must be a numeric range with at least one of ${RANGE_KEYS.join(', ')}`);
      } else if (!FIELD_SCHEMAS[key].safeParse(0).success) {
        problems.push(`${here}: a range is only valid on a numeric field`);
      } else if (isEmptyRange(expected)) {
        problems.push(`${here}: ${describe(expected)} contains no number, so it never matches`);
      }
    } else {
      const p = fieldValueProblem(key, expected);
      if (p) problems.push(`${here}: ${p}`);
    }
  }
  return problems;
}

function isCatchAll(rule: PolicyRule): boolean {
  return Object.keys(rule.when).length === 0;
}

/**
 * Throws if the policy could silently misbehave: a rule references a field that is not a decision input,
 * a value impossible for that field (e.g. verdict: 'afected', attacker_reachable: true), a malformed or empty
 * range, a `not: {}` (never matches), duplicate rule ids, a catch-all before the end (later rules unreachable), or no final catch-all.
 */
export function validatePolicyFields(policy: Policy): void {
  const problems: string[] = [];
  const seen = new Set<string>();
  policy.rules.forEach((rule, i) => {
    const at = `rules[${i}] (${rule.id})`;
    if (seen.has(rule.id)) problems.push(`${at}: duplicate rule id "${rule.id}"`);
    seen.add(rule.id);
    problems.push(...conditionProblems(rule.when, `${at}.when`));
    if (isCatchAll(rule) && i < policy.rules.length - 1) {
      problems.push(`${at}: matches everything, so the ${policy.rules.length - 1 - i} rule(s) after it are unreachable`);
    }
  });
  const last = policy.rules.at(-1);
  if (!last || !isCatchAll(last)) problems.push('the last rule must be a catch-all (when: {}) so every finding gets a decision');
  if (problems.length) throw new Error(`Invalid policy:\n${problems.map((p) => `  ${p}`).join('\n')}`);
}
