import { z } from 'zod';
import { ACTIONS } from '../types';

// ---------- config/vigiles.yaml ----------
export const TriageConfigDefSchema = z.object({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  prompt_version: z.string(),
  model: z.string(),
  effort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']),
  code_access: z.boolean(),
});
export type TriageConfigDef = z.infer<typeof TriageConfigDefSchema>;

export const VigilesConfigSchema = z
  .object({
    data_dir: z.string().default('~/.vigiles'),
    bin: z
      .object({
        claude: z.string().default('claude'),
        osv_scanner: z.string().default('osv-scanner'),
        git: z.string().default('git'),
      })
      .prefault({}),
    osv: z
      .object({
        /** Ecosystems whose offline DB `sync-osv` keeps fresh, in addition to those detected from lockfiles */
        ecosystems: z.array(z.string()).default([]),
        base_url: z.string().default('https://osv-vulnerabilities.storage.googleapis.com'),
      })
      .prefault({}),
    triage: z.object({
      active_config: z.string(),
      min_priority: z.enum(['P0', 'P1', 'P2', 'P3']).default('P2'),
      max_per_run: z.number().int().positive().default(25),
      concurrency: z.number().int().positive().default(2),
      timeout_minutes: z.number().positive().default(10),
      max_budget_usd_per_run: z.number().positive().default(3),
      configs: z.array(TriageConfigDefSchema).min(1),
    }),
    staleness: z
      .object({
        osv_max_age_hours: z.number().default(24),
        refresh_max_age_days: z.number().default(7),
      })
      .prefault({}),
  })
  .superRefine((c, ctx) => {
    if (!c.triage.configs.some((x) => x.name === c.triage.active_config)) {
      ctx.addIssue({ code: 'custom', message: `triage.active_config "${c.triage.active_config}" is not in triage.configs` });
    }
  });
export type VigilesConfig = z.infer<typeof VigilesConfigSchema>;

// ---------- config/policy.yaml (spec §8, §10) ----------
const Scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);
const Range = z
  .object({ gte: z.number().optional(), lte: z.number().optional(), gt: z.number().optional(), lt: z.number().optional() })
  .strict();

/**
 * A rule condition: every key must match (AND).
 * - scalar value → equality
 * - array → any of
 * - {gte,lte,gt,lt} → numeric range (null input never matches a range)
 * - `not: Condition` → negation of a nested condition
 * - `{}` → always matches
 */
export type Condition = { [field: string]: unknown; not?: Condition };
export const ConditionSchema: z.ZodType<Condition> = z.lazy(() =>
  z.record(z.string(), z.union([Scalar, z.array(Scalar), Range, ConditionSchema])).superRefine((obj, ctx) => {
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'not') {
        if (typeof v !== 'object' || v === null || Array.isArray(v)) ctx.addIssue({ code: 'custom', message: '`not` must be a condition object' });
      }
    }
  }),
) as z.ZodType<Condition>;

export const PolicyRuleSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  when: ConditionSchema,
  then: z.enum(ACTIONS),
  note: z.string().optional(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  /**
   * Findings of the same advisory in the same project and lockfile (one problem on several packages, e.g. one
   * Sentry advisory on @sentry/node, @sentry/node-core and @sentry/nestjs) get the most urgent action any of them
   * received ('max'), so separate LLM runs on one problem never disagree. 'off' decides each finding alone.
   */
  same_advisory: z.enum(['max', 'off']).default('max'),
  thresholds: z.object({
    epss_high: z.number().min(0).max(1),
    epss_medium: z.number().min(0).max(1),
    cvss_critical: z.number().min(0).max(10),
    cvss_high: z.number().min(0).max(10),
  }),
  rules: z.array(PolicyRuleSchema).min(1),
});
export type Policy = z.infer<typeof PolicySchema>;
