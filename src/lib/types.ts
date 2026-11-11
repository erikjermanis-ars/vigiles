/**
 * Shared domain types and zod schemas. Every module imports enums and JSON shapes from here
 * so the DB, jobs, policy engine and UI agree on one vocabulary.
 */
import { z } from 'zod';

// ---------- enums ----------
export const PRIORITIES = ['P0', 'P1', 'P2', 'P3'] as const;
export type Priority = (typeof PRIORITIES)[number];

export const ACTIONS = ['ping', 'digest', 'log'] as const;
export type Action = (typeof ACTIONS)[number];

export const VERDICTS = ['affected', 'likely_affected', 'likely_not_affected', 'not_affected'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const RUNTIME_USAGES = [
  'server',
  'browser',
  'server_and_browser',
  'build_or_tooling_only',
  'not_used',
  'unknown',
] as const;
export type RuntimeUsage = (typeof RUNTIME_USAGES)[number];

export const TRISTATE = ['yes', 'no', 'unknown'] as const;
export type Tristate = (typeof TRISTATE)[number];

export const AFFECTED_TRUTHS = ['yes', 'no', 'unsure'] as const;
export type AffectedTruth = (typeof AFFECTED_TRUTHS)[number];

export const FINDING_STATUSES = ['open', 'fixed', 'no_longer_matches'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const FINDING_ORIGINS = ['baseline', 'new_advisory', 'new_dependency'] as const;
export type FindingOrigin = (typeof FINDING_ORIGINS)[number];

export const EVENT_TYPES = [
  'created',
  'fixed',
  'reopened',
  'no_longer_matches',
  'advisory_changed',
  'escalated',
  'decision_changed',
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const JOB_STATUSES = ['queued', 'running', 'succeeded', 'failed', 'cancelled'] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

export const TRIAGE_RUN_STATUSES = ['ok', 'failed', 'invalid', 'timeout', 'cancelled'] as const;
export type TriageRunStatus = (typeof TRIAGE_RUN_STATUSES)[number];

/** Triage status of a finding as seen by the policy (§10). */
export const TRIAGE_STATUSES = ['ok', 'failed', 'pending', 'skipped'] as const;
export type TriageStatus = (typeof TRIAGE_STATUSES)[number];

export const EXPOSURES = ['internal', 'vpn', 'internet-facing'] as const;
export type Exposure = (typeof EXPOSURES)[number];

export const CRITICALITIES = ['low', 'medium', 'high'] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export const JOB_TYPES = ['noop', 'sync-osv', 'sync-kev', 'scan', 'enrich', 'triage', 'decide', 'refresh-all'] as const;
export type JobType = (typeof JOB_TYPES)[number];

/** Fixed remediation for a malicious package in a lockfile (spec §9.1); no LLM triage is needed. */
export const MALICIOUS_REMEDIATION =
  'Remove the package, reinstall from a clean state, and rotate every secret that was on the affected machines or in CI.';

// ---------- JSON shapes ----------

/** A file in the snapshot that imports a package (or the direct dependency that brings it in). */
export const ImportSiteSchema = z.object({
  file: z.string(),
  line: z.number().int().positive(),
  /** The module specifier that matched, e.g. 'zod' or 'next/image' */
  specifier: z.string(),
  /** Which package was searched for: the vulnerable package itself or the direct dependency it comes through */
  via: z.string(),
});
export type ImportSite = z.infer<typeof ImportSiteSchema>;

/** Dependency facts for one installed version of a finding's package (spec §7.3). */
export const FindingInstanceSchema = z.object({
  version: z.string(),
  /** null = unknown (flat ecosystems, unparsed lockfiles) */
  direct: z.boolean().nullable(),
  devOnly: z.boolean(),
  /** Up to 3 shortest chains from the root for this version */
  paths: z.array(z.array(z.string())),
});
export type FindingInstance = z.infer<typeof FindingInstanceSchema>;

/** Project profile: the parsed contents of projects/<id>.yaml (spec §14). */
export const ProjectProfileSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, 'kebab-case id'),
  name: z.string(),
  enabled: z.boolean().default(true),
  repo_path: z.string(),
  ref: z.string().default('origin/main'),
  fetch_before_scan: z.boolean().default(true),
  exclude: z.array(z.string()).default([]),
  /** Explicit lockfile list (repo-relative). When set, discovery is skipped. */
  lockfiles: z.array(z.string()).optional(),
  owners: z.array(z.string()).default([]),
  criticality: z.enum(CRITICALITIES),
  exposure: z.enum(EXPOSURES),
  data_classes: z.array(z.string()).default([]),
  runtime: z.record(z.string(), z.unknown()).default({}),
  deployments: z.array(z.record(z.string(), z.unknown())).default([]),
  third_party_services: z.array(z.string()).default([]),
  mitigations: z.string().default(''),
  notes: z.string().default(''),
});
export type ProjectProfile = z.infer<typeof ProjectProfileSchema>;

/** LLM triage output (spec §9.4). Mirrors prompts/triage/v1.schema.json. */
export const TriageOutputSchema = z.object({
  verdict: z.enum(VERDICTS),
  confidence: z.enum(CONFIDENCES),
  runtime_usage: z.enum(RUNTIME_USAGES),
  vulnerable_code_used: z.enum(TRISTATE),
  attacker_reachable: z.enum(TRISTATE),
  deployment_conditions_met: z.enum(TRISTATE),
  summary: z.string(),
  evidence: z.array(
    z.object({
      file: z.string(),
      line: z.number().int().nullable(),
      note: z.string(),
    }),
  ),
  exploit_conditions: z.string(),
  remediation: z.string(),
  workaround: z.string().nullable(),
  suggested_action: z.enum(ACTIONS),
  suggested_action_reason: z.string(),
});
export type TriageOutput = z.infer<typeof TriageOutputSchema>;

/** Everything a policy rule can look at (spec §10). Stored on each decision for traceability. */
export const DecisionInputsSchema = z.object({
  priority: z.enum(PRIORITIES).nullable(),
  malicious: z.boolean(),
  in_kev: z.boolean(),
  epss: z.number().nullable(),
  cvss: z.number().nullable(),
  exposure: z.enum(EXPOSURES),
  criticality: z.enum(CRITICALITIES),
  direct: z.boolean().nullable(),
  dev_only: z.boolean(),
  fix_available: z.boolean(),
  triage_status: z.enum(TRIAGE_STATUSES),
  verdict: z.enum(VERDICTS).nullable(),
  confidence: z.enum(CONFIDENCES).nullable(),
  runtime_usage: z.enum(RUNTIME_USAGES).nullable(),
  vulnerable_code_used: z.enum(TRISTATE).nullable(),
  attacker_reachable: z.enum(TRISTATE).nullable(),
  deployment_conditions_met: z.enum(TRISTATE).nullable(),
  suggested_action: z.enum(ACTIONS).nullable(),
});
export type DecisionInputs = z.infer<typeof DecisionInputsSchema>;
