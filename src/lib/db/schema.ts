/**
 * Vigiles database schema (SQLite via Drizzle). See docs/poc-spec.md §13.
 *
 * Conventions
 * - Timestamps are ISO-8601 strings (`new Date().toISOString()`), stored as text.
 * - JSON columns use `text(..., { mode: 'json' })` and are typed with `$type<>()`.
 *   Validate external JSON with the zod schemas in `src/lib/types.ts` before writing.
 * - Booleans use `integer(..., { mode: 'boolean' })`.
 * - Keep it portable to Postgres: no SQLite-only features beyond what Drizzle abstracts.
 */
import { sql } from 'drizzle-orm';
import { index, integer, primaryKey, real, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';
import type {
  Action,
  AffectedTruth,
  DecisionInputs,
  EventType,
  FindingInstance,
  FindingOrigin,
  OwnerBrief,
  OwnerCaseStatus,
  FindingStatus,
  ImportSite,
  JobStatus,
  Priority,
  ProjectProfile,
  TriageOutput,
  TriageRunStatus,
} from '../types';

const now = sql`(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`;

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey(), // slug from projects/<id>.yaml
  name: text('name').notNull(),
  enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
  repoPath: text('repo_path').notNull(),
  ref: text('ref').notNull(),
  profile: text('profile', { mode: 'json' }).$type<ProjectProfile>().notNull(),
  profileHash: text('profile_hash').notNull(),
  /** Hash of only the profile fields the triage prompt shows (spec §9.1 input hash); scanner-only keys excluded */
  triageProfileHash: text('triage_profile_hash').notNull().default(''),
  lastScanId: integer('last_scan_id'),
  updatedAt: text('updated_at').notNull().default(now),
});

export const jobRuns = sqliteTable(
  'job_runs',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    type: text('type').notNull(),
    params: text('params', { mode: 'json' }).$type<Record<string, unknown>>().notNull().default({}),
    status: text('status').$type<JobStatus>().notNull().default('queued'),
    parentId: integer('parent_id'),
    progress: text('progress'),
    log: text('log').notNull().default(''),
    stats: text('stats', { mode: 'json' }).$type<Record<string, unknown>>(),
    error: text('error'),
    cancelRequested: integer('cancel_requested', { mode: 'boolean' }).notNull().default(false),
    /** OS pid of the process running the job (worker or inline CLI); lets restarts skip rows owned by live processes */
    pid: integer('pid'),
    createdAt: text('created_at').notNull().default(now),
    startedAt: text('started_at'),
    finishedAt: text('finished_at'),
  },
  (t) => [index('job_runs_status_idx').on(t.status), index('job_runs_parent_idx').on(t.parentId)],
);

export const feedState = sqliteTable('feed_state', {
  feed: text('feed').primaryKey(), // 'osv:npm', 'osv:SwiftURL', 'kev', 'epss'
  lastSuccessAt: text('last_success_at'),
  lastAttemptAt: text('last_attempt_at'),
  lastError: text('last_error'),
  meta: text('meta', { mode: 'json' }).$type<Record<string, unknown>>(),
});

export const scans = sqliteTable(
  'scans',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    projectId: text('project_id').notNull(),
    jobRunId: integer('job_run_id'),
    ref: text('ref').notNull(),
    commitSha: text('commit_sha'),
    commitDate: text('commit_date'),
    fetched: integer('fetched', { mode: 'boolean' }).notNull().default(false),
    fetchError: text('fetch_error'),
    lockfiles: text('lockfiles', { mode: 'json' }).$type<string[]>().notNull().default([]),
    /** Manifests without a lockfile, e.g. supabase/functions/x/deno.json */
    coverageGaps: text('coverage_gaps', { mode: 'json' }).$type<string[]>().notNull().default([]),
    osvDbDate: text('osv_db_date'),
    status: text('status').$type<'running' | 'succeeded' | 'failed'>().notNull().default('running'),
    stats: text('stats', { mode: 'json' }).$type<Record<string, unknown>>(),
    error: text('error'),
    startedAt: text('started_at').notNull().default(now),
    finishedAt: text('finished_at'),
  },
  (t) => [index('scans_project_idx').on(t.projectId)],
);

export const inventory = sqliteTable(
  'inventory',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    scanId: integer('scan_id').notNull(),
    lockfile: text('lockfile').notNull(),
    ecosystem: text('ecosystem').notNull(),
    name: text('name').notNull(),
    version: text('version').notNull(),
    direct: integer('direct', { mode: 'boolean' }), // null = unknown (flat ecosystems)
    devOnly: integer('dev_only', { mode: 'boolean' }).notNull().default(false),
  },
  (t) => [index('inventory_scan_idx').on(t.scanId), index('inventory_name_idx').on(t.scanId, t.lockfile, t.name)],
);

export const advisories = sqliteTable('advisories', {
  osvId: text('osv_id').primaryKey(), // GHSA-..., MAL-..., etc.
  aliases: text('aliases', { mode: 'json' }).$type<string[]>().notNull().default([]),
  cves: text('cves', { mode: 'json' }).$type<string[]>().notNull().default([]),
  summary: text('summary'),
  details: text('details'),
  cvssVector: text('cvss_vector'),
  /** Numeric score (osv-scanner's group max_severity, else GHSA label fallback) */
  cvssScore: real('cvss_score'),
  severityLabel: text('severity_label'), // GHSA database_specific.severity: CRITICAL|HIGH|MODERATE|LOW
  cwes: text('cwes', { mode: 'json' }).$type<string[]>().notNull().default([]),
  references: text('references', { mode: 'json' }).$type<string[]>().notNull().default([]),
  published: text('published'),
  modified: text('modified'),
  withdrawn: text('withdrawn'),
  malicious: integer('malicious', { mode: 'boolean' }).notNull().default(false),
  raw: text('raw', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
  updatedAt: text('updated_at').notNull().default(now),
});

export const kev = sqliteTable('kev', {
  cve: text('cve').primaryKey(),
  dateAdded: text('date_added'),
  dueDate: text('due_date'),
  ransomware: text('ransomware'), // 'Known' | 'Unknown'
  vendor: text('vendor'),
  product: text('product'),
  name: text('name'),
  shortDescription: text('short_description'),
});

export const findings = sqliteTable(
  'findings',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    projectId: text('project_id').notNull(),
    lockfile: text('lockfile').notNull(),
    ecosystem: text('ecosystem').notNull(),
    packageName: text('package_name').notNull(),
    osvId: text('osv_id').notNull(),
    installedVersions: text('installed_versions', { mode: 'json' }).$type<string[]>().notNull().default([]),
    fixedVersions: text('fixed_versions', { mode: 'json' }).$type<string[]>().notNull().default([]),
    direct: integer('direct', { mode: 'boolean' }),
    devOnly: integer('dev_only', { mode: 'boolean' }).notNull().default(false),
    /** Up to 3 shortest chains from the root, each like ['shadcn','@modelcontextprotocol/sdk','express','proxy-addr'] */
    paths: text('paths', { mode: 'json' }).$type<string[][]>().notNull().default([]),
    importSites: text('import_sites', { mode: 'json' }).$type<ImportSite[]>().notNull().default([]),
    /** Uncapped number of import sites found (importSites holds at most MAX_IMPORT_SITES) */
    importSiteCount: integer('import_site_count').notNull().default(0),
    /** Per installed version facts; direct/devOnly/paths above are the merged view across instances */
    instances: text('instances', { mode: 'json' }).$type<FindingInstance[]>().notNull().default([]),
    status: text('status').$type<FindingStatus>().notNull().default('open'),
    origin: text('origin').$type<FindingOrigin>().notNull(),
    firstSeenScanId: integer('first_seen_scan_id').notNull(),
    lastSeenScanId: integer('last_seen_scan_id').notNull(),
    firstSeenAt: text('first_seen_at').notNull().default(now),
    resolvedAt: text('resolved_at'),
    /** advisories.modified as of the last scan that saw this finding */
    advisoryModified: text('advisory_modified'),
    // signals (written by `enrich`)
    priority: text('priority').$type<Priority>(),
    priorityReasons: text('priority_reasons', { mode: 'json' }).$type<string[]>().notNull().default([]),
    inKev: integer('in_kev', { mode: 'boolean' }).notNull().default(false),
    kevDateAdded: text('kev_date_added'),
    epss: real('epss'),
    epssPercentile: real('epss_percentile'),
    cvssScore: real('cvss_score'),
    enrichedAt: text('enriched_at'),
    // current decision for the active policy + active triage config (written by `decide`)
    currentAction: text('current_action').$type<Action>(),
    currentRuleId: text('current_rule_id'),
    activeTriageRunId: integer('active_triage_run_id'),
    decidedAt: text('decided_at'),
    createdAt: text('created_at').notNull().default(now),
    updatedAt: text('updated_at').notNull().default(now),
  },
  (t) => [
    uniqueIndex('findings_key_idx').on(t.projectId, t.lockfile, t.ecosystem, t.packageName, t.osvId),
    index('findings_status_idx').on(t.status),
    index('findings_project_idx').on(t.projectId),
  ],
);

export const triageConfigs = sqliteTable('triage_configs', {
  name: text('name').primaryKey(),
  promptVersion: text('prompt_version').notNull(),
  model: text('model').notNull(),
  effort: text('effort').notNull(),
  codeAccess: integer('code_access', { mode: 'boolean' }).notNull(),
  active: integer('active', { mode: 'boolean' }).notNull().default(false),
  createdAt: text('created_at').notNull().default(now),
});

export const triageRuns = sqliteTable(
  'triage_runs',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    findingId: integer('finding_id').notNull(),
    configName: text('config_name').notNull(),
    jobRunId: integer('job_run_id'),
    /** The scan and commit whose snapshot this run read (evidence file:line refers to this commit) */
    scanId: integer('scan_id'),
    commitSha: text('commit_sha'),
    inputHash: text('input_hash').notNull(),
    status: text('status').$type<TriageRunStatus>().notNull(),
    output: text('output', { mode: 'json' }).$type<TriageOutput>(),
    /** The CLI's full JSON result (minus nothing), for audit */
    raw: text('raw', { mode: 'json' }).$type<Record<string, unknown>>(),
    prompt: text('prompt').notNull(),
    modelResolved: text('model_resolved'),
    claudeVersion: text('claude_version'),
    costUsd: real('cost_usd'),
    inputTokens: integer('input_tokens'),
    outputTokens: integer('output_tokens'),
    cacheReadTokens: integer('cache_read_tokens'),
    numTurns: integer('num_turns'),
    durationMs: integer('duration_ms'),
    attempts: integer('attempts').notNull().default(1),
    error: text('error'),
    tag: text('tag'), // e.g. 'consistency'
    createdAt: text('created_at').notNull().default(now),
  },
  (t) => [
    index('triage_runs_finding_idx').on(t.findingId, t.configName),
    index('triage_runs_hash_idx').on(t.findingId, t.configName, t.inputHash),
  ],
);

export const policyVersions = sqliteTable('policy_versions', {
  hash: text('hash').primaryKey(),
  content: text('content').notNull(),
  firstSeenAt: text('first_seen_at').notNull().default(now),
});

export const decisions = sqliteTable(
  'decisions',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    findingId: integer('finding_id').notNull(),
    policyHash: text('policy_hash').notNull(),
    configName: text('config_name').notNull(),
    triageRunId: integer('triage_run_id'),
    action: text('action').$type<Action>().notNull(),
    ruleId: text('rule_id').notNull(),
    inputs: text('inputs', { mode: 'json' }).$type<DecisionInputs>().notNull(),
    decidedAt: text('decided_at').notNull().default(now),
  },
  (t) => [uniqueIndex('decisions_key_idx').on(t.findingId, t.policyHash, t.configName)],
);

export const labels = sqliteTable(
  'labels',
  {
    findingId: integer('finding_id').notNull(),
    labeler: text('labeler').notNull().default('me'),
    expectedAction: text('expected_action').$type<Action>().notNull(),
    affectedTruth: text('affected_truth').$type<AffectedTruth>(),
    note: text('note'),
    labeledAt: text('labeled_at').notNull().default(now),
  },
  (t) => [primaryKey({ columns: [t.findingId, t.labeler] })],
);

export const events = sqliteTable(
  'events',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    findingId: integer('finding_id').notNull(),
    type: text('type').$type<EventType>().notNull(),
    jobRunId: integer('job_run_id'),
    data: text('data', { mode: 'json' }).$type<Record<string, unknown>>(),
    at: text('at').notNull().default(now),
  },
  (t) => [index('events_finding_idx').on(t.findingId), index('events_at_idx').on(t.at)],
);

/**
 * Cases the system asks the owner to decide (the /decide page): only "taste" questions, at most a handful,
 * each with a plain-language brief. Answering writes a label (labeler = answeredBy) for the finding.
 */
export const ownerCases = sqliteTable(
  'owner_cases',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    findingId: integer('finding_id').notNull(),
    status: text('status').$type<OwnerCaseStatus>().notNull().default('open'),
    brief: text('brief', { mode: 'json' }).$type<OwnerBrief>().notNull(),
    /** Why the owner is asked (shown only after answering, so it does not anchor the answer) */
    reason: text('reason').notNull(),
    /** The system's current action and the agent labelers' call, revealed after answering */
    systemAction: text('system_action').$type<Action>(),
    agentAction: text('agent_action').$type<Action>(),
    batch: text('batch'),
    answer: text('answer').$type<Action>(),
    answeredBy: text('answered_by'),
    note: text('note'),
    createdAt: text('created_at').notNull().default(now),
    answeredAt: text('answered_at'),
  },
  (t) => [index('owner_cases_status_idx').on(t.status), index('owner_cases_finding_idx').on(t.findingId)],
);
