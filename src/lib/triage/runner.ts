/**
 * Triages one finding end to end (spec §9.5): gathers the prompt inputs from the DB, prepares the
 * code snapshot (or none), runs claude and stores a triage_runs row. Every attempt is stored,
 * including setup failures, so the dashboard can show why a finding has no verdict.
 */
import { eq, inArray } from 'drizzle-orm';
import type { DataPaths } from '../config/load';
import type { VigilesConfig } from '../config/schema';
import type { Db } from '../db/client';
import { advisories, findings, kev, projects, scans, triageConfigs, triageRuns } from '../db/schema';
import { ensureSnapshot } from '../git';
import { runClaudeTriage, type ClaudeTriageResult } from './claude';
import { osvRangesFor, renderUserPrompt, type CodeInput, type TriagePrompt, type TriagePromptInputs } from './prompt';
import type { TriageCandidate } from './select';

// Lives in ./concurrency (no DB); re-exported so existing imports keep working.
export { forEachConcurrent } from './concurrency';

type FindingRow = typeof findings.$inferSelect;
type ProjectRow = typeof projects.$inferSelect;
type ScanRow = typeof scans.$inferSelect;
type AdvisoryRow = typeof advisories.$inferSelect;
type TriageConfigRow = typeof triageConfigs.$inferSelect;

export type SnapshotProvider = (projectId: string, repoPath: string, sha: string) => Promise<string>;

/**
 * Shares one snapshot build per (project, sha) between concurrent triage runs. ensureSnapshot itself is
 * safe under concurrent calls (unique temp dirs); this only avoids building the same snapshot twice.
 */
export function memoizedSnapshots(git: string, snapshotsRoot: string): SnapshotProvider {
  const inflight = new Map<string, Promise<string>>();
  return (projectId, repoPath, sha) => {
    const key = `${projectId}@${sha}`;
    let p = inflight.get(key);
    if (!p) {
      p = ensureSnapshot(git, snapshotsRoot, projectId, repoPath, sha);
      inflight.set(key, p);
      p.catch(() => inflight.delete(key));
    }
    return p;
  };
}

// ---------- prompt inputs ----------

export interface FindingContext {
  project: ProjectRow;
  scan: ScanRow | null;
  advisory: AdvisoryRow;
  kevRansomware: string | null;
}

export function loadFindingContext(db: Db, finding: FindingRow): FindingContext {
  const project = db.select().from(projects).where(eq(projects.id, finding.projectId)).get();
  if (!project) throw new Error(`project ${finding.projectId} not found`);
  const advisory = db.select().from(advisories).where(eq(advisories.osvId, finding.osvId)).get();
  if (!advisory) throw new Error(`advisory ${finding.osvId} not found`);
  const scan = db.select().from(scans).where(eq(scans.id, finding.lastSeenScanId)).get() ?? null;
  const kevRow = advisory.cves.length
    ? db.select({ ransomware: kev.ransomware }).from(kev).where(inArray(kev.cve, advisory.cves)).get()
    : undefined;
  return { project, scan, advisory, kevRansomware: kevRow?.ransomware ?? null };
}

export function buildPromptInputs(finding: FindingRow, ctx: FindingContext, code: CodeInput): TriagePromptInputs {
  const { advisory } = ctx;
  const osv = osvRangesFor(advisory.raw, finding.packageName, finding.ecosystem);
  return {
    advisory: {
      osvId: advisory.osvId,
      aliases: advisory.aliases,
      summary: advisory.summary,
      details: advisory.details,
      published: advisory.published,
      modified: advisory.modified,
      withdrawn: advisory.withdrawn,
      cwes: advisory.cwes,
      references: advisory.references,
      affectedRanges: osv.ranges,
      fixedVersions: osv.fixed.length ? osv.fixed : finding.fixedVersions,
    },
    signals: {
      cvssScore: finding.cvssScore ?? advisory.cvssScore,
      cvssVector: advisory.cvssVector,
      severityLabel: advisory.severityLabel,
      inKev: finding.inKev,
      kevDateAdded: finding.kevDateAdded,
      kevRansomware: finding.inKev ? ctx.kevRansomware : null,
      epss: finding.epss,
      epssPercentile: finding.epssPercentile,
    },
    dependency: {
      ecosystem: finding.ecosystem,
      lockfile: finding.lockfile,
      packageName: finding.packageName,
      installedVersions: finding.installedVersions,
      fixedVersions: finding.fixedVersions,
      direct: finding.direct,
      devOnly: finding.devOnly,
      paths: finding.paths,
      instances: finding.instances,
      importSites: finding.importSites,
      importSiteCount: finding.importSiteCount,
    },
    profile: ctx.project.profile,
    code,
  };
}

// ---------- one finding ----------

export interface TriageEnv {
  db: Db;
  config: VigilesConfig;
  paths: DataPaths;
  triageConfig: TriageConfigRow;
  prompt: TriagePrompt;
  claudeVersion: string | null;
  jobRunId: number | null;
  tag: string | null;
  signal: AbortSignal;
  snapshots: SnapshotProvider;
  /** Claude attempts per finding (default 2: one retry) */
  maxAttempts?: number;
}

export interface TriageOutcome {
  runId: number;
  result: ClaudeTriageResult;
}

async function codeInputFor(env: TriageEnv, ctx: FindingContext): Promise<{ input: CodeInput; snapshotDir?: string }> {
  if (!env.triageConfig.codeAccess) return { input: { access: false } };
  const sha = ctx.scan?.commitSha;
  if (!ctx.scan || !sha) throw new Error(`scan ${ctx.scan?.id ?? '?'} has no commit SHA, so there is no code snapshot`);
  const snapshotDir = await env.snapshots(ctx.project.id, ctx.project.repoPath, sha);
  return {
    input: { access: true, workdir: snapshotDir, commitSha: sha, ref: ctx.scan.ref, commitDate: ctx.scan.commitDate },
    snapshotDir,
  };
}

function setupFailure(err: unknown, aborted: boolean): ClaudeTriageResult {
  return {
    status: aborted ? 'cancelled' : 'failed',
    output: null,
    raw: null,
    modelResolved: null,
    costUsd: null,
    inputTokens: null,
    outputTokens: null,
    cacheReadTokens: null,
    numTurns: null,
    durationMs: null,
    attempts: 0,
    error: aborted ? 'cancelled' : `setup failed: ${err instanceof Error ? err.message : String(err)}`,
    retriedErrors: [],
    permissionDenials: 0,
  };
}

export async function triageFinding(env: TriageEnv, { finding, state }: TriageCandidate): Promise<TriageOutcome> {
  const { triageConfig: tc } = env;
  let prompt = '';
  let result: ClaudeTriageResult;
  // The scan whose facts (and, with code access, whose snapshot) the prompt was built from.
  // Evidence file:line refers to this commit, not to whatever the finding's latest scan is later.
  let scan: ScanRow | null = null;
  try {
    const ctx = loadFindingContext(env.db, finding);
    scan = ctx.scan;
    const code = await codeInputFor(env, ctx);
    prompt = renderUserPrompt(env.prompt.userTemplate, buildPromptInputs(finding, ctx, code.input));
    result = await runClaudeTriage({
      bin: env.config.bin.claude,
      model: tc.model,
      effort: tc.effort,
      codeAccess: tc.codeAccess,
      systemPrompt: env.prompt.system,
      schemaJson: env.prompt.schemaJson,
      maxBudgetUsd: env.config.triage.max_budget_usd_per_run,
      snapshotDir: code.snapshotDir,
      scratchDir: env.paths.scratch,
      userPrompt: prompt,
      timeoutMs: Math.round(env.config.triage.timeout_minutes * 60_000),
      signal: env.signal,
      maxAttempts: env.maxAttempts,
    });
  } catch (err) {
    result = setupFailure(err, env.signal.aborted);
  }

  const row = env.db
    .insert(triageRuns)
    .values({
      findingId: finding.id,
      configName: tc.name,
      jobRunId: env.jobRunId,
      scanId: scan?.id ?? null,
      commitSha: scan?.commitSha ?? null,
      inputHash: state.inputHash,
      status: result.status,
      output: result.output,
      raw: result.raw,
      prompt,
      modelResolved: result.modelResolved,
      claudeVersion: env.claudeVersion,
      costUsd: result.costUsd,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      cacheReadTokens: result.cacheReadTokens,
      numTurns: result.numTurns,
      durationMs: result.durationMs,
      attempts: result.attempts,
      error: result.error,
      tag: env.tag,
    })
    .returning({ id: triageRuns.id })
    .get();
  return { runId: row.id, result };
}
