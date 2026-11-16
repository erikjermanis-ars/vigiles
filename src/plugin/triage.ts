/**
 * Triages the findings of the last scan with the POC's locked-down `claude -p` call (src/lib/triage/claude.ts)
 * and its prompt (src/lib/triage/prompt.ts), storing each verdict in `.vigiles/verdicts.json` as soon as it
 * arrives, so an interrupted run keeps everything it finished.
 *
 * What runs: every non-malicious finding without a verdict for its current inputs (all of them with `force`),
 * optionally narrowed by `only`, in the POC's order (src/lib/triage/select.ts compareCandidates), cut to
 * `limit`. Malicious packages are never sent to the model (the policy pings them as they are).
 *
 * The prompt inputs mirror src/lib/triage/runner.ts buildPromptInputs field for field (a test holds them
 * equal); that module reads the DB, so it cannot be bundled into the plugin.
 */
import path from 'node:path';
import { ensureSnapshot } from '../lib/git';
import { runClaudeTriage, type ClaudeTriageRequest, type ClaudeTriageResult } from '../lib/triage/claude';
import { forEachConcurrent, MAX_CONSECUTIVE_CLI_FAILURES } from '../lib/triage/concurrency';
import { promptFingerprint } from '../lib/triage/input-hash';
import { triageProfileHash } from '../lib/triage/profile';
import { loadTriagePrompt, osvRangesFor, renderUserPrompt, type CodeInput, type TriagePromptInputs } from '../lib/triage/prompt';
import { PRIORITIES, type ProjectProfile, type TriageRunStatus } from '../lib/types';
import { bins, ensureDir } from './paths';
import { ACTION_LABELS, type ScanAdvisory, type ScanFinding, type ScanResult, type StoredVerdict, type TriageFailures } from './types';
import { saveFailures, type VerdictStore } from './verdicts';

export type ClaudeRunner = (req: ClaudeTriageRequest) => Promise<ClaudeTriageResult>;

/** The scan no longer matches the triage inputs (prompt or profile changed since): scan again first. */
export class StaleScanError extends Error {}

export interface RunTriageOptions {
  scan: ScanResult;
  /** The project profile as triage sees it (the caller converts the plugin profile with toProjectProfile). */
  profile: ProjectProfile;
  /** Directory holding prompts/triage/<version>.* */
  assetRoot: string;
  verdicts: VerdictStore;
  verdictsFile: string;
  /** Mutated in place and saved after every finished run. */
  failures: TriageFailures;
  failuresFile: string;
  /** Working directory for runs without code access */
  scratchDir: string;
  /** Default: bins().git */
  git?: string;
  /** Default: bins().claude */
  claudeBin?: string;
  /** At most this many runs (default: all) */
  limit?: number;
  /** Only findings matching one of these: an OSV id or alias, a CVE id, or a finding id */
  only?: string[];
  /** Re-triage findings that already have a current verdict */
  force?: boolean;
  /** Default: the scan's triage config */
  concurrency?: number;
  /** Claude attempts per finding (default 2: one retry) */
  maxAttempts?: number;
  /** Aborting kills the in-flight claude processes; verdicts saved so far stay. */
  signal?: AbortSignal;
  /** One line per event (progress and summary). */
  log?: (line: string) => void;
  /** Injectable for tests; defaults to the real runClaudeTriage. */
  runClaude?: ClaudeRunner;
  now?: () => Date;
}

export interface TriageOutcome {
  findingId: string;
  status: TriageRunStatus;
  error: string | null;
  costUsd: number | null;
  wallMs: number;
}

export interface TriageSummary {
  /** Findings that needed triage (after `only`, before `limit`) */
  eligible: number;
  /** Findings picked for this run (after `limit`) */
  selected: number;
  ok: number;
  failed: number;
  cancelled: number;
  /** Eligible findings that did not get a verdict or a failure this run (limit, interruption or an early stop) */
  remaining: number;
  /** Findings skipped because they have a verdict for their current inputs (within `only`, when given) */
  alreadyCurrent: number;
  /** Malicious findings (never triaged) */
  malicious: number;
  /** `only` values that matched no finding */
  unmatched: string[];
  /** Sum of the CLI's total_cost_usd (API list-price equivalent) */
  costUsd: number;
  wallMs: number;
  /**
   * Set when new runs were stopped because claude cannot work: not logged in, a usage limit, a missing binary, or
   * MAX_CONSECUTIVE_CLI_FAILURES CLI failures in a row (an outage)
   */
  stopReason: string | null;
  interrupted: boolean;
  /** In finishing order */
  outcomes: TriageOutcome[];
}

// ---------- prompt inputs (mirror of runner.ts buildPromptInputs) ----------

/** The prompt inputs for one finding: field for field what src/lib/triage/runner.ts buildPromptInputs builds. */
export function promptInputsFor(
  finding: ScanFinding,
  advisory: ScanAdvisory,
  profile: ProjectProfile,
  code: CodeInput,
): TriagePromptInputs {
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
      kevRansomware: finding.inKev ? finding.kevRansomware : null,
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
    profile,
    code,
  };
}

/** What the prompt's code note calls the audited ref: the branch, else the requested ref. */
export function auditedRef(scan: Pick<ScanResult, 'branch' | 'ref'>): string {
  return scan.branch ?? scan.ref;
}

// ---------- selection ----------

function priorityRank(p: ScanFinding['priority'] | null): number {
  return p ? PRIORITIES.indexOf(p) : PRIORITIES.length;
}

/** Nulls sort last; larger numbers first. */
function descNullsLast(a: number | null, b: number | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return b - a;
}

/** src/lib/triage/select.ts compareCandidates: priority (P0 first), EPSS desc, CVSS desc, then id. */
export function compareCandidates(a: ScanFinding, b: ScanFinding): number {
  return (
    priorityRank(a.priority) - priorityRank(b.priority) ||
    descNullsLast(a.epss, b.epss) ||
    descNullsLast(a.cvssScore, b.cvssScore) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  );
}

export function isMaliciousFinding(f: ScanFinding, advisory: ScanAdvisory | null | undefined): boolean {
  return f.malicious || Boolean(advisory?.malicious) || f.osvId.startsWith('MAL-');
}

function matchesOnly(f: ScanFinding, advisory: ScanAdvisory | undefined, wanted: Set<string>): string[] {
  const ids = [f.osvId, ...f.cves, ...(advisory?.aliases ?? []), ...(advisory?.cves ?? [])].map((s) => s.toUpperCase());
  const hits = ids.filter((id) => wanted.has(id));
  if (wanted.has(f.id.toUpperCase())) hits.push(f.id.toUpperCase());
  return hits;
}

export interface TriageSelection {
  eligible: ScanFinding[];
  alreadyCurrent: number;
  malicious: number;
  unmatched: string[];
}

export function selectFindings(scan: ScanResult, verdicts: VerdictStore, opts: { only?: string[]; force?: boolean } = {}): TriageSelection {
  const only = (opts.only ?? []).map((s) => s.trim()).filter(Boolean);
  const wanted = new Set(only.map((s) => s.toUpperCase()));
  const matched = new Set<string>();
  const eligible: ScanFinding[] = [];
  let alreadyCurrent = 0;
  let malicious = 0;
  for (const f of scan.findings) {
    const advisory = scan.advisories[f.osvId];
    if (wanted.size) {
      const hits = matchesOnly(f, advisory, wanted);
      if (!hits.length) continue;
      for (const h of hits) matched.add(h);
    }
    if (isMaliciousFinding(f, advisory)) {
      malicious++;
      continue;
    }
    if (!opts.force && verdicts.current(f)) {
      alreadyCurrent++;
      continue;
    }
    eligible.push(f);
  }
  eligible.sort(compareCandidates);
  return { eligible, alreadyCurrent, malicious, unmatched: only.filter((s) => !matched.has(s.toUpperCase())) };
}

// ---------- account problems ----------

const NOT_LOGGED_IN = /\/login|not logged in|log ?in again|invalid api key|authenticat|unauthori[sz]ed|oauth token|\b401\b/i;
/** The CLI prints e.g. "You've hit your 5-hour limit · resets 9:40pm (Europe/Zagreb)" or "Claude AI usage limit reached". */
const USAGE_LIMIT =
  /usage limit|hit your [\w -]*limit|limit (reached|exceeded)|resets \d|rate[ _-]?limit|credit balance|quota/i;
/** Errors runClaudeTriage records for an attempt that printed no JSON result (the text is then the CLI's own). */
const NO_RESULT_ERROR = /^(claude exited |claude stdout is not a JSON object|could not start )/;

/**
 * The CLI's own words in a failed run. A result that is not is_error is the model's answer (e.g. about a
 * rate-limiting advisory), whose words say nothing about the account; as in src/lib/triage/select.ts.
 */
function cliMessage(result: Pick<ClaudeTriageResult, 'error'> & { raw?: ClaudeTriageResult['raw'] }): string {
  const error = result.error ?? '';
  const raw = result.raw;
  if (raw && typeof raw.result === 'string' && raw.is_error !== true && !NO_RESULT_ERROR.test(error)) return '';
  return error;
}

/** Why no further run can succeed (so new runs stop), or null for a failure about this finding only. */
export function accountProblem(
  result: Pick<ClaudeTriageResult, 'status' | 'error'> & { raw?: ClaudeTriageResult['raw'] },
  bin: string,
): string | null {
  if (result.status !== 'failed' || !result.error) return null;
  const error = result.error;
  if (error.startsWith('could not start ')) return `Could not start \`${bin}\`: is Claude Code installed and on PATH? (${error})`;
  const message = cliMessage(result);
  if (NOT_LOGGED_IN.test(message))
    return `Claude Code is not logged in (or the login expired): ${oneLine(error)}. Run \`claude\`, log in with /login, then run the audit again.`;
  if (USAGE_LIMIT.test(message))
    return `Claude Code hit a usage or rate limit: ${oneLine(error)}. Wait for the limit to reset, then run triage again.`;
  return null;
}

/** The stop reason after MAX_CONSECUTIVE_CLI_FAILURES CLI failures in a row (the POC triage job's breaker). */
export function repeatedFailureProblem(count: number, lastError: string): string {
  return (
    `Claude failed for ${count} findings in a row (a usage limit or an outage?). Last error: ${oneLine(lastError)}. ` +
    'Wait a while (for a usage limit, until it resets), then run triage again.'
  );
}

// ---------- formatting ----------

function seconds(ms: number): string {
  return `${Math.round(ms / 1000)}s`;
}

export function formatWallTime(ms: number): string {
  const total = Math.round(ms / 1000);
  if (total < 60) return `${total}s`;
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

function packageLabel(f: ScanFinding): string {
  return `${f.packageName}@${f.installedVersions.join(',') || '?'}`;
}

function oneLine(s: string, max = 200): string {
  const line = s.replace(/\s+/g, ' ').trim();
  return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}

export function formatTriageSummary(s: TriageSummary): string[] {
  const counts = [`${s.ok} ok`, `${s.failed} failed`, ...(s.cancelled ? [`${s.cancelled} cancelled`] : [])].join(', ');
  const lines = [
    `Triage ${s.interrupted ? 'interrupted' : 'done'}: ${counts} in ${formatWallTime(s.wallMs)} · $${s.costUsd.toFixed(2)} at API list price`,
  ];
  if (s.stopReason) lines.push(`Stopped early. ${s.stopReason}`);
  if (s.remaining > 0)
    lines.push(
      `${s.remaining} finding${s.remaining === 1 ? '' : 's'} still need${s.remaining === 1 ? 's' : ''} triage; run triage again to continue.`,
    );
  if (s.unmatched.length) lines.push(`No finding matched: ${s.unmatched.join(', ')}`);
  return lines;
}

// ---------- running ----------

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

/** The scan's code snapshot (<snapshots>/<projectKey>/<sha>), rebuilt from git when the cache lost it. */
async function prepareSnapshot(scan: ScanResult, git: string, signal?: AbortSignal): Promise<string> {
  const projectDir = path.dirname(scan.snapshotDir);
  try {
    return await ensureSnapshot(git, path.dirname(projectDir), path.basename(projectDir), scan.repoRoot, scan.commit, { signal });
  } catch (err) {
    throw new Error(
      `could not prepare the code snapshot of ${scan.commit.slice(0, 12)}: ${err instanceof Error ? err.message : String(err)}`,
      {
        cause: err,
      },
    );
  }
}

/** The command that scans the same ref again: plain `scan` audits HEAD, so another ref needs its --ref. */
export function rescanCommand(ref: string): string {
  return ref === 'HEAD' ? 'scan' : `scan --ref ${ref}`;
}

/** Throws StaleScanError when the prompt files or the profile changed after the scan computed the input hashes. */
export function assertScanCurrent(scan: ScanResult, profile: ProjectProfile, assetRoot: string): void {
  const tc = scan.triageConfig;
  const rescan = scan.ref === 'HEAD' ? 'run scan again' : `run \`${rescanCommand(scan.ref)}\` again`;
  const fingerprint = promptFingerprint(tc.promptVersion, assetRoot);
  if (fingerprint !== tc.promptFingerprint) {
    throw new StaleScanError(`the triage prompt changed since the last scan (${tc.promptFingerprint} → ${fingerprint}); ${rescan}`);
  }
  const profileHash = triageProfileHash(profile);
  if (profileHash !== scan.profileHash) {
    throw new StaleScanError(`.vigiles/profile.yaml changed since the last scan; ${rescan}`);
  }
}

export async function runTriage(opts: RunTriageOptions): Promise<TriageSummary> {
  const { scan, profile, verdicts, failures } = opts;
  const tc = scan.triageConfig;
  const log = opts.log ?? (() => {});
  const now = opts.now ?? (() => new Date());
  const runClaude = opts.runClaude ?? runClaudeTriage;
  const claudeBin = opts.claudeBin ?? bins().claude;
  const git = opts.git ?? bins().git;
  const started = Date.now();

  assertScanCurrent(scan, profile, opts.assetRoot);
  const selection = selectFindings(scan, verdicts, { only: opts.only, force: opts.force });
  const limit = opts.limit === undefined ? Infinity : Math.max(0, opts.limit);
  const candidates = selection.eligible.slice(0, limit);

  const summary: TriageSummary = {
    eligible: selection.eligible.length,
    selected: candidates.length,
    ok: 0,
    failed: 0,
    cancelled: 0,
    remaining: selection.eligible.length,
    alreadyCurrent: selection.alreadyCurrent,
    malicious: selection.malicious,
    unmatched: selection.unmatched,
    costUsd: 0,
    wallMs: 0,
    stopReason: null,
    interrupted: false,
    outcomes: [],
  };
  if (!candidates.length) {
    summary.wallMs = Date.now() - started;
    return summary;
  }

  const prompt = loadTriagePrompt(opts.assetRoot, tc.promptVersion);
  const ref = auditedRef(scan);
  let code: CodeInput = { access: false };
  let snapshotDir: string | undefined;
  if (tc.codeAccess) {
    snapshotDir = await prepareSnapshot(scan, git, opts.signal);
    code = { access: true, workdir: snapshotDir, commitSha: scan.commit, ref, commitDate: scan.commitDate };
  } else {
    ensureDir(opts.scratchDir);
  }

  // `stop` ends the starting of new runs; opts.signal (the user's interrupt) also kills the in-flight ones.
  const stop = new AbortController();
  const onAbort = () => stop.abort();
  if (opts.signal?.aborted) stop.abort();
  opts.signal?.addEventListener('abort', onAbort, { once: true });

  const concurrency = Math.max(1, opts.concurrency ?? tc.concurrency);
  log(
    `Triaging ${candidates.length} finding${candidates.length === 1 ? '' : 's'} with ${tc.name} (concurrency ${concurrency})` +
      (selection.alreadyCurrent ? `; ${selection.alreadyCurrent} already have a current verdict` : ''),
  );

  let finished = 0;
  let cliFailuresInARow = 0;
  let lastCliError = '';
  try {
    await forEachConcurrent(candidates, concurrency, stop.signal, async (finding) => {
      const t0 = Date.now();
      let result: ClaudeTriageResult;
      try {
        const advisory = scan.advisories[finding.osvId];
        if (!advisory) throw new Error(`advisory ${finding.osvId} is missing from the scan`);
        const userPrompt = renderUserPrompt(prompt.userTemplate, promptInputsFor(finding, advisory, profile, code));
        result = await runClaude({
          bin: claudeBin,
          model: tc.model,
          effort: tc.effort,
          codeAccess: tc.codeAccess,
          systemPrompt: prompt.system,
          schemaJson: prompt.schemaJson,
          maxBudgetUsd: tc.maxBudgetUsd,
          snapshotDir,
          scratchDir: opts.scratchDir,
          userPrompt,
          timeoutMs: Math.round(tc.timeoutMinutes * 60_000),
          signal: opts.signal,
          maxAttempts: opts.maxAttempts ?? 2,
        });
      } catch (err) {
        result = setupFailure(err, Boolean(opts.signal?.aborted));
      }
      const wallMs = Date.now() - t0;
      finished++;
      summary.costUsd += result.costUsd ?? 0;
      summary.outcomes.push({ findingId: finding.id, status: result.status, error: result.error, costUsd: result.costUsd, wallMs });
      const head = `[${finished}/${candidates.length}]`;

      if (result.status === 'ok' && result.output) {
        const verdict: StoredVerdict = {
          osvId: finding.osvId,
          ecosystem: finding.ecosystem,
          packageName: finding.packageName,
          lockfile: finding.lockfile,
          inputHash: finding.inputHash,
          config: tc.name,
          prompt: tc.promptFingerprint,
          model: result.modelResolved,
          triagedAt: now().toISOString(),
          commit: scan.commit,
          ref,
          costUsd: result.costUsd,
          durationMs: result.durationMs,
          output: result.output,
        };
        verdicts.upsert(verdict);
        verdicts.save(opts.verdictsFile);
        if (failures[finding.id]) {
          delete failures[finding.id];
          saveFailures(opts.failuresFile, failures);
        }
        summary.ok++;
        log(
          `${head} ok ${packageLabel(finding)} ${finding.osvId} → suggests ${ACTION_LABELS[result.output.suggested_action]} (${result.output.verdict}, ${seconds(wallMs)})`,
        );
        if (result.attempts > 0) cliFailuresInARow = 0;
        return;
      }

      if (result.status === 'cancelled') {
        summary.cancelled++;
        log(`${head} cancelled ${packageLabel(finding)} ${finding.osvId}`);
        return;
      }

      const error = result.error ?? result.status;
      failures[finding.id] = { inputHash: finding.inputHash, error, at: now().toISOString() };
      saveFailures(opts.failuresFile, failures);
      summary.failed++;
      log(`${head} failed ${packageLabel(finding)} ${finding.osvId}: ${oneLine(error)} (${seconds(wallMs)})`);
      // As in the POC triage job: setup failures (attempts 0) say nothing about claude's health; any other
      // finished run resets the count, and CLI failures in a row stop new runs (usage limit, outage).
      if (result.status === 'failed' && result.attempts > 0) {
        cliFailuresInARow++;
        lastCliError = error;
      } else if (result.attempts > 0) {
        cliFailuresInARow = 0;
      }
      const problem =
        accountProblem(result, claudeBin) ??
        (cliFailuresInARow >= MAX_CONSECUTIVE_CLI_FAILURES ? repeatedFailureProblem(cliFailuresInARow, lastCliError) : null);
      if (problem && !summary.stopReason) {
        summary.stopReason = problem;
        stop.abort();
      }
    });
  } finally {
    opts.signal?.removeEventListener('abort', onAbort);
  }

  summary.interrupted = Boolean(opts.signal?.aborted);
  summary.remaining = summary.eligible - summary.ok - summary.failed;
  summary.wallMs = Date.now() - started;
  for (const line of formatTriageSummary(summary)) log(line);
  return summary;
}

/**
 * An AbortSignal that aborts on the first SIGINT or SIGTERM (in-flight claude processes are then killed and the
 * verdicts saved so far stay); a second SIGINT exits at once. Call dispose() when done.
 */
export function interruptSignal(onInterrupt?: () => void): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController();
  const handler = (sig: NodeJS.Signals) => {
    if (controller.signal.aborted) process.exit(sig === 'SIGINT' ? 130 : 143);
    onInterrupt?.();
    controller.abort();
  };
  process.on('SIGINT', handler);
  process.on('SIGTERM', handler);
  return {
    signal: controller.signal,
    dispose: () => {
      process.off('SIGINT', handler);
      process.off('SIGTERM', handler);
    },
  };
}
