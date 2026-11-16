/**
 * Shapes shared by the Vigiles Claude Code plugin CLI (src/plugin). The plugin reuses the POC's domain
 * modules in src/lib; its state lives in files instead of SQLite:
 *
 *   <repo>/.vigiles/profile.yaml    project profile (meant to be committed)
 *   <repo>/.vigiles/verdicts.json   triage verdicts = the triage cache (meant to be committed)
 *   <repo>/.vigiles/report.md       the latest report (gitignored by .vigiles/.gitignore)
 *   <cache>/osv-db, kev.json, snapshots/, repos/<projectKey>/{scan.json,triage-failures.json}
 *
 * <cache> is $VIGILES_CACHE_DIR, else $XDG_CACHE_HOME/vigiles, else ~/.cache/vigiles.
 */
import { z } from 'zod';
import {
  ProjectProfileSchema,
  TriageOutputSchema,
  type Action,
  type DecisionInputs,
  type FindingInstance,
  type ImportSite,
  type Priority,
  type TriageStatus,
} from '../lib/types';

// ---------- profile ----------

/**
 * The POC's project profile with `repo_path` optional: the plugin always audits the repository it runs in.
 * Key order (and so the triage-visible profile and its hash) is the same as the POC's, which keeps triage
 * input hashes comparable with the dashboard's. `enabled` and `fetch_before_scan` are accepted and ignored.
 * `ref` is informational for the plugin: the production branch, shown to triage as part of the profile.
 */
export const PluginProfileSchema = ProjectProfileSchema.extend({ repo_path: z.string().optional() });
export type PluginProfile = z.infer<typeof PluginProfileSchema>;

// ---------- configuration ----------

/** The triage configuration the plugin ships (built from config/vigiles.yaml's active config). */
export interface TriageConfig {
  /** e.g. 'v3-opus-high-code' */
  name: string;
  /** Prompt version, e.g. 'v3' (prompts/triage/<version>.*) */
  promptVersion: string;
  /** `<version>@<hash of the prompt files>` (src/lib/triage/input-hash promptFingerprint) */
  promptFingerprint: string;
  model: string;
  effort: string;
  codeAccess: boolean;
  concurrency: number;
  timeoutMinutes: number;
  maxBudgetUsd: number;
}

// ---------- scan ----------

export const STATE_FORMAT = 1 as const;

/** One advisory matched against one package in one lockfile (the POC's finding), plus its signals. */
export interface ScanFinding {
  /** findingId(): `${osvId} ${ecosystem}:${packageName} ${lockfile}`; stable and human-readable */
  id: string;
  lockfile: string;
  ecosystem: string;
  packageName: string;
  osvId: string;
  installedVersions: string[];
  fixedVersions: string[];
  /** Merged over instances: any instance is direct (null = unknown) */
  direct: boolean | null;
  /** Merged over instances: every instance is dev-only */
  devOnly: boolean;
  paths: string[][];
  instances: FindingInstance[];
  /** At most MAX_IMPORT_SITES */
  importSites: ImportSite[];
  importSiteCount: number;
  advisoryModified: string | null;
  // signals (the POC's enrich step)
  cves: string[];
  malicious: boolean;
  inKev: boolean;
  kevDateAdded: string | null;
  /** CISA knownRansomwareCampaignUse of the matching KEV entry */
  kevRansomware: string | null;
  epss: number | null;
  epssPercentile: number | null;
  cvssScore: number | null;
  priority: Priority;
  priorityReasons: string[];
  /** Triage input hash under the shipped triage config (computeInputHash); the verdict cache key */
  inputHash: string;
}

/** What triage and the report need from an OSV record (advisoryFromRecord, without DB types). */
export interface ScanAdvisory {
  osvId: string;
  aliases: string[];
  cves: string[];
  summary: string | null;
  details: string | null;
  cvssVector: string | null;
  cvssScore: number | null;
  severityLabel: string | null;
  cwes: string[];
  references: string[];
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  malicious: boolean;
  raw: Record<string, unknown>;
}

export interface ScanResult {
  format: typeof STATE_FORMAT;
  /** Plugin version that wrote it */
  toolVersion: string;
  scannedAt: string;
  repoRoot: string;
  projectId: string;
  projectName: string;
  /** The ref as requested ('HEAD' by default) */
  ref: string;
  /** Branch name when the ref is HEAD on a branch, or the ref itself; null for a detached HEAD */
  branch: string | null;
  commit: string;
  commitDate: string | null;
  /** Lockfiles and manifests with uncommitted changes (only checked when auditing HEAD); this scan did not see them */
  uncommittedDependencyFiles: string[];
  snapshotDir: string;
  lockfiles: string[];
  skippedLockfiles: string[];
  coverageGaps: string[];
  ecosystems: string[];
  warnings: string[];
  data: {
    /** Oldest OSV database date among the ecosystems used */
    osvDbDate: string | null;
    kevCatalogDate: string | null;
    kevAvailable: boolean;
    epssDate: string | null;
    /** CVEs whose EPSS lookup failed */
    epssFailedCves: number;
  };
  triageConfig: TriageConfig;
  /** triageProfileHash(profile) */
  profileHash: string;
  /** Hash of the policy file the priorities were computed with */
  policyHash: string;
  stats: { packages: number; vulnerablePackages: number };
  findings: ScanFinding[];
  advisories: Record<string, ScanAdvisory>;
}

// ---------- verdicts (committed) ----------

export const StoredVerdictSchema = z.object({
  osvId: z.string(),
  ecosystem: z.string(),
  packageName: z.string(),
  lockfile: z.string(),
  /** ScanFinding.inputHash the verdict was produced for; a different hash means re-triage */
  inputHash: z.string(),
  /** Triage config name, e.g. 'v3-opus-high-code' */
  config: z.string(),
  /** Prompt fingerprint, e.g. 'v3@1a2b3c4d' */
  prompt: z.string(),
  /** Resolved model id, e.g. 'claude-opus-5-5' */
  model: z.string().nullable(),
  triagedAt: z.string(),
  /** Commit and ref the triage read; evidence file:line refer to this commit */
  commit: z.string(),
  ref: z.string(),
  costUsd: z.number().nullable(),
  durationMs: z.number().nullable(),
  output: TriageOutputSchema,
});
export type StoredVerdict = z.infer<typeof StoredVerdictSchema>;

/** .vigiles/verdicts.json. Entries are sorted (osvId, ecosystem, packageName, lockfile) so diffs stay small. */
export interface VerdictFile {
  format: typeof STATE_FORMAT;
  verdicts: StoredVerdict[];
}

// ---------- triage failures (cache only, never committed) ----------

export interface TriageFailure {
  inputHash: string;
  error: string;
  at: string;
}

/** <cache>/repos/<projectKey>/triage-failures.json, keyed by ScanFinding.id */
export type TriageFailures = Record<string, TriageFailure>;

// ---------- decisions ----------

export interface DecidedFinding {
  finding: ScanFinding;
  advisory: ScanAdvisory | null;
  /** ok = a verdict for the current inputs; failed = last triage of these inputs failed; pending = not triaged; skipped = malicious (no LLM) */
  triageStatus: TriageStatus;
  /** The verdict used (triageStatus ok only) */
  verdict: StoredVerdict | null;
  /** The failure message (triageStatus failed only) */
  failure: string | null;
  action: Action;
  /** Policy rule id, or 'same-advisory' when raised to match another package of the same advisory */
  ruleId: string;
  inputs: DecisionInputs;
}

export interface Decisions {
  policyHash: string;
  findings: DecidedFinding[];
  counts: Record<Action, number> & { untriaged: number };
}

/** Labels used in the report and in CLI output. */
export const ACTION_LABELS: Record<Action, string> = {
  ping: 'Fix now',
  digest: 'Fix soon',
  log: 'Logged',
};

/** POC averages for prompt v3 on Opus at effort high (docs/poc-results.md): used for the estimate shown before triage. */
export const TRIAGE_ESTIMATE = { usdPerFinding: 0.12, secondsPerFinding: 21 } as const;
