/**
 * The Vigiles CLI: `plugin/bin/vigiles` (bundled from src/plugin/main.ts, which calls main() below) and
 * `npm run vigiles` in development. The /vigiles:audit skill drives it; people can run it directly too.
 *
 *   doctor · init · profile · scan · triage · report · audit
 *
 * Results go to stdout and progress to stderr; both are written to be read by Claude and by people. Exit codes:
 * 0 ok, 1 unexpected error, 2 an input to fix (usage, profile, missing or stale scan, verdicts.json), 3 a missing
 * prerequisite (Node, git, osv-scanner, claude or its login, the plugin's files, a writable cache), 130 interrupted.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { loadPolicy } from '../lib/config/load';
import { relativeTime, shortDate } from '../lib/format';
import { gitResolveRef } from '../lib/git';
import { minimalEnv, runProcess } from '../lib/proc';
import { triageProfileHash } from '../lib/triage/profile';
import { PRIORITIES, type Priority } from '../lib/types';
import { decide } from './decide';
import { currentBranch } from './git-info';
import { readSidecar } from './osv-db';
import {
  bins as defaultBins,
  cacheDir,
  ensureDir,
  findAssetRoot,
  assertRealDirectory,
  findRepoRoot,
  pluginPaths,
  repoPaths,
  UnsafeRepoFileError,
  VIGILES_GITIGNORE,
  writeRepoFile,
  type Bins,
  type PluginPaths,
} from './paths';
import {
  detectFacts,
  formatFacts,
  loadProfile,
  ProfileInvalidError,
  ProfileMissingError,
  profileTemplate,
  toProjectProfile,
} from './profile';
import { renderReport, renderSummary } from './report';
import { assertSafeRef, InvalidRefError, loadTriageConfig, readScanResult, runScan, type RunScanOptions } from './scan';
import {
  assertScanCurrent,
  interruptSignal,
  rescanCommand,
  runTriage,
  selectFindings,
  StaleScanError,
  type ClaudeRunner,
  type TriageSummary,
} from './triage';
import { TRIAGE_ESTIMATE, type PluginProfile, type ScanResult, type TriageFailures } from './types';
import { loadFailures, loadVerdicts, type VerdictStore } from './verdicts';

/** Set by the bundle build (scripts/build-plugin.mjs) from plugin/.claude-plugin/plugin.json; undefined from source. */
declare const __VIGILES_VERSION__: string | undefined;

export const EXIT = { ok: 0, error: 1, input: 2, prerequisite: 3, interrupted: 130 } as const;

/** An error with the exit code it maps to; its message is printed as is. */
export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number = EXIT.input,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

export interface CliDeps {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** One call per line (no trailing newline) */
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  /** Default: findAssetRoot() */
  assetRoot?: string;
  /** Test hooks for runScan (no network, no osv-scanner) */
  scan?: Pick<RunScanOptions, 'fetchFn' | 'runOsvScanner' | 'osvBaseUrl' | 'clock'>;
  /** Test hook for triage (no claude) */
  runClaude?: ClaudeRunner;
  /** Replaces the SIGINT/SIGTERM handling */
  signal?: AbortSignal;
  now?: () => Date;
}

interface Ctx {
  cwd: string;
  env: NodeJS.ProcessEnv;
  out: (...lines: string[]) => void;
  err: (...lines: string[]) => void;
  bins: Bins;
  deps: CliDeps;
  now: () => Date;
  version: string;
  signal?: AbortSignal;
  /** Lazily resolved: --help and --version work without the assets */
  plugin: () => PluginPaths;
}

// ---------- version ----------

/** The plugin version: the bundle's build-time constant, else plugin.json next to the assets (source runs). */
export function toolVersion(assetRoot: string | null): string {
  if (typeof __VIGILES_VERSION__ === 'string') return __VIGILES_VERSION__;
  const candidates = assetRoot
    ? [path.join(assetRoot, '.claude-plugin', 'plugin.json'), path.join(assetRoot, 'plugin', '.claude-plugin', 'plugin.json')]
    : [];
  for (const file of candidates) {
    try {
      const version = (JSON.parse(readFileSync(file, 'utf8')) as { version?: unknown }).version;
      if (typeof version === 'string') return version;
    } catch {
      // try the next one
    }
  }
  return '0.0.0-dev';
}

// ---------- commands and options ----------

type OptionDef = { type: 'string' | 'boolean'; multiple?: boolean; short?: string };
type Values = Record<string, string | boolean | (string | boolean)[] | undefined>;

interface CommandDef {
  summary: string;
  options: Record<string, OptionDef>;
  /** [flag, description] lines for the help */
  help: [string, string][];
  run: (ctx: Ctx, values: Values) => Promise<number>;
}

const REPO_HELP: [string, string] = ['--repo <path>', 'Repository to audit (default: the current directory)'];
const SCAN_OPTIONS: Record<string, OptionDef> = { ref: { type: 'string' }, fetch: { type: 'boolean' }, 'refresh-db': { type: 'boolean' } };
const SCAN_HELP: [string, string][] = [
  ['--ref <ref>', 'Audit this ref instead of the checked-out commit (HEAD), e.g. origin/main'],
  ['--fetch', 'git fetch the remote-tracking ref (origin/main) first'],
  ['--refresh-db', 'Re-check the OSV databases and the CISA KEV catalog now (default: once a day)'],
];
const TRIAGE_OPTIONS: Record<string, OptionDef> = {
  limit: { type: 'string' },
  only: { type: 'string', multiple: true },
  force: { type: 'boolean' },
  concurrency: { type: 'string' },
};
const TRIAGE_HELP: [string, string][] = [
  ['--limit <n>', 'Triage at most n findings, most urgent first'],
  ['--only <ids>', 'Only these advisories: OSV, GHSA or CVE ids, or finding ids (comma-separated or repeated)'],
  ['--force', 'Triage again even when a verdict for the current inputs exists'],
  ['--concurrency <n>', 'Claude runs in parallel (default 3)'],
];

const COMMANDS: Record<string, CommandDef> = {
  doctor: {
    summary: 'Check Node, git, osv-scanner, claude (and its login), the cache, the repository and the profile',
    options: {},
    help: [],
    run: doctorCommand,
  },
  init: {
    summary: 'Create .vigiles/ and print detected facts and a profile template (never overwrites a profile)',
    options: {},
    help: [],
    run: initCommand,
  },
  profile: {
    summary: 'Validate .vigiles/profile.yaml and summarize it',
    options: {},
    help: [],
    run: profileCommand,
  },
  scan: {
    summary: 'Match the lockfiles against OSV, add KEV/EPSS signals, and show what needs triage',
    options: { ...SCAN_OPTIONS, json: { type: 'boolean' } },
    help: [...SCAN_HELP, ['--json', 'Print a machine-readable summary']],
    run: scanCommand,
  },
  triage: {
    summary: 'Triage the findings of the last scan that have no current verdict (spends Claude usage)',
    options: TRIAGE_OPTIONS,
    help: TRIAGE_HELP,
    run: triageCommand,
  },
  report: {
    summary: 'Apply the decision policy and write .vigiles/report.md',
    options: {},
    help: [],
    run: reportCommand,
  },
  audit: {
    summary: 'scan, then triage everything that needs it, then report',
    options: { ...SCAN_OPTIONS, ...TRIAGE_OPTIONS },
    help: [...SCAN_HELP, ...TRIAGE_HELP],
    run: auditCommand,
  },
};

const COMMON_OPTIONS: Record<string, OptionDef> = { repo: { type: 'string' }, help: { type: 'boolean', short: 'h' } };

function helpRows(rows: [string, string][], indent: string): string[] {
  const width = Math.max(0, ...rows.map(([flag]) => flag.length)) + 2;
  return rows.map(([flag, text]) => `${indent}${flag.padEnd(width)}${text}`);
}

export function usage(version: string, env: NodeJS.ProcessEnv = process.env): string {
  const names = Object.keys(COMMANDS);
  const width = Math.max(...names.map((n) => n.length)) + 2;
  return [
    `vigiles ${version}: dependency vulnerability audit (the /vigiles:audit Claude Code skill)`,
    '',
    'Usage: vigiles <command> [options]',
    '',
    'Commands:',
    ...names.map((n) => `  ${n.padEnd(width)}${COMMANDS[n]!.summary}`),
    '',
    'Options:',
    ...helpRows([REPO_HELP, ['-h, --help', 'Help for a command (vigiles scan --help)'], ['--version', 'Print the version']], '  '),
    '',
    'Exit codes: 0 ok · 1 error · 2 fix the named input (usage, profile, scan, verdicts.json) · 3 missing prerequisite',
    'Files: commit .vigiles/ (profile.yaml, verdicts.json, .gitignore); .vigiles/report.md is gitignored.',
    `Cache: ${cacheDir(env)} (OSV databases, KEV catalog, code snapshots, last scan).`,
  ].join('\n');
}

function commandUsage(name: string): string {
  const def = COMMANDS[name]!;
  const flags = def.help.map(([flag]) => `[${flag}]`).join(' ');
  return [
    `Usage: vigiles ${name} ${flags ? `${flags} ` : ''}[--repo <path>]`,
    '',
    def.summary,
    '',
    'Options:',
    ...helpRows([...def.help, REPO_HELP], '  '),
  ].join('\n');
}

function parseCommandArgs(name: string, args: string[]): Values {
  const options = { ...COMMON_OPTIONS, ...COMMANDS[name]!.options };
  try {
    return parseArgs({ args, options, strict: true, allowPositionals: false }).values as Values;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    const message = err instanceof Error ? err.message : String(err);
    const quoted = /'([^']+)'/.exec(message)?.[1];
    let text: string;
    if (code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') text = `unknown option ${quoted ?? ''} for ${name}`;
    else if (code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL') text = `unexpected argument ${quoted ?? ''} for ${name}`;
    else if (code === 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE') {
      const option = /'(-[\w-]+)/.exec(message)?.[1] ?? 'an option';
      if (/argument missing/.test(message)) text = `${option} needs a value`;
      // The next argument starts with '-' (`--limit -1`, or a forgotten value before another option).
      else if (/ambiguous/.test(message)) text = `${option} needs a value (for a value starting with -, write ${option}=<value>)`;
      else if (/does not take an argument/.test(message)) text = `${option} takes no value`;
      else text = message;
    } else text = message;
    throw new CliError(`${text.replace(/\s+/g, ' ').trim()}; see \`vigiles ${name} --help\``);
  }
}

function stringOpt(values: Values, key: string): string | undefined {
  const v = values[key];
  return typeof v === 'string' ? v : undefined;
}

function boolOpt(values: Values, key: string): boolean {
  return values[key] === true;
}

function intOpt(values: Values, key: string, min: number, max = Number.MAX_SAFE_INTEGER): number | undefined {
  const raw = stringOpt(values, key);
  if (raw === undefined) return undefined;
  if (!/^\d+$/.test(raw.trim()) || Number(raw) < min || Number(raw) > max) {
    throw new CliError(
      `--${key} must be a whole number${max < Number.MAX_SAFE_INTEGER ? ` from ${min} to ${max}` : ` of at least ${min}`} (got "${raw}")`,
    );
  }
  return Number(raw);
}

/** --only a,b --only c → [a, b, c] */
function listOpt(values: Values, key: string): string[] | undefined {
  const v = values[key];
  if (v === undefined) return undefined;
  const items = (Array.isArray(v) ? v : [v])
    .filter((x): x is string => typeof x === 'string')
    .flatMap((x) => x.split(','))
    .map((x) => x.trim())
    .filter(Boolean);
  if (!items.length) throw new CliError(`--${key} needs at least one id`);
  return items;
}

// ---------- shared steps ----------

function errorCode(err: unknown): string | undefined {
  for (let e: unknown = err; e; e = (e as { cause?: unknown }).cause) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code) return code;
  }
  return undefined;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The top-level directory of the repository at --repo (default: the working directory). */
async function resolveRepo(ctx: Ctx, values: Values): Promise<string> {
  const dir = path.resolve(ctx.cwd, stringOpt(values, 'repo') ?? '.');
  if (!existsSync(dir)) throw new CliError(`${dir} does not exist`);
  try {
    return await findRepoRoot(dir, ctx.bins.git);
  } catch (err) {
    if (errorCode(err) === 'ENOENT') throw new CliError(`git not found (${ctx.bins.git}); install git`, EXIT.prerequisite);
    throw new CliError(message(err));
  }
}

function profileFile(repoRoot: string): string {
  return path.join(repoRoot, '.vigiles', 'profile.yaml');
}

/** Writes .vigiles/.gitignore (ignoring report.md) unless there is one already. Refuses a symlinked .vigiles/. */
function ensureVigilesGitignore(vigilesDir: string): boolean {
  assertRealDirectory(vigilesDir);
  const file = path.join(vigilesDir, '.gitignore');
  if (existsSync(file)) return false;
  mkdirSync(vigilesDir, { recursive: true });
  writeRepoFile(file, VIGILES_GITIGNORE);
  return true;
}

/** A path as the user should see it: relative to the working directory when inside it. */
function shown(ctx: Ctx, file: string): string {
  const rel = path.relative(ctx.cwd, file);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : file;
}

/** `HEAD (main)`, `detached HEAD` or the requested ref. */
export function refText(scan: Pick<ScanResult, 'ref' | 'branch'>): string {
  if (scan.ref === 'HEAD') return scan.branch ? `HEAD (${scan.branch})` : 'detached HEAD';
  return scan.ref;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
}

interface LoadedState {
  repoRoot: string;
  plugin: PluginPaths;
  profile: PluginProfile;
  profileWarnings: string[];
  paths: ReturnType<typeof repoPaths>;
  scan: ScanResult;
  verdicts: VerdictStore;
  verdictWarnings: string[];
  failures: TriageFailures;
}

/** Profile, last scan, verdicts and failures of the repository (exit 2 when the scan or verdicts.json is missing or broken). */
async function loadState(ctx: Ctx, values: Values): Promise<LoadedState> {
  const repoRoot = await resolveRepo(ctx, values);
  const plugin = ctx.plugin();
  const { profile, warnings: profileWarnings } = loadProfile(profileFile(repoRoot));
  const paths = repoPaths(repoRoot, profile.id, plugin);
  let scan: ScanResult | null;
  try {
    scan = readScanResult(paths.scanFile);
  } catch (err) {
    throw new CliError(`the last scan cannot be read (${message(err)}); run \`vigiles scan\` again`);
  }
  if (!scan) throw new CliError('no scan of this repository yet; run `vigiles scan` first');
  let loaded: ReturnType<typeof loadVerdicts>;
  try {
    loaded = loadVerdicts(paths.verdictsFile);
  } catch (err) {
    throw new CliError(message(err));
  }
  return {
    repoRoot,
    plugin,
    profile,
    profileWarnings,
    paths,
    scan,
    verdicts: loaded.store,
    verdictWarnings: loaded.warnings,
    failures: loadFailures(paths.failuresFile),
  };
}

// ---------- scan summary ----------

export interface ScanSummary {
  ref: string;
  branch: string | null;
  commit: string;
  commitDate: string | null;
  lockfiles: string[];
  skippedLockfiles: string[];
  /** Manifests without a lockfile: their dependencies are not audited */
  manifestsWithoutLockfile: string[];
  packages: number;
  findings: number;
  vulnerablePackages: number;
  byPriority: Record<Priority, number>;
  /** Findings with a verdict for their current inputs */
  current: number;
  /** Findings that need triage (no verdict, or one made for other inputs) */
  toTriage: number;
  /** Of toTriage: findings whose verdict was made for older inputs */
  changed: number;
  /** Of toTriage: findings whose last triage of the same inputs failed */
  failedBefore: number;
  /** Malicious packages: never triaged, always Fix now */
  malicious: number;
  estimate: { findings: number; usd: number; seconds: number; concurrency: number };
  warnings: string[];
}

export function summarizeScan(scan: ScanResult, verdicts: VerdictStore, failures: TriageFailures): ScanSummary {
  const selection = selectFindings(scan, verdicts);
  const byPriority = Object.fromEntries(PRIORITIES.map((p) => [p, 0])) as Record<Priority, number>;
  for (const f of scan.findings) byPriority[f.priority]++;
  const n = selection.eligible.length;
  const concurrency = Math.max(1, scan.triageConfig.concurrency);
  return {
    ref: scan.ref,
    branch: scan.branch,
    commit: scan.commit,
    commitDate: scan.commitDate,
    lockfiles: scan.lockfiles,
    skippedLockfiles: scan.skippedLockfiles,
    manifestsWithoutLockfile: scan.coverageGaps.filter((g) => !scan.skippedLockfiles.includes(g)),
    packages: scan.stats.packages,
    findings: scan.findings.length,
    vulnerablePackages: scan.stats.vulnerablePackages,
    byPriority,
    current: selection.alreadyCurrent,
    toTriage: n,
    changed: selection.eligible.filter((f) => verdicts.get(f)).length,
    failedBefore: selection.eligible.filter((f) => failures[f.id]?.inputHash === f.inputHash).length,
    malicious: selection.malicious,
    estimate: {
      findings: n,
      usd: Math.round(n * TRIAGE_ESTIMATE.usdPerFinding * 100) / 100,
      seconds: Math.ceil(n / concurrency) * TRIAGE_ESTIMATE.secondsPerFinding,
      concurrency,
    },
    warnings: scan.warnings,
  };
}

function aboutDuration(seconds: number): string {
  if (seconds < 60) return 'under a minute';
  const minutes = Math.round(seconds / 60);
  return minutes < 90 ? `about ${minutes} min` : `about ${(seconds / 3600).toFixed(1)} h`;
}

function aboutUsd(usd: number): string {
  return usd >= 10 ? `$${Math.round(usd)}` : `$${usd.toFixed(2)}`;
}

export function formatScanSummary(s: ScanSummary): string[] {
  const committed = s.commitDate ? ` (committed ${shortDate(s.commitDate, 'UTC')})` : '';
  const lines = [
    `Audited ${refText(s)} at ${s.commit.slice(0, 10)}${committed}: ${plural(s.lockfiles.length, 'lockfile')}, ${plural(s.packages, 'package')}`,
  ];
  if (s.lockfiles.length) lines.push(`  lockfiles: ${s.lockfiles.join(', ')}`);
  if (s.skippedLockfiles.length) lines.push(`  skipped (not audited): ${s.skippedLockfiles.join(', ')}`);
  if (s.manifestsWithoutLockfile.length) lines.push(`  no lockfile (not audited): ${s.manifestsWithoutLockfile.join(', ')}`);
  if (!s.findings) {
    lines.push('Findings: none. No known vulnerabilities in the audited lockfiles.');
  } else {
    const prio = PRIORITIES.map((p) => `${p} ${s.byPriority[p]}`).join(' · ');
    lines.push(`Findings: ${s.findings} in ${plural(s.vulnerablePackages, 'package')} (${prio})`);
    const detail = [
      ...(s.changed ? [`${s.changed} changed since their verdict`] : []),
      ...(s.failedBefore ? [`${s.failedBefore} failed last time`] : []),
    ];
    lines.push(
      `Verdicts: ${s.current} cached (current) · ${s.toTriage} to triage${detail.length ? ` (${detail.join(', ')})` : ''}` +
        (s.malicious ? ` · ${s.malicious} malicious (never triaged; always Fix now)` : ''),
    );
    if (s.toTriage) {
      const e = s.estimate;
      lines.push(
        `Estimate: ${plural(e.findings, 'finding')}, ${aboutDuration(e.seconds)} (${e.concurrency} at a time), about ` +
          `${aboutUsd(e.usd)} of Claude usage at API list prices`,
      );
    }
  }
  if (s.warnings.length) lines.push('Warnings:', ...s.warnings.map((w) => `  - ${w.replace(/\s+/g, ' ')}`));
  lines.push(
    s.toTriage ? 'Next: `vigiles triage` (--limit <n> for the most urgent first), then `vigiles report`' : 'Next: `vigiles report`',
  );
  return lines;
}

// ---------- doctor ----------

type CheckStatus = 'ok' | 'missing' | 'warn';

async function versionOf(
  bin: string,
  args: string[],
  env?: NodeJS.ProcessEnv,
): Promise<{ ok: true; text: string } | { ok: false; reason: string }> {
  try {
    const r = await runProcess(bin, args, { timeoutMs: 20_000, env });
    const text = `${r.stdout}\n${r.stderr}`.trim().split('\n')[0]!.trim();
    if (r.code !== 0) return { ok: false, reason: `exited ${r.code ?? r.signal}${text ? `: ${text}` : ''}` };
    return { ok: true, text };
  } catch (err) {
    return { ok: false, reason: errorCode(err) === 'ENOENT' ? 'not found' : message(err) };
  }
}

function semver(text: string): { text: string; major: number } | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(text);
  return m ? { text: m[0], major: Number(m[1]) } : null;
}

/** `claude auth status --json` under the environment triage uses (minimalEnv: no API keys from the shell). */
async function claudeLogin(bin: string): Promise<{ status: CheckStatus; detail: string }> {
  let r;
  try {
    r = await runProcess(bin, ['auth', 'status', '--json'], { timeoutMs: 20_000, env: minimalEnv() });
  } catch (err) {
    return { status: 'warn', detail: `could not check (${message(err)})` };
  }
  let status: { loggedIn?: unknown; authMethod?: unknown; subscriptionType?: unknown };
  try {
    status = JSON.parse(r.stdout) as typeof status;
  } catch {
    const text = `${r.stdout}\n${r.stderr}`.trim().split('\n')[0] ?? '';
    return { status: 'warn', detail: `could not check (\`claude auth status\` said: ${text.slice(0, 160) || `exit ${r.code}`})` };
  }
  if (status.loggedIn === true) {
    const how = [status.authMethod, status.subscriptionType].filter((x): x is string => typeof x === 'string' && x !== '');
    return { status: 'ok', detail: `logged in${how.length ? ` (${how.join(', ')})` : ''}` };
  }
  return {
    status: 'missing',
    detail: 'not logged in; run `claude` in a terminal and log in with /login (triage runs claude without API keys from your shell)',
  };
}

function cachedOsvDatabases(osvDbDir: string, now: Date): string {
  let ecosystems: string[];
  try {
    ecosystems = readdirSync(path.join(osvDbDir, 'osv-scalibr')).filter((e) =>
      existsSync(path.join(osvDbDir, 'osv-scalibr', e, 'all.zip')),
    );
  } catch {
    ecosystems = [];
  }
  if (!ecosystems.length) return 'none downloaded yet; the first scan downloads what the lockfiles need (npm is about 200 MB)';
  return ecosystems
    .sort()
    .map((e) => {
      const checked = readSidecar(osvDbDir, e).checkedAt;
      return checked ? `${e} (checked ${relativeTime(checked, now)})` : e;
    })
    .join(', ');
}

async function doctorCommand(ctx: Ctx, values: Values): Promise<number> {
  let prerequisiteMissing = false;
  let inputProblem = false;
  const line = (status: CheckStatus, check: string, detail: string) => {
    if (status === 'missing') prerequisiteMissing = true;
    ctx.out(`${status} ${check}: ${detail}`);
  };

  const node = process.versions.node;
  if (Number(node.split('.')[0]) >= 20) line('ok', 'node', node);
  else line('missing', 'node', `${node}; Vigiles needs Node.js 20 or newer`);

  let plugin: PluginPaths | null = null;
  try {
    plugin = ctx.plugin();
    const tc = loadTriageConfig(plugin.assetRoot);
    line('ok', 'vigiles', `${ctx.version} (triage ${tc.name}, prompt ${tc.promptFingerprint})`);
  } catch (err) {
    line('missing', 'vigiles', `the plugin's files are incomplete: ${message(err)}; reinstall the plugin`);
  }

  const git = await versionOf(ctx.bins.git, ['--version']);
  if (git.ok) line('ok', 'git', semver(git.text)?.text ?? git.text);
  else line('missing', 'git', `${git.reason} (${ctx.bins.git}); install git`);

  const osv = await versionOf(ctx.bins.osvScanner, ['--version']);
  const osvVersion = osv.ok ? semver(osv.text) : null;
  if (!osv.ok) {
    line(
      'missing',
      'osv-scanner',
      `${osv.reason} (${ctx.bins.osvScanner}); install it: \`brew install osv-scanner\` or https://google.github.io/osv-scanner/installation/`,
    );
  } else if (osvVersion && osvVersion.major < 2) {
    line('missing', 'osv-scanner', `${osvVersion.text}; Vigiles needs osv-scanner 2 or newer (\`brew upgrade osv-scanner\`)`);
  } else {
    line('ok', 'osv-scanner', osvVersion?.text ?? osv.text);
  }

  const claude = await versionOf(ctx.bins.claude, ['--version'], minimalEnv());
  if (!claude.ok) {
    line('missing', 'claude', `${claude.reason} (${ctx.bins.claude}); install Claude Code: https://claude.com/claude-code`);
  } else {
    line('ok', 'claude', semver(claude.text)?.text ?? claude.text);
    const login = await claudeLogin(ctx.bins.claude);
    line(login.status, 'claude login', login.detail);
  }

  const cache = plugin?.cacheDir ?? cacheDir(ctx.env);
  try {
    ensureDir(cache);
    const probe = path.join(cache, `.write-test-${process.pid}`);
    writeFileSync(probe, '');
    rmSync(probe, { force: true });
    line('ok', 'cache', `${cache} (writable)`);
    if (plugin) line('ok', 'osv databases', cachedOsvDatabases(plugin.osvDbDir, ctx.now()));
  } catch (err) {
    line('missing', 'cache', `${cache} is not writable (${message(err)}); set VIGILES_CACHE_DIR to a writable directory`);
  }

  let repoRoot: string | null = null;
  try {
    repoRoot = await resolveRepo(ctx, values);
  } catch (err) {
    if (err instanceof CliError && err.exitCode === EXIT.prerequisite) {
      // git itself is missing: already reported
    } else {
      inputProblem = true;
      ctx.out(`missing repository: ${message(err)}; run Vigiles inside the repository to audit`);
    }
  }
  if (repoRoot) {
    const branch = await currentBranch(ctx.bins.git, repoRoot).catch(() => null);
    const head = await gitResolveRef(ctx.bins.git, repoRoot, 'HEAD').catch(() => null);
    if (head) line('ok', 'repository', `${repoRoot} (${branch ?? 'detached HEAD'} @ ${head.sha.slice(0, 7)})`);
    else line('warn', 'repository', `${repoRoot} has no commit yet; Vigiles audits committed lockfiles`);

    try {
      const { profile, warnings } = loadProfile(profileFile(repoRoot));
      line('ok', 'profile', `.vigiles/profile.yaml (${profile.id}: ${profile.exposure}, criticality ${profile.criticality})`);
      for (const w of warnings) line('warn', 'profile', w.replace(/^profile: /, ''));
      if (plugin) {
        const scan = (() => {
          try {
            return readScanResult(repoPaths(repoRoot, profile.id, plugin).scanFile);
          } catch {
            return null;
          }
        })();
        if (scan) {
          line(
            'ok',
            'last scan',
            `${refText(scan)} @ ${scan.commit.slice(0, 7)}, ${relativeTime(scan.scannedAt, ctx.now())}: ${plural(scan.findings.length, 'finding')}`,
          );
        }
      }
    } catch (err) {
      if (err instanceof ProfileMissingError) {
        ctx.out('missing profile: no .vigiles/profile.yaml yet; run `vigiles init` to create one');
      } else {
        const lines = message(err).split('\n');
        const detail = (lines[1] ?? lines[0] ?? '').trim().replace(/^Invalid \S+: /, '');
        ctx.out(`warn profile: invalid (${detail}); run \`vigiles profile\` for details`);
      }
    }
  }

  if (prerequisiteMissing) return EXIT.prerequisite;
  return inputProblem ? EXIT.input : EXIT.ok;
}

// ---------- init ----------

async function initCommand(ctx: Ctx, values: Values): Promise<number> {
  const repoRoot = await resolveRepo(ctx, values);
  const vigilesDir = path.join(repoRoot, '.vigiles');
  assertRealDirectory(vigilesDir);
  const createdDir = !existsSync(vigilesDir);
  mkdirSync(vigilesDir, { recursive: true });
  const createdIgnore = ensureVigilesGitignore(vigilesDir);
  const file = profileFile(repoRoot);
  const exists = existsSync(file);

  const created = [...(createdDir ? ['.vigiles/'] : []), ...(createdIgnore ? ['.vigiles/.gitignore (ignores report.md)'] : [])];
  if (created.length) ctx.out(`Created ${created.join(' and ')}.`);
  if (exists) {
    ctx.out(`${shown(ctx, file)} already exists and was not changed; run \`vigiles profile\` to check it.`);
  } else {
    ctx.out(`No profile yet. Write ${shown(ctx, file)} from the template below: replace every TODO, then run \`vigiles profile\`.`);
  }

  const facts = await detectFacts(repoRoot, ctx.bins.git);
  ctx.out('', '## Detected at HEAD', '', formatFacts(facts));
  ctx.out('', exists ? '## Profile template (for reference)' : '## Profile template', '', profileTemplate(facts).trimEnd());
  return EXIT.ok;
}

// ---------- profile ----------

async function profileCommand(ctx: Ctx, values: Values): Promise<number> {
  const repoRoot = await resolveRepo(ctx, values);
  const file = profileFile(repoRoot);
  const { profile, warnings } = loadProfile(file);
  const hash = triageProfileHash(toProjectProfile(profile, repoRoot));
  const list = (items: string[]) => (items.length ? items.join(', ') : 'none');
  ctx.out(
    `${shown(ctx, file)} is valid.`,
    `  id: ${profile.id} · name: ${profile.name} · production branch: ${profile.ref}`,
    `  exposure: ${profile.exposure} · criticality: ${profile.criticality} · data classes: ${list(profile.data_classes)}`,
    `  deployments: ${profile.deployments.length} · third-party services: ${list(profile.third_party_services)}`,
    `  triage profile hash: ${hash} (verdicts are reused while it stays the same)`,
  );
  for (const w of warnings) ctx.out(`warn: ${w.replace(/^profile: /, '')}`);

  let scan: ScanResult | null = null;
  try {
    scan = readScanResult(repoPaths(repoRoot, profile.id, ctx.plugin()).scanFile);
  } catch {
    scan = null;
  }
  if (scan && scan.profileHash !== hash) {
    ctx.out('Changed since the last scan: run `vigiles scan`; findings are triaged again under the new profile.');
  }
  return EXIT.ok;
}

// ---------- scan ----------

/** Refuses a --ref git could read as an option or a refspec, before any work (runScan checks it again). */
function refArg(values: Values): string | undefined {
  const ref = stringOpt(values, 'ref');
  if (ref === undefined) return undefined;
  try {
    assertSafeRef(ref);
  } catch (err) {
    throw new CliError(message(err));
  }
  return ref;
}

async function scan(ctx: Ctx, values: Values): Promise<{ result: ScanResult; summary: ScanSummary }> {
  const ref = refArg(values);
  const repoRoot = await resolveRepo(ctx, values);
  const plugin = ctx.plugin();
  let result: ScanResult;
  try {
    result = await runScan({
      repoRoot,
      plugin,
      toolVersion: ctx.version,
      ref,
      fetch: boolOpt(values, 'fetch'),
      refreshDb: boolOpt(values, 'refresh-db'),
      bins: ctx.bins,
      signal: ctx.signal,
      progress: (l) => ctx.err(`· ${l}`),
      ...ctx.deps.scan,
    });
  } catch (err) {
    if (err instanceof ProfileMissingError || err instanceof ProfileInvalidError || ctx.signal?.aborted) throw err;
    if (err instanceof InvalidRefError) throw new CliError(message(err));
    if (message(err).startsWith('osv-scanner not found')) throw new CliError(message(err), EXIT.prerequisite);
    if (message(err).startsWith('cannot resolve ')) throw new CliError(message(err));
    throw err;
  }
  const paths = repoPaths(repoRoot, result.projectId, plugin);
  const { store } = loadVerdictsOrFail(paths.verdictsFile);
  return { result, summary: summarizeScan(result, store, loadFailures(paths.failuresFile)) };
}

function loadVerdictsOrFail(file: string): ReturnType<typeof loadVerdicts> {
  try {
    return loadVerdicts(file);
  } catch (err) {
    throw new CliError(message(err));
  }
}

async function scanCommand(ctx: Ctx, values: Values): Promise<number> {
  const { summary } = await scan(ctx, values);
  if (boolOpt(values, 'json')) ctx.out(JSON.stringify(summary, null, 2));
  else ctx.out(...formatScanSummary(summary));
  return EXIT.ok;
}

// ---------- triage ----------

interface TriageArgs {
  limit?: number;
  only?: string[];
  force: boolean;
  concurrency?: number;
}

/** Validated before any work starts (audit would otherwise find a bad --limit only after the scan). */
function triageArgs(values: Values): TriageArgs {
  return {
    limit: intOpt(values, 'limit', 0),
    only: listOpt(values, 'only'),
    force: boolOpt(values, 'force'),
    concurrency: intOpt(values, 'concurrency', 1, 10),
  };
}

async function triage(ctx: Ctx, values: Values, args: TriageArgs): Promise<{ summary: TriageSummary; exitCode: number }> {
  const state = await loadState(ctx, values);
  const { scan, paths } = state;
  for (const w of state.verdictWarnings) ctx.err(`warning: ${w}`);
  const { only } = args;
  ensureVigilesGitignore(paths.vigilesDir);
  ctx.out(`Triage of ${refText(scan)} @ ${scan.commit.slice(0, 7)} (scanned ${relativeTime(scan.scannedAt, ctx.now())})`);

  const summary = await runTriage({
    scan,
    profile: toProjectProfile(state.profile, state.repoRoot),
    assetRoot: state.plugin.assetRoot,
    verdicts: state.verdicts,
    verdictsFile: paths.verdictsFile,
    failures: state.failures,
    failuresFile: paths.failuresFile,
    scratchDir: state.plugin.scratchDir,
    git: ctx.bins.git,
    claudeBin: ctx.bins.claude,
    limit: args.limit,
    only,
    force: args.force,
    concurrency: args.concurrency,
    signal: ctx.signal,
    log: (l) => ctx.out(l),
    runClaude: ctx.deps.runClaude,
    now: ctx.now,
  });

  if (summary.selected === 0) {
    if (summary.unmatched.length) ctx.out(`No finding matched: ${summary.unmatched.join(', ')}`);
    if (only && summary.unmatched.length === only.length) return { summary, exitCode: EXIT.input };
    if (summary.eligible > 0) {
      ctx.out(`Nothing triaged (--limit 0); ${plural(summary.eligible, 'finding')} still need triage.`);
    } else {
      const parts = [
        `${plural(summary.alreadyCurrent, 'finding')} already ${summary.alreadyCurrent === 1 ? 'has' : 'have'} a current verdict`,
        ...(summary.malicious ? [`${summary.malicious} malicious (never triaged)`] : []),
      ];
      ctx.out(`Nothing to triage: ${parts.join('; ')}.`);
    }
  }
  if (summary.interrupted) return { summary, exitCode: EXIT.interrupted };
  if (summary.stopReason) return { summary, exitCode: EXIT.prerequisite };
  return { summary, exitCode: EXIT.ok };
}

async function triageCommand(ctx: Ctx, values: Values): Promise<number> {
  const { exitCode } = await triage(ctx, values, triageArgs(values));
  if (exitCode === EXIT.ok || exitCode === EXIT.prerequisite) ctx.out('Next: `vigiles report`');
  return exitCode;
}

// ---------- report ----------

/** Why the report may not describe what the developer expects: inputs changed after the scan. */
async function staleness(ctx: Ctx, state: LoadedState): Promise<string[]> {
  const out: string[] = [];
  try {
    assertScanCurrent(state.scan, toProjectProfile(state.profile, state.repoRoot), state.plugin.assetRoot);
  } catch (err) {
    if (!(err instanceof StaleScanError)) throw err;
    out.push(`${message(err)}; verdicts are checked against the inputs of the last scan until then.`);
  }
  try {
    const { ref } = state.scan;
    const now = await gitResolveRef(ctx.bins.git, state.repoRoot, ref);
    if (now.sha !== state.scan.commit) {
      out.push(
        `${ref} is now at ${now.sha.slice(0, 7)}, but this report is for the scanned commit ${state.scan.commit.slice(0, 7)}; ` +
          `run \`${rescanCommand(ref)}\` to audit the new commit.`,
      );
    }
  } catch {
    // the ref is gone (deleted branch, detached elsewhere): the report still describes the scanned commit
  }
  return out;
}

async function report(ctx: Ctx, values: Values): Promise<number> {
  const state = await loadState(ctx, values);
  const policy = loadPolicy(state.plugin.assetRoot);
  const decisions = decide(state.scan, state.verdicts, state.failures, policy, state.profile);
  const markdown = renderReport({
    scan: state.scan,
    decisions,
    profile: state.profile,
    generatedAt: ctx.now().toISOString(),
    toolVersion: ctx.version,
    warnings: [...state.profileWarnings, ...state.verdictWarnings, ...(await staleness(ctx, state))],
  });
  ensureVigilesGitignore(state.paths.vigilesDir);
  writeRepoFile(state.paths.reportFile, markdown);
  ctx.out(renderSummary(decisions, state.scan, shown(ctx, state.paths.reportFile)));
  return EXIT.ok;
}

async function reportCommand(ctx: Ctx, values: Values): Promise<number> {
  return report(ctx, values);
}

// ---------- audit ----------

async function auditCommand(ctx: Ctx, values: Values): Promise<number> {
  const args = triageArgs(values);
  refArg(values);
  const { summary } = await scan(ctx, values);
  ctx.out(...formatScanSummary(summary).filter((l) => !l.startsWith('Next: ')), '');
  let exitCode: number = EXIT.ok;
  if (summary.toTriage > 0) {
    const result = await triage(ctx, values, args);
    exitCode = result.exitCode;
    if (exitCode === EXIT.interrupted || exitCode === EXIT.input) return exitCode;
    ctx.out('');
  }
  await report(ctx, values);
  return exitCode;
}

// ---------- main ----------

export async function main(argv: string[], deps: CliDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const out = deps.stdout ?? ((l: string) => process.stdout.write(`${l}\n`));
  const err = deps.stderr ?? ((l: string) => process.stderr.write(`${l}\n`));
  let assetRoot: string | null = deps.assetRoot ?? null;
  const resolveAssetRoot = (): string => {
    if (assetRoot) return assetRoot;
    try {
      assetRoot = findAssetRoot(undefined, env);
    } catch (e) {
      throw new CliError(`${message(e)}; reinstall the plugin`, EXIT.prerequisite);
    }
    return assetRoot;
  };
  const version = toolVersion(
    (() => {
      try {
        return resolveAssetRoot();
      } catch {
        return null;
      }
    })(),
  );
  const [command, ...rest] = argv;

  if (command === undefined) {
    err(usage(version, env));
    return EXIT.input;
  }
  if (command === '--version' || command === '-V' || command === 'version') {
    out(`vigiles ${version}`);
    return EXIT.ok;
  }
  if (command === '--help' || command === '-h' || command === 'help') {
    const topic = rest[0];
    out(topic && COMMANDS[topic] ? commandUsage(topic) : usage(version, env));
    return EXIT.ok;
  }
  const def = COMMANDS[command];
  if (!def) {
    err(`vigiles: unknown ${command.startsWith('-') ? 'option' : 'command'} ${command}; run \`vigiles --help\``);
    return EXIT.input;
  }

  let interrupt: { signal: AbortSignal; dispose: () => void } | null = null;
  const ctx: Ctx = {
    cwd: deps.cwd ?? process.cwd(),
    env,
    out: (...lines: string[]) => lines.forEach((l) => out(l)),
    err: (...lines: string[]) => lines.forEach((l) => err(l)),
    bins: defaultBins(env),
    deps,
    now: deps.now ?? (() => new Date()),
    version,
    plugin: () => pluginPaths({ assetRoot: resolveAssetRoot(), env }),
  };
  try {
    const values = parseCommandArgs(command, rest);
    if (values.help) {
      out(commandUsage(command));
      return EXIT.ok;
    }
    if (deps.signal) {
      ctx.signal = deps.signal;
    } else if (command === 'scan' || command === 'triage' || command === 'audit') {
      interrupt = interruptSignal(() =>
        err('vigiles: interrupted; stopping (verdicts saved so far are kept). Press Ctrl-C again to quit at once.'),
      );
      ctx.signal = interrupt.signal;
    }
    return await def.run(ctx, values);
  } catch (e) {
    if (ctx.signal?.aborted) {
      err('vigiles: interrupted');
      return EXIT.interrupted;
    }
    if (e instanceof CliError) {
      err(`vigiles: ${e.message}`);
      return e.exitCode;
    }
    if (e instanceof ProfileMissingError || e instanceof ProfileInvalidError || e instanceof StaleScanError || e instanceof UnsafeRepoFileError) {
      err(`vigiles: ${e.message}`);
      return EXIT.input;
    }
    err(`vigiles: error: ${message(e)}`);
    if (env.VIGILES_DEBUG && e instanceof Error && e.stack) err(e.stack);
    return EXIT.error;
  } finally {
    interrupt?.dispose();
  }
}
