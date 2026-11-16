/**
 * The project profile of the audited repository (.vigiles/profile.yaml): loading and validating it, turning it
 * into the POC's ProjectProfile (whose triage-visible part feeds the prompt and the triage input hash), and the
 * commented template `vigiles init` prints, pre-filled with facts detected from the repository at HEAD.
 */
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { gitLsTree, gitResolveRef, gitShowFile } from '../lib/git';
import { discoverLockfiles, lockfileEcosystem } from '../lib/inventory/lockfiles';
import { runChecked } from '../lib/proc';
import { ProjectProfileSchema, type ProjectProfile } from '../lib/types';
import { currentBranch, defaultRemoteBranch, listRemotes, type GitRemote } from './git-info';
import { readRegularFile, UnsafeRepoFileError } from './paths';
import { PluginProfileSchema, type PluginProfile } from './types';

// ---------- loading ----------

/** No .vigiles/profile.yaml: the CLI tells the user to run `init`. */
export class ProfileMissingError extends Error {
  constructor(readonly file: string) {
    super(`no project profile at ${file}; run \`vigiles init\` and fill it in`);
    this.name = 'ProfileMissingError';
  }
}

/** The profile exists but is not valid YAML or does not match the schema. */
export class ProfileInvalidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProfileInvalidError';
  }
}

export interface LoadedProfile {
  profile: PluginProfile;
  /** Values that still hold a template placeholder; triage reads them as written */
  warnings: string[];
}

const PLACEHOLDER = /⚠|\bTODO\b|Fill in/;

function formatZodError(file: string, err: { issues: { path: PropertyKey[]; message: string }[] }): string {
  const lines = err.issues.map((i) => `  ${i.path.map(String).join('.') || '(root)'}: ${i.message}`);
  return `Invalid ${file}:\n${lines.join('\n')}`;
}

/** Paths (`mitigations`, `deployments[0].hosting`) of string values that still contain a placeholder. */
export function placeholderPaths(value: unknown, at = ''): string[] {
  if (typeof value === 'string') return PLACEHOLDER.test(value) ? [at || '(root)'] : [];
  if (Array.isArray(value)) return value.flatMap((v, i) => placeholderPaths(v, `${at}[${i}]`));
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([k, v]) => placeholderPaths(v, at ? `${at}.${k}` : k));
  }
  return [];
}

/** 1-based line and column of a character offset. */
function lineColumn(text: string, offset: number): { line: number; column: number } {
  const before = text.slice(0, Math.max(0, Math.min(offset, text.length)));
  const lines = before.split('\n');
  return { line: lines.length, column: lines[lines.length - 1]!.length + 1 };
}

/**
 * The YAML error as code and position only. The parser's own message can quote the offending lines, and the
 * message is printed into the Claude session: the file's content must never be echoed.
 */
function yamlErrorText(text: string, err: unknown): string {
  const e = err as { code?: unknown; pos?: unknown };
  const code = typeof e.code === 'string' ? e.code : 'SYNTAX_ERROR';
  const offset = Array.isArray(e.pos) && typeof e.pos[0] === 'number' ? e.pos[0] : null;
  if (offset === null) return `not valid YAML (${code})`;
  const { line, column } = lineColumn(text, offset);
  return `not valid YAML (${code} at line ${line}, column ${column})`;
}

export function loadProfile(file: string): LoadedProfile {
  let text: string;
  try {
    text = readRegularFile(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') throw new ProfileMissingError(file);
    if (err instanceof UnsafeRepoFileError) throw new ProfileInvalidError(err.message);
    throw err;
  }
  let raw: unknown;
  try {
    // logLevel 'error': no warnings printed to the console (they would quote the file too).
    raw = parseYaml(text, { prettyErrors: false, logLevel: 'error' });
  } catch (err) {
    throw new ProfileInvalidError(`Invalid ${file}: ${yamlErrorText(text, err)}`);
  }
  if (raw === null || raw === undefined) throw new ProfileInvalidError(`Invalid ${file}: the file is empty`);
  const parsed = PluginProfileSchema.safeParse(raw);
  if (!parsed.success) throw new ProfileInvalidError(formatZodError(file, parsed.error));
  const placeholders = placeholderPaths(parsed.data);
  const warnings = placeholders.length
    ? [`profile: ${placeholders.join(', ')} still hold a placeholder (⚠, TODO or "Fill in"); triage reads them as written, so fill them in`]
    : [];
  return { profile: parsed.data, warnings };
}

/**
 * The POC's ProjectProfile for this repository (repo_path = the repository root). Key order is the schema's, as in
 * the POC, so triageProfileHash() of the result equals the dashboard's for the same values. repo_path and the other
 * scanner settings are hidden from triage, so where the repository lives never invalidates a verdict.
 */
export function toProjectProfile(p: PluginProfile, repoRoot: string): ProjectProfile {
  return ProjectProfileSchema.parse({ ...p, repo_path: repoRoot });
}

// ---------- detected facts ----------

export interface RepoFacts {
  repoRoot: string;
  /** Kebab-case id derived from the repository directory name */
  suggestedId: string;
  suggestedName: string;
  /** null when the repository has no commit yet */
  head: { commit: string; date: string } | null;
  currentBranch: string | null;
  /** origin's default branch, e.g. 'origin/main' */
  defaultBranch: string | null;
  remotes: GitRemote[];
  lockfiles: { file: string; ecosystem: string }[];
  ecosystems: string[];
  /** Manifests at HEAD with no lockfile (their dependencies cannot be matched) */
  coverageGaps: string[];
  /** Deployment, CI and infrastructure files at HEAD (directories end with '/'), capped at MAX_INFRA_FILES */
  infraFiles: string[];
  infraFilesTotal: number;
  /** Notable runtime packages declared in package.json files next to npm lockfiles */
  frameworks: { manifest: string; packages: string[] }[];
  /** .nvmrc / .node-version / engines.node of the root package.json */
  nodeVersion: string | null;
  /** Guessed from the ecosystems (and TypeScript) */
  languages: string[];
}

export const MAX_INFRA_FILES = 40;
const MAX_MANIFESTS = 20;

const INFRA_BASENAMES: RegExp[] = [
  /^dockerfile/i,
  /^(docker-)?compose([.-].+)?\.ya?ml$/i,
  /^\.dockerignore$/i,
  /^amplify\.ya?ml$/i,
  /^vercel\.json$/i,
  /^netlify\.toml$/i,
  /^fly\.toml$/i,
  /^render\.ya?ml$/i,
  /^serverless\.(ya?ml|ts|js|json)$/i,
  /^procfile$/i,
  /^app\.ya?ml$/i,
  /^buildspec.*\.ya?ml$/i,
  /^appspec\.ya?ml$/i,
  /^\.gitlab-ci\.ya?ml$/i,
  /^bitbucket-pipelines\.ya?ml$/i,
  /^cloudbuild\.ya?ml$/i,
  /^jenkinsfile$/i,
  /^wrangler\.(toml|json|jsonc)$/i,
  /^firebase\.json$/i,
  /^cdk\.json$/i,
  /^skaffold\.ya?ml$/i,
  /^chart\.ya?ml$/i,
  /^ecosystem\.config\.(c?js|json)$/i,
];
const INFRA_DIRS = new Set(['k8s', 'kubernetes', 'helm', 'charts', 'terraform']);

/** The entry to list for a deployment/infra file, or null. Kubernetes/Helm/Terraform trees collapse to their directory. */
export function infraEntry(file: string): string | null {
  const segments = file.split('/');
  if (segments.includes('node_modules')) return null;
  const dirIndex = segments.slice(0, -1).findIndex((s) => INFRA_DIRS.has(s.toLowerCase()));
  if (dirIndex !== -1) return `${segments.slice(0, dirIndex + 1).join('/')}/`;
  if (file.startsWith('.github/workflows/') && /\.ya?ml$/i.test(file)) return file;
  if (/\.tf$/i.test(file)) return `${path.posix.dirname(file) === '.' ? '' : `${path.posix.dirname(file)}/`}*.tf`;
  const base = segments[segments.length - 1]!;
  return INFRA_BASENAMES.some((re) => re.test(base)) ? file : null;
}

/** Runtime packages worth naming in the profile (exact names, or a prefix ending in '/'). */
const NOTABLE_PACKAGES = [
  'next',
  'react',
  'react-native',
  'expo',
  'vue',
  'nuxt',
  'svelte',
  '@sveltejs/kit',
  '@angular/core',
  'astro',
  'gatsby',
  '@remix-run/',
  'react-router',
  'vite',
  'electron',
  'express',
  'fastify',
  'koa',
  'hono',
  '@hapi/hapi',
  '@nestjs/core',
  '@trpc/server',
  'graphql',
  '@apollo/server',
  'apollo-server',
  'socket.io',
  'next-auth',
  '@auth/core',
  'passport',
  '@supabase/supabase-js',
  'firebase',
  'firebase-admin',
  '@prisma/client',
  'drizzle-orm',
  'typeorm',
  'sequelize',
  'mongoose',
  'pg',
  'mysql2',
  'redis',
  'ioredis',
  '@aws-sdk/',
  'aws-sdk',
  'stripe',
  '@sentry/',
  'puppeteer',
  'playwright',
  'sharp',
  'typescript',
];

function notable(name: string): string | null {
  for (const p of NOTABLE_PACKAGES) {
    if (p.endsWith('/') ? name.startsWith(p) : name === p) return p.endsWith('/') ? `${p}*` : name;
  }
  return null;
}

/** Notable packages from a package.json's dependencies and devDependencies (`name@spec`, prefixes collapsed to `@scope/*`). */
export function notablePackages(manifestJson: string): string[] {
  let pkg: { dependencies?: unknown; devDependencies?: unknown };
  try {
    pkg = JSON.parse(manifestJson) as typeof pkg;
  } catch {
    return [];
  }
  const out = new Map<string, string>();
  for (const deps of [pkg.dependencies, pkg.devDependencies]) {
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      const key = notable(name);
      if (!key || out.has(key)) continue;
      out.set(key, key.endsWith('*') || typeof spec !== 'string' ? key : `${name}@${spec}`);
    }
  }
  return [...out.values()];
}

const LANGUAGE_BY_ECOSYSTEM: Record<string, string> = {
  npm: 'javascript',
  PyPI: 'python',
  Go: 'go',
  'crates.io': 'rust',
  RubyGems: 'ruby',
  Packagist: 'php',
  Pub: 'dart',
  Maven: 'java/kotlin',
  SwiftURL: 'swift',
  CocoaPods: 'swift/objective-c',
};

export function suggestId(repoRoot: string): string {
  const id = path
    .basename(repoRoot)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return id || 'project';
}

function titleCase(id: string): string {
  return id
    .split('-')
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join(' ');
}

async function headCommit(git: string, repoRoot: string): Promise<{ commit: string; date: string } | null> {
  const r = await runChecked(git, ['-C', repoRoot, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}'], {
    timeoutMs: 15_000,
    okCodes: [0, 1, 128],
  });
  if (r.code !== 0) return null;
  const { sha, date } = await gitResolveRef(git, repoRoot, 'HEAD');
  return { commit: sha, date };
}

async function showOrNull(git: string, repoRoot: string, sha: string, file: string): Promise<string | null> {
  try {
    return await gitShowFile(git, repoRoot, sha, file);
  } catch {
    return null;
  }
}

/**
 * What the profile template can be pre-filled with, read from git at HEAD (committed files only; the working tree
 * and ignored files, `.env*` included, are never read).
 */
export async function detectFacts(repoRoot: string, git: string): Promise<RepoFacts> {
  const id = suggestId(repoRoot);
  const [head, branch, defaultBranch, remotes] = await Promise.all([
    headCommit(git, repoRoot),
    currentBranch(git, repoRoot),
    defaultRemoteBranch(git, repoRoot),
    listRemotes(git, repoRoot),
  ]);
  const facts: RepoFacts = {
    repoRoot,
    suggestedId: id,
    suggestedName: titleCase(id) || id,
    head,
    currentBranch: branch,
    defaultBranch,
    remotes,
    lockfiles: [],
    ecosystems: [],
    coverageGaps: [],
    infraFiles: [],
    infraFilesTotal: 0,
    frameworks: [],
    nodeVersion: null,
    languages: [],
  };
  if (!head) return facts;

  const files = await gitLsTree(git, repoRoot, head.commit);
  const present = new Set(files);
  const { lockfiles, coverageGaps } = discoverLockfiles(files, { exclude: [] });
  facts.lockfiles = lockfiles.map((file) => ({ file, ecosystem: lockfileEcosystem(file)! }));
  facts.ecosystems = [...new Set(facts.lockfiles.map((l) => l.ecosystem))].sort();
  facts.coverageGaps = coverageGaps;

  const infra = [...new Set(files.map(infraEntry).filter((e): e is string => e !== null))].sort();
  facts.infraFilesTotal = infra.length;
  facts.infraFiles = infra.slice(0, MAX_INFRA_FILES);

  // package.json next to each npm lockfile (root first), then the root one if no lockfile sits there.
  const npmDirs = facts.lockfiles.filter((l) => l.ecosystem === 'npm').map((l) => path.posix.dirname(l.file));
  const manifests = [...new Set(['.', ...npmDirs])]
    .map((dir) => (dir === '.' ? 'package.json' : `${dir}/package.json`))
    .filter((m) => present.has(m))
    .slice(0, MAX_MANIFESTS);
  let usesTypeScript = files.some((f) => path.posix.basename(f) === 'tsconfig.json' && !f.includes('node_modules/'));
  for (const manifest of manifests) {
    const text = await showOrNull(git, repoRoot, head.commit, manifest);
    if (text === null) continue;
    const packages = notablePackages(text);
    if (packages.some((p) => p.startsWith('typescript@'))) usesTypeScript = true;
    if (packages.length) facts.frameworks.push({ manifest, packages });
    if (manifest === 'package.json' && !facts.nodeVersion) {
      try {
        const engines = (JSON.parse(text) as { engines?: { node?: unknown } }).engines;
        if (typeof engines?.node === 'string') facts.nodeVersion = engines.node;
      } catch {
        // not JSON: nothing to read
      }
    }
  }
  for (const file of ['.nvmrc', '.node-version']) {
    if (!present.has(file)) continue;
    const text = (await showOrNull(git, repoRoot, head.commit, file))?.trim();
    if (text && /^[\w.*^~<>=|\s-]{1,40}$/.test(text)) {
      facts.nodeVersion = text;
      break;
    }
  }

  facts.languages = [
    ...new Set(facts.ecosystems.map((e) => (e === 'npm' && usesTypeScript ? 'typescript' : (LANGUAGE_BY_ECOSYSTEM[e] ?? e)))),
  ];
  return facts;
}

// ---------- template ----------

/** One line, printable: newlines and other control characters in file names become '?'. */
function oneLine(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    out += code < 0x20 || code === 0x7f ? '?' : ch;
  }
  return out;
}

function detectedLines(facts: RepoFacts): string[] {
  if (!facts.head) return ['# No commit at HEAD yet: commit your lockfiles before the first audit.'];
  const where = facts.currentBranch ? `on ${facts.currentBranch}` : 'detached HEAD';
  const out = [`# Detected at HEAD (${facts.head.commit.slice(0, 10)} ${where}, ${facts.head.date.slice(0, 10)}):`];
  out.push(
    `#   lockfiles: ${facts.lockfiles.length ? facts.lockfiles.map((l) => `${oneLine(l.file)} (${l.ecosystem})`).join(', ') : 'none found'}`,
  );
  if (facts.coverageGaps.length) out.push(`#   manifests without a lockfile (not audited): ${facts.coverageGaps.map(oneLine).join(', ')}`);
  if (facts.infraFiles.length) {
    const more = facts.infraFilesTotal > facts.infraFiles.length ? ` (+${facts.infraFilesTotal - facts.infraFiles.length} more)` : '';
    out.push(`#   deployment/CI/infra files: ${facts.infraFiles.map(oneLine).join(', ')}${more}`);
  }
  for (const r of facts.remotes) out.push(`#   remote ${oneLine(r.name)}: ${oneLine(r.url)}`);
  if (facts.defaultBranch) out.push(`#   default branch: ${oneLine(facts.defaultBranch)}`);
  for (const f of facts.frameworks) out.push(`#   ${oneLine(f.manifest)}: ${f.packages.map(oneLine).join(', ')}`);
  return out;
}

/**
 * The commented .vigiles/profile.yaml template, pre-filled with what `facts` could tell. Fields only a person (or
 * Claude reading the code) can answer hold `TODO`: criticality and exposure fail validation until they are set, and
 * the free-text ones produce a placeholder warning until they are filled in.
 */
export function profileTemplate(facts: RepoFacts): string {
  const q = (s: string) => JSON.stringify(oneLine(s));
  const list = (items: string[]) => `[${items.map(q).join(', ')}]`;
  const frameworks = [...new Set(facts.frameworks.flatMap((f) => f.packages).filter((p) => !p.startsWith('typescript@')))];
  const lines = [
    '# Vigiles project profile (.vigiles/profile.yaml). Commit it: teammates reuse it, and the triage verdicts in',
    '# .vigiles/verdicts.json stay valid only while the values triage reads stay the same.',
    '#',
    '# Triage reads every value below except exclude and lockfiles. Write facts about how this code runs in',
    '# production, not guesses: where it is deployed, who can reach it, what protects it, which packages are',
    '# build-only or never imported. Comments are dropped when the profile is loaded, so anything triage should',
    '# know goes into a value. Replace every TODO before the first audit (`vigiles profile` checks the file).',
    '',
    ...detectedLines(facts),
    '',
    '# Kebab-case id (a-z, 0-9, -). Names this repository in the Vigiles cache.',
    `id: ${q(facts.suggestedId)}`,
    '# Display name, used as the report title.',
    `name: ${q(facts.suggestedName)}`,
    '# The production branch, i.e. what is deployed. Triage sees it; an audit still reads your checked-out commit',
    '# unless you pass --ref.',
    `ref: ${q(facts.defaultBranch ?? 'origin/main')}`,
    '# Globs (repo-relative) left out of lockfile discovery and the import search, e.g. ["examples/**"].',
    'exclude: []',
    '# Explicit lockfile list. Leave it out to audit every lockfile found at the audited commit.',
    '# lockfiles: [package-lock.json]',
    '# People responsible for this code (names only).',
    'owners: []',
    '# How bad a compromise would be: low | medium | high. high = personal or regulated data, money, credentials,',
    '# or something many people depend on.',
    'criticality: TODO',
    '# Who can reach it: internal | vpn | internet-facing (anything public, including APIs used by a mobile app).',
    'exposure: TODO',
    '# Kinds of data it stores or handles, e.g. [pii, minors-pii, credentials, payments, health]. [] if none.',
    'data_classes: [TODO]',
    '# How it runs. Free-form keys: add what matters (platform, build, runtime versions pinned outside lockfiles).',
    'runtime:',
    `  language: ${q(facts.languages.join(', ') || 'TODO')}`,
    facts.nodeVersion ? `  node: ${q(facts.nodeVersion)}` : '  # node: "22"',
    `  frameworks: ${list(frameworks)}`,
    '# One entry per deployed component: what runs, where and how, and who can reach it. Free-form keys.',
    'deployments:',
    '  - env: production',
    `    component: ${q('TODO: what runs (e.g. web app with SSR, REST API, static site, background worker)')}`,
    `    hosting: ${q('TODO: where and how (e.g. AWS ECS container, Vercel, static files on S3 + CloudFront)')}`,
    `    public: ${q('TODO: reachable from the internet? by whom (anonymous visitors, signed-in users, staff)?')}`,
    '# External services the code talks to, e.g. [supabase, stripe, aws-s3, sentry].',
    'third_party_services: []',
    '# What limits an attacker: authentication (who can sign up, what sits behind login), WAF/CDN/rate limits,',
    '# request body and upload size limits, sandboxing. Write "none known" rather than leaving it empty.',
    'mitigations: >',
    '  TODO',
    '# Anything else that changes whether a vulnerable package matters here: packages that are build-only, dev-only',
    '# or never imported; code that runs only in development or QA; what dependency matching does not cover.',
    'notes: >',
    '  TODO',
    '',
  ];
  return lines.join('\n');
}

/** The detected facts as plain text for `vigiles init` output. */
export function formatFacts(facts: RepoFacts): string {
  const lines = [`repository: ${facts.repoRoot}`];
  if (!facts.head) {
    lines.push('HEAD: no commit yet');
    return lines.join('\n');
  }
  lines.push(`HEAD: ${facts.head.commit} (${facts.currentBranch ?? 'detached'}, ${facts.head.date})`);
  lines.push(`default branch: ${facts.defaultBranch ?? 'unknown'}`);
  for (const r of facts.remotes) lines.push(`remote ${r.name}: ${r.url}`);
  lines.push(`lockfiles: ${facts.lockfiles.map((l) => `${l.file} (${l.ecosystem})`).join(', ') || 'none'}`);
  if (facts.coverageGaps.length) lines.push(`manifests without a lockfile: ${facts.coverageGaps.join(', ')}`);
  lines.push(`languages: ${facts.languages.join(', ') || 'unknown'}`);
  if (facts.nodeVersion) lines.push(`node: ${facts.nodeVersion}`);
  for (const f of facts.frameworks) lines.push(`${f.manifest}: ${f.packages.join(', ')}`);
  if (facts.infraFiles.length) {
    const more = facts.infraFilesTotal > facts.infraFiles.length ? ` (+${facts.infraFilesTotal - facts.infraFiles.length} more)` : '';
    lines.push(`deployment/CI/infra files: ${facts.infraFiles.join(', ')}${more}`);
  }
  return lines.map(oneLine).join('\n');
}
