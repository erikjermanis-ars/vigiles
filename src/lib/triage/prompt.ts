/**
 * Triage prompts (spec §9.2): loads prompts/triage/<version>.{system.md,user.md,schema.json} and
 * renders the user prompt. Rendering is pure; the runner gathers the inputs from the DB.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { stringify as toYaml } from 'yaml';
import { importSiteKind, MAX_IMPORT_SITES } from '../inventory/import-sites';
import type { FindingInstance, ImportSite, ProjectProfile } from '../types';
import { triageVisibleProfile } from './profile';

export interface TriagePrompt {
  version: string;
  system: string;
  userTemplate: string;
  /** Minified JSON Schema for `claude --json-schema` */
  schemaJson: string;
}

const VERSION_RE = /^[a-z0-9][a-z0-9._-]*$/i;

export function loadTriagePrompt(root: string, version: string): TriagePrompt {
  if (!VERSION_RE.test(version)) throw new Error(`invalid prompt version "${version}"`);
  const base = path.join(root, 'prompts', 'triage', version);
  const read = (ext: string) => readFileSync(`${base}.${ext}`, 'utf8');
  return {
    version,
    system: read('system.md').trim(),
    userTemplate: read('user.md'),
    schemaJson: JSON.stringify(JSON.parse(read('schema.json'))),
  };
}

// ---------- inputs ----------

export interface AdvisoryInput {
  osvId: string;
  aliases: string[];
  summary: string | null;
  details: string | null;
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  cwes: string[];
  references: string[];
  /** Ranges for this package only, already human-readable (see osvRangesFor) */
  affectedRanges: string[];
  fixedVersions: string[];
}

export interface SignalsInput {
  cvssScore: number | null;
  cvssVector: string | null;
  severityLabel: string | null;
  inKev: boolean;
  kevDateAdded: string | null;
  /** CISA's knownRansomwareCampaignUse: 'Known' | 'Unknown' */
  kevRansomware: string | null;
  epss: number | null;
  epssPercentile: number | null;
}

export interface DependencyInput {
  ecosystem: string;
  lockfile: string;
  packageName: string;
  installedVersions: string[];
  fixedVersions: string[];
  /** Merged facts; rendered only when `instances` is empty (findings not rescanned since instances existed) */
  direct: boolean | null;
  devOnly: boolean;
  paths: string[][];
  /** Facts per installed version; one line each */
  instances: FindingInstance[];
  /** At most MAX_IMPORT_SITES are listed */
  importSites: ImportSite[];
  /** Uncapped number of import sites (findings.import_site_count) */
  importSiteCount: number;
}

export type CodeInput = { access: true; workdir: string; commitSha: string; ref: string; commitDate: string | null } | { access: false };

export interface TriagePromptInputs {
  advisory: AdvisoryInput;
  signals: SignalsInput;
  dependency: DependencyInput;
  profile: ProjectProfile;
  code: CodeInput;
}

// ---------- OSV helpers ----------

interface OsvRange {
  type?: string;
  events?: Record<string, string>[];
}
interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
  versions?: string[];
  database_specific?: { last_known_affected_version_range?: string };
}

const MAX_LISTED_VERSIONS = 20;

/** The affected ranges and fixed versions an OSV record gives for one package. */
export function osvRangesFor(raw: Record<string, unknown>, packageName: string, ecosystem: string): { ranges: string[]; fixed: string[] } {
  const affected = (Array.isArray(raw.affected) ? raw.affected : []) as OsvAffected[];
  const byName = affected.filter((a) => a.package?.name === packageName);
  const byEco = byName.filter((a) => a.package?.ecosystem?.toLowerCase() === ecosystem.toLowerCase());
  const entries = byEco.length ? byEco : byName;

  const ranges: string[] = [];
  const fixed = new Set<string>();
  for (const entry of entries) {
    const lastKnown = entry.database_specific?.last_known_affected_version_range;
    for (const range of entry.ranges ?? []) {
      const events = (range.events ?? []).flatMap((e) => Object.entries(e).map(([k, v]) => `${k} ${v}`));
      for (const e of range.events ?? []) if (e.fixed) fixed.add(e.fixed);
      ranges.push(
        `${range.type ?? 'RANGE'}: ${events.join(', ') || '(no events)'}${lastKnown ? ` (last known affected: ${lastKnown})` : ''}`,
      );
    }
    if (!entry.ranges?.length && entry.versions?.length) {
      const shown = entry.versions.slice(0, MAX_LISTED_VERSIONS).join(', ');
      const more = entry.versions.length - MAX_LISTED_VERSIONS;
      ranges.push(`versions: ${shown}${more > 0 ? ` (and ${more} more)` : ''}`);
    }
  }
  return { ranges, fixed: [...fixed] };
}

// ---------- rendering ----------

const MAX_DETAILS_CHARS = 16_000;
const MAX_REFERENCES = 15;

/**
 * Makes advisory text unable to close (or reopen) the <advisory> wrapper, so text after a fake
 * closing tag can't pose as instructions outside the untrusted block.
 */
export function neutraliseAdvisoryTags(text: string): string {
  return text.replace(/<(\s*\/?\s*advisory)/gi, '&lt;$1');
}

function oneLine(s: string | null): string {
  return (s ?? '').replace(/\s+/g, ' ').trim();
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n[... truncated: ${s.length - max} more characters]`;
}

function bulletList(items: string[], empty: string, indent = '  '): string[] {
  return items.length ? items.map((i) => `${indent}- ${i}`) : [`${indent}- ${empty}`];
}

/** The body of the <advisory> block, already neutralised. */
export function renderAdvisory(a: AdvisoryInput): string {
  const refs = a.references.slice(0, MAX_REFERENCES);
  const moreRefs = a.references.length - refs.length;
  const lines = [
    `id: ${a.osvId}`,
    `aliases: ${a.aliases.join(', ') || '(none)'}`,
    ...(a.published ? [`published: ${a.published}`] : []),
    ...(a.modified ? [`modified: ${a.modified}`] : []),
    ...(a.withdrawn ? [`withdrawn: ${a.withdrawn}`] : []),
    `summary: ${oneLine(a.summary) || '(none)'}`,
    'affected ranges for this package:',
    ...bulletList(a.affectedRanges, '(not listed)'),
    `fixed versions: ${a.fixedVersions.join(', ') || '(none published)'}`,
    `CWEs: ${a.cwes.join(', ') || '(none)'}`,
    'references:',
    ...bulletList(refs, '(none)'),
    ...(moreRefs > 0 ? [`  - (and ${moreRefs} more)`] : []),
    'details:',
    truncate((a.details ?? '').trim() || '(none)', MAX_DETAILS_CHARS),
  ];
  return neutraliseAdvisoryTags(lines.join('\n'));
}

function formatNumber(n: number, digits: number): string {
  return String(Number(n.toFixed(digits)));
}

export function renderSignals(s: SignalsInput): string {
  const cvss = s.cvssScore === null ? 'not available' : `${formatNumber(s.cvssScore, 1)}${s.cvssVector ? ` (${s.cvssVector})` : ''}`;
  const kev = s.inKev
    ? `listed${s.kevDateAdded ? ` since ${s.kevDateAdded}` : ''}${s.kevRansomware ? `; known ransomware use: ${s.kevRansomware}` : ''} (exploited in the wild)`
    : 'not listed';
  const epss =
    s.epss === null
      ? 'not available'
      : `${formatNumber(s.epss, 5)}${s.epssPercentile === null ? '' : ` (percentile ${formatNumber(s.epssPercentile * 100, 1)})`}`;
  return [`- CVSS: ${cvss}`, `- Severity label: ${s.severityLabel ?? 'none'}`, `- CISA KEV: ${kev}`, `- EPSS: ${epss}`].join('\n');
}

/** The lockfile's directory, repo-relative ('' for the repository root). */
function packageDir(lockfile: string): string {
  const dir = path.posix.dirname(lockfile);
  return dir === '.' ? '' : dir;
}

function lockfileNote(lockfile: string): string {
  const dir = packageDir(lockfile);
  return dir ? `${lockfile} (package root: ${dir}/)` : `${lockfile} (at the repository root)`;
}

function relationship(direct: boolean | null): string {
  if (direct === null) return 'unknown (this ecosystem does not record it)';
  return direct ? 'direct dependency' : 'transitive dependency';
}

function pathList(paths: string[][], direct: boolean | null): string {
  if (!paths.length) return direct === null ? 'unknown (not recorded for this ecosystem)' : 'none found';
  return paths.map((p) => p.join(' > ')).join(' | ');
}

/** One line per installed version, with that version's own facts. */
function instanceLine(packageName: string, i: FindingInstance): string {
  return `${packageName}@${i.version}: ${relationship(i.direct)}; dev_only: ${i.devOnly}; paths: ${pathList(i.paths, i.direct)}`;
}

/** Merged facts, for findings stored before per-version instances existed. */
function mergedFactLines(d: DependencyInput): string[] {
  return [
    `- Relationship: ${relationship(d.direct)}`,
    d.devOnly
      ? '- dev_only: true (every installed instance is marked dev in the lockfile)'
      : '- dev_only: false (at least one installed instance is not marked dev in the lockfile)',
    '- Dependency paths from the project root (up to 3 shortest):',
    ...bulletList(
      d.paths.map((p) => p.join(' > ')),
      'unknown (not recorded for this ecosystem)',
    ),
  ];
}

const SITE_KIND_TAG = { source: '', config: ' [config file]', script: ' [script]' } as const;

function importSiteLine(site: ImportSite, d: DependencyInput): string {
  const via = site.via !== d.packageName ? ` (via ${site.via})` : '';
  return `${site.file}:${site.line} imports \`${site.specifier}\`${via}${SITE_KIND_TAG[importSiteKind(site.file, packageDir(d.lockfile))]}`;
}

/** "3", "showing 20 of 132", or "20 or more" for rows stored before the uncapped count existed. */
function importSiteCountLabel(d: DependencyInput, listed: number): string {
  // Rows stored before findings.import_site_count existed have 0 there; their list was capped at
  // MAX_IMPORT_SITES too, so a full list may hide more sites.
  if (d.importSiteCount < d.importSites.length) return listed >= MAX_IMPORT_SITES ? `${listed} or more` : String(listed);
  return listed < d.importSiteCount ? `showing ${listed} of ${d.importSiteCount}` : String(d.importSiteCount);
}

export function renderDependencyFacts(d: DependencyInput): string {
  const sites = d.importSites.slice(0, MAX_IMPORT_SITES).map((s) => importSiteLine(s, d));
  const count = importSiteCountLabel(d, sites.length);
  const lines = [
    `- Package: ${d.packageName} (${d.ecosystem})`,
    `- Lockfile: ${lockfileNote(d.lockfile)}`,
    `- Installed versions: ${d.installedVersions.join(', ') || '(unknown)'}`,
    `- Fixed versions: ${d.fixedVersions.join(', ') || '(none published)'}`,
    ...(d.instances.length
      ? [
          '- Installed instances (each installed version with its own facts; paths are up to 3 shortest chains from the project root):',
          ...bulletList(
            d.instances.map((i) => instanceLine(d.packageName, i)),
            '(none)',
          ),
        ]
      : mergedFactLines(d)),
    // Import sites are searched only with a dependency graph (npm package-lock.json); direct is null without one.
    ...(d.direct === null && sites.length === 0
      ? ['- Import sites: not searched (the scanner has no dependency graph for this lockfile)']
      : [
          `- Import sites (${count}; a regex hint over source files, tests and stories excluded; it includes config files and scripts, which are tagged):`,
          ...bulletList(sites, 'none found'),
        ]),
  ];
  return lines.join('\n');
}

/** The profile as a fenced YAML block. The fence lives here, not in the template, so a formatter can't mangle a placeholder inside a code block. */
export function renderProfile(profile: ProjectProfile): string {
  return ['```yaml', toYaml(triageVisibleProfile(profile), { lineWidth: 0 }).trim(), '```'].join('\n');
}

export function renderCodeNote(code: CodeInput): string {
  if (!code.access) {
    return [
      'No code is available for this triage. You have no tools and cannot read the repository.',
      'Reason only from the advisory, the signals, the dependency facts and the project profile.',
      'Answer `unknown` where the answer depends on code, and do not invent file paths or line numbers.',
    ].join(' ');
  }
  const committed = code.commitDate ? `, committed ${code.commitDate}` : '';
  return [
    `Your working directory is \`${code.workdir}\`: a read-only snapshot of this project at commit ${code.commitSha} (ref ${code.ref}${committed}).`,
    'It contains git-tracked files only: no node_modules (dependency source code is not available), no build output and no .env files.',
    'Read needs absolute paths under this directory; cite repo-relative paths in evidence.',
    'Tools: Read, Grep, Glob. Start from the import sites above.',
  ].join(' ');
}

/** Replaces {{name}} placeholders in one pass (inserted values are never re-scanned). */
export function renderTemplate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}/gi, (_, name: string) => {
    const value = vars[name];
    if (value === undefined) throw new Error(`prompt template uses unknown placeholder {{${name}}}`);
    return value;
  });
}

export function renderUserPrompt(template: string, inputs: TriagePromptInputs): string {
  return renderTemplate(template, {
    osv_id: inputs.advisory.osvId,
    package: inputs.dependency.packageName,
    ecosystem: inputs.dependency.ecosystem,
    project_id: inputs.profile.id,
    advisory: renderAdvisory(inputs.advisory),
    signals: renderSignals(inputs.signals),
    dependency_facts: renderDependencyFacts(inputs.dependency),
    profile: renderProfile(inputs.profile),
    code: renderCodeNote(inputs.code),
  });
}
