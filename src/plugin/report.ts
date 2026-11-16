/**
 * The audit report (`.vigiles/report.md`) and the short stdout summary. The report is what developers read:
 * the urgent items first, each short and self-contained (why, verdict and signals, what it is, when it is
 * exploitable here, where in the code, how to fix, how the package gets in), then the logged items folded away.
 *
 * One advisory on several packages in one lockfile is one item (the policy decides such a group as one problem),
 * so the Fix now / Fix soon / Logged counts are items, not findings; items without a verdict are a part of them.
 * Ordering is stable: action, priority, malicious first, CVSS (desc), package, advisory.
 *
 * Advisory text, model output and verdicts.json are untrusted: they are written so that they cannot form links,
 * images or HTML (a remote image in a Markdown preview would be a beacon, or carry text out in its URL).
 */
import { formatDateTime, osvUrl, shortDate } from '../lib/format';
import { SAME_ADVISORY_RULE } from '../lib/policy/same-advisory';
import { MALICIOUS_REMEDIATION, PRIORITIES, type Action, type Priority } from '../lib/types';
import { ACTION_LABELS, type DecidedFinding, type Decisions, type PluginProfile, type ScanFinding, type ScanResult } from './types';

export interface ReportOptions {
  scan: ScanResult;
  decisions: Decisions;
  profile: PluginProfile;
  /** ISO timestamp */
  generatedAt: string;
  toolVersion: string;
  /** More warnings to list (profile placeholders, verdicts.json problems, ...); duplicates of scan warnings are dropped */
  warnings?: string[];
  /** IANA zone for dates (default: the machine's) */
  timeZone?: string;
}

/** One advisory in one lockfile with every package it matched there, decided as one action. */
export interface ReportItem {
  action: Action;
  lockfile: string;
  osvId: string;
  /** The member whose own decision and verdict the item shows, then the others */
  members: DecidedFinding[];
  lead: DecidedFinding;
  priority: Priority;
  cvss: number | null;
}

const ACTION_ORDER: Action[] = ['ping', 'digest', 'log'];
const MAX_EVIDENCE = 5;
const MAX_TITLE = 120;
const MAX_HEADING_PACKAGES = 3;
/** Items per section in the stdout summary; the report has them all. */
const SUMMARY_ITEMS = 15;

// ---------- text helpers ----------

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function descNullsLast(a: number | null, b: number | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return b - a;
}

function rank(p: Priority): number {
  return PRIORITIES.indexOf(p);
}

/** Plain text on one line: whitespace collapsed (newlines too). Not escaped: escape with inline() when writing. */
function collapse(s: string | null | undefined): string {
  return (s ?? '').replace(/\s+/g, ' ').trim();
}

/**
 * Untrusted text (advisories, model output) as one Markdown line: whitespace collapsed; `\\` escaped first (so it
 * cannot undo the escapes after it), then `[` and `]` (no link, image or reference can form), then a `<` that
 * could open an HTML tag or an autolink, so a Markdown viewer shows it instead of acting on it.
 */
export function inline(s: string | null | undefined): string {
  return collapse(s)
    .replace(/\\/g, '\\\\')
    .replace(/[[\]]/g, (c) => `\\${c}`)
    .replace(/<(?=[A-Za-z/!?])/g, '\\<');
}

/** A Markdown table cell: inline text with `|` escaped. */
export function cell(s: string | null | undefined): string {
  return inline(s).replace(/\|/g, '\\|');
}

/** A code span on one line, with a fence longer than any run of backticks inside it. */
export function code(s: string): string {
  const text = collapse(s);
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  if (!longest) return `\`${text}\``;
  const fence = '`'.repeat(longest + 1);
  return `${fence} ${text} ${fence}`;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

/** The first sentence, as plain text (escape it when writing). */
function firstSentence(s: string, max = 160): string {
  const text = collapse(s);
  const m = /^.*?[.!?](?=\s|$)/.exec(text);
  return truncate(m ? m[0] : text, max);
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
}

function label(v: string): string {
  return v.replace(/_/g, ' ');
}

function epssLabel(epss: number): string {
  const pct = epss * 100;
  if (pct >= 1) return `${Math.round(pct)}%`;
  if (pct >= 0.1) return `${pct.toFixed(1)}%`;
  return '<0.1%';
}

function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

// ---------- grouping ----------

function isTriaged(d: DecidedFinding): boolean {
  return d.triageStatus === 'ok' || d.triageStatus === 'skipped';
}

/** The member that speaks for the group: its own decision (not raised), triaged, most urgent, then by name. */
function compareMembers(a: DecidedFinding, b: DecidedFinding): number {
  return (
    Number(a.ruleId === SAME_ADVISORY_RULE) - Number(b.ruleId === SAME_ADVISORY_RULE) ||
    Number(!isTriaged(a)) - Number(!isTriaged(b)) ||
    rank(a.inputs.priority ?? a.finding.priority) - rank(b.inputs.priority ?? b.finding.priority) ||
    descNullsLast(a.finding.cvssScore, b.finding.cvssScore) ||
    cmp(a.finding.packageName, b.finding.packageName)
  );
}

function firstName(item: ReportItem): string {
  return [...item.members].map((m) => m.finding.packageName).sort(cmp)[0] ?? '';
}

/** Action, priority, a malicious package before the rest of its tier (the install is already compromised), CVSS desc, name. */
export function compareItems(a: ReportItem, b: ReportItem): number {
  return (
    ACTION_ORDER.indexOf(a.action) - ACTION_ORDER.indexOf(b.action) ||
    rank(a.priority) - rank(b.priority) ||
    Number(!a.lead.inputs.malicious) - Number(!b.lead.inputs.malicious) ||
    descNullsLast(a.cvss, b.cvss) ||
    cmp(firstName(a), firstName(b)) ||
    cmp(a.osvId, b.osvId) ||
    cmp(a.lockfile, b.lockfile)
  );
}

/** Groups decided findings by (action, lockfile, advisory) and orders the groups for the report. */
export function reportItems(decisions: Decisions): ReportItem[] {
  const groups = new Map<string, DecidedFinding[]>();
  for (const d of decisions.findings) {
    const key = `${d.action}\0${d.finding.lockfile}\0${d.finding.osvId}`;
    const g = groups.get(key);
    if (g) g.push(d);
    else groups.set(key, [d]);
  }
  const items: ReportItem[] = [];
  for (const members of groups.values()) {
    members.sort(compareMembers);
    const lead = members[0]!;
    const priority = members.map((m) => m.inputs.priority ?? m.finding.priority).sort((a, b) => rank(a) - rank(b))[0]!;
    const scores = members.map((m) => m.finding.cvssScore).filter((x): x is number => x !== null);
    items.push({
      action: lead.action,
      lockfile: lead.finding.lockfile,
      osvId: lead.finding.osvId,
      members,
      lead,
      priority,
      cvss: scores.length ? Math.max(...scores) : null,
    });
  }
  return items.sort(compareItems);
}

// ---------- item parts ----------

function packageLabel(f: ScanFinding): string {
  return `${f.packageName}@${f.installedVersions.join(', ') || '?'}`;
}

function packagesLabel(item: ReportItem, max = MAX_HEADING_PACKAGES): string {
  const names = item.members.map((m) => packageLabel(m.finding));
  if (names.length <= max) return names.join(', ');
  return `${names.slice(0, max).join(', ')} and ${names.length - max} more`;
}

/** The CVE ids of the advisory (or of the finding when the advisory is missing). */
function cvesOf(d: DecidedFinding): string[] {
  const cves = d.advisory?.cves.length ? d.advisory.cves : d.finding.cves;
  return cves.filter((c) => c !== d.finding.osvId);
}

/** First CVE, else the OSV id: the id people search for. */
export function displayId(d: DecidedFinding): string {
  return cvesOf(d)[0] ?? d.finding.osvId;
}

/** The advisory summary (or id), plain text. */
function titleOf(item: ReportItem): string {
  const summary = collapse(item.lead.advisory?.summary);
  return summary ? truncate(summary, MAX_TITLE) : item.osvId;
}

/** "next@15.1.0 — Authorization bypass in Next.js middleware", as plain text (the stdout summary). */
export function plainItemTitle(item: ReportItem): string {
  return `${packagesLabel(item)} — ${titleOf(item)}`;
}

/** The item title as Markdown (escaped). */
export function itemTitle(item: ReportItem): string {
  return inline(plainItemTitle(item));
}

function signalsLabel(d: DecidedFinding): string {
  const f = d.finding;
  const parts: string[] = [d.inputs.priority ?? f.priority];
  if (d.inputs.malicious) parts.push('malicious package');
  if (f.cvssScore !== null) parts.push(`CVSS ${f.cvssScore.toFixed(1)}`);
  if (f.inKev) {
    const since = f.kevDateAdded ? `, since ${shortDate(f.kevDateAdded, 'UTC')}` : '';
    const ransomware = f.kevRansomware === 'Known' ? ', used in ransomware campaigns' : '';
    parts.push(`exploited in the wild (CISA KEV${since}${ransomware})`);
  }
  if (f.epss !== null) parts.push(`EPSS ${epssLabel(f.epss)}`);
  return parts.join(' · ');
}

function dependencyLabel(f: ScanFinding): string {
  const kind = f.direct === null ? 'direct or transitive (unknown)' : f.direct ? 'direct' : 'transitive';
  const scope = f.devOnly ? ', dev only' : '';
  const chain = f.paths.find((p) => p.length > 1);
  if (!chain) return `${kind}${scope}`;
  // A direct dependency that other packages also pull in: the chain is not how it gets in, only another way.
  return f.direct ? `${kind}${scope} (also via ${code(chain.join(' > '))})` : `${kind}${scope} via ${code(chain.join(' > '))}`;
}

function fixedLabel(f: ScanFinding): string {
  return f.fixedVersions.length ? `Fixed in ${f.fixedVersions.join(', ')}.` : 'No fixed version is published yet.';
}

function untriagedReason(d: DecidedFinding): string {
  const where = ACTION_LABELS[d.action];
  const reasons = d.finding.priorityReasons.length ? ` (${d.finding.priorityReasons.map(inline).join('; ')})` : '';
  const signals = `It is in ${where} because of its signals alone: ${d.inputs.priority ?? d.finding.priority}${reasons}.`;
  const lead =
    d.triageStatus === 'failed'
      ? `Triage failed (${inline(truncate(collapse(d.failure), 160))}), so there is no verdict yet.`
      : 'Not triaged yet, so there is no verdict.';
  return `${lead} ${signals} Run ${code('/vigiles:audit')} again to triage it.`;
}

function otherMembersLine(item: ReportItem): string | null {
  const others = item.members.slice(1);
  if (!others.length) return null;
  const parts = others.map((m) => {
    const v = m.verdict?.output;
    const state = v
      ? `${label(v.verdict)}, ${v.confidence} confidence`
      : m.triageStatus === 'failed'
        ? 'triage failed'
        : m.triageStatus === 'pending'
          ? 'not triaged yet'
          : 'malicious';
    const raised = m.ruleId === SAME_ADVISORY_RULE ? '; raised to match' : '';
    return `${code(packageLabel(m.finding))} (${state}${raised})`;
  });
  return `- **Same advisory, also in:** ${parts.join(', ')}. One fix usually covers all of them.`;
}

function renderItem(item: ReportItem, scan: ScanResult): string[] {
  const d = item.lead;
  const f = d.finding;
  const ids = [`[${inline(f.osvId)}](${osvUrl(f.osvId)})`, ...cvesOf(d).map(inline)].join(' · ');
  const lines = [`### ${itemTitle(item)}`, '', `${ids} · ${code(item.lockfile)}`, ''];
  const v = d.verdict?.output;

  if (d.inputs.malicious) {
    lines.push(
      '- **Why:** This package version is known malware. Installing it can run attacker code on developer machines and in CI.',
      `- **Signals:** ${signalsLabel(d)}. No AI triage needed: malicious packages always go to Fix now.`,
      `- **Fix:** ${MALICIOUS_REMEDIATION}`,
    );
  } else if (v) {
    lines.push(`- **Why:** ${inline(v.suggested_action_reason)}`);
    lines.push(`- **Verdict:** ${label(v.verdict)}, ${v.confidence} confidence · ${signalsLabel(d)}`);
    if (v.suggested_action !== d.action) {
      lines.push(
        `- **Placement:** the AI suggested ${ACTION_LABELS[v.suggested_action]}; policy rule ${code(d.ruleId)} puts it in ${ACTION_LABELS[d.action]}.`,
      );
    }
    if (v.summary.trim()) lines.push(`- **Summary:** ${inline(v.summary)}`);
    if (v.exploit_conditions.trim()) lines.push(`- **Exploitable when:** ${inline(v.exploit_conditions)}`);
    if (v.evidence.length) {
      const asOf = d.verdict && d.verdict.commit !== scan.commit ? ` (as of ${code(shortSha(d.verdict.commit))})` : '';
      lines.push(`- **Where in the code${asOf}:**`);
      for (const e of v.evidence.slice(0, MAX_EVIDENCE)) {
        lines.push(`  - ${code(e.line === null ? e.file : `${e.file}:${e.line}`)}${e.note.trim() ? ` — ${inline(e.note)}` : ''}`);
      }
      if (v.evidence.length > MAX_EVIDENCE) lines.push(`  - and ${v.evidence.length - MAX_EVIDENCE} more`);
    }
    // The remediation usually names the target version already; repeat the fixed versions only when it does not.
    const namesFix = f.fixedVersions.some((x) => v.remediation.includes(x));
    const fix = [inline(v.remediation), namesFix ? '' : fixedLabel(f), v.workaround?.trim() ? `Workaround: ${inline(v.workaround)}` : '']
      .filter(Boolean)
      .join(' ');
    lines.push(`- **Fix:** ${fix}`);
  } else {
    lines.push(`- **Why:** ${untriagedReason(d)}`);
    lines.push(`- **Signals:** ${signalsLabel(d)}`);
    lines.push(`- **Fix:** ${fixedLabel(f)}`);
  }
  lines.push(`- **Dependency:** ${dependencyLabel(f)}`);
  const others = otherMembersLine(item);
  if (others) lines.push(others);
  lines.push('');
  return lines;
}

// ---------- sections ----------

function refLabel(scan: ScanResult): string {
  if (scan.branch) return code(scan.branch);
  return scan.ref === 'HEAD' ? 'detached HEAD' : code(scan.ref);
}

function mentions(texts: string[], needle: string | RegExp): boolean {
  return texts.some((t) => (typeof needle === 'string' ? t.includes(needle) : needle.test(t)));
}

/** Everything the reader should know before trusting the lists. Structured facts the scan also put into its own warnings are not repeated. */
export function reportWarnings(scan: ScanResult, decisions: Decisions, extra: string[] = []): string[] {
  const own = [...scan.warnings, ...extra];
  const out: string[] = [];
  const unc = scan.uncommittedDependencyFiles;
  if (unc.length && !mentions(own, unc[0]!)) {
    out.push(
      `Not audited: uncommitted changes in ${unc.map(code).join(', ')}. This audit read the committed state; commit them and run again to include them.`,
    );
  }
  // coverageGaps holds manifests without a lockfile (src/lib/inventory/scan-results.ts) plus the skipped lockfiles,
  // which have their own line below.
  const gaps = scan.coverageGaps.filter((g) => !scan.skippedLockfiles.includes(g) && !mentions(own, g));
  if (gaps.length) {
    out.push(`No lockfile, so their dependencies were not audited: ${gaps.map(code).join(', ')}.`);
  }
  const skipped = scan.skippedLockfiles.filter((l) => !mentions(own, l));
  if (skipped.length) out.push(`Skipped (could not be read): ${skipped.map(code).join(', ')}.`);
  if (!scan.data.kevAvailable && !mentions(own, /KEV/)) {
    out.push('The CISA KEV catalog was unavailable: exploited-in-the-wild flags are missing, so some items may be ranked too low.');
  }
  if (scan.data.epssFailedCves > 0 && !mentions(own, /EPSS/)) {
    out.push(`EPSS scores could not be fetched for ${plural(scan.data.epssFailedCves, 'CVE')}; their priority may be too low.`);
  }
  out.push(...own);
  const failed = decisions.findings.filter((d) => d.triageStatus === 'failed').length;
  const pending = decisions.findings.filter((d) => d.triageStatus === 'pending').length;
  if (failed + pending) {
    const parts = [...(failed ? [`${failed} failed`] : []), ...(pending ? [`${pending} not triaged yet`] : [])].join(', ');
    out.push(
      `${plural(failed + pending, 'finding')} without a verdict (${parts}): placed by their signals alone. See Not triaged; run ${code('/vigiles:audit')} again to triage them.`,
    );
  }
  return [...new Set(out)];
}

function hasUntriaged(item: ReportItem): boolean {
  return item.members.some((m) => m.triageStatus === 'pending' || m.triageStatus === 'failed');
}

/**
 * `Fix now 3 · Fix soon 2 · Logged 2` (items), and how many of those items have no verdict yet: a part of the
 * total, never a fourth bucket.
 */
function counts(items: ReportItem[]): { main: string; untriaged: string | null } {
  const n = (a: Action) => items.filter((i) => i.action === a).length;
  const main = ACTION_ORDER.map((a) => `${ACTION_LABELS[a]} ${n(a)}`).join(' · ');
  const untriaged = items.filter(hasUntriaged).length;
  return { main, untriaged: untriaged ? `${untriaged} of these ${plural(items.length, 'item')} not triaged yet` : null };
}

function countsLine(items: ReportItem[]): string {
  const { main, untriaged } = counts(items);
  return untriaged ? `**${main}** (${untriaged}; placed by their signals)` : `**${main}**`;
}

/** Plain text (cell() escapes it). */
function whyLogged(d: DecidedFinding): string {
  const v = d.verdict?.output;
  if (v) return `${label(v.verdict)}: ${firstSentence(v.suggested_action_reason)}`;
  return d.triageStatus === 'failed' ? 'triage failed; placed by its signals' : 'not triaged yet; placed by its signals';
}

function loggedSummary(items: ReportItem[]): string {
  const untriaged = items.filter((i) => !isTriaged(i.lead)).length;
  if (!untriaged) return `${plural(items.length, 'item')} judged not a real threat in this project`;
  return `${plural(items.length, 'item')} with no action needed (${untriaged} of them not triaged yet, placed here by their signals)`;
}

/** More than one lockfile has findings: the tables and the summary then say which lockfile a row is about. */
function multiLockfile(decisions: Decisions): boolean {
  return new Set(decisions.findings.map((d) => d.finding.lockfile)).size > 1;
}

function loggedSection(items: ReportItem[], showLockfile: boolean): string[] {
  const lines = [`## ${ACTION_LABELS.log} (${items.length})`, ''];
  if (!items.length) return [...lines, 'None.', ''];
  const lockCol = showLockfile ? ' Lockfile |' : '';
  lines.push(
    '<details>',
    `<summary>${loggedSummary(items)}</summary>`,
    '',
    `| Package |${lockCol} Advisory | Priority | Why |`,
    `|---|${showLockfile ? '---|' : ''}---|---|---|`,
  );
  for (const item of items) {
    const lock = showLockfile ? ` ${cell(item.lockfile)} |` : '';
    lines.push(
      `| ${cell(packagesLabel(item, Infinity))} |${lock} ${cell(displayId(item.lead))} | ${item.priority} | ${cell(whyLogged(item.lead))} |`,
    );
  }
  lines.push('', '</details>', '');
  return lines;
}

function notTriagedSection(decisions: Decisions, showLockfile: boolean): string[] {
  const rows = decisions.findings
    .filter((d) => d.triageStatus === 'pending' || d.triageStatus === 'failed')
    .sort(
      (a, b) =>
        ACTION_ORDER.indexOf(a.action) - ACTION_ORDER.indexOf(b.action) ||
        rank(a.inputs.priority ?? a.finding.priority) - rank(b.inputs.priority ?? b.finding.priority) ||
        descNullsLast(a.finding.cvssScore, b.finding.cvssScore) ||
        cmp(a.finding.packageName, b.finding.packageName) ||
        cmp(a.finding.id, b.finding.id),
    );
  if (!rows.length) return [];
  const failed = rows.filter((d) => d.triageStatus === 'failed').length;
  const pending = rows.length - failed;
  const parts = [...(failed ? [`${failed} failed`] : []), ...(pending ? [`${pending} not triaged yet`] : [])].join(', ');
  const lines = [
    `## Not triaged (${rows.length})`,
    '',
    `No verdict yet, so these findings are placed by their signals alone; each is also shown in its section above. Run ${code('/vigiles:audit')} again to triage them.`,
    '',
    '<details>',
    `<summary>${parts}</summary>`,
    '',
    `| Package |${showLockfile ? ' Lockfile |' : ''} Advisory | Priority | Placed in | Status |`,
    `|---|${showLockfile ? '---|' : ''}---|---|---|---|`,
  ];
  for (const d of rows) {
    const status = d.triageStatus === 'failed' ? `failed: ${truncate(collapse(d.failure), 160)}` : 'not triaged yet';
    const lock = showLockfile ? ` ${cell(d.finding.lockfile)} |` : '';
    lines.push(
      `| ${cell(packageLabel(d.finding))} |${lock} ${cell(displayId(d))} | ${d.inputs.priority ?? d.finding.priority} | ${ACTION_LABELS[d.action]} | ${cell(status)} |`,
    );
  }
  lines.push('', '</details>', '');
  return lines;
}

function dateOrUnavailable(d: string | null): string {
  return d ? shortDate(d, 'UTC') : 'unavailable';
}

// ---------- report ----------

export function renderReport(opts: ReportOptions): string {
  const { scan, decisions, profile } = opts;
  const items = reportItems(decisions);
  const byAction = (a: Action) => items.filter((i) => i.action === a);
  const committed = scan.commitDate ? ` (committed ${shortDate(scan.commitDate, opts.timeZone)})` : '';

  const lines: string[] = [
    `# Dependency audit: ${inline(profile.name)}`,
    '',
    [
      `Audited ${refLabel(scan)} at ${code(shortSha(scan.commit))}${committed}`,
      plural(scan.lockfiles.length, 'lockfile'),
      plural(scan.stats.packages, 'package'),
      `generated ${formatDateTime(opts.generatedAt, opts.timeZone)}`,
    ].join(' · '),
    '',
    countsLine(items),
    '',
    `**${ACTION_LABELS.ping}**: real harm is possible soon; fix today. **${ACTION_LABELS.digest}**: real but not urgent; fix within 1–2 weeks. **${ACTION_LABELS.log}**: not a real threat in this project; no action needed.`,
    '',
  ];

  const warnings = reportWarnings(scan, decisions, opts.warnings);
  if (warnings.length) {
    lines.push('## Warnings', '', ...warnings.map((w) => `- ${inline(w)}`), '');
  }

  if (!decisions.findings.length) {
    lines.push('No known vulnerabilities in the audited lockfiles.', '');
  } else {
    for (const action of ['ping', 'digest'] as const) {
      const section = byAction(action);
      lines.push(`## ${ACTION_LABELS[action]} (${section.length})`, '');
      if (!section.length) lines.push('None.', '');
      for (const item of section) lines.push(...renderItem(item, scan));
    }
    const showLockfile = multiLockfile(decisions);
    lines.push(...loggedSection(byAction('log'), showLockfile));
    lines.push(...notTriagedSection(decisions, showLockfile));
  }

  const tc = scan.triageConfig;
  lines.push(
    '---',
    '',
    `Data: OSV database ${dateOrUnavailable(scan.data.osvDbDate)} · CISA KEV ${dateOrUnavailable(scan.data.kevCatalogDate)} · EPSS ${dateOrUnavailable(scan.data.epssDate)}. ` +
      `Triage: ${tc.name} (prompt ${tc.promptFingerprint}). Policy ${decisions.policyHash}. Vigiles ${opts.toolVersion}.`,
    '',
    `Commit the ${code('.vigiles/')} directory (this report is gitignored) so teammates reuse these verdicts.`,
    '',
  );
  return lines.join('\n');
}

/** The few lines printed after a run: counts, the Fix now and Fix soon items, and where the report is. */
export function renderSummary(decisions: Decisions, scan: ScanResult, reportFile?: string): string {
  const items = reportItems(decisions);
  const { main, untriaged } = counts(items);
  const showLockfile = multiLockfile(decisions);
  const lines = [`${main} (${refLabel(scan).replace(/`/g, '')} @ ${shortSha(scan.commit)})${untriaged ? `; ${untriaged}` : ''}`];
  for (const action of ['ping', 'digest'] as const) {
    const section = items.filter((i) => i.action === action);
    if (!section.length) continue;
    lines.push(`${ACTION_LABELS[action]}:`);
    for (const item of section.slice(0, SUMMARY_ITEMS)) {
      const id = displayId(item.lead);
      const where = showLockfile ? ` in ${item.lockfile}` : '';
      lines.push(`  - ${plainItemTitle(item)} (${id})${where}${hasUntriaged(item) ? ' [not triaged]' : ''}`);
    }
    if (section.length > SUMMARY_ITEMS) lines.push(`  - … and ${section.length - SUMMARY_ITEMS} more in the report`);
  }
  if (reportFile) lines.push(`Report: ${reportFile}`);
  return lines.join('\n');
}
