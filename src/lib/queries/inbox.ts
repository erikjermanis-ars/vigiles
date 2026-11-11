/**
 * Inbox (spec §12): "what Slack would have received". Ping and digest findings grouped as one
 * message per (project, package), optionally limited to what changed since the previous Refresh all (§4.4).
 * Findings of disabled projects are left out: scan and triage skip them, so they could never be cleared.
 */
import { and, desc, eq, gt, inArray, isNull, or, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, events, findings, jobRuns, projects, triageRuns } from '../db/schema';
import { highestVersion, upgradeTarget } from '../eval/version';
import { displayVulnId } from '../format';
import { isMalicious } from '../policy/inputs';
import { PRIORITIES, TriageOutputSchema, type Action, type Confidence, type EventType, type Priority, type Verdict } from '../types';

/** The fixed remediation for a malicious package (spec §9.1): there is no version to upgrade to. */
export { MALICIOUS_REMEDIATION } from '../types';

export type InboxView = 'since' | 'all';

export function parseInboxView(v: string | string[] | undefined): InboxView {
  return v === 'all' ? 'all' : 'since';
}

/** Event types that make a finding show up in the "since last refresh" view. */
export const SINCE_EVENT_TYPES = [
  'created',
  'reopened',
  'escalated',
  'decision_changed',
  'advisory_changed',
] as const satisfies readonly EventType[];

export interface InboxItem {
  findingId: number;
  projectId: string;
  projectName: string;
  packageName: string;
  lockfile: string;
  osvId: string;
  vulnId: string;
  action: Action;
  priority: Priority | null;
  priorityReasons: string[];
  verdict: Verdict | null;
  confidence: Confidence | null;
  summary: string | null;
  ruleId: string | null;
  fixedVersions: string[];
  installedVersions: string[];
  devOnly: boolean;
  direct: boolean | null;
  /** A malicious package (MAL-*): the fix is MALICIOUS_REMEDIATION, not an upgrade */
  malicious: boolean;
}

export interface InboxGroup {
  key: string;
  projectId: string;
  projectName: string;
  packageName: string;
  /** Distinct advisories; one advisory found in two lockfiles of the project is two items but one advisory */
  advisoryCount: number;
  /** Distinct malicious advisories in the group; their remediation is MALICIOUS_REMEDIATION */
  malicious: number;
  /** The version that fixes every non-malicious advisory of the group that has a fix (see upgradeTarget), or null when none has one */
  upgradeTo: string | null;
  /** Distinct non-malicious advisories in the group without a fixed release (so "upgrade to" does not cover them) */
  withoutFix: number;
  /** Lockfiles the group's findings come from (several in a multi-package repo such as held-api) */
  lockfiles: string[];
  installedVersions: string[];
  topPriority: Priority | null;
  items: InboxItem[];
}

export interface LastRefresh {
  id: number;
  startedAt: string;
  finishedAt: string | null;
}

export interface InboxData {
  view: InboxView;
  /** The latest succeeded top-level Refresh all */
  lastRefresh: LastRefresh | null;
  /** The succeeded Refresh all before the latest one: the 'since' view counts events after it finished */
  previousRefresh: LastRefresh | null;
  /** Events strictly after this instant count in the 'since' view (null: every open finding is shown) */
  sinceAt: string | null;
  /** 'since' was requested but fewer than two Refresh all runs have succeeded, so all open findings are shown */
  sinceFallback: boolean;
  ping: InboxGroup[];
  digest: InboxGroup[];
  counts: {
    pingMessages: number;
    pingFindings: number;
    digestMessages: number;
    digestFindings: number;
    logged: number;
    undecided: number;
    /** Undecided findings that enrich has not scored yet (decide leaves them undecided) */
    unenriched: number;
  };
  /** Logged findings in this view; in the 'since' view the link to them must name exactly these */
  loggedIds: number[];
  /** Totals regardless of view, for empty states (enabled projects only) */
  totals: { findings: number; open: number };
  /** Disabled projects and their open findings, which the Inbox leaves out */
  disabled: { projectIds: string[]; open: number };
  enabledProjectIds: string[];
}

const priorityRank = (p: Priority | null) => (p ? PRIORITIES.indexOf(p) : PRIORITIES.length);

/** First sentence of a paragraph (for one-line summaries); long sentences are cut with an ellipsis. */
export function firstSentence(text: string | null | undefined, max = 220): string | null {
  if (!text) return null;
  const t = text.replace(/\s+/g, ' ').trim();
  if (!t) return null;
  // A stop ends the sentence only before whitespace and a capital, digit or quote (or the end), so
  // "16.2.13" and "e.g. for uploads" do not.
  const m = /^(.+?[.!?])(?=\s+[A-Z0-9"'`([]|$)/.exec(t);
  const s = m?.[1] ?? t;
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

/** One group per (project, package), the most urgent first. */
export function groupInboxItems(items: readonly InboxItem[]): InboxGroup[] {
  const groups = new Map<string, InboxGroup>();
  for (const item of items) {
    const key = `${item.projectId}\u0000${item.packageName}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        projectId: item.projectId,
        projectName: item.projectName,
        packageName: item.packageName,
        advisoryCount: 0,
        malicious: 0,
        upgradeTo: null,
        withoutFix: 0,
        lockfiles: [],
        installedVersions: [],
        topPriority: null,
        items: [],
      };
      groups.set(key, g);
    }
    g.items.push(item);
  }
  const out = [...groups.values()].map((g): InboxGroup => {
    const sortedItems = [...g.items].sort(
      (a, b) =>
        priorityRank(a.priority) - priorityRank(b.priority) || a.vulnId.localeCompare(b.vulnId) || a.lockfile.localeCompare(b.lockfile),
    );
    const advisories = new Set(sortedItems.map((i) => i.osvId));
    // A malicious package has no upgrade: its fix is MALICIOUS_REMEDIATION, so it neither sets nor lacks a target.
    const malicious = new Set(sortedItems.filter((i) => i.malicious).map((i) => i.osvId));
    const upgradable = sortedItems.filter((i) => !malicious.has(i.osvId));
    // Each advisory's own target on the installed release line; the highest of them fixes them all.
    const targets = upgradable.map((i) => ({ osvId: i.osvId, target: upgradeTarget(i.installedVersions, i.fixedVersions) }));
    const fixed = new Set(targets.filter((t) => t.target !== null).map((t) => t.osvId));
    return {
      ...g,
      items: sortedItems,
      advisoryCount: advisories.size,
      malicious: malicious.size,
      upgradeTo: highestVersion(targets.flatMap((t) => (t.target ? [t.target] : []))),
      withoutFix: [...advisories].filter((id) => !malicious.has(id) && !fixed.has(id)).length,
      lockfiles: [...new Set(sortedItems.map((i) => i.lockfile))].sort(),
      installedVersions: [...new Set(sortedItems.flatMap((i) => i.installedVersions))],
      topPriority: sortedItems[0]?.priority ?? null,
    };
  });
  return out.sort(
    (a, b) =>
      priorityRank(a.topPriority) - priorityRank(b.topPriority) ||
      b.advisoryCount - a.advisoryCount ||
      a.projectName.localeCompare(b.projectName) ||
      a.packageName.localeCompare(b.packageName),
  );
}

/**
 * Succeeded top-level Refresh all runs, the most recently finished first. Ordered by when they finished, not by
 * id: if two ever overlapped (an inline CLI run beside the worker), the "previous" one still finished before the
 * latest, so the 'since' anchor can never fall after the latest refresh's own decisions.
 */
export function succeededRefreshAlls(db: Db, limit: number): LastRefresh[] {
  return db
    .select({ id: jobRuns.id, startedAt: jobRuns.startedAt, createdAt: jobRuns.createdAt, finishedAt: jobRuns.finishedAt })
    .from(jobRuns)
    .where(and(eq(jobRuns.type, 'refresh-all'), eq(jobRuns.status, 'succeeded'), isNull(jobRuns.parentId)))
    .orderBy(desc(sql`coalesce(${jobRuns.finishedAt}, ${jobRuns.startedAt}, ${jobRuns.createdAt})`), desc(jobRuns.id))
    .limit(limit)
    .all()
    .map((row) => ({ id: row.id, startedAt: row.startedAt ?? row.createdAt, finishedAt: row.finishedAt }));
}

/** Latest succeeded top-level Refresh all: the reference point of the staleness banner. */
export function lastSucceededRefreshAll(db: Db): LastRefresh | null {
  return succeededRefreshAlls(db, 1)[0] ?? null;
}

/**
 * Where "since last refresh" starts: when the Refresh all before the latest succeeded one finished. Everything
 * after it counts, so the view covers the latest refresh plus whatever ran around it (a failed or cancelled
 * Refresh all, standalone jobs), and an event is never lost because the run that wrote it did not succeed.
 * Null with fewer than two succeeded runs: there is no "before", so every open finding is shown.
 */
export function inboxSinceAnchor(db: Db): { latest: LastRefresh | null; previous: LastRefresh | null; sinceAt: string | null } {
  const [latest = null, previous = null] = succeededRefreshAlls(db, 2);
  return { latest, previous, sinceAt: previous ? (previous.finishedAt ?? previous.startedAt) : null };
}

/** Findings with a created/reopened/escalated/decision_changed/advisory_changed event strictly after `sinceIso` (as a subquery). */
function changedSinceQuery(db: Db, sinceIso: string) {
  return db
    .selectDistinct({ id: events.findingId })
    .from(events)
    .where(and(inArray(events.type, [...SINCE_EVENT_TYPES]), gt(events.at, sinceIso)));
}

export function getInbox(db: Db, view: InboxView): InboxData {
  const anchor = inboxSinceAnchor(db);
  const sinceFallback = view === 'since' && !anchor.sinceAt;
  const since = view === 'since' ? anchor.sinceAt : null;

  const changedSince = since ? changedSinceQuery(db, since) : null;
  const projectRows = db.select({ id: projects.id, enabled: projects.enabled }).from(projects).orderBy(projects.id).all();
  const disabledIds = projectRows.filter((p) => !p.enabled).map((p) => p.id);
  // A finding whose project row is missing is still shown (it cannot be "disabled").
  const enabledProject = or(isNull(projects.id), eq(projects.enabled, true));

  const rows = db
    .select({
      findingId: findings.id,
      projectId: findings.projectId,
      projectName: projects.name,
      packageName: findings.packageName,
      lockfile: findings.lockfile,
      osvId: findings.osvId,
      action: findings.currentAction,
      ruleId: findings.currentRuleId,
      priority: findings.priority,
      priorityReasons: findings.priorityReasons,
      fixedVersions: findings.fixedVersions,
      installedVersions: findings.installedVersions,
      devOnly: findings.devOnly,
      direct: findings.direct,
      enrichedAt: findings.enrichedAt,
      cves: advisories.cves,
      advisorySummary: advisories.summary,
      malicious: advisories.malicious,
      triageStatus: triageRuns.status,
      triageOutput: triageRuns.output,
    })
    .from(findings)
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .leftJoin(advisories, eq(advisories.osvId, findings.osvId))
    .leftJoin(triageRuns, eq(triageRuns.id, findings.activeTriageRunId))
    .where(and(eq(findings.status, 'open'), enabledProject, changedSince ? inArray(findings.id, changedSince) : undefined))
    .orderBy(findings.id)
    .all();

  const items: InboxItem[] = [];
  const loggedIds: number[] = [];
  let undecided = 0;
  let unenriched = 0;
  for (const r of rows) {
    if (r.action === 'log') loggedIds.push(r.findingId);
    if (!r.action) {
      undecided++;
      if (!r.enrichedAt) unenriched++;
    }
    if (r.action !== 'ping' && r.action !== 'digest') continue;
    // active_triage_run_id can point at a failed run (the decide job keeps it for the trace); only an ok run has a verdict.
    const triage = r.triageStatus === 'ok' && r.triageOutput ? TriageOutputSchema.safeParse(r.triageOutput) : null;
    const output = triage?.success ? triage.data : null;
    items.push({
      findingId: r.findingId,
      projectId: r.projectId,
      projectName: r.projectName ?? r.projectId,
      packageName: r.packageName,
      lockfile: r.lockfile,
      osvId: r.osvId,
      vulnId: displayVulnId(r.osvId, r.cves),
      action: r.action,
      priority: r.priority,
      priorityReasons: r.priorityReasons,
      verdict: output?.verdict ?? null,
      confidence: output?.confidence ?? null,
      summary: firstSentence(output?.summary) ?? firstSentence(r.advisorySummary),
      ruleId: r.ruleId,
      fixedVersions: r.fixedVersions,
      installedVersions: r.installedVersions,
      devOnly: r.devOnly,
      direct: r.direct,
      malicious: isMalicious(r, r.malicious === null ? null : { malicious: r.malicious }),
    });
  }

  const ping = groupInboxItems(items.filter((i) => i.action === 'ping'));
  const digest = groupInboxItems(items.filter((i) => i.action === 'digest'));
  const statusRows = db
    .select({ status: findings.status, enabled: projects.enabled })
    .from(findings)
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .all();
  const shown = statusRows.filter((r) => r.enabled !== false);

  return {
    view,
    lastRefresh: anchor.latest,
    previousRefresh: anchor.previous,
    sinceAt: since,
    sinceFallback,
    ping,
    digest,
    counts: {
      pingMessages: ping.length,
      pingFindings: ping.reduce((n, g) => n + g.items.length, 0),
      digestMessages: digest.length,
      digestFindings: digest.reduce((n, g) => n + g.items.length, 0),
      logged: loggedIds.length,
      undecided,
      unenriched,
    },
    loggedIds,
    totals: { findings: shown.length, open: shown.filter((r) => r.status === 'open').length },
    disabled: { projectIds: disabledIds, open: statusRows.filter((r) => r.enabled === false && r.status === 'open').length },
    enabledProjectIds: projectRows.filter((p) => p.enabled).map((p) => p.id),
  };
}

/**
 * The Findings link behind "N findings logged". In the 'since' view it names exactly the changed logged
 * findings (null when there are none); otherwise it lists every open logged finding of the projects shown.
 */
export function loggedFindingsHref(inbox: Pick<InboxData, 'sinceAt' | 'loggedIds' | 'disabled' | 'enabledProjectIds'>): string | null {
  if (inbox.sinceAt) return inbox.loggedIds.length ? `/findings?action=log&ids=${inbox.loggedIds.join(',')}` : null;
  const qs = new URLSearchParams({ action: 'log' });
  // Disabled projects are not in the Inbox; keep them out of the count's link too.
  if (inbox.disabled.open && inbox.enabledProjectIds.length) qs.set('project', inbox.enabledProjectIds.join(','));
  return `/findings?${qs.toString().replaceAll('%2C', ',')}`;
}
