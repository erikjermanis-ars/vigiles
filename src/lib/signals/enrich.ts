/**
 * Enrichment of open findings (spec §6 `enrich`, §8): EPSS, KEV join, CVSS score, base priority,
 * and `escalated` events on upward moves. Network first, then every write in one transaction.
 * Findings of disabled projects are inactive: they are left as they are until the project is enabled again.
 */
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, events, findings, projects } from '../db/schema';
import { PRIORITIES, type Priority } from '../types';
import { computeFindingSignals, type EnrichRow, type SignalSources } from './compute';
import { normalizeCves } from './cve';
import { fetchEpssScores } from './epss';
import type { SignalSnapshot } from './escalation';
import { recordFeedFailure, recordFeedSuccess } from './feed-state';
import type { FetchFn } from './http';
import { loadKevIndex } from './kev';
import type { PriorityThresholds } from './priority';

// The pure per-finding computation lives in ./compute; re-exported so existing imports keep working.
export { computeFindingSignals, resolveFindingEpss, type EnrichRow, type FindingSignals, type SignalSources } from './compute';

/** Used when a finding's project row is missing: assume the worst so nothing gets quietly downgraded. */
const UNKNOWN_PROFILE = { exposure: 'internet-facing', criticality: 'high' } as const;

export function loadOpenFindings(db: Db): { rows: EnrichRow[]; missingProfiles: string[]; disabledSkipped: number } {
  const raw = db
    .select({
      id: findings.id,
      projectId: findings.projectId,
      osvId: findings.osvId,
      priority: findings.priority,
      inKev: findings.inKev,
      epss: findings.epss,
      epssPercentile: findings.epssPercentile,
      enrichedAt: findings.enrichedAt,
      advOsvId: advisories.osvId,
      advCves: advisories.cves,
      advCvss: advisories.cvssScore,
      advLabel: advisories.severityLabel,
      advMalicious: advisories.malicious,
      profile: projects.profile,
      enabled: projects.enabled,
    })
    .from(findings)
    .leftJoin(advisories, eq(advisories.osvId, findings.osvId))
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .where(eq(findings.status, 'open'))
    .orderBy(findings.id)
    .all();

  const missingProfiles = new Set<string>();
  // A missing project row (enabled null) is still enriched, assuming the worst profile.
  const active = raw.filter((r) => r.enabled !== false);
  const rows = active.map((r): EnrichRow => {
    if (!r.profile) missingProfiles.add(r.projectId);
    return {
      id: r.id,
      projectId: r.projectId,
      osvId: r.osvId,
      priority: r.priority,
      inKev: r.inKev,
      epss: r.epss,
      epssPercentile: r.epssPercentile,
      enrichedAt: r.enrichedAt,
      advisory:
        r.advOsvId === null
          ? null
          : { cves: r.advCves ?? [], cvssScore: r.advCvss, severityLabel: r.advLabel, malicious: r.advMalicious ?? false },
      exposure: r.profile?.exposure ?? UNKNOWN_PROFILE.exposure,
      criticality: r.profile?.criticality ?? UNKNOWN_PROFILE.criticality,
    };
  });
  return { rows, missingProfiles: [...missingProfiles], disabledSkipped: raw.length - active.length };
}

export type EnrichStats = {
  findings: number;
  cves: number;
  byPriority: Record<Priority, number>;
  inKev: number;
  escalated: number;
  epssFetched: number;
  epssFailed: number;
  /** Open findings of disabled projects, left untouched */
  disabledSkipped: number;
};

export interface EnrichOptions {
  thresholds: PriorityThresholds;
  fetchFn?: FetchFn;
  signal?: AbortSignal;
  jobRunId?: number;
  log?: (message: string) => void;
  progress?: (text: string) => void;
  throwIfCancelled?: () => void;
  now?: () => string;
}

export async function enrichOpenFindings(db: Db, opts: EnrichOptions): Promise<EnrichStats> {
  const log = opts.log ?? (() => {});
  const progress = opts.progress ?? (() => {});
  const now = opts.now ?? (() => new Date().toISOString());

  const { rows, missingProfiles, disabledSkipped } = loadOpenFindings(db);
  for (const id of missingProfiles) log(`warning: project "${id}" has no profile row; assuming internet-facing, criticality high`);
  if (disabledSkipped) log(`${disabledSkipped} open finding(s) of disabled projects skipped`);

  const kevIndex = loadKevIndex(db);
  if (kevIndex.size === 0) log('warning: the KEV catalog is empty (run sync-kev); no finding will be marked in KEV');

  const cves = normalizeCves(rows.flatMap((r) => r.advisory?.cves ?? []));
  log(`${rows.length} open findings, ${cves.length} distinct CVEs`);
  const epss = await fetchEpssScores(cves, {
    fetchFn: opts.fetchFn,
    signal: opts.signal,
    onBatch: (i, total) => {
      opts.throwIfCancelled?.();
      progress(`EPSS batch ${i + 1}/${total}`);
    },
  });
  for (const e of epss.errors) log(`warning: EPSS ${e}; keeping previous scores for those CVEs`);
  log(`EPSS: ${epss.scores.size} CVEs scored${epss.date ? ` (model date ${epss.date})` : ''}, ${epss.failedCves.size} unavailable`);
  opts.throwIfCancelled?.();

  progress(`scoring ${rows.length} findings`);
  const stats: EnrichStats = {
    findings: rows.length,
    cves: cves.length,
    byPriority: Object.fromEntries(PRIORITIES.map((p) => [p, 0])) as Record<Priority, number>,
    inKev: 0,
    escalated: 0,
    epssFetched: epss.scores.size,
    epssFailed: epss.failedCves.size,
    disabledSkipped,
  };
  const at = now();
  const src: SignalSources = { kevIndex, epss, thresholds: opts.thresholds };

  db.transaction((tx) => {
    for (const row of rows) {
      const s = computeFindingSignals(row, src);
      stats.byPriority[s.priority]++;
      if (s.inKev) stats.inKev++;

      tx.update(findings)
        .set({
          priority: s.priority,
          priorityReasons: s.priorityReasons,
          inKev: s.inKev,
          kevDateAdded: s.kevDateAdded,
          epss: s.epss,
          epssPercentile: s.epssPercentile,
          cvssScore: s.cvssScore,
          enrichedAt: at,
          updatedAt: at,
        })
        .where(eq(findings.id, row.id))
        .run();

      if (s.escalation.length) {
        stats.escalated++;
        const from: SignalSnapshot = { priority: row.priority, inKev: row.inKev, epss: row.epss };
        const to: SignalSnapshot = { priority: s.priority, inKev: s.inKev, epss: s.epss };
        tx.insert(events)
          .values({
            findingId: row.id,
            type: 'escalated',
            jobRunId: opts.jobRunId ?? null,
            data: { from, to, reasons: s.escalation, priorityReasons: s.priorityReasons },
            at,
          })
          .run();
      }
    }

    if (epss.errors.length) recordFeedFailure(tx, 'epss', epss.errors.join('; '), at);
    else recordFeedSuccess(tx, 'epss', { cves: cves.length, date: epss.date }, at);
  });

  const summary = PRIORITIES.map((p) => `${p} ${stats.byPriority[p]}`).join(', ');
  log(`enriched ${rows.length} findings (${summary}); ${stats.inKev} in KEV, ${stats.escalated} escalated`);
  return stats;
}
