/**
 * Blind review queue (spec §11.1). The review item deliberately omits the verdict, confidence,
 * suggested action and the policy decision until a label exists, so none of it reaches the page
 * (not even hidden in the payload) before you commit to an answer.
 */
import { and, desc, eq, inArray, isNull, or } from 'drizzle-orm';
import type { Db } from '../db/client';
import { advisories, findings, labels, projects, triageRuns } from '../db/schema';
import type {
  Action,
  AffectedTruth,
  Confidence,
  Criticality,
  Exposure,
  FindingInstance,
  FindingOrigin,
  FindingStatus,
  ImportSite,
  Priority,
  TriageOutput,
  Verdict,
} from '../types';
import { comparePriorityOrder, getLabel, LABELER, parseTriageOutput, type LabelRow } from './findings';

/** Findings that enter the review queue (spec §11.1: "label only P0–P2 at first"). */
export const REVIEW_PRIORITIES = ['P0', 'P1', 'P2'] as const satisfies readonly Priority[];

export interface ReviewQueue {
  /** Every open P0–P2 finding of an enabled project, in review order (labeled or not) */
  order: number[];
  /** The unlabeled subset, same order */
  unlabeled: number[];
  total: number;
  labeled: number;
}

/**
 * The labeler's queue. Findings of disabled projects are left out: they are neither scanned nor
 * triaged any more, so their facts and evidence go stale.
 */
export function getReviewQueue(db: Db, labeler = LABELER): ReviewQueue {
  const rows = db
    .select({
      id: findings.id,
      priority: findings.priority,
      epss: findings.epss,
      findingCvss: findings.cvssScore,
      advisoryCvss: advisories.cvssScore,
      labeled: labels.findingId,
    })
    .from(findings)
    .leftJoin(projects, eq(projects.id, findings.projectId))
    .leftJoin(advisories, eq(advisories.osvId, findings.osvId))
    .leftJoin(labels, and(eq(labels.findingId, findings.id), eq(labels.labeler, labeler)))
    .where(
      and(
        eq(findings.status, 'open'),
        inArray(findings.priority, [...REVIEW_PRIORITIES]),
        // A finding whose project row is gone counts as enabled, as on the Findings page.
        or(isNull(projects.id), eq(projects.enabled, true)),
      ),
    )
    .all()
    .map((r) => ({ ...r, cvssScore: r.findingCvss ?? r.advisoryCvss, isLabeled: r.labeled !== null }))
    .sort(comparePriorityOrder);
  const unlabeled = rows.filter((r) => !r.isLabeled).map((r) => r.id);
  return { order: rows.map((r) => r.id), unlabeled, total: rows.length, labeled: rows.length - unlabeled.length };
}

/** The finding to show: the requested one, else the first unlabeled one (null when the queue is done). */
export function pickReviewTarget(queue: ReviewQueue, requestedId: number | null): number | null {
  return requestedId ?? queue.unlabeled[0] ?? null;
}

/**
 * Keyboard navigation. `next` is the first unlabeled finding after the current one in review order
 * (wrapping, so skipped findings come back around); `prev` is the finding just before it, labeled or not.
 */
export function reviewNeighbors(queue: ReviewQueue, currentId: number): { next: number | null; prev: number | null } {
  const unlabeled = new Set(queue.unlabeled);
  const idx = queue.order.indexOf(currentId);
  if (idx === -1) return { next: queue.unlabeled.find((id) => id !== currentId) ?? null, prev: null };
  let next: number | null = null;
  for (let step = 1; step < queue.order.length; step++) {
    const id = queue.order[(idx + step) % queue.order.length]!;
    if (unlabeled.has(id)) {
      next = id;
      break;
    }
  }
  return { next, prev: idx > 0 ? queue.order[idx - 1]! : null };
}

/** Triage facts that are safe to show before labeling: no verdict, confidence or suggested action. */
export type BlindTriageEvidence = Pick<
  TriageOutput,
  | 'summary'
  | 'runtime_usage'
  | 'vulnerable_code_used'
  | 'attacker_reachable'
  | 'deployment_conditions_met'
  | 'evidence'
  | 'exploit_conditions'
  | 'remediation'
  | 'workaround'
> & {
  runId: number;
  configName: string;
  createdAt: string;
  /** False when this is an older successful run because the decision's own run failed or is missing */
  isDecisionRun: boolean;
};

/** Explicit field copy (not a spread) so fields added to the output schema later are not revealed. */
export function toBlindEvidence(
  run: { id: number; configName: string; createdAt: string },
  out: TriageOutput,
  isDecisionRun = true,
): BlindTriageEvidence {
  return {
    runId: run.id,
    configName: run.configName,
    createdAt: run.createdAt,
    isDecisionRun,
    summary: out.summary,
    runtime_usage: out.runtime_usage,
    vulnerable_code_used: out.vulnerable_code_used,
    attacker_reachable: out.attacker_reachable,
    deployment_conditions_met: out.deployment_conditions_met,
    evidence: out.evidence,
    exploit_conditions: out.exploit_conditions,
    remediation: out.remediation,
    workaround: out.workaround,
  };
}

/** What the system decided; only loaded once you have labeled the finding. */
export interface ReviewReveal {
  policyAction: Action | null;
  ruleId: string | null;
  verdict: Verdict | null;
  confidence: Confidence | null;
  suggestedAction: Action | null;
  suggestedActionReason: string | null;
}

export interface ReviewItem {
  finding: {
    id: number;
    projectId: string;
    lockfile: string;
    ecosystem: string;
    packageName: string;
    osvId: string;
    installedVersions: string[];
    fixedVersions: string[];
    status: FindingStatus;
    origin: FindingOrigin;
    priority: Priority | null;
    priorityReasons: string[];
    direct: boolean | null;
    devOnly: boolean;
    paths: string[][];
    /** Per installed version facts; empty for findings scanned before they were recorded */
    instances: FindingInstance[];
    importSites: ImportSite[];
    /** Uncapped number of import sites (importSites is capped) */
    importSiteCount: number;
    inKev: boolean;
    kevDateAdded: string | null;
    epss: number | null;
    epssPercentile: number | null;
    cvssScore: number | null;
  };
  project: { name: string; enabled: boolean; exposure: Exposure; criticality: Criticality; notes: string; mitigations: string } | null;
  advisory: {
    summary: string | null;
    details: string | null;
    aliases: string[];
    cves: string[];
    cvssVector: string | null;
    severityLabel: string | null;
    cwes: string[];
    references: string[];
    published: string | null;
    modified: string | null;
    withdrawn: string | null;
    malicious: boolean;
  } | null;
  /** Null when the finding has no successful triage run under the active config */
  evidence: BlindTriageEvidence | null;
  label: LabelRow | null;
  /** Present only when `label` is */
  reveal: ReviewReveal | null;
}

/**
 * The run behind the current decision when it succeeded; otherwise (no decision yet, or the decision
 * kept a failed run for its trace) the newest successful run of the active config.
 */
function evidenceRun(db: Db, activeTriageRunId: number | null, findingId: number, activeConfig: string) {
  const cols = {
    id: triageRuns.id,
    configName: triageRuns.configName,
    createdAt: triageRuns.createdAt,
    status: triageRuns.status,
    output: triageRuns.output,
  };
  const byDecision = activeTriageRunId ? db.select(cols).from(triageRuns).where(eq(triageRuns.id, activeTriageRunId)).get() : undefined;
  const decisionOutput = byDecision?.status === 'ok' ? parseTriageOutput(byDecision.output) : null;
  if (byDecision && decisionOutput) return { run: byDecision, output: decisionOutput, isDecisionRun: true };

  const latestOk = db
    .select(cols)
    .from(triageRuns)
    .where(and(eq(triageRuns.findingId, findingId), eq(triageRuns.configName, activeConfig), eq(triageRuns.status, 'ok')))
    .orderBy(desc(triageRuns.id))
    .limit(1)
    .get();
  const output = latestOk ? parseTriageOutput(latestOk.output) : null;
  return latestOk && output ? { run: latestOk, output, isDecisionRun: false } : null;
}

export function getReviewItem(db: Db, id: number, opts: { activeConfig: string; labeler?: string }): ReviewItem | null {
  const f = db.select().from(findings).where(eq(findings.id, id)).get();
  if (!f) return null;
  const adv = db.select().from(advisories).where(eq(advisories.osvId, f.osvId)).get();
  const proj = db
    .select({ name: projects.name, enabled: projects.enabled, profile: projects.profile })
    .from(projects)
    .where(eq(projects.id, f.projectId))
    .get();
  const label = getLabel(db, id, opts.labeler ?? LABELER);
  const triage = evidenceRun(db, f.activeTriageRunId, f.id, opts.activeConfig);

  return {
    finding: {
      id: f.id,
      projectId: f.projectId,
      lockfile: f.lockfile,
      ecosystem: f.ecosystem,
      packageName: f.packageName,
      osvId: f.osvId,
      installedVersions: f.installedVersions,
      fixedVersions: f.fixedVersions,
      status: f.status,
      origin: f.origin,
      priority: f.priority,
      priorityReasons: f.priorityReasons,
      direct: f.direct,
      devOnly: f.devOnly,
      paths: f.paths,
      instances: f.instances,
      importSites: f.importSites,
      importSiteCount: f.importSiteCount,
      inKev: f.inKev,
      kevDateAdded: f.kevDateAdded,
      epss: f.epss,
      epssPercentile: f.epssPercentile,
      cvssScore: f.cvssScore ?? adv?.cvssScore ?? null,
    },
    project: proj
      ? {
          name: proj.name,
          enabled: proj.enabled,
          exposure: proj.profile.exposure,
          criticality: proj.profile.criticality,
          notes: proj.profile.notes,
          mitigations: proj.profile.mitigations,
        }
      : null,
    advisory: adv
      ? {
          summary: adv.summary,
          details: adv.details,
          aliases: adv.aliases,
          cves: adv.cves,
          cvssVector: adv.cvssVector,
          severityLabel: adv.severityLabel,
          cwes: adv.cwes,
          references: adv.references,
          published: adv.published,
          modified: adv.modified,
          withdrawn: adv.withdrawn,
          malicious: adv.malicious,
        }
      : null,
    evidence: triage ? toBlindEvidence(triage.run, triage.output, triage.isDecisionRun) : null,
    label,
    reveal: label
      ? {
          policyAction: f.currentAction,
          ruleId: f.currentRuleId,
          verdict: triage?.output.verdict ?? null,
          confidence: triage?.output.confidence ?? null,
          suggestedAction: triage?.output.suggested_action ?? null,
          suggestedActionReason: triage?.output.suggested_action_reason ?? null,
        }
      : null,
  };
}

export type Agreement = 'agree' | 'disagree' | 'n/a';

export interface LabelComparison {
  policy: Agreement;
  llm: Agreement;
  /** Your affected_truth vs the LLM verdict (yes ↔ affected/likely_affected) */
  verdict: Agreement;
}

const AFFECTED_VERDICTS: readonly Verdict[] = ['affected', 'likely_affected'];

export function compareLabel(label: { expectedAction: Action; affectedTruth: AffectedTruth | null }, reveal: ReviewReveal): LabelComparison {
  const same = (other: Action | null): Agreement => (other === null ? 'n/a' : other === label.expectedAction ? 'agree' : 'disagree');
  let verdict: Agreement = 'n/a';
  if (reveal.verdict && (label.affectedTruth === 'yes' || label.affectedTruth === 'no')) {
    const llmSaysAffected = AFFECTED_VERDICTS.includes(reveal.verdict);
    verdict = llmSaysAffected === (label.affectedTruth === 'yes') ? 'agree' : 'disagree';
  }
  return { policy: same(reveal.policyAction), llm: same(reveal.suggestedAction), verdict };
}
