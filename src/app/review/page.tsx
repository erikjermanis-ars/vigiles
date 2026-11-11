import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
import { AdvisoryBody, ExternalLink } from '@/components/finding/advisory';
import { AgreementBadge, ProjectDisabledBadge, VerdictBadge } from '@/components/finding/badges';
import { DependencyFacts, PriorityReasons, SignalsList } from '@/components/finding/facts';
import { humanize, MALICIOUS_REMEDIATION } from '@/components/finding/helpers';
import { ReviewLabelForm } from '@/components/finding/review-label-form';
import { ReviewNavKeys } from '@/components/finding/review-nav-keys';
import { TriageEvidenceView } from '@/components/finding/triage-evidence';
import { ActionBadge, Button, ButtonLink, Card, CardBody, CardHeader, Empty, Kv, Mono, PageHeader, PriorityBadge, cx } from '@/components/ui';
import { saveReviewLabelAction, setLabelerAction } from '@/app/review/actions';
import { currentLabeler } from '@/app/review/labeler';
import { getDb } from '@/lib/db/client';
import { displayVulnId, osvUrl, relativeTime } from '@/lib/format';
import { loadDecisionContext, type SearchParams } from '@/lib/queries/findings';
import {
  compareLabel,
  getReviewItem,
  getReviewQueue,
  pickReviewTarget,
  reviewNeighbors,
  type Agreement,
  type ReviewItem,
  type ReviewQueue,
} from '@/lib/queries/review';

const reviewHref = (id: number | null) => (id === null ? null : `/review?id=${id}`);

/** "Labeling as: [me] Change": the labeler whose queue, labels and reveal this page shows (a cookie). */
function LabelerControl({ labeler, targetId, error }: { labeler: string; targetId: number | null; error: boolean }) {
  return (
    <form action={setLabelerAction} className="flex flex-wrap items-center gap-2 text-sm">
      {targetId !== null ? <input type="hidden" name="id" value={targetId} /> : null}
      <label htmlFor="labeler-name" className="text-muted">
        Labeling as
      </label>
      <input
        id="labeler-name"
        name="labeler"
        defaultValue={labeler}
        required
        maxLength={32}
        pattern="[A-Za-z0-9][A-Za-z0-9_\-]{0,31}"
        title="1–32 letters, digits, _ or -, starting with a letter or digit"
        aria-invalid={error || undefined}
        className={cx('w-28 rounded-md border bg-panel px-2 py-1 font-mono text-sm', error ? 'border-ping' : 'border-border')}
      />
      <Button type="submit">Change</Button>
      {error ? (
        <span role="alert" className="text-xs text-ping">
          Invalid name: use 1–32 letters, digits, _ or -.
        </span>
      ) : null}
    </form>
  );
}

function Progress({ queue, labeler }: { queue: ReviewQueue; labeler: string }) {
  const pct = queue.total ? Math.round((queue.labeled / queue.total) * 100) : 0;
  return (
    <div className="mb-5">
      <div className="mb-1 flex justify-between text-sm">
        <span>
          <Mono>{labeler}</Mono> labeled <strong>{queue.labeled}</strong> of {queue.total} open P0–P2 findings (enabled projects)
        </span>
        <span className="text-muted">{queue.unlabeled.length} to go</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
        <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function FindingHeading({ item }: { item: ReviewItem }) {
  const f = item.finding;
  const malicious = item.advisory?.malicious ?? false;
  return (
    <Card>
      <CardBody className="space-y-2">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h2 className="text-lg font-semibold">{f.packageName}</h2>
          <span className="text-sm">
            <Mono>{f.installedVersions.join(', ')}</Mono>
            <span className="text-muted"> → </span>
            {malicious ? <span className="text-ping">remove (malicious package)</span> : <Mono>{f.fixedVersions.join(', ') || 'no fixed version'}</Mono>}
          </span>
          <ExternalLink href={osvUrl(f.osvId)}>
            <span className="font-mono text-sm">{displayVulnId(f.osvId, item.advisory?.cves)}</span>
          </ExternalLink>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <PriorityBadge priority={f.priority} />
          <PriorityReasons reasons={f.priorityReasons} />
          <span className="text-muted">
            · {item.project?.name ?? f.projectId} · <Mono>{f.lockfile}</Mono> · {humanize(f.origin)}
          </span>
          {item.project && !item.project.enabled ? <ProjectDisabledBadge /> : null}
        </div>
        {malicious ? (
          <p className="rounded-md bg-ping-bg px-3 py-2 text-sm text-ping">
            <strong>Malicious package</strong> (not triaged). Remediation: {MALICIOUS_REMEDIATION}
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}

function ProjectContext({ item }: { item: ReviewItem }) {
  if (!item.project) return null;
  const p = item.project;
  return (
    <Card>
      <CardHeader title="Project context" />
      <CardBody className="space-y-2">
        <Kv
          items={[
            ['Exposure', p.exposure],
            ['Criticality', p.criticality],
          ]}
        />
        {p.mitigations ? <p className="text-sm whitespace-pre-line text-muted">Mitigations: {p.mitigations}</p> : null}
        {p.notes ? <p className="text-sm whitespace-pre-line text-muted">Notes: {p.notes}</p> : null}
      </CardBody>
    </Card>
  );
}

function Reveal({ item, nextHref, prevHref }: { item: ReviewItem; nextHref: string; prevHref: string | null }) {
  const label = item.label!;
  const reveal = item.reveal!;
  const cmp = compareLabel(label, reveal);
  const row = (title: string, value: ReactNode, agreement: Agreement) => (
    <div className={cx('rounded-md border px-3 py-2', agreement === 'disagree' ? 'border-ping' : 'border-border')}>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-xs font-medium tracking-wide text-muted uppercase">{title}</span>
        <AgreementBadge value={agreement} />
      </div>
      {value}
    </div>
  );
  return (
    <Card>
      <CardHeader title="Saved: you vs. the system" />
      <CardBody className="space-y-3">
        <div className="rounded-md bg-panel-2 px-3 py-2">
          <div className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">Your label</div>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <ActionBadge action={label.expectedAction} />
            <span>affected: {label.affectedTruth ?? '—'}</span>
            <span className="text-muted">{relativeTime(label.labeledAt)}</span>
          </div>
          {label.note ? <p className="mt-1 text-sm whitespace-pre-line text-muted">{label.note}</p> : null}
        </div>
        {row(
          'Policy',
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <ActionBadge action={reveal.policyAction} />
            {reveal.ruleId ? (
              <span>
                rule <Mono>{reveal.ruleId}</Mono>
              </span>
            ) : null}
          </div>,
          cmp.policy,
        )}
        {row(
          'LLM suggestion',
          <div className="space-y-1 text-sm">
            <ActionBadge action={reveal.suggestedAction} />
            {reveal.suggestedActionReason ? <p className="text-muted">{reveal.suggestedActionReason}</p> : null}
            {item.evidence && !item.evidence.isDecisionRun ? (
              <p className="text-xs text-muted">From run #{item.evidence.runId}, which the current decision does not use.</p>
            ) : null}
          </div>,
          cmp.llm,
        )}
        {row('LLM verdict vs your "affected"', <VerdictBadge verdict={reveal.verdict} confidence={reveal.confidence} />, cmp.verdict)}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <ButtonLink href={nextHref} variant="primary">
            Next
          </ButtonLink>
          {prevHref ? <ButtonLink href={prevHref}>Previous</ButtonLink> : null}
          <Link href={`/findings/${item.finding.id}`} className="text-sm">
            Open finding page
          </Link>
        </div>
        <p className="text-xs text-muted">
          <kbd className="font-mono">j</kbd> or <kbd className="font-mono">Enter</kbd> next · <kbd className="font-mono">k</kbd> previous · change
          the label on the finding page
        </p>
        <ReviewNavKeys nextHref={nextHref} prevHref={prevHref} />
      </CardBody>
    </Card>
  );
}

export default async function ReviewPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const sp = await searchParams;
  const requested = Number(Array.isArray(sp.id) ? sp.id[0] : sp.id);
  const db = getDb();
  const labeler = await currentLabeler();
  const queue = getReviewQueue(db, labeler);
  const targetId = pickReviewTarget(queue, Number.isInteger(requested) && requested > 0 ? requested : null);

  const header = (
    <PageHeader
      title="Review"
      subtitle="Blind labeling: decide before seeing what the policy and the LLM decided."
      actions={
        <>
          <LabelerControl labeler={labeler} targetId={targetId} error={sp.labelerError !== undefined} />
          <ButtonLink href="/findings?labeled=yes&status=all">Labeled findings</ButtonLink>
        </>
      }
    />
  );

  if (targetId === null) {
    return (
      <>
        {header}
        <Progress queue={queue} labeler={labeler} />
        <Empty>
          {queue.total === 0 ? (
            'No open P0–P2 findings yet. Run Refresh all on the Jobs page.'
          ) : (
            <>
              Every open P0–P2 finding is labeled. See how the system did on the <Link href="/eval">Eval</Link> page.
            </>
          )}
        </Empty>
      </>
    );
  }

  const item = getReviewItem(db, targetId, { activeConfig: loadDecisionContext().activeConfig, labeler });
  if (!item) notFound();
  const { next, prev } = reviewNeighbors(queue, targetId);
  const nextHref = reviewHref(next);
  const prevHref = reviewHref(prev);
  const position = queue.order.indexOf(targetId);

  return (
    <>
      {header}
      <Progress queue={queue} labeler={labeler} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="min-w-0 space-y-4">
          <FindingHeading item={item} />
          <Card>
            <CardHeader title="Advisory" />
            <CardBody>
              {item.advisory ? (
                <AdvisoryBody advisory={item.advisory} collapseReferences />
              ) : (
                <p className="text-sm text-muted">The advisory record is missing.</p>
              )}
            </CardBody>
          </Card>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader title="Signals" />
              <CardBody>
                <SignalsList
                  s={{
                    priority: item.finding.priority,
                    priorityReasons: item.finding.priorityReasons,
                    inKev: item.finding.inKev,
                    kevDateAdded: item.finding.kevDateAdded,
                    epss: item.finding.epss,
                    epssPercentile: item.finding.epssPercentile,
                    cvssScore: item.finding.cvssScore,
                    cvssVector: item.advisory?.cvssVector ?? null,
                    severityLabel: item.advisory?.severityLabel ?? null,
                    malicious: item.advisory?.malicious ?? false,
                  }}
                />
              </CardBody>
            </Card>
            <Card>
              <CardHeader title="Dependency" />
              <CardBody>
                <DependencyFacts d={{ ...item.finding, findingId: item.finding.id, malicious: item.advisory?.malicious ?? false }} newTab />
              </CardBody>
            </Card>
          </div>
          <Card>
            <CardHeader title={item.evidence ? `Triage evidence (${item.evidence.configName}, run #${item.evidence.runId})` : 'Triage evidence'} />
            <CardBody className="space-y-3">
              {item.evidence && !item.evidence.isDecisionRun ? (
                <p className="rounded-md bg-digest-bg px-3 py-2 text-sm text-digest">
                  The current decision does not use this run (triage for the current inputs failed or is pending, or Decide has not run since).
                </p>
              ) : null}
              {item.evidence ? (
                <TriageEvidenceView findingId={item.finding.id} runId={item.evidence.runId} t={item.evidence} newTab />
              ) : item.advisory?.malicious ? (
                <p className="text-sm text-muted">Malicious packages are not triaged: there is nothing to reason about (spec §9.1).</p>
              ) : (
                <p className="text-sm text-muted">No successful triage run under the active config yet. Label from the advisory and facts.</p>
              )}
            </CardBody>
          </Card>
        </div>
        <div className="space-y-4 lg:sticky lg:top-16 lg:self-start">
          {item.label && item.reveal ? (
            <Reveal item={item} nextHref={nextHref ?? '/review'} prevHref={prevHref} />
          ) : (
            <Card>
              <CardHeader
                title="Your label"
                actions={<span className="text-xs text-muted">{position >= 0 ? `#${position + 1} in queue` : 'outside the queue'}</span>}
              />
              <CardBody>
                <ReviewLabelForm key={item.finding.id} findingId={item.finding.id} saveAction={saveReviewLabelAction} nextHref={nextHref} prevHref={prevHref} />
              </CardBody>
            </Card>
          )}
          <ProjectContext item={item} />
        </div>
      </div>
    </>
  );
}
