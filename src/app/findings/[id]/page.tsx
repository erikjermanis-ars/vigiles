import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
import { AdvisoryBody, ExternalLink } from '@/components/finding/advisory';
import { OriginBadge, ProjectDisabledBadge, RunStatusBadge, StatusBadge, TriageStateBadge, VerdictBadge } from '@/components/finding/badges';
import { DependencyFacts, PriorityReasons, SignalsList } from '@/components/finding/facts';
import { humanize, MALICIOUS_REMEDIATION, summarizeEventData } from '@/components/finding/helpers';
import { LabelForm } from '@/components/finding/label-form';
import { TriageEvidenceView } from '@/components/finding/triage-evidence';
import { AutoRefresh } from '@/components/auto-refresh';
import { ActionBadge, Badge, Button, ButtonLink, Card, CardBody, CardHeader, Kv, Mono, PageHeader, PriorityBadge, Table, Td, Th, cx } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { displayVulnId, formatDateTime, formatDuration, formatUsd, osvUrl, relativeTime, shortDate } from '@/lib/format';
import {
  commitFromPrompt,
  getFindingDetail,
  loadDecisionContext,
  type DecisionContext,
  type FindingDetail,
  type SearchParams,
  type TriageRunView,
} from '@/lib/queries/findings';
import { enqueueDecideAction, enqueueTriageAction, saveLabelAction } from '@/app/findings/actions';
import { currentLabeler } from '@/app/review/labeler';

function firstParam(v: string | string[] | undefined): string | null {
  return (Array.isArray(v) ? v[0] : v) ?? null;
}

function Header({ d }: { d: FindingDetail }) {
  const f = d.finding;
  const malicious = d.advisory?.malicious ?? false;
  // The header's action is the current decision's; flag it when triage moved on since (same rule as the Decision card).
  const headerStale = d.decision?.isCurrent && d.project?.enabled !== false ? d.decision.stale : null;
  const vulnId = displayVulnId(f.osvId, d.advisory?.cves);
  const otherIds = [f.osvId, ...(d.advisory?.aliases ?? [])].filter((a, i, all) => a !== vulnId && all.indexOf(a) === i);
  return (
    <>
      <PageHeader
        title={f.packageName}
        subtitle={
          <>
            {d.project?.name ?? f.projectId} · <Mono>{f.lockfile}</Mono> · {f.ecosystem}
          </>
        }
        actions={<ButtonLink href="/findings">All findings</ButtonLink>}
      />
      <div className="mb-5 space-y-2 text-sm">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Mono>{f.installedVersions.join(', ') || '—'}</Mono>
          <span className="text-muted">→</span>
          {malicious ? <span className="text-ping">remove (malicious package)</span> : <Mono>{f.fixedVersions.join(', ') || 'no fixed version'}</Mono>}
          <span className="text-muted">·</span>
          <ExternalLink href={osvUrl(f.osvId)}>
            <span className="font-mono">{vulnId}</span>
          </ExternalLink>
          {otherIds.length ? <span className="text-muted">also {otherIds.join(', ')}</span> : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <PriorityBadge priority={f.priority} />
          <PriorityReasons reasons={f.priorityReasons} />
          <span className="text-muted">·</span>
          <ActionBadge action={f.currentAction} />
          {headerStale ? (
            <Badge tone="digest" title={`${headerStale.reason} See the Decision card below.`}>
              stale decision
            </Badge>
          ) : null}
          {f.currentRuleId ? (
            <span className="text-muted">
              rule <Mono>{f.currentRuleId}</Mono>
            </span>
          ) : null}
          <span className="text-muted">·</span>
          <StatusBadge status={f.status} />
          <OriginBadge origin={f.origin} />
          {d.project && !d.project.enabled ? <ProjectDisabledBadge /> : null}
          <span className="text-muted">
            first seen <span title={formatDateTime(f.firstSeenAt)}>{shortDate(f.firstSeenAt)}</span>
            {f.resolvedAt ? (
              <>
                {' · resolved '}
                <span title={formatDateTime(f.resolvedAt)}>{shortDate(f.resolvedAt)}</span>
              </>
            ) : null}
          </span>
        </div>
        {malicious ? (
          <div className="rounded-md bg-ping-bg px-3 py-2 text-ping">
            <strong>Malicious package.</strong> It is not triaged (there is nothing to reason about) and the policy pings. Remediation:{' '}
            {MALICIOUS_REMEDIATION}
          </div>
        ) : null}
        {d.project && !d.project.enabled ? (
          <p className="text-muted">
            Project {d.project.name} is disabled in <Mono>projects/{d.project.id}.yaml</Mono>: scans and triage skip it, so these facts are from its last scan.
          </p>
        ) : null}
      </div>
    </>
  );
}

function Signals({ d }: { d: FindingDetail }) {
  const f = d.finding;
  return (
    <Card>
      <CardHeader title="Signals" />
      <CardBody>
        <SignalsList
          s={{
            priority: f.priority,
            priorityReasons: f.priorityReasons,
            inKev: f.inKev,
            kevDateAdded: f.kevDateAdded,
            kevRansomware: d.kevEntries.find((k) => k.ransomware === 'Known')?.ransomware ?? null,
            epss: f.epss,
            epssPercentile: f.epssPercentile,
            cvssScore: f.cvssScore ?? d.advisory?.cvssScore ?? null,
            cvssVector: d.advisory?.cvssVector ?? null,
            severityLabel: d.advisory?.severityLabel ?? null,
            malicious: d.advisory?.malicious ?? false,
          }}
        />
      </CardBody>
    </Card>
  );
}

function Dependency({ d }: { d: FindingDetail }) {
  const f = d.finding;
  return (
    <Card>
      <CardHeader title="Dependency" />
      <CardBody>
        <DependencyFacts
          d={{
            findingId: f.id,
            projectId: f.projectId,
            lockfile: f.lockfile,
            ecosystem: f.ecosystem,
            packageName: f.packageName,
            installedVersions: f.installedVersions,
            fixedVersions: f.fixedVersions,
            direct: f.direct,
            devOnly: f.devOnly,
            paths: f.paths,
            instances: f.instances,
            importSites: f.importSites,
            importSiteCount: f.importSiteCount,
            malicious: d.advisory?.malicious ?? false,
          }}
        />
        {d.lastScan?.commitSha ? (
          <p className="mt-3 text-xs text-muted">
            Last seen in scan #{d.lastScan.id} of <Mono>{d.lastScan.ref}</Mono> at <Mono>{d.lastScan.commitSha.slice(0, 10)}</Mono>
            {d.lastScan.commitDate ? ` (committed ${formatDateTime(d.lastScan.commitDate)})` : ''}. Import-site links open this commit.
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}

function JsonDetails({ summary, value }: { summary: string; value: unknown }) {
  return (
    <details className="rounded-md border border-border">
      <summary className="cursor-pointer px-3 py-1.5 text-sm text-muted">{summary}</summary>
      <pre className="max-h-96 overflow-auto border-t border-border px-3 py-2 font-mono text-xs whitespace-pre-wrap break-words">
        {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

/** `readCommit`: the commit whose snapshot the run read (recorded, or named in a legacy run's prompt). */
function RunMeta({ run, readCommit }: { run: TriageRunView; readCommit: string | null }) {
  const tokens = [run.inputTokens, run.outputTokens].some((n) => n !== null)
    ? `${run.inputTokens ?? '—'} in / ${run.outputTokens ?? '—'} out${run.cacheReadTokens ? ` / ${run.cacheReadTokens} cache` : ''}`
    : '—';
  return (
    <Kv
      items={[
        ['Model', run.modelResolved ?? '—'],
        ['Cost', `${formatUsd(run.costUsd)} (list-price equivalent)`],
        ['Duration', formatDuration(run.durationMs)],
        ['Turns', run.numTurns ?? '—'],
        ['Tokens', tokens],
        ['Attempts', run.attempts],
        ['Created', `${formatDateTime(run.createdAt)} (${relativeTime(run.createdAt)})`],
        ['Input hash', <Mono key="h">{run.inputHash}</Mono>],
        ...(readCommit ? ([['Commit read', <Mono key="c">{readCommit.slice(0, 10)}</Mono>]] as [ReactNode, ReactNode][]) : []),
        ...(run.claudeVersion ? ([['Claude CLI', run.claudeVersion]] as [ReactNode, ReactNode][]) : []),
        ...(run.tag ? ([['Tag', run.tag]] as [ReactNode, ReactNode][]) : []),
        ...(run.jobRunId ? ([['Job', `#${run.jobRunId}`]] as [ReactNode, ReactNode][]) : []),
      ]}
    />
  );
}

function SelectedRun({ d, run }: { d: FindingDetail; run: TriageRunView }) {
  const raw = d.triage.selectedRunRaw;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Run #{run.id}</span>
        <RunStatusBadge status={run.status} />
        {run.output ? <VerdictBadge verdict={run.output.verdict} confidence={run.output.confidence} /> : null}
        <span className="text-sm text-muted">{relativeTime(run.createdAt)}</span>
      </div>
      {run.error ? <pre className="rounded-md bg-ping-bg px-3 py-2 text-xs whitespace-pre-wrap text-ping">{run.error}</pre> : null}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="min-w-0 space-y-4">
          {run.output ? (
            <>
              <TriageEvidenceView findingId={d.finding.id} runId={run.id} t={run.output} />
              <div>
                <h3 className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">Suggested action</h3>
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <ActionBadge action={run.output.suggested_action} />
                  <span>{run.output.suggested_action_reason}</span>
                </div>
              </div>
            </>
          ) : run.invalidOutput ? (
            <p className="text-sm text-ping">The stored output does not match the triage schema; see the raw JSON below.</p>
          ) : (
            <p className="text-sm text-muted">No structured output.</p>
          )}
        </div>
        <RunMeta run={run} readCommit={run.commitSha ?? commitFromPrompt(raw?.prompt)} />
      </div>
      <div className="space-y-2">
        {run.output || run.invalidOutput ? <JsonDetails summary="Structured output (JSON)" value={run.output ?? run.invalidOutput} /> : null}
        {raw?.raw ? <JsonDetails summary="Raw CLI result (JSON)" value={raw.raw} /> : null}
        {raw?.prompt ? <JsonDetails summary="Rendered prompt" value={raw.prompt} /> : null}
      </div>
    </div>
  );
}

function OlderRuns({ d }: { d: FindingDetail }) {
  const { runs, selectedRun, selectedConfig } = d.triage;
  if (runs.length < 2) return null;
  return (
    <div>
      <h3 className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">All runs of {selectedConfig}</h3>
      <Table>
        <thead>
          <tr>
            <Th>Run</Th>
            <Th>Created</Th>
            <Th>Status</Th>
            <Th>Verdict</Th>
            <Th>Suggested</Th>
            <Th>Cost</Th>
            <Th>Duration</Th>
            <Th>Model</Th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.id} className={cx(r.id === selectedRun?.id && 'bg-panel-2')}>
              <Td>
                <Link href={`/findings/${d.finding.id}?config=${encodeURIComponent(r.configName)}&run=${r.id}`}>#{r.id}</Link>
                {r.tag ? <span className="ml-1 text-xs text-muted">{r.tag}</span> : null}
              </Td>
              <Td className="whitespace-nowrap">{formatDateTime(r.createdAt)}</Td>
              <Td>
                <RunStatusBadge status={r.status} />
              </Td>
              <Td>{r.output ? <VerdictBadge verdict={r.output.verdict} confidence={r.output.confidence} /> : '—'}</Td>
              <Td>{r.output ? <ActionBadge action={r.output.suggested_action} /> : '—'}</Td>
              <Td className="tabular-nums">{formatUsd(r.costUsd)}</Td>
              <Td className="whitespace-nowrap">{formatDuration(r.durationMs)}</Td>
              <Td className="text-xs">{r.modelResolved ?? '—'}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function TriageButtons({ d, ctx }: { d: FindingDetail; ctx: DecisionContext }) {
  const pending = d.triageJobs.filter((j) => j.status === 'queued' || j.status === 'running');
  // A job without `config` runs the active one (same rule as findPendingTriageJob, which the action enforces).
  const pendingConfigs = new Set(pending.map((j) => j.config ?? ctx.activeConfig));
  return (
    <div className="space-y-2 border-t border-border pt-3">
      <div className="flex flex-wrap gap-2">
        {ctx.configNames.map((name) => (
          <form key={name} action={enqueueTriageAction}>
            <input type="hidden" name="findingId" value={d.finding.id} />
            <input type="hidden" name="config" value={name} />
            <Button
              type="submit"
              variant={name === ctx.activeConfig ? 'primary' : 'secondary'}
              disabled={pendingConfigs.has(name)}
              title={pendingConfigs.has(name) ? 'A triage job for this config is already queued or running' : undefined}
            >
              Triage with {name}
            </Button>
          </form>
        ))}
      </div>
      <p className="text-xs text-muted">
        Enqueues a forced <Mono>triage</Mono> job for this finding; under the active config (<Mono>{ctx.activeConfig}</Mono>) a{' '}
        <Mono>decide</Mono> job follows so the decision uses the new verdict. Other configs are experiments and never change decisions. The
        worker must be running (<Mono>npm run dev</Mono> or <Mono>npm run worker</Mono>) to pick them up.
      </p>
      {d.triageJobs.length ? (
        <ul className="space-y-1 text-sm">
          {d.triageJobs.map((j) => (
            <li key={j.id} className="flex flex-wrap items-center gap-2">
              <Link href="/jobs">job #{j.id}</Link>
              <Badge tone={j.status === 'failed' ? 'ping' : j.status === 'succeeded' ? 'ok' : j.status === 'cancelled' ? 'neutral' : 'digest'}>
                {j.status}
              </Badge>
              {j.config ? <Mono>{j.config}</Mono> : null}
              <span className="text-muted">{relativeTime(j.finishedAt ?? j.createdAt)}</span>
              {j.error ? <span className="text-xs break-all text-ping">{j.error.split('\n')[0]}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
      <AutoRefresh active={pending.length > 0} intervalMs={3000} />
    </div>
  );
}

function Triage({ d, ctx }: { d: FindingDetail; ctx: DecisionContext }) {
  const t = d.triage;
  return (
    <Card>
      <CardHeader title="Triage" />
      <CardBody className="space-y-4">
        {t.tabs.length ? (
          <nav className="flex flex-wrap gap-1.5" aria-label="Triage configs">
            {t.tabs.map((tab) => (
              <Link
                key={tab.configName}
                href={`/findings/${d.finding.id}?config=${encodeURIComponent(tab.configName)}`}
                className={cx(
                  'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-sm no-underline',
                  tab.configName === t.selectedConfig ? 'border-accent bg-panel-2 text-text' : 'border-border text-muted hover:bg-panel-2',
                )}
              >
                <Mono>{tab.configName}</Mono>
                {tab.active ? <Badge tone="accent">active</Badge> : null}
                <span className="text-xs">{tab.runCount} run{tab.runCount === 1 ? '' : 's'}</span>
                <RunStatusBadge status={tab.latestStatus} />
              </Link>
            ))}
          </nav>
        ) : (
          <p className="text-sm text-muted">Not triaged under any config yet.</p>
        )}

        {t.state ? (
          <p className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-muted">For the current inputs under</span>
            <Mono>{t.selectedConfig ?? ctx.activeConfig}</Mono>
            <TriageStateBadge status={t.state.status} />
            {t.state.reason ? <span className="text-muted">{t.state.reason}</span> : null}
            {t.state.status === 'pending' && t.selectedRun ? (
              <span className="text-muted">(inputs changed since the runs below, or none succeeded)</span>
            ) : null}
            {t.state.runId && t.selectedRun && t.state.runId !== t.selectedRun.id ? (
              <span className="text-muted">
                (current run is <Link href={`/findings/${d.finding.id}?config=${encodeURIComponent(t.selectedConfig ?? '')}&run=${t.state.runId}`}>#{t.state.runId}</Link>)
              </span>
            ) : null}
          </p>
        ) : null}

        {t.selectedRun ? <SelectedRun d={d} run={t.selectedRun} /> : null}
        <OlderRuns d={d} />
        <TriageButtons d={d} ctx={ctx} />
      </CardBody>
    </Card>
  );
}

function formatInput(v: unknown): ReactNode {
  if (v === null || v === undefined) return <span className="text-muted">—</span>;
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (typeof v === 'number') return String(v);
  return humanize(String(v));
}

function ReevaluateButton({ d }: { d: FindingDetail }) {
  const pending = d.pendingDecide;
  return (
    <form action={enqueueDecideAction} className="flex flex-wrap items-center gap-2">
      <input type="hidden" name="findingId" value={d.finding.id} />
      <Button
        type="submit"
        disabled={pending?.status === 'queued'}
        title={pending?.status === 'queued' ? 'A decide job is already queued' : 'Enqueues a decide job: current policy, active config, no LLM calls'}
      >
        Re-evaluate policy
      </Button>
      {pending ? (
        <span className="text-xs text-muted">
          <Link href={`/jobs/${pending.id}`}>decide job #{pending.id}</Link> {pending.status}
        </span>
      ) : null}
    </form>
  );
}

function Decision({ d, ctx }: { d: FindingDetail; ctx: DecisionContext }) {
  const dec = d.decision;
  const llm = dec?.run?.output ?? null;
  // Decide skips findings of disabled projects (and clears their current decision), so re-evaluating cannot help.
  const disabled = d.project !== null && !d.project.enabled;
  const stale = dec?.isCurrent && !disabled ? dec.stale : null;
  return (
    <Card>
      <CardHeader title="Decision" actions={dec && (stale || !dec.isCurrent || disabled) ? <Badge tone="digest">stale</Badge> : null} />
      <CardBody className="space-y-4">
        {ctx.policyError ? <p className="text-sm text-ping">config/policy.yaml does not parse: {ctx.policyError}</p> : null}
        <AutoRefresh active={d.pendingDecide !== null} intervalMs={3000} />
        {disabled ? (
          <p className="text-sm text-muted">
            The project is disabled, so Decide skips this finding and it has no current decision.
            {dec ? ' Below is the last decision made before it was disabled.' : ''}
          </p>
        ) : null}
        {!dec ? (
          disabled ? null : (
            <div className="space-y-2">
              <p className="text-sm text-muted">No decision yet. Run Decide (or Refresh all).</p>
              <ReevaluateButton d={d} />
            </div>
          )
        ) : (
          <>
            {!dec.isCurrent && !disabled ? (
              <div className="space-y-2 rounded-md bg-digest-bg px-3 py-2 text-sm text-digest">
                <p>
                  No decision for the current policy ({ctx.policyHash ?? 'unknown'}) and active config ({ctx.activeConfig}) yet. Showing the latest
                  one (policy {dec.row.policyHash}, config {dec.row.configName}).
                </p>
                <ReevaluateButton d={d} />
              </div>
            ) : null}
            {stale ? (
              <div className="space-y-2 rounded-md bg-digest-bg px-3 py-2 text-sm text-digest">
                <p>
                  {stale.reason} The action below may change when the policy is re-evaluated.
                  {stale.currentRunId ? (
                    <>
                      {' '}
                      <Link href={`/findings/${d.finding.id}?config=${encodeURIComponent(ctx.activeConfig)}&run=${stale.currentRunId}`}>
                        See run #{stale.currentRunId}
                      </Link>
                      .
                    </>
                  ) : null}
                </p>
                <ReevaluateButton d={d} />
              </div>
            ) : null}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-md border border-border p-3">
                <div className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">Policy</div>
                <div className="flex flex-wrap items-center gap-2">
                  <ActionBadge action={dec.row.action} />
                  <span className="text-sm">
                    rule <Mono>{dec.row.ruleId}</Mono>
                  </span>
                </div>
                <div className="mt-1 text-xs text-muted">
                  policy <Mono>{dec.row.policyHash}</Mono> · config <Mono>{dec.row.configName}</Mono> · {relativeTime(dec.row.decidedAt)}
                </div>
              </div>
              <div className="rounded-md border border-border p-3">
                <div className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">LLM suggested_action</div>
                <div className="flex flex-wrap items-center gap-2">
                  <ActionBadge action={dec.row.inputs.suggested_action} />
                  {dec.row.inputs.suggested_action && dec.row.inputs.suggested_action !== dec.row.action ? (
                    <Badge tone="digest">differs from policy</Badge>
                  ) : null}
                </div>
                {llm ? <div className="mt-1 text-xs text-muted">{llm.suggested_action_reason}</div> : null}
                {dec.row.triageRunId ? <div className="mt-1 text-xs text-muted">from triage run #{dec.row.triageRunId}</div> : null}
              </div>
            </div>
            <div>
              <h3 className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">Inputs the rules saw</h3>
              <Kv items={Object.entries(dec.row.inputs).map(([k, v]) => [<Mono key={k}>{k}</Mono>, formatInput(v)])} />
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}

function Events({ d }: { d: FindingDetail }) {
  return (
    <Card>
      <CardHeader title="Events" />
      <CardBody>
        {d.events.length === 0 ? (
          <p className="text-sm text-muted">No events.</p>
        ) : (
          <ol className="space-y-2">
            {d.events.map((e) => (
              <li key={e.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 text-sm">
                <span className="w-44 shrink-0 text-muted tabular-nums" title={e.at}>
                  {formatDateTime(e.at)}
                </span>
                <Badge tone={e.type === 'escalated' || e.type === 'reopened' ? 'digest' : e.type === 'fixed' ? 'ok' : 'neutral'}>
                  {humanize(e.type)}
                </Badge>
                <span className="min-w-0 break-words text-muted">{summarizeEventData(e.data)}</span>
                {e.jobRunId ? <span className="text-xs text-muted">job #{e.jobRunId}</span> : null}
              </li>
            ))}
          </ol>
        )}
      </CardBody>
    </Card>
  );
}

export default async function FindingPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<SearchParams>;
}) {
  const { id: idParam } = await params;
  const sp = await searchParams;
  const id = Number(idParam);
  if (!Number.isInteger(id) || id <= 0) notFound();

  const ctx = loadDecisionContext();
  const runParam = Number(firstParam(sp.run));
  const d = getFindingDetail(getDb(), id, ctx, {
    config: firstParam(sp.config),
    runId: Number.isInteger(runParam) && runParam > 0 ? runParam : null,
    labeler: await currentLabeler(),
  });
  if (!d) notFound();

  return (
    <>
      <Header d={d} />
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <Signals d={d} />
          <Dependency d={d} />
        </div>
        <Card>
          <CardHeader title="Advisory" />
          <CardBody>
            {d.advisory ? <AdvisoryBody advisory={d.advisory} /> : <p className="text-sm text-muted">The advisory record is missing.</p>}
          </CardBody>
        </Card>
        <Triage d={d} ctx={ctx} />
        <div className="grid gap-4 lg:grid-cols-2">
          <Decision d={d} ctx={ctx} />
          <Card>
            <CardHeader
              title="Your label"
              actions={
                <span className="text-xs text-muted">
                  labeling as <Mono>{d.labeler}</Mono> · <Link href={`/review?id=${d.finding.id}`}>change on Review</Link>
                </span>
              }
            />
            <CardBody>
              <LabelForm findingId={d.finding.id} label={d.label} action={saveLabelAction} />
            </CardBody>
          </Card>
        </div>
        <Events d={d} />
      </div>
    </>
  );
}
