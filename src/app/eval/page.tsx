/** Evaluation (spec §11.2): how often base priority, the LLM and the policy agree with your labels. */
import { currentProjectScope } from '@/app/projects/scope';
import { currentLabeler } from '@/app/review/labeler';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { AutoRefresh } from '@/components/auto-refresh';
import { ConfusionMatrix } from '@/components/eval/confusion-matrix';
import { EvalPickers } from '@/components/eval/eval-pickers';
import { LabeledRowsTable } from '@/components/eval/labeled-rows-table';
import { RatioValue, Target } from '@/components/eval/ratio-value';
import { ProjectTag, ScopePill } from '@/components/inbox/project-tag';
import { RunJobForm } from '@/components/jobs/run-job-form';
import { ActionBadge, Card, CardBody, CardHeader, Empty, Mono, PageHeader, Table, Td, Th } from '@/components/ui';
import { loadVigilesConfig } from '@/lib/config/load';
import { getDb } from '@/lib/db/client';
import { TARGETS, type VolumeRow } from '@/lib/eval/metrics';
import { formatDuration, formatUsd, pct, relativeTime } from '@/lib/format';
import { colorFor, projectColors, scopeLabel, scopeParam, type ProjectScope, type ScopeContext } from '@/lib/project-scope';
import { listActiveJobs, workerSeemsDown } from '@/lib/queries/jobs';
import {
  cellKey,
  DECIDERS,
  getEvalOptions,
  getEvalReport,
  loadCurrentPolicy,
  parseCellKey,
  PER_REFRESH_LIMIT,
  resolveSelection,
  rowsForCell,
  type CellKey,
  type EvalReport,
  type EvalSelection,
  type RefreshVolume,
} from '@/lib/queries/eval';
import type { Action, Priority } from '@/lib/types';

type SearchParams = Record<string, string | string[] | undefined>;

function configMinPriority(): Priority {
  try {
    return loadVigilesConfig().triage.min_priority;
  } catch {
    return 'P2';
  }
}

/** An Eval link; a `?project=` override is kept so drill-downs stay in the same project scope. */
function evalHref(sel: EvalSelection, scope: ProjectScope, cell?: CellKey): string {
  const qs = new URLSearchParams({ config: sel.configName, policy: sel.policyHash, labeler: sel.labeler });
  const project = scopeParam(scope);
  if (project) qs.set('project', project);
  if (cell) qs.set('cell', cellKey(cell));
  return `/eval?${qs.toString().replaceAll('%2C', ',')}${cell ? '#cell' : ''}`;
}

/** A project's coloured tag in the volume tables. */
function ProjectCell({ id, scope }: { id: string; scope: ScopeContext }) {
  const p = scope.projects.find((x) => x.id === id);
  const colors = projectColors(scope.projects.map((x) => x.id));
  return <ProjectTag name={p?.name ?? id} color={colorFor(colors, id)} enabled={p?.enabled ?? true} />;
}

function Section({ title, actions, children }: { title: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <Card className="mb-5">
      <CardHeader title={title} actions={actions} />
      {children}
    </Card>
  );
}

function DecisionCoverage({
  report,
  policyIsCurrent,
  policyKnown,
}: {
  report: EvalReport;
  policyIsCurrent: boolean;
  /** The decide job can only evaluate the policy file on disk or a stored policy_versions row */
  policyKnown: boolean;
}) {
  const { missingDecisions: missing, staleDecisions: stale, selection: sel } = report;
  if (!missing.open && !missing.closed && !missing.disabled && !stale) return null;
  const canFix = (missing.open > 0 || stale > 0) && report.configFound && policyKnown;
  return (
    <div className="mb-5 rounded-lg border border-border bg-digest-bg px-4 py-3 text-sm text-digest">
      {missing.open ? (
        <p>
          {missing.open} labeled open finding{missing.open === 1 ? ' has' : 's have'} no decision for policy <Mono>{sel.policyHash}</Mono> ×
          config <Mono>{sel.configName}</Mono>, so the policy column leaves {missing.open === 1 ? 'it' : 'them'} out.
        </p>
      ) : null}
      {stale ? (
        <p>
          {stale} decision{stale === 1 ? ' was' : 's were'} made from a different triage verdict than the one that counts now (a newer run,
          or changed inputs).
        </p>
      ) : null}
      {missing.disabled ? (
        <p>
          {missing.disabled} labeled open finding{missing.disabled === 1 ? ' belongs' : 's belong'} to a disabled project; the decide job
          skips disabled projects, so the policy column leaves {missing.disabled === 1 ? 'it' : 'them'} out.
        </p>
      ) : null}
      {missing.closed ? (
        <p>
          {missing.closed} labeled finding{missing.closed === 1 ? ' is' : 's are'} no longer open and{' '}
          {missing.closed === 1 ? 'has' : 'have'} no decision for this combination; the decide job only evaluates open findings.
        </p>
      ) : null}
      {!canFix && (missing.open > 0 || stale > 0) ? (
        <p className="mt-2 text-xs">
          {report.configFound ? 'This policy version is not stored' : `Triage config ${sel.configName || '(none)'} is not in the database`},
          so it cannot be evaluated. Pick another one above.
        </p>
      ) : null}
      {canFix ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RunJobForm
            type="decide"
            label="Evaluate this policy × config"
            fixedParams={{ policy: sel.policyHash, config: sel.configName }}
          />
          {!policyIsCurrent ? (
            <span className="text-xs">This is not the policy file on disk; the decide job evaluates the stored version.</span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function DeciderTable({ report }: { report: EvalReport }) {
  const rows: { label: ReactNode; cell: (d: EvalReport['deciders'][number]) => ReactNode }[] = [
    { label: 'Findings scored', cell: (d) => <span className="tabular-nums">{d.metrics.n}</span> },
    {
      label: (
        <>
          Ping recall <Target>100%</Target>
        </>
      ),
      cell: (d) => <RatioValue ratio={d.metrics.pingRecall} target={TARGETS.pingRecall} />,
    },
    {
      label: (
        <>
          Ping precision <Target>≥ 80%</Target>
        </>
      ),
      cell: (d) => <RatioValue ratio={d.metrics.pingPrecision} target={TARGETS.pingPrecision} />,
    },
    { label: 'Exact action accuracy', cell: (d) => <RatioValue ratio={d.metrics.accuracy} /> },
    {
      label: 'Excluded',
      cell: (d) => (d.excluded ? <span className="text-digest tabular-nums">{d.excluded}</span> : <span className="text-muted">0</span>),
    },
  ];
  return (
    <Table>
      <thead>
        <tr>
          <Th>Metric</Th>
          {report.deciders.map((d) => (
            <Th key={d.name}>{d.title}</Th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <Td className="whitespace-nowrap">{r.label}</Td>
            {report.deciders.map((d) => (
              <Td key={d.name}>{r.cell(d)}</Td>
            ))}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function CellList({ report, cell, scope }: { report: EvalReport; cell: CellKey; scope: ProjectScope }) {
  const rows = rowsForCell(report, cell);
  const title = DECIDERS.find((d) => d.name === cell.decider)?.title ?? cell.decider;
  return (
    <div id="cell" className="scroll-mt-16">
      <Section
        title={
          <span className="inline-flex flex-wrap items-center gap-1.5">
            {title}: you labeled <ActionBadge action={cell.label} />, it decided <ActionBadge action={cell.decided} /> · {rows.length}{' '}
            finding{rows.length === 1 ? '' : 's'}
          </span>
        }
        actions={
          <Link href={evalHref(report.selection, scope)} className="text-xs">
            close
          </Link>
        }
      >
        {rows.length ? <LabeledRowsTable rows={rows} /> : <CardBody className="text-sm text-muted">No findings in this cell.</CardBody>}
      </Section>
    </div>
  );
}

function VolumeCell({ row, action }: { row: VolumeRow | undefined; action: Exclude<Action, 'log'> }) {
  if (!row) return <span className="text-muted">—</span>;
  const messages = action === 'ping' ? row.pingMessages : row.digestMessages;
  const findings = action === 'ping' ? row.pingFindings : row.digestFindings;
  return (
    <span className="tabular-nums">
      {messages}{' '}
      <span className="text-xs text-muted">
        ({findings} finding{findings === 1 ? '' : 's'})
      </span>
    </span>
  );
}

function VolumeTable({
  volume,
  selectedIsCurrent,
  scope,
}: {
  volume: EvalReport['volume'];
  selectedIsCurrent: boolean;
  scope: ScopeContext;
}) {
  const projectIds = [...new Set([...volume.current, ...volume.selected].map((r) => r.projectId))].sort();
  if (!projectIds.length) return <CardBody className="text-sm text-muted">No open findings.</CardBody>;
  const find = (rows: VolumeRow[], id: string) => rows.find((r) => r.projectId === id);
  return (
    <Table>
      <thead>
        <tr>
          <Th>Project</Th>
          <Th>Ping messages</Th>
          <Th>Digest messages</Th>
          <Th>Logged</Th>
          <Th title="Open findings the first scan found (origin baseline), with their current decisions">
            Baseline-origin findings, current decisions: ping / digest
          </Th>
          <Th title="Open findings found after the first scan (new advisory or new dependency), with their current decisions">
            Found after baseline, current decisions: ping / digest
          </Th>
          {selectedIsCurrent ? null : <Th>Selected policy × config ping / digest</Th>}
        </tr>
      </thead>
      <tbody>
        {projectIds.map((id) => {
          const cur = find(volume.current, id);
          const base = find(volume.baseline, id);
          const after = find(volume.afterBaseline, id);
          const sel = find(volume.selected, id);
          return (
            <tr key={id}>
              <Td>
                <ProjectCell id={id} scope={scope} />
              </Td>
              <Td>
                <VolumeCell row={cur} action="ping" />
              </Td>
              <Td>
                <VolumeCell row={cur} action="digest" />
              </Td>
              <Td className="tabular-nums">{cur?.logFindings ?? 0}</Td>
              <Td className="tabular-nums">
                {base?.pingMessages ?? 0} / {base?.digestMessages ?? 0}
              </Td>
              <Td className="tabular-nums">
                {after?.pingMessages ?? 0} / {after?.digestMessages ?? 0}
              </Td>
              {selectedIsCurrent ? null : (
                <Td className="tabular-nums">
                  {sel?.pingMessages ?? 0} / {sel?.digestMessages ?? 0}
                </Td>
              )}
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

function PerRefreshTable({ refreshes, scope }: { refreshes: RefreshVolume[]; scope: ScopeContext }) {
  if (!refreshes.length) return <CardBody className="text-sm text-muted">No Refresh all has succeeded yet.</CardBody>;
  return (
    <Table>
      <thead>
        <tr>
          <Th>Refresh all</Th>
          <Th>Finished</Th>
          <Th>Ping messages</Th>
          <Th>Digest messages</Th>
          <Th>Changed to log</Th>
          <Th>By project (ping / digest messages)</Th>
        </tr>
      </thead>
      <tbody>
        {refreshes.map((r) => (
          <tr key={r.refresh.id}>
            <Td>
              <Link href={`/jobs/${r.refresh.id}`}>#{r.refresh.id}</Link>
            </Td>
            <Td className="whitespace-nowrap text-muted" title={r.refresh.finishedAt ?? undefined}>
              {relativeTime(r.refresh.finishedAt ?? r.refresh.startedAt)}
            </Td>
            <Td>
              <VolumeCell row={{ projectId: '', ...r.total }} action="ping" />
            </Td>
            <Td>
              <VolumeCell row={{ projectId: '', ...r.total }} action="digest" />
            </Td>
            <Td className="tabular-nums">{r.total.logFindings}</Td>
            <Td className="text-xs">
              {r.projects.filter((p) => p.pingMessages || p.digestMessages).length ? (
                r.projects
                  .filter((p) => p.pingMessages || p.digestMessages)
                  .map((p) => (
                    <span key={p.projectId} className="mr-3 inline-flex items-center gap-1 whitespace-nowrap">
                      <ProjectCell id={p.projectId} scope={scope} />
                      <span className="tabular-nums">
                        {p.pingMessages} / {p.digestMessages}
                      </span>
                    </span>
                  ))
              ) : (
                <span className="text-muted">nothing sent</span>
              )}
              {r.newWithoutDecision ? (
                <span
                  className="block text-digest"
                  title="Created in this refresh but no decision event was recorded in it: refreshes from before first decisions were recorded as events, or findings decide left undecided"
                >
                  {r.newWithoutDecision} new finding{r.newWithoutDecision === 1 ? '' : 's'} without a recorded decision
                </span>
              ) : null}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export default async function EvalPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const sp = await searchParams;
  const db = getDb();
  const policyFile = loadCurrentPolicy();
  const options = getEvalOptions(db, policyFile.hash);
  // Default to the labeler picked on the Review page (cookie), so Eval shows "your" labels.
  const sel = resolveSelection({ ...options.defaults, labeler: await currentLabeler() }, sp);
  const scope = await currentProjectScope(sp);
  const report = getEvalReport(db, sel, { minPriority: configMinPriority(), currentPolicy: policyFile.loaded, projectIds: scope.ids });
  const cell = parseCellKey(sp.cell);
  const activeConfig = options.configs.find((c) => c.active)?.name;
  const policyIsCurrent = sel.policyHash === policyFile.hash;
  const selectedIsCurrent = policyIsCurrent && sel.configName === activeConfig;
  const labeled = report.rows.length;
  // Re-render when a decide job finishes, so "Evaluate this policy × config" shows its result without a manual reload.
  const active = listActiveJobs(db);
  const deciding = active.filter((j) => j.type === 'decide');
  const decideRunning = deciding.some((j) => j.status === 'running');
  const workerDown = workerSeemsDown(active);
  const policyKnown = policyIsCurrent || options.policies.some((p) => p.hash === sel.policyHash);

  return (
    <>
      <AutoRefresh active={deciding.length > 0} intervalMs={3000} />
      <PageHeader
        title="Eval"
        subtitle={
          <>
            <ScopePill scope={scope} className="mr-2 align-middle" />
            {labeled} finding{labeled === 1 ? '' : 's'} labeled by <Mono>{sel.labeler}</Mono> · config <Mono>{sel.configName || '—'}</Mono>{' '}
            · policy <Mono>{sel.policyHash || '—'}</Mono>
            {deciding.length ? (
              <span className="text-digest">
                {' '}
                · a decide job is {decideRunning ? 'running' : 'queued'}; this page refreshes until it finishes
                {workerDown ? (
                  <>
                    {' '}
                    (the worker does not seem to be running, see <Link href="/jobs">Jobs</Link>)
                  </>
                ) : null}
              </span>
            ) : null}
          </>
        }
      />
      <Card className="mb-5">
        <CardBody>
          <EvalPickers options={options} selection={sel} />
          {policyFile.error ? (
            <p className="mt-2 text-xs text-ping">config/policy.yaml could not be loaded: {policyFile.error.split('\n')[0]}</p>
          ) : null}
        </CardBody>
      </Card>

      {labeled === 0 ? (
        <div className="mb-5">
          <Empty>
            No labels from <Mono>{sel.labeler}</Mono>
            {scope.ids === null ? '' : ` on ${scopeLabel(scope)}`} yet. Label findings on the <Link href="/review">Review</Link> page, then come
            back.
          </Empty>
        </div>
      ) : (
        <>
          <DecisionCoverage report={report} policyIsCurrent={policyIsCurrent} policyKnown={policyKnown} />

          <Section title="Deciders vs. your labels">
            <DeciderTable report={report} />
            <CardBody className="space-y-1 text-xs text-muted">
              {report.deciders
                .filter((d) => d.excludedNote)
                .map((d) => (
                  <p key={d.name}>
                    {d.title}: {d.excludedNote}
                  </p>
                ))}
              <p>Base priority only: P0/P1 → ping, P2 → digest, P3 → log. Click a matrix cell to list its findings.</p>
            </CardBody>
            <CardBody className="grid gap-6 border-t border-border md:grid-cols-3">
              {report.deciders.map((d) => (
                <ConfusionMatrix
                  key={d.name}
                  title={`${d.title} (n = ${d.metrics.n})`}
                  matrix={d.metrics.matrix}
                  cellHref={(label, decided) => evalHref(sel, scope, { decider: d.name, label, decided })}
                  selected={cell?.decider === d.name ? cell : null}
                />
              ))}
            </CardBody>
          </Section>

          {cell ? <CellList report={report} cell={cell} scope={scope} /> : null}

          <Section title="Verdict accuracy (LLM verdict vs. your affected answer)">
            <CardBody className="text-sm">
              <p>
                <RatioValue ratio={report.verdict} />
                <span className="ml-2 text-xs text-muted">
                  yes ↔ affected / likely affected; no ↔ not affected / likely not affected. Excluded: {report.verdict.excludedNoTruth}{' '}
                  without a yes/no answer, {report.verdict.excludedNoVerdict} without an ok verdict for <Mono>{sel.configName}</Mono>.
                </span>
              </p>
            </CardBody>
          </Section>

          <Section title={`Disagreements: policy ≠ your label (${report.disagreements.length})`}>
            {report.disagreements.length ? (
              <LabeledRowsTable rows={report.disagreements} showKind />
            ) : (
              <CardBody className="text-sm text-muted">The policy agrees with every label it decided.</CardBody>
            )}
          </Section>
        </>
      )}

      <Section
        title="Cost and time per triage config"
        actions={
          <span className="text-xs text-muted">
            all projects; all runs, including failed attempts; cancelled runs only count in runs and total cost
          </span>
        }
      >
        {report.cost.length ? (
          <Table>
            <thead>
              <tr>
                <Th>Config</Th>
                <Th>Runs</Th>
                <Th>Ok rate</Th>
                <Th>Median time</Th>
                <Th>p90 time</Th>
                <Th>Median cost</Th>
                <Th>p90 cost</Th>
                <Th>Total cost</Th>
                <Th>Median turns</Th>
              </tr>
            </thead>
            <tbody>
              {report.cost.map((c) => (
                <tr key={c.configName}>
                  <Td>
                    <Mono>{c.configName}</Mono>
                  </Td>
                  <Td className="tabular-nums">{c.runs}</Td>
                  <Td>
                    <RatioValue ratio={c.okRate} />
                  </Td>
                  <Td className="tabular-nums">{formatDuration(c.durationMs.median)}</Td>
                  <Td className="tabular-nums">{formatDuration(c.durationMs.p90)}</Td>
                  <Td className="tabular-nums">{formatUsd(c.costUsd.median)}</Td>
                  <Td className="tabular-nums">{formatUsd(c.costUsd.p90)}</Td>
                  <Td className="tabular-nums">{formatUsd(c.costUsd.total)}</Td>
                  <Td className="tabular-nums">{c.medianTurns ?? '—'}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <CardBody className="text-sm text-muted">No triage runs yet.</CardBody>
        )}
      </Section>

      <Section
        title={
          <>
            Consistency <Target>≥ {pct(TARGETS.consistency)} identical policy action</Target>
          </>
        }
        actions={
          <span className="text-xs text-muted">
            all projects; findings with ≥ 2 ok runs for the same config and input hash; each run put through policy{' '}
            <Mono>{report.consistencyPolicy.hash || '—'}</Mono>
          </span>
        }
      >
        {report.consistency.length ? (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Config</Th>
                  <Th>Findings</Th>
                  <Th>Runs</Th>
                  <Th title="Share of findings whose runs all lead to the same action under the selected policy">
                    Identical policy action
                  </Th>
                  <Th>Identical verdict</Th>
                  <Th>Identical suggested action</Th>
                </tr>
              </thead>
              <tbody>
                {report.consistency.map((c) => (
                  <tr key={c.configName}>
                    <Td>
                      <Mono>{c.configName}</Mono>
                    </Td>
                    <Td className="tabular-nums">{c.groups}</Td>
                    <Td className="tabular-nums">{c.runs}</Td>
                    <Td>
                      <RatioValue ratio={c.identicalPolicyAction} target={TARGETS.consistency} />
                    </Td>
                    <Td>
                      <RatioValue ratio={c.identicalVerdict} />
                    </Td>
                    <Td>
                      <RatioValue ratio={c.identicalAction} />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <CardBody className="space-y-1 text-xs text-muted">
              {report.consistencyPolicy.error ? (
                <p className="text-ping">Policy action not computed: {report.consistencyPolicy.error}.</p>
              ) : null}
              <p>
                The exit criterion is the policy action: two runs that differ only in fields the policy ignores still count as consistent.
                Verdict and suggested action are shown for reference.
              </p>
            </CardBody>
          </>
        ) : (
          <CardBody className="text-sm text-muted">
            No repeated runs yet. Re-run a config on a sample, for example{' '}
            <Mono>npm run job -- triage --config {sel.configName || '<config>'} --sample 20 --force --tag consistency</Mono>.
          </CardBody>
        )}
      </Section>

      <Section
        title="Volume: messages per project"
        actions={
          <span className="text-xs text-muted">
            one message per (project, package) and action; current decisions of open findings; disabled projects left out
          </span>
        }
      >
        <VolumeTable volume={report.volume} selectedIsCurrent={selectedIsCurrent} scope={scope} />
      </Section>

      <Section
        title={`Volume per refresh (last ${PER_REFRESH_LIMIT} successful Refresh all runs)`}
        actions={
          <span className="text-xs text-muted">
            findings whose decision the refresh set or changed, by the new action, grouped like the Inbox
          </span>
        }
      >
        <PerRefreshTable refreshes={report.volume.perRefresh} scope={scope} />
      </Section>

      {options.labelerCount > 1 ? (
        <Section
          title={
            <>
              Inter-labeler agreement with <Mono>{sel.labeler}</Mono>
            </>
          }
        >
          {report.agreement.length ? (
            <Table>
              <thead>
                <tr>
                  <Th>Other labeler</Th>
                  <Th>Shared findings</Th>
                  <Th>Same action</Th>
                  <Th>Cohen&apos;s κ</Th>
                  <Th>Same affected answer</Th>
                </tr>
              </thead>
              <tbody>
                {report.agreement.map((a) => (
                  <tr key={a.other}>
                    <Td>
                      <Link href={evalHref({ ...sel, labeler: a.other }, scope)}>{a.other}</Link>
                    </Td>
                    <Td className="tabular-nums">{a.action.n}</Td>
                    <Td>
                      <RatioValue ratio={a.action.agree} />
                    </Td>
                    <Td className="tabular-nums">{a.action.kappa === null ? '—' : a.action.kappa.toFixed(2)}</Td>
                    <Td>
                      <RatioValue ratio={a.affected} />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <CardBody className="text-sm text-muted">No other labeler.</CardBody>
          )}
        </Section>
      ) : null}
    </>
  );
}
