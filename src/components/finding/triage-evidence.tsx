/**
 * The "blind" part of a triage output: facts and evidence without verdict, confidence or suggested
 * action. Shared by the Finding page and the Review page (where the rest stays hidden until labeled).
 */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { Kv } from '@/components/ui';
import type { TriageOutput } from '@/lib/types';
import { RuntimeUsageBadge, TristateBadge } from './badges';
import { isFileCitation, sourceHref } from './helpers';

export type BlindTriageFields = Pick<
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
>;

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="mb-1 text-xs font-medium tracking-wide text-muted uppercase">{title}</h3>
      {children}
    </div>
  );
}

export function SubAnswers({ t }: { t: BlindTriageFields }) {
  return (
    <Kv
      items={[
        ['Runtime usage', <RuntimeUsageBadge key="r" value={t.runtime_usage} />],
        ['Vulnerable code used', <TristateBadge key="v" value={t.vulnerable_code_used} />],
        ['Attacker reachable', <TristateBadge key="a" value={t.attacker_reachable} />],
        ['Deployment conditions met', <TristateBadge key="d" value={t.deployment_conditions_met} />],
      ]}
    />
  );
}

/** `runId` is the run that cited the evidence: its links open the snapshot of the commit that run read. */
export function EvidenceList({
  findingId,
  runId,
  evidence,
  newTab = false,
}: {
  findingId: number;
  runId: number | null;
  evidence: TriageOutput['evidence'];
  newTab?: boolean;
}) {
  if (!evidence.length) return <p className="text-sm text-muted">No evidence cited.</p>;
  return (
    <ul className="space-y-1.5 text-sm">
      {evidence.map((e, i) => (
        <li key={i} className="break-words">
          {isFileCitation(e.file) ? (
            <Link href={sourceHref(findingId, e.file, e.line, runId)} className="font-mono text-[0.85em]" target={newTab ? '_blank' : undefined}>
              {e.file}
              {e.line ? `:${e.line}` : ''}
            </Link>
          ) : (
            <span className="font-mono text-[0.85em] text-muted">{e.file}</span>
          )}
          <span className="text-muted"> · </span>
          {e.note}
        </li>
      ))}
    </ul>
  );
}

/**
 * `runId` is the triage run `t` came from (evidence links carry it). `newTab` opens source links in a
 * new tab (the Review page keeps an unsaved label in place).
 */
export function TriageEvidenceView({
  findingId,
  runId,
  t,
  newTab = false,
}: {
  findingId: number;
  runId: number | null;
  t: BlindTriageFields;
  newTab?: boolean;
}) {
  return (
    <div className="space-y-4">
      <p className="text-sm whitespace-pre-line">{t.summary}</p>
      <SubAnswers t={t} />
      <Section title="Evidence">
        <EvidenceList findingId={findingId} runId={runId} evidence={t.evidence} newTab={newTab} />
      </Section>
      <Section title="Exploit conditions">
        <p className="text-sm whitespace-pre-line">{t.exploit_conditions || '—'}</p>
      </Section>
      <Section title="Remediation">
        <p className="text-sm whitespace-pre-line">{t.remediation || '—'}</p>
      </Section>
      {t.workaround ? (
        <Section title="Workaround">
          <p className="text-sm whitespace-pre-line">{t.workaround}</p>
        </Section>
      ) : null}
    </div>
  );
}
