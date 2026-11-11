/** Labeled findings with each decider's answer (used for disagreements and matrix-cell drill-downs). */
import Link from 'next/link';
import { VerdictBadge } from '@/components/inbox/verdict-badge';
import { ActionBadge, Badge, Mono, PriorityBadge, Table, Td, Th } from '@/components/ui';
import type { LabeledRow } from '@/lib/queries/eval';

function errorKind(r: LabeledRow) {
  if (r.policy === null || r.policy === r.label) return null;
  if (r.label === 'ping') return <Badge tone="ping">missed ping</Badge>;
  if (r.policy === 'ping') return <Badge tone="digest">false ping</Badge>;
  return <Badge>off by one</Badge>;
}

export function LabeledRowsTable({ rows, showKind = false }: { rows: LabeledRow[]; showKind?: boolean }) {
  return (
    <Table>
      <thead>
        <tr>
          <Th>Finding</Th>
          <Th>Package</Th>
          <Th>Priority</Th>
          <Th>Your label</Th>
          <Th>Policy</Th>
          <Th>LLM</Th>
          <Th>Base</Th>
          <Th>Verdict</Th>
          {showKind ? <Th>Kind</Th> : null}
          <Th>Note</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.findingId}>
            <Td className="whitespace-nowrap">
              <Link href={`/findings/${r.findingId}`} className="font-mono text-[0.85em]">
                {r.vulnId}
              </Link>
              {r.status !== 'open' ? <span className="ml-1 text-xs text-muted">({r.status.replaceAll('_', ' ')})</span> : null}
            </Td>
            <Td>
              <span className="text-muted">{r.projectId} · </span>
              <Mono>{r.packageName}</Mono>
            </Td>
            <Td>
              <PriorityBadge priority={r.priority} />
            </Td>
            <Td>
              <ActionBadge action={r.label} />
            </Td>
            <Td className="whitespace-nowrap">
              {r.policy ? (
                <>
                  <ActionBadge action={r.policy} /> <span className="text-xs text-muted">{r.policyRuleId}</span>
                  {r.decisionStale ? (
                    <span className="ml-1 text-xs text-digest" title="decided from an older triage run">
                      stale
                    </span>
                  ) : null}
                </>
              ) : (
                <span className="text-xs text-muted">no decision</span>
              )}
            </Td>
            <Td>{r.llm ? <ActionBadge action={r.llm} /> : <span className="text-xs text-muted">{r.triageStatus ?? '—'}</span>}</Td>
            <Td>
              <ActionBadge action={r.base} />
            </Td>
            <Td>
              <VerdictBadge verdict={r.verdict} confidence={r.confidence} />
            </Td>
            {showKind ? <Td>{errorKind(r)}</Td> : null}
            <Td className="max-w-xs text-xs text-muted">{r.note ?? ''}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
