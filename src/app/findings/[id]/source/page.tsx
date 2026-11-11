import { notFound } from 'next/navigation';
import { ButtonLink, Card, Empty, Mono, PageHeader, cx } from '@/components/ui';
import { dataPaths, loadVigilesConfig } from '@/lib/config/load';
import { getDb } from '@/lib/db/client';
import { getFindingSource, type SearchParams, type SourceCommit } from '@/lib/queries/findings';

function firstParam(v: string | string[] | undefined): string {
  return (Array.isArray(v) ? v[0] : v) ?? '';
}

function positiveInt(v: string): number | null {
  const n = Number(v);
  return v !== '' && Number.isInteger(n) && n > 0 ? n : null;
}

const VIA_LABEL: Record<SourceCommit['via'], string> = {
  run: 'the commit this triage run read',
  'run-scan': 'the commit of the scan this triage run used',
  'run-prompt': 'the commit named in this triage run’s prompt',
  'last-scan': 'the finding’s latest scanned commit',
};

function CommitNotes({ commit }: { commit: SourceCommit | undefined }) {
  if (!commit?.notes.length) return null;
  return (
    <div className="mb-4 space-y-1 rounded-md bg-digest-bg px-3 py-2 text-sm text-digest">
      {commit.notes.map((n) => (
        <p key={n}>{n}</p>
      ))}
    </div>
  );
}

/**
 * Read-only view of one snapshot file, ±40 lines around a line. Evidence links pass `run`, so the
 * file is shown at the commit that triage run read; import-site links show the latest scanned commit.
 */
export default async function SourcePage({
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

  const file = firstParam(sp.file);
  const line = positiveInt(firstParam(sp.line));
  const runId = positiveInt(firstParam(sp.run));
  const snapshots = dataPaths(loadVigilesConfig()).snapshots;
  const src = getFindingSource(getDb(), id, file, line, snapshots, { runId });
  if (!src.ok && src.missingFinding) notFound();

  const commit = src.commit;
  const backHref =
    commit?.runId && commit.runConfig
      ? `/findings/${id}?config=${encodeURIComponent(commit.runConfig)}&run=${commit.runId}`
      : `/findings/${id}`;
  const back = <ButtonLink href={backHref}>Back to finding</ButtonLink>;
  const origin = commit ? (
    <>
      {' · '}
      {commit.runId ? `run #${commit.runId}: ` : ''}
      {VIA_LABEL[commit.via]}
    </>
  ) : null;

  if (!src.ok) {
    return (
      <>
        <PageHeader
          title={file || 'Source'}
          subtitle={
            src.commitSha ? (
              <>
                {src.projectId} @ <Mono>{src.commitSha.slice(0, 10)}</Mono>
                {origin}
              </>
            ) : undefined
          }
          actions={back}
        />
        <CommitNotes commit={commit} />
        <Empty>{src.message}</Empty>
      </>
    );
  }

  const { excerpt } = src;
  const last = excerpt.startLine + excerpt.lines.length - 1;
  return (
    <>
      <PageHeader
        title={src.file}
        subtitle={
          <>
            {src.projectId} @ <Mono>{src.commitSha.slice(0, 10)}</Mono>
            {origin} · lines {excerpt.startLine}–{last} of {excerpt.totalLines}
            {excerpt.line ? ` · line ${excerpt.line} highlighted` : ''}
          </>
        }
        actions={back}
      />
      <CommitNotes commit={commit} />
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <pre className="py-2 font-mono text-xs leading-5">
            {excerpt.lines.map((text, i) => {
              const n = excerpt.startLine + i;
              return (
                <div key={n} id={`L${n}`} className={cx('flex scroll-mt-24', n === excerpt.line && 'bg-digest-bg')}>
                  <span className="w-14 shrink-0 pr-3 text-right text-muted select-none">{n}</span>
                  <code className="pr-4 whitespace-pre">{text || ' '}</code>
                </div>
              );
            })}
          </pre>
        </div>
      </Card>
    </>
  );
}
