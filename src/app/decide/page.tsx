/**
 * "Your call": the one place where the owner gives taste decisions. Each case is a finding whose technical
 * question (does it affect the app?) is settled; the owner only says how loudly the team should hear about it
 * (ping / digest / log). One case at a time; after answering, the page reveals how the system and the agent
 * reviewers compare and why the case was asked.
 */
import type { Metadata } from 'next';
import { answerCaseAction } from '@/app/decide/actions';
import { AskPanel, CaseBrief, DecidedList, DecideProgress, NothingOpen, Reveal } from '@/components/decide/case-view';
import { getDb } from '@/lib/db/client';
import { projectColors } from '@/lib/project-scope';
import type { SearchParams } from '@/lib/queries/findings';
import { getDecideView, parseCaseParam } from '@/lib/queries/owner-cases';
import { listScopeProjects } from '@/lib/queries/projects';

export const metadata: Metadata = { title: 'Your call · Vigiles' };

export default async function DecidePage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const sp = await searchParams;
  const db = getDb();
  const view = getDecideView(db, parseCaseParam(sp.case));
  const current = view.current;
  // Every case is shown whatever project the header is scoped to (this queue is short); each carries its
  // project's tag, coloured from the full project list so it matches the header switcher.
  const colors = projectColors(listScopeProjects(db).map((p) => p.id));

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Your call</h1>
        <p className="mt-1 max-w-[68ch] text-base text-muted">
          Decide how the team should hear about each problem. Whether it can hurt the app has already been checked for you.
        </p>
      </header>

      {view.total > 0 ? <DecideProgress decided={view.decided} total={view.total} /> : null}

      {view.requestedMissing ? (
        <p role="status" className="rounded-lg bg-panel-2 px-4 py-2.5 text-sm">
          That case is no longer open.{current ? ' Here is the next one.' : ''}
        </p>
      ) : null}

      {current === null ? (
        <NothingOpen total={view.total} />
      ) : current.status === 'answered' ? (
        <>
          <Reveal c={current} nextId={view.nextId} action={answerCaseAction} changeOpen={sp.change !== undefined} />
          <CaseBrief c={current} colors={colors} />
        </>
      ) : (
        <>
          <CaseBrief c={current} colors={colors} />
          <AskPanel c={current} nextId={view.nextId} action={answerCaseAction} />
        </>
      )}

      <DecidedList cases={view.answered} currentId={current?.id ?? null} colors={colors} />
    </div>
  );
}
