/**
 * Server-rendered parts of the decide page: progress, the case brief, the ask panel, the reveal after an
 * answer, and the compact list of decided cases. Plain words, big type for the brief, ~70ch lines.
 */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { ProjectTag } from '@/components/inbox/project-tag';
import { cx } from '@/components/ui';
import { relativeTime } from '@/lib/format';
import { colorFor, type ProjectColor } from '@/lib/project-scope';
import type { OwnerCaseView } from '@/lib/queries/owner-cases';
import type { Action } from '@/lib/types';
import { AnswerForm, type DecideSaveState } from './answer-form';
import { ACTION_LABEL, AgreementMarker, AnswerPill, ExploitableBadge } from './parts';
import { RevealKeys } from './reveal-keys';

type SaveAction = (prev: DecideSaveState, formData: FormData) => Promise<DecideSaveState>;

export const caseHref = (id: number) => `/decide?case=${id}`;

/** Project colours, the same as the header switcher's (see projectColors in src/lib/project-scope.ts). */
export type ProjectColors = ReadonlyMap<string, ProjectColor>;

function CaseProject({ c, colors, className }: { c: OwnerCaseView; colors: ProjectColors; className?: string }) {
  return <ProjectTag name={c.projectName ?? 'Unknown project'} color={colorFor(colors, c.projectId ?? '')} className={className} />;
}

/** "just now" for the first minute (relativeTime would say "0 seconds ago"), then "5 minutes ago". */
export function answeredWhen(iso: string, now = new Date()): string {
  const ms = now.getTime() - new Date(iso).getTime();
  return ms >= 0 && ms < 60_000 ? 'just now' : relativeTime(iso, now);
}

// Link colours sit on an inner <span>: globals.css colours every <a> outside Tailwind's layers, and an
// unlayered rule beats text-* utilities placed on the <a> itself.

/** A small, quiet secondary link. */
function QuietLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="group underline decoration-border underline-offset-2 hover:decoration-accent">
      <span className="text-muted group-hover:text-accent">{children}</span>
    </Link>
  );
}

/** The large primary "Next case" link. */
function PrimaryLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="inline-flex items-center rounded-md border border-accent bg-accent px-5 py-2.5 text-base font-medium no-underline hover:opacity-90"
    >
      <span className="text-panel">{children}</span>
    </Link>
  );
}

export function DecideProgress({ decided, total }: { decided: number; total: number }) {
  const left = total - decided;
  const pct = total ? Math.round((decided / total) * 100) : 0;
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-base">
          <strong className="font-semibold">
            {decided} of {total}
          </strong>{' '}
          decided
        </span>
        <span className="text-sm text-muted">{left === 0 ? 'All done' : `${left} left`}</span>
      </div>
      <div
        className="mt-2 h-1.5 overflow-hidden rounded-full bg-panel-2"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={decided}
        aria-label="Cases decided"
      >
        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Section({ label, aside, children }: { label: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <h3 className="text-sm font-semibold text-muted">{label}</h3>
        {aside}
      </div>
      <p className="mt-1.5 max-w-[68ch] text-base leading-7 whitespace-pre-line sm:text-[17px]">{children}</p>
    </section>
  );
}

const GONE: Record<string, string> = {
  fixed: 'This problem is already gone from the app (the package was updated or removed).',
  no_longer_matches: 'This problem no longer applies to the app (the advisory no longer matches).',
};

/** The case itself: project, title, and short plain-language sections. */
export function CaseBrief({ c, colors }: { c: OwnerCaseView; colors: ProjectColors }) {
  const b = c.brief;
  const gone = c.findingStatus ? GONE[c.findingStatus] : undefined;
  return (
    <article className="rounded-xl border border-border bg-panel px-5 py-6 sm:px-8 sm:py-7">
      <CaseProject c={c} colors={colors} className="text-sm" />
      <h2 className="mt-2.5 max-w-[40ch] text-2xl leading-snug font-semibold tracking-tight">{c.title}</h2>
      {gone ? (
        <p className="mt-4 max-w-[68ch] rounded-lg bg-panel-2 px-4 py-2.5 text-sm">
          {gone} Your answer still helps with similar cases later.
        </p>
      ) : null}
      {b ? (
        <div className="mt-6 space-y-6">
          <Section label="What it is">{b.whatItIs}</Section>
          <Section label="What an attacker could do">{b.attackerCouldDo}</Section>
          <Section label="What it takes">{b.whatItTakes}</Section>
          <Section label="Your app" aside={<ExploitableBadge value={b.exploitableToday} />}>
            {b.yourApp}
          </Section>
          <Section label="Fix">{b.fix}</Section>
          {b.similarTo ? <Section label="Similar earlier case">{b.similarTo}</Section> : null}
        </div>
      ) : (
        <p className="mt-6 max-w-[68ch] text-base leading-7 text-muted">
          The plain-language summary for this case is missing. The technical details below have everything, or skip this one for now.
        </p>
      )}
      <p className="mt-7 text-sm">
        <QuietLink href={`/findings/${c.findingId}`}>See full technical details</QuietLink>
      </p>
    </article>
  );
}

/** The question and the three answers, for an open case. */
export function AskPanel({ c, nextId, action }: { c: OwnerCaseView; nextId: number | null; action: SaveAction }) {
  return (
    <section className="rounded-xl border border-border bg-panel px-5 py-6 sm:px-8" aria-labelledby="ask-heading">
      <h2 id="ask-heading" className="mb-4 text-lg font-semibold">
        How should the team hear about this?
      </h2>
      <AnswerForm key={c.id} caseId={c.id} action={action} mode="ask" />
      {nextId !== null ? (
        <p className="mt-4 text-sm">
          <QuietLink href={caseHref(nextId)}>Skip for now</QuietLink>
        </p>
      ) : null}
    </section>
  );
}

function CompareRow({ label, value, answer }: { label: string; value: Action | null; answer: Action }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 px-4 py-3">
      <dt className="text-sm text-muted">{label}</dt>
      <dd className="flex items-center gap-2.5">
        {value ? (
          <>
            <span className="font-semibold">{ACTION_LABEL[value]}</span>
            <AgreementMarker same={value === answer} />
          </>
        ) : (
          <span className="text-sm text-muted">Not recorded</span>
        )}
      </dd>
    </div>
  );
}

/** Shown after answering: the answer, how the system and the agent reviewers compare, why it was asked, Next. */
export function Reveal({
  c,
  nextId,
  action,
  changeOpen,
}: {
  c: OwnerCaseView;
  nextId: number | null;
  action: SaveAction;
  changeOpen: boolean;
}) {
  const answer = c.answer!;
  const nextHref = nextId !== null ? caseHref(nextId) : '/decide';
  return (
    <section className="space-y-5 rounded-xl border border-border bg-panel px-5 py-6 sm:px-8" aria-labelledby="reveal-heading">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h2 id="reveal-heading" className="text-lg font-semibold">
          You chose
        </h2>
        <AnswerPill action={answer} />
        {c.answeredAt ? (
          <span className="text-sm text-muted">
            {answeredWhen(c.answeredAt)}
            {c.answeredBy && c.answeredBy !== 'me' ? ` by ${c.answeredBy}` : ''}
          </span>
        ) : null}
      </div>
      {c.note ? <p className="max-w-[68ch] text-base text-muted">Your note: “{c.note}”</p> : null}
      <div>
        <dl className="divide-y divide-border rounded-lg border border-border">
          <CompareRow label="What the system does now" value={c.systemAction} answer={answer} />
          <CompareRow label="What the agent reviewers said" value={c.agentAction} answer={answer} />
        </dl>
        <p className="mt-2 text-sm text-muted">Saved. Where these differ, your answer is the one that counts.</p>
      </div>
      <div>
        <h3 className="text-sm font-semibold text-muted">Why you were asked</h3>
        <p className="mt-1.5 max-w-[68ch] text-base leading-7 whitespace-pre-line">{c.reason}</p>
      </div>
      <div className="flex flex-wrap items-center gap-3 pt-1">
        <PrimaryLink href={nextHref}>{nextId !== null ? 'Next case →' : 'Finish'}</PrimaryLink>
        {/* Keyboard hints only where there is likely a keyboard (not on phones). */}
        <span className="hidden text-xs text-muted sm:inline">
          or press <kbd className="font-mono">Enter</kbd>
        </span>
      </div>
      <details open={changeOpen} className="border-t border-border pt-4">
        <summary className="cursor-pointer text-sm text-muted hover:text-text">Change your answer or note</summary>
        <div className="mt-4">
          <AnswerForm key={`${c.id}-${c.answeredAt}`} caseId={c.id} action={action} mode="change" current={answer} initialNote={c.note} />
        </div>
      </details>
      <RevealKeys key={`${c.id}-${c.answeredAt}`} nextHref={nextHref} />
    </section>
  );
}

/** Nothing open: either no cases at all, or every case answered. */
export function NothingOpen({ total }: { total: number }) {
  return (
    <div className="rounded-xl border border-dashed border-border px-6 py-12 text-center">
      <p className="text-lg font-semibold">{total === 0 ? 'Nothing needs your call right now.' : `All ${total} decided.`}</p>
      {total > 0 ? (
        <p className="mt-1 text-base text-muted">Nothing else needs your call right now. You can change any answer below.</p>
      ) : null}
    </div>
  );
}

/** Answered cases, compact; each opens its reveal with the change form expanded. */
export function DecidedList({ cases, currentId, colors }: { cases: OwnerCaseView[]; currentId: number | null; colors: ProjectColors }) {
  if (!cases.length) return null;
  return (
    <section aria-labelledby="decided-heading">
      <h2 id="decided-heading" className="mb-2 text-sm font-semibold text-muted">
        Decided ({cases.length})
      </h2>
      <ul className="divide-y divide-border overflow-hidden rounded-xl border border-border bg-panel">
        {cases.map((c) => (
          <li key={c.id}>
            <Link
              href={`${caseHref(c.id)}&change=1`}
              aria-current={c.id === currentId ? 'true' : undefined}
              className={cx('flex items-center gap-3 px-4 py-2.5 no-underline hover:bg-panel-2', c.id === currentId && 'bg-panel-2')}
            >
              {c.answer ? <AnswerPill action={c.answer} size="sm" /> : null}
              {/* A wrapper: "hidden" on the tag itself would lose to the tag's own inline-flex. */}
              <span className="hidden shrink-0 sm:inline-flex">
                <CaseProject c={c} colors={colors} />
              </span>
              <span className="min-w-0 flex-1 truncate text-text">
                {/* Phones: no room for the tag, so the name leads the (truncated) line instead. */}
                <span className="text-muted sm:hidden">{c.projectName ?? 'Unknown project'} · </span>
                {c.title}
              </span>
              <span className="shrink-0 text-sm text-accent">Change</span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
