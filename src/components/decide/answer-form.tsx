'use client';

/**
 * The owner's answer: three large buttons (Ping / Digest / Log), each with its definition, and an optional
 * note. Clicking a button (or pressing 1 / 2 / 3 in "ask" mode) saves at once; the server action then shows
 * the reveal. In "change" mode (on the reveal) the current answer is highlighted and there are no shortcuts.
 * Mount it with a `key` that changes with the case and its answer so local state resets.
 */
import { useActionState, useEffect, useRef, useState, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { keyInputFromEvent } from '@/components/finding/review-keys';
import { cx } from '@/components/ui';
import type { Action } from '@/lib/types';
import { decideKeyCommand } from './decide-keys';
import { ACTION_TONE, ANSWER_CHOICES } from './parts';

export interface DecideSaveState {
  error: string | null;
}

const NOTE_MAX = 500;

export function AnswerForm({
  caseId,
  action,
  mode,
  current = null,
  initialNote = null,
}: {
  caseId: number;
  action: (prev: DecideSaveState, formData: FormData) => Promise<DecideSaveState>;
  mode: 'ask' | 'change';
  current?: Action | null;
  initialNote?: string | null;
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const buttons = useRef<Partial<Record<Action, HTMLButtonElement | null>>>({});
  // Controlled so React's automatic form reset after an action cannot wipe it on a failed save.
  const [note, setNote] = useState(initialNote ?? '');
  const [chosen, setChosen] = useState<Action | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  const [state, formAction, pending] = useActionState(action, { error: null });
  const big = mode === 'ask';

  useEffect(() => {
    if (mode !== 'ask') return;
    function onKeyDown(e: KeyboardEvent) {
      const cmd = decideKeyCommand(keyInputFromEvent(e), 'ask');
      if (cmd?.kind !== 'answer') return;
      e.preventDefault();
      const button = buttons.current[cmd.value];
      if (button && !button.disabled) formRef.current?.requestSubmit(button);
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [mode]);

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    // preventDefault also stops React from running the form action.
    const submitter = (e.nativeEvent as SubmitEvent).submitter;
    const value = submitter instanceof HTMLButtonElement ? (submitter.value as Action) : null;
    if (pending || !value) {
      e.preventDefault();
      if (!value) setHint('Choose Ping, Digest or Log to save.');
      return;
    }
    setHint(null);
    setChosen(value);
  }

  function onNoteKeyDown(e: ReactKeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Escape') e.currentTarget.blur();
    if (e.key !== 'Enter') return;
    // Enter would submit with the first button (Ping). Only save the note under the answer already given.
    e.preventDefault();
    const button = current ? buttons.current[current] : null;
    if (button) formRef.current?.requestSubmit(button);
    else setHint('Choose Ping, Digest or Log to save.');
  }

  const error = hint ?? state.error;
  return (
    <form ref={formRef} action={formAction} onSubmit={onSubmit} className="space-y-4">
      <input type="hidden" name="caseId" value={caseId} />
      <div className="grid gap-3 sm:grid-cols-3">
        {ANSWER_CHOICES.map((c) => {
          const isCurrent = current === c.value;
          const isSaving = pending && chosen === c.value;
          return (
            <button
              key={c.value}
              ref={(el) => {
                buttons.current[c.value] = el;
              }}
              type="submit"
              name="answer"
              value={c.value}
              disabled={pending}
              aria-pressed={mode === 'change' ? isCurrent : undefined}
              aria-keyshortcuts={big ? c.key : undefined}
              className={cx(
                'flex flex-col items-start rounded-xl border-2 text-left transition-colors disabled:cursor-wait',
                'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
                big ? 'gap-1.5 px-4 py-4' : 'gap-1 px-3 py-2.5',
                isCurrent ? ACTION_TONE[c.value] : 'border-border bg-panel text-text hover:border-muted hover:bg-panel-2',
                isSaving && 'border-accent',
                pending && !isSaving && 'opacity-50',
              )}
            >
              <span className="flex w-full items-center justify-between gap-2">
                <span className={cx('font-semibold', big ? 'text-lg' : 'text-base')}>
                  {isSaving ? 'Saving…' : c.label}
                  {isCurrent && !isSaving ? <span className="ml-1.5 text-xs font-medium">(your answer)</span> : null}
                </span>
                {big ? (
                  <kbd className="hidden rounded border border-border px-1.5 font-mono text-xs text-muted sm:inline">{c.key}</kbd>
                ) : null}
              </span>
              <span className={cx('leading-snug', big ? 'text-sm' : 'text-xs', isCurrent ? 'opacity-90' : 'text-muted')}>
                {c.definition}
              </span>
            </button>
          );
        })}
      </div>
      <div>
        <label htmlFor={`decide-note-${caseId}`} className="mb-1 block text-sm text-muted">
          Note <span className="text-xs">(optional, one line)</span>
        </label>
        <input
          id={`decide-note-${caseId}`}
          name="note"
          type="text"
          maxLength={NOTE_MAX}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          onKeyDown={onNoteKeyDown}
          placeholder={mode === 'ask' ? 'Anything you want to remember about this call' : 'Change the note, then press Enter'}
          className="w-full max-w-xl rounded-md border border-border bg-panel px-3 py-2 text-sm"
        />
      </div>
      {error ? (
        <p role="alert" className="text-sm text-ping">
          {error}
        </p>
      ) : big ? (
        <p className="text-xs text-muted">
          <span className="hidden sm:inline">
            Press <kbd className="font-mono">1</kbd>, <kbd className="font-mono">2</kbd> or <kbd className="font-mono">3</kbd> to
            answer.{' '}
          </span>
          You can change it later.
        </p>
      ) : null}
    </form>
  );
}
