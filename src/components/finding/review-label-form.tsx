'use client';

/**
 * Blind-review label form with keyboard shortcuts (spec §11.1). Mount it with `key={findingId}` so
 * the choices reset when moving to another finding. Saving redirects (server-side) to the reveal view.
 */
import { useRouter } from 'next/navigation';
import { useActionState, useEffect, useRef, useState, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { flushSync } from 'react-dom';
import { Button } from '@/components/ui';
import type { Action, AffectedTruth } from '@/lib/types';
import { AFFECTED_CHOICES, ChoiceGroup, EXPECTED_ACTION_CHOICES } from './choice-group';
import { keyInputFromEvent, REVIEW_SHORTCUTS, reviewKeyCommand } from './review-keys';

export interface ReviewSaveState {
  error: string | null;
}

export function ShortcutLegend() {
  return (
    <p className="text-xs text-muted">
      {REVIEW_SHORTCUTS.map((s, i) => (
        <span key={s.keys} className="whitespace-nowrap">
          {i > 0 ? ' · ' : ''}
          <kbd className="font-mono">{s.keys}</kbd> {s.label}
        </span>
      ))}
    </p>
  );
}

export function ReviewLabelForm({
  findingId,
  saveAction,
  nextHref,
  prevHref,
}: {
  findingId: number;
  saveAction: (prev: ReviewSaveState, formData: FormData) => Promise<ReviewSaveState>;
  nextHref: string | null;
  prevHref: string | null;
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [expected, setExpected] = useState<Action | null>(null);
  const [affected, setAffected] = useState<AffectedTruth | null>(null);
  // Controlled so React's automatic form reset after an action cannot wipe it on a failed save.
  const [note, setNote] = useState('');
  const [hint, setHint] = useState<string | null>(null);
  const [state, formAction, pending] = useActionState(saveAction, { error: null });

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const cmd = reviewKeyCommand(keyInputFromEvent(e));
      if (!cmd) return;
      e.preventDefault();
      switch (cmd.kind) {
        // flushSync commits the checked radio to the DOM at once, so "1 then Enter" typed within
        // one frame submits the new choice rather than a stale one.
        case 'expected':
          flushSync(() => {
            setExpected(cmd.value);
            setHint(null);
          });
          break;
        case 'affected':
          flushSync(() => setAffected(cmd.value));
          break;
        case 'save':
          formRef.current?.requestSubmit();
          break;
        case 'next':
          if (nextHref) router.push(nextHref);
          break;
        case 'prev':
          if (prevHref) router.push(prevHref);
          break;
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [nextHref, prevHref, router]);

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    // Read the DOM, not state, so a submit right after a shortcut sees the committed choice.
    // preventDefault also stops React from running the form action.
    const chosen = new FormData(e.currentTarget).get('expectedAction');
    if (pending || !chosen) {
      e.preventDefault();
      if (!chosen) setHint('Choose an expected action first (1, 2 or 3).');
    }
  }

  function onNoteKeyDown(e: ReactKeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Escape') e.currentTarget.blur();
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      formRef.current?.requestSubmit();
    }
  }

  return (
    <form ref={formRef} action={formAction} onSubmit={onSubmit} className="space-y-3">
      <input type="hidden" name="findingId" value={findingId} />
      <ChoiceGroup
        name="expectedAction"
        legend="Expected action"
        choices={EXPECTED_ACTION_CHOICES}
        value={expected}
        onChange={(v) => {
          setExpected(v as Action);
          setHint(null);
        }}
      />
      <ChoiceGroup
        name="affectedTruth"
        legend="Actually affected? (optional)"
        choices={AFFECTED_CHOICES}
        value={affected}
        onChange={(v) => setAffected(v as AffectedTruth)}
      />
      <div>
        <label htmlFor="review-note" className="mb-1.5 block text-xs font-medium tracking-wide text-muted uppercase">
          Note <span className="font-normal normal-case">(shortcuts are off while typing; Esc leaves, ⌘/Ctrl+Enter saves)</span>
        </label>
        <textarea
          id="review-note"
          name="note"
          rows={3}
          maxLength={5000}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          onKeyDown={onNoteKeyDown}
          className="w-full rounded-md border border-border bg-panel px-2.5 py-1.5 text-sm"
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" variant="primary" disabled={pending}>
          {pending ? 'Saving…' : 'Save label'}
        </Button>
        <Button type="button" disabled={!prevHref} onClick={() => prevHref && router.push(prevHref)}>
          Previous
        </Button>
        <Button type="button" disabled={!nextHref} onClick={() => nextHref && router.push(nextHref)}>
          Skip
        </Button>
      </div>
      {hint || state.error ? (
        <p role="alert" className="text-sm text-ping">
          {hint ?? state.error}
        </p>
      ) : null}
      <ShortcutLegend />
    </form>
  );
}
