/** Keyboard shortcuts of the blind Review page (spec §11.1), as a pure mapping so it can be tested. */
import type { Action, AffectedTruth } from '@/lib/types';

export type ReviewKeyCommand =
  | { kind: 'expected'; value: Action }
  | { kind: 'affected'; value: AffectedTruth }
  | { kind: 'save' }
  | { kind: 'next' }
  | { kind: 'prev' };

export interface ReviewKeyInput {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  isComposing?: boolean;
  /** Auto-repeat of a held key */
  repeat?: boolean;
  /** Upper-case tag name of the event target */
  targetTag: string | null;
  /** The `type` of an <input> target */
  targetType?: string | null;
  targetEditable?: boolean;
}

export const REVIEW_SHORTCUTS: { keys: string; label: string }[] = [
  { keys: '1 2 3', label: 'ping / digest / log' },
  { keys: 'y n u', label: 'affected yes / no / unsure' },
  { keys: 'Enter', label: 'save' },
  { keys: 'j', label: 'next (skip)' },
  { keys: 'k', label: 'previous' },
];

const EXPECTED: Record<string, Action> = { '1': 'ping', '2': 'digest', '3': 'log' };
const AFFECTED: Record<string, AffectedTruth> = { y: 'yes', n: 'no', u: 'unsure' };
const NON_TEXT_INPUT_TYPES = new Set(['radio', 'checkbox', 'button', 'submit', 'reset']);

/** True when typing goes into the focused element (the note textarea, a text input, a select). */
export function isTextEntryTarget(t: Pick<ReviewKeyInput, 'targetTag' | 'targetType' | 'targetEditable'>): boolean {
  if (t.targetEditable) return true;
  if (t.targetTag === 'TEXTAREA' || t.targetTag === 'SELECT') return true;
  if (t.targetTag === 'INPUT') return !NON_TEXT_INPUT_TYPES.has((t.targetType ?? 'text').toLowerCase());
  return false;
}

/** Elements where Enter already does something (click, follow, toggle a <details>). */
const ENTER_NATIVE_TAGS = new Set(['BUTTON', 'A', 'SUMMARY']);

export function reviewKeyCommand(e: ReviewKeyInput): ReviewKeyCommand | null {
  // A held Enter would otherwise save, then skip past the reveal once the page swaps in the Next handler.
  if (e.metaKey || e.ctrlKey || e.altKey || e.isComposing || e.repeat) return null;
  if (isTextEntryTarget(e)) return null;
  // Enter on a focused button, link or <summary> keeps its native meaning (no double submit).
  if (e.key === 'Enter') return e.targetTag !== null && ENTER_NATIVE_TAGS.has(e.targetTag) ? null : { kind: 'save' };
  const key = e.key.toLowerCase();
  const expected = EXPECTED[key];
  if (expected) return { kind: 'expected', value: expected };
  const affected = AFFECTED[key];
  if (affected) return { kind: 'affected', value: affected };
  if (key === 'j') return { kind: 'next' };
  if (key === 'k') return { kind: 'prev' };
  return null;
}

/** Browser-only: reads the fields reviewKeyCommand needs from a DOM keyboard event. */
export function keyInputFromEvent(e: KeyboardEvent): ReviewKeyInput {
  const target = e.target instanceof HTMLElement ? e.target : null;
  return {
    key: e.key,
    metaKey: e.metaKey,
    ctrlKey: e.ctrlKey,
    altKey: e.altKey,
    isComposing: e.isComposing,
    repeat: e.repeat,
    targetTag: target?.tagName ?? null,
    targetType: target instanceof HTMLInputElement ? target.type : null,
    targetEditable: target?.isContentEditable ?? false,
  };
}
