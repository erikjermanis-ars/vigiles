/**
 * Keyboard shortcuts of the decide page, as a pure mapping so it can be tested:
 * while a case is open, 1 / 2 / 3 answer Ping / Digest / Log; after answering, Enter or n goes to the next case.
 * Keys typed into the note field never count.
 */
import { isTextEntryTarget, type ReviewKeyInput } from '@/components/finding/review-keys';
import type { Action } from '@/lib/types';

export type DecideKeyCommand = { kind: 'answer'; value: Action } | { kind: 'next' };

const ANSWER_KEYS: Record<string, Action> = { '1': 'ping', '2': 'digest', '3': 'log' };
/** Elements where Enter already does something (click, follow, toggle a <details>). */
const ENTER_NATIVE_TAGS = new Set(['BUTTON', 'A', 'SUMMARY']);

export function decideKeyCommand(e: ReviewKeyInput, mode: 'ask' | 'reveal'): DecideKeyCommand | null {
  if (e.metaKey || e.ctrlKey || e.altKey || e.isComposing || e.repeat) return null;
  if (isTextEntryTarget(e)) return null;
  if (mode === 'ask') {
    const value = ANSWER_KEYS[e.key];
    return value ? { kind: 'answer', value } : null;
  }
  if (e.key === 'Enter') return e.targetTag !== null && ENTER_NATIVE_TAGS.has(e.targetTag) ? null : { kind: 'next' };
  return e.key.toLowerCase() === 'n' ? { kind: 'next' } : null;
}
