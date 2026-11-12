import { describe, expect, it } from 'vitest';
import type { ReviewKeyInput } from '@/components/finding/review-keys';
import { decideKeyCommand } from './decide-keys';

const key = (k: string, extra: Partial<ReviewKeyInput> = {}): ReviewKeyInput => ({
  key: k,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  targetTag: 'BODY',
  ...extra,
});

describe('decideKeyCommand', () => {
  it('answers with 1 / 2 / 3 while asking', () => {
    expect(decideKeyCommand(key('1'), 'ask')).toEqual({ kind: 'answer', value: 'ping' });
    expect(decideKeyCommand(key('2'), 'ask')).toEqual({ kind: 'answer', value: 'digest' });
    expect(decideKeyCommand(key('3'), 'ask')).toEqual({ kind: 'answer', value: 'log' });
    expect(decideKeyCommand(key('4'), 'ask')).toBeNull();
    expect(decideKeyCommand(key('Enter'), 'ask')).toBeNull();
    expect(decideKeyCommand(key('n'), 'ask')).toBeNull();
  });

  it('goes to the next case with Enter or n after answering, and never answers there', () => {
    expect(decideKeyCommand(key('Enter'), 'reveal')).toEqual({ kind: 'next' });
    expect(decideKeyCommand(key('N'), 'reveal')).toEqual({ kind: 'next' });
    expect(decideKeyCommand(key('1'), 'reveal')).toBeNull();
    // Enter on a focused button, link or <summary> keeps its own meaning.
    for (const targetTag of ['BUTTON', 'A', 'SUMMARY']) expect(decideKeyCommand(key('Enter', { targetTag }), 'reveal')).toBeNull();
  });

  it('ignores typing in the note, modifiers, IME composition and auto-repeat', () => {
    expect(decideKeyCommand(key('1', { targetTag: 'INPUT', targetType: 'text' }), 'ask')).toBeNull();
    expect(decideKeyCommand(key('n', { targetTag: 'INPUT', targetType: 'text' }), 'reveal')).toBeNull();
    expect(decideKeyCommand(key('1', { metaKey: true }), 'ask')).toBeNull();
    expect(decideKeyCommand(key('1', { isComposing: true }), 'ask')).toBeNull();
    expect(decideKeyCommand(key('2', { repeat: true }), 'ask')).toBeNull();
    // A focused answer button is not a text field: the shortcut still works.
    expect(decideKeyCommand(key('3', { targetTag: 'BUTTON' }), 'ask')).toEqual({ kind: 'answer', value: 'log' });
  });
});
