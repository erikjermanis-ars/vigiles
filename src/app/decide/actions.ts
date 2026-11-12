'use server';

/** Server action of the owner's decision page (/decide). */
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { currentLabeler } from '@/app/review/labeler';
import type { DecideSaveState } from '@/components/decide/answer-form';
import { getDb } from '@/lib/db/client';
import { answerOwnerCase, parseAnswerInput } from '@/lib/queries/owner-cases';

/**
 * Saves (or changes) the owner's answer to a case, which also records the current labeler's label for the
 * finding, then shows the same case again, now with the reveal.
 */
export async function answerCaseAction(_prev: DecideSaveState, formData: FormData): Promise<DecideSaveState> {
  const parsed = parseAnswerInput(formData);
  if (!parsed.ok) return { error: parsed.error };
  try {
    answerOwnerCase(getDb(), parsed.value, await currentLabeler());
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
  // The nav badge (layout), the Findings pages and Eval all read the case or the label.
  revalidatePath('/', 'layout');
  redirect(`/decide?case=${parsed.value.caseId}`);
}
