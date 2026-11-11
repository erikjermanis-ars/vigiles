'use server';

/** Server actions of the blind Review page. */
import { revalidatePath } from 'next/cache';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import type { ReviewSaveState } from '@/components/finding/review-label-form';
import { getDb } from '@/lib/db/client';
import { LABELER_COOKIE, parseLabeler, parseLabelInput, upsertLabel } from '@/lib/queries/findings';
import { currentLabeler, LABELER_COOKIE_OPTIONS } from './labeler';

function reviewPath(id: FormDataEntryValue | null, extra: Record<string, string> = {}): string {
  const n = Number(id);
  const qs = new URLSearchParams(extra);
  if (Number.isInteger(n) && n > 0) qs.set('id', String(n));
  const s = qs.toString();
  return s ? `/review?${s}` : '/review';
}

/** Saves the current labeler's label, then shows the same finding again, which now reveals the system's answer. */
export async function saveReviewLabelAction(_prev: ReviewSaveState, formData: FormData): Promise<ReviewSaveState> {
  const parsed = parseLabelInput(formData);
  if (!parsed.ok) return { error: parsed.error };
  try {
    upsertLabel(getDb(), parsed.value, await currentLabeler());
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
  revalidatePath('/findings');
  revalidatePath(`/findings/${parsed.value.findingId}`);
  redirect(`/review?id=${parsed.value.findingId}`);
}

/**
 * "Labeling as: …": switches the labeler whose queue, labels and reveal the dashboard shows. An invalid
 * name changes nothing and comes back as `?labelerError=1`. Stays on the finding that was open (`id`).
 */
export async function setLabelerAction(formData: FormData): Promise<void> {
  const labeler = parseLabeler(formData.get('labeler'));
  if (!labeler) redirect(reviewPath(formData.get('id'), { labelerError: '1' }));
  (await cookies()).set(LABELER_COOKIE, labeler, LABELER_COOKIE_OPTIONS);
  revalidatePath('/', 'layout');
  redirect(reviewPath(formData.get('id')));
}
