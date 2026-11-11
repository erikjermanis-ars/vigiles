'use server';

/** Server actions of the Finding page. */
import { revalidatePath } from 'next/cache';
import { currentLabeler } from '@/app/review/labeler';
import { loadVigilesConfig } from '@/lib/config/load';
import { getDb } from '@/lib/db/client';
import { enqueueJob } from '@/lib/jobs/queue';
import { findingExists, findPendingDecideJob, findPendingTriageJob, parseLabelInput, upsertLabel } from '@/lib/queries/findings';

function positiveInt(value: FormDataEntryValue | null): number | null {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** Saves the label of the current labeler (chosen on the Review page). */
export async function saveLabelAction(formData: FormData): Promise<void> {
  const parsed = parseLabelInput(formData);
  if (!parsed.ok) throw new Error(parsed.error);
  upsertLabel(getDb(), parsed.value, await currentLabeler());
  revalidatePath(`/findings/${parsed.value.findingId}`);
  revalidatePath('/findings');
}

/**
 * Enqueues a forced triage of one finding under one configured triage config (the worker runs it).
 * Under the active config a `decide` job follows (the worker runs jobs in order), so the finding's
 * decision picks up the new verdict. Other configs are experiments: they never change decisions, so
 * nothing follows them. Decide is not run inside the triage job itself, because forced consistency
 * and eval triage runs must not rewrite current decisions.
 */
export async function enqueueTriageAction(formData: FormData): Promise<void> {
  const findingId = positiveInt(formData.get('findingId'));
  const config = String(formData.get('config') ?? '');
  if (!findingId) throw new Error('invalid finding id');
  const { triage } = loadVigilesConfig();
  if (!triage.configs.some((c) => c.name === config)) throw new Error(`unknown triage config "${config}"`);
  const db = getDb();
  if (!findingExists(db, findingId)) throw new Error(`finding ${findingId} not found`);
  // Synchronous check-then-insert (better-sqlite3), so a double click cannot enqueue two paid runs.
  if (findPendingTriageJob(db, findingId, config, triage.active_config) === null) {
    enqueueJob(db, 'triage', { findings: [findingId], config, force: true });
    if (config === triage.active_config) enqueueJob(db, 'decide', {});
  }
  revalidatePath(`/findings/${findingId}`);
  revalidatePath('/jobs');
}

/**
 * "Re-evaluate policy" on a stale decision: enqueues a `decide` job (current policy, active config).
 * No LLM calls. A decide job that is still queued already covers it.
 */
export async function enqueueDecideAction(formData: FormData): Promise<void> {
  const findingId = positiveInt(formData.get('findingId'));
  const db = getDb();
  if (findPendingDecideJob(db)?.status !== 'queued') enqueueJob(db, 'decide', {});
  if (findingId) revalidatePath(`/findings/${findingId}`);
  revalidatePath('/jobs');
  revalidatePath('/', 'layout');
}
