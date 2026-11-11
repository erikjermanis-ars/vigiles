'use server';

/** Shared server actions. Page-specific actions live next to their page. */
import { revalidatePath } from 'next/cache';
import { getDb } from '@/lib/db/client';
import { enqueueJob, isJobType, requestCancel } from '@/lib/jobs/queue';

export async function enqueueJobAction(type: string, params: Record<string, unknown> = {}): Promise<number> {
  if (!isJobType(type)) throw new Error(`unknown job type ${type}`);
  const id = enqueueJob(getDb(), type, params);
  revalidatePath('/', 'layout'); // every page shows job-derived state (banner, inbox, eval buttons)
  return id;
}

export async function cancelJobAction(id: number): Promise<void> {
  requestCancel(getDb(), id);
  revalidatePath('/', 'layout');
}
