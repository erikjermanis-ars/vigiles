'use server';

/** Server actions of the header's project switcher. */
import { revalidatePath } from 'next/cache';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getDb } from '@/lib/db/client';
import { parseScopeValue, PROJECT_COOKIE, PROJECT_COOKIE_OPTIONS, scopeReturnPath } from '@/lib/project-scope';
import { listScopeProjects } from '@/lib/queries/projects';

/**
 * Switches the dashboard's project scope: `project` is one project id or 'all'. An unknown id changes nothing.
 * Returns to the page it came from (`returnTo`) without its `?project=` override, so the new scope shows.
 */
export async function setProjectScopeAction(formData: FormData): Promise<void> {
  const known = listScopeProjects(getDb()).map((p) => p.id);
  const value = formData.get('project');
  const parsed = parseScopeValue(typeof value === 'string' ? value : undefined, known);
  const store = await cookies();
  if (parsed === null) store.delete(PROJECT_COOKIE);
  else if (parsed?.length === 1) store.set(PROJECT_COOKIE, parsed[0]!, PROJECT_COOKIE_OPTIONS);
  revalidatePath('/', 'layout');
  redirect(scopeReturnPath(formData.get('returnTo')));
}
