/**
 * The request's project scope (see src/lib/project-scope.ts): `?project=` when the page has one, else the
 * header switcher's cookie, else every project. Server-only (reads request cookies and the DB); not a server
 * action module, so nothing here is callable from the client.
 */
import { cookies } from 'next/headers';
import { getDb } from '@/lib/db/client';
import { PROJECT_COOKIE, resolveProjectScope, type ScopeContext } from '@/lib/project-scope';
import type { SearchParams } from '@/lib/queries/findings';
import { listScopeProjects } from '@/lib/queries/projects';

export async function currentProjectScope(searchParams?: SearchParams): Promise<ScopeContext> {
  const projects = listScopeProjects(getDb());
  const cookie = (await cookies()).get(PROJECT_COOKIE)?.value;
  const knownIds = projects.map((p) => p.id);
  const scope = resolveProjectScope({ query: searchParams?.project, cookie, knownIds });
  const cookieIds = resolveProjectScope({ cookie, knownIds }).ids;
  return { ...scope, projects, cookieIds };
}

/** The scope the header shows before it sees the URL: the cookie, else every project. */
export async function cookieProjectScope(): Promise<ScopeContext> {
  return currentProjectScope(undefined);
}
