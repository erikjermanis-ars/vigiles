/**
 * The dashboard's current labeler. Labels are keyed by (finding, labeler); a second developer picks
 * their own name on the Review page ("Labeling as …"), which sets a cookie read by the Review queue,
 * the reveal panel, the Finding page label form and the Findings list's labeled filter.
 * Server-only (reads request cookies); not a server action module, so nothing here is callable from the client.
 */
import { cookies } from 'next/headers';
import { LABELER_COOKIE, labelerOrDefault } from '@/lib/queries/findings';

export async function currentLabeler(): Promise<string> {
  return labelerOrDefault((await cookies()).get(LABELER_COOKIE)?.value);
}

/** Cookie attributes: readable by the server only, sent on same-site navigations, kept for a year. */
export const LABELER_COOKIE_OPTIONS = { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 24 * 365 } as const;
