/**
 * `sync-osv` job (spec §6): refreshes the offline OSV database of every ecosystem in use, configured, or
 * synced before (so a database the staleness banner checks never goes stale unnoticed), with conditional
 * downloads (osv-scanner itself never refreshes an existing zip).
 */
import { and, desc, eq } from 'drizzle-orm';
import type { Db } from '../lib/db/client';
import { projects, scans } from '../lib/db/schema';
import { lockfileEcosystem } from '../lib/inventory/lockfiles';
import { ecosystemsWithFeedState, OsvDatabaseUnavailableError, refreshOsvZip, selectSyncEcosystems } from '../lib/osv/database';
import type { JobHandler } from '../lib/jobs/types';

/** Ecosystems of the lockfiles in each enabled project's latest succeeded scan. */
export function ecosystemsInUse(db: Db): string[] {
  const out = new Set<string>();
  for (const p of db.select({ id: projects.id }).from(projects).where(eq(projects.enabled, true)).all()) {
    const last = db
      .select({ lockfiles: scans.lockfiles })
      .from(scans)
      .where(and(eq(scans.projectId, p.id), eq(scans.status, 'succeeded')))
      .orderBy(desc(scans.id))
      .limit(1)
      .get();
    for (const lf of last?.lockfiles ?? []) {
      const eco = lockfileEcosystem(lf);
      if (eco) out.add(eco);
    }
  }
  return [...out];
}

export const run: JobHandler = async (ctx) => {
  const ecosystems = selectSyncEcosystems(ctx.config.osv.ecosystems, ecosystemsInUse(ctx.db), ecosystemsWithFeedState(ctx.db));
  ctx.log(`ecosystems: ${ecosystems.join(', ')}`);
  const perEcosystem: Record<string, Record<string, unknown>> = {};
  const failures: string[] = [];
  for (const [i, ecosystem] of ecosystems.entries()) {
    ctx.throwIfCancelled();
    ctx.progress(`osv ${i + 1}/${ecosystems.length}: ${ecosystem}`);
    try {
      const r = await refreshOsvZip(ctx.db, ecosystem, {
        baseUrl: ctx.config.osv.base_url,
        osvDbDir: ctx.paths.osvDb,
        signal: ctx.signal,
      });
      perEcosystem[ecosystem] = { status: r.status, bytes: r.bytes, lastModified: r.lastModified, durationMs: r.durationMs };
      ctx.log(
        `${ecosystem}: ${r.status === 'downloaded' ? `downloaded ${r.bytes} bytes` : 'not modified'} in ${r.durationMs} ms (data as of ${r.lastModified ?? '?'})`,
      );
    } catch (err) {
      ctx.throwIfCancelled();
      if (err instanceof OsvDatabaseUnavailableError) {
        perEcosystem[ecosystem] = { status: 'unavailable' };
        ctx.log(`${ecosystem}: ${err.message}; its lockfiles cannot be matched`);
        continue;
      }
      const message = err instanceof Error ? err.message : String(err);
      perEcosystem[ecosystem] = { status: 'failed', error: message };
      failures.push(message);
      ctx.log(`${ecosystem}: FAILED: ${message}`);
    }
  }
  if (failures.length) throw new Error(failures.join('; '));
  return { ecosystems: perEcosystem };
};
