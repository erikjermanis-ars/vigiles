/**
 * CISA Known Exploited Vulnerabilities catalog (spec §4.3, §8). A snapshot feed: each sync
 * replaces the whole `kev` table, so there is no cursor. The DB-free half (schema, fetch, rows,
 * matching) lives in ./kev-feed and is re-exported here.
 */
import type { Db } from '../db/client';
import { kev } from '../db/schema';
import { recordFeedSuccess } from './feed-state';
import { kevRowsFromFeed, type KevFeed, type KevRow } from './kev-feed';

export {
  fetchKevFeed,
  KEV_FEED_URL,
  KevEntrySchema,
  KevFeedSchema,
  kevRowsFromFeed,
  matchKev,
  parseKevFeed,
  type KevEntry,
  type KevFeed,
  type KevMatch,
  type KevRow,
} from './kev-feed';

// KevRow is declared without the DB; it must stay the kev table's insert shape.
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const kevRowMatchesTable: Equal<KevRow, typeof kev.$inferInsert> = true;
void kevRowMatchesTable;

const INSERT_CHUNK = 500;

/** Replaces the catalog and marks the feed fresh, atomically: readers never see a half-written table. */
export function replaceKevCatalog(db: Db, feed: KevFeed, at = new Date().toISOString()): { count: number } {
  const rows = kevRowsFromFeed(feed);
  db.transaction((tx) => {
    tx.delete(kev).run();
    for (let i = 0; i < rows.length; i += INSERT_CHUNK) tx.insert(kev).values(rows.slice(i, i + INSERT_CHUNK)).run();
    recordFeedSuccess(tx, 'kev', { catalogVersion: feed.catalogVersion, dateReleased: feed.dateReleased, count: rows.length }, at);
  });
  return { count: rows.length };
}

/** cve → dateAdded for the whole catalog (about 1,500 rows, cheap to hold in memory). */
export function loadKevIndex(db: Db): Map<string, string | null> {
  const rows = db.select({ cve: kev.cve, dateAdded: kev.dateAdded }).from(kev).all();
  return new Map(rows.map((r) => [r.cve, r.dateAdded]));
}
