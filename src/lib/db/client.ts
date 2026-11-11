import Database from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import path from 'node:path';
import { dataPaths, loadVigilesConfig, repoRoot } from '../config/load';
import * as schema from './schema';

export type Db = BetterSQLite3Database<typeof schema> & { $client: Database.Database };

/**
 * Opens a database and applies migrations from ./drizzle.
 * Use `openDb(':memory:')` in tests.
 */
export function openDb(file: string, root = repoRoot()): Db {
  const sqlite = new Database(file);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('busy_timeout = 5000');
  sqlite.pragma('foreign_keys = ON');
  const db = drizzle(sqlite, { schema }) as Db;
  migrate(db, { migrationsFolder: path.join(root, 'drizzle') });
  return db;
}

const globalForDb = globalThis as unknown as { __vigilesDb?: Db };

/** Process-wide singleton (survives Next.js hot reloads). */
export function getDb(): Db {
  if (!globalForDb.__vigilesDb) {
    const paths = dataPaths(loadVigilesConfig());
    globalForDb.__vigilesDb = openDb(paths.db);
  }
  return globalForDb.__vigilesDb;
}

export { schema };
