/**
 * The verdict cache: `.vigiles/verdicts.json` (committed, so teammates reuse each other's triage) and the
 * per-repo triage failures in the cache dir (never committed). A verdict counts for a finding only while its
 * inputHash equals the finding's current one (the POC's "ok run for the current input hash").
 */
import { readFileSync } from 'node:fs';
import { readRegularFile, writeFileAtomic, writeRepoFile } from './paths';
import {
  STATE_FORMAT,
  StoredVerdictSchema,
  type ScanFinding,
  type StoredVerdict,
  type TriageFailure,
  type TriageFailures,
  type VerdictFile,
} from './types';

/** The fields that identify a finding across scans (a verdict's key). */
export type VerdictKey = Pick<ScanFinding, 'osvId' | 'ecosystem' | 'packageName' | 'lockfile'>;

function keyOf(k: VerdictKey): string {
  return [k.osvId, k.ecosystem, k.packageName, k.lockfile].join('\0');
}

/** Plain code-unit order (not locale order), so the file sorts the same on every machine. */
function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareVerdicts(a: StoredVerdict, b: StoredVerdict): number {
  return (
    compareStrings(a.osvId, b.osvId) ||
    compareStrings(a.ecosystem, b.ecosystem) ||
    compareStrings(a.packageName, b.packageName) ||
    compareStrings(a.lockfile, b.lockfile)
  );
}

function errorCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | null)?.code;
}

export class VerdictStore {
  private readonly byKey = new Map<string, StoredVerdict>();

  constructor(verdicts: Iterable<StoredVerdict> = []) {
    for (const v of verdicts) this.upsert(v);
  }

  get size(): number {
    return this.byKey.size;
  }

  /** The stored verdict for this finding, whatever inputs it was made for. */
  get(f: VerdictKey): StoredVerdict | null {
    return this.byKey.get(keyOf(f)) ?? null;
  }

  /** The stored verdict only when it was made for the finding's current inputs. */
  current(f: VerdictKey & Pick<ScanFinding, 'inputHash'>): StoredVerdict | null {
    const v = this.get(f);
    return v && v.inputHash === f.inputHash ? v : null;
  }

  /** Adds or replaces the verdict for its finding. Validated and normalised (schema key order) on the way in. */
  upsert(v: StoredVerdict): void {
    const parsed = StoredVerdictSchema.parse(v);
    this.byKey.set(keyOf(parsed), parsed);
  }

  /** Every verdict, sorted (osvId, ecosystem, packageName, lockfile). */
  all(): StoredVerdict[] {
    return [...this.byKey.values()].sort(compareVerdicts);
  }

  toFile(): VerdictFile {
    return { format: STATE_FORMAT, verdicts: this.all() };
  }

  /** Atomic write, 2-space JSON with a trailing newline (small, reviewable diffs). Refuses a symlinked directory. */
  save(file: string): void {
    writeRepoFile(file, `${JSON.stringify(this.toFile(), null, 2)}\n`);
  }
}

function describeEntry(entry: unknown, index: number): string {
  const e = entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : {};
  const what = [e.osvId, e.packageName].filter((x) => typeof x === 'string').join(' ');
  return `entry ${index + 1}${what ? ` (${what})` : ''}`;
}

/**
 * Where JSON.parse failed, as ` (line L, column C)`, or ''. Never V8's message itself: it quotes the input.
 */
function jsonErrorPosition(text: string, err: unknown): string {
  const message = err instanceof Error ? err.message : '';
  const lc = /line (\d+) column (\d+)/.exec(message);
  if (lc) return ` (line ${lc[1]}, column ${lc[2]})`;
  const pos = /position (\d+)/.exec(message);
  if (!pos) return '';
  const lines = text.slice(0, Number(pos[1])).split('\n');
  return ` (line ${lines.length}, column ${lines[lines.length - 1]!.length + 1})`;
}

/**
 * Loads `.vigiles/verdicts.json`. A missing file is an empty store. Entries that fail validation are skipped
 * with a warning (they are re-triaged). A file that is not a verdict file at all (bad JSON, an unresolved
 * merge conflict, another format) is an error: silently ignoring it would re-triage everything and then
 * overwrite it.
 */
export function loadVerdicts(file: string): { store: VerdictStore; warnings: string[] } {
  let text: string;
  try {
    text = readRegularFile(file);
  } catch (err) {
    if (errorCode(err) === 'ENOENT') return { store: new VerdictStore(), warnings: [] };
    throw err;
  }

  if (/^(<{7}|={7}|>{7})( |$)/m.test(text)) {
    throw new Error(`${file} has unresolved merge conflict markers; resolve them (keeping either side is fine) and run again`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (err) {
    throw new Error(`${file} is not valid JSON${jsonErrorPosition(text, err)}`);
  }
  if (!json || typeof json !== 'object' || Array.isArray(json))
    throw new Error(`${file} is not a Vigiles verdict file (expected an object)`);
  const obj = json as Record<string, unknown>;
  if (obj.format !== STATE_FORMAT) {
    const newer = typeof obj.format === 'number' && obj.format > STATE_FORMAT;
    throw new Error(
      newer
        ? `${file} was written by a newer Vigiles (format ${obj.format}); update the plugin`
        : `${file} has an unknown format ${JSON.stringify(obj.format)} (expected ${STATE_FORMAT})`,
    );
  }
  if (!Array.isArray(obj.verdicts)) throw new Error(`${file}: "verdicts" must be an array`);

  const warnings: string[] = [];
  const store = new VerdictStore();
  obj.verdicts.forEach((entry, i) => {
    const parsed = StoredVerdictSchema.safeParse(entry);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const where = issue ? `${issue.path.map(String).join('.') || '(root)'}: ${issue.message}` : 'invalid';
      warnings.push(`verdicts.json ${describeEntry(entry, i)} is invalid and was ignored (${where}); it will be triaged again`);
      return;
    }
    const existing = store.get(parsed.data);
    if (existing) {
      // Two entries for one finding (e.g. a hand-merged file): keep the newer one.
      warnings.push(`verdicts.json ${describeEntry(entry, i)} duplicates another entry; kept the newer one`);
      if (existing.triagedAt >= parsed.data.triagedAt) return;
    }
    store.upsert(parsed.data);
  });
  return { store, warnings };
}

// ---------- triage failures (cache only) ----------

function isFailure(v: unknown): v is TriageFailure {
  if (!v || typeof v !== 'object') return false;
  const f = v as Record<string, unknown>;
  return typeof f.inputHash === 'string' && typeof f.error === 'string' && typeof f.at === 'string';
}

/** The last triage failure per finding id. A missing or unreadable file is empty (it is only a cache). */
export function loadFailures(file: string): TriageFailures {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return {};
  const out: TriageFailures = {};
  for (const [id, v] of Object.entries(json as Record<string, unknown>)) {
    if (isFailure(v)) out[id] = { inputHash: v.inputHash, error: v.error, at: v.at };
  }
  return out;
}

export function saveFailures(file: string, failures: TriageFailures): void {
  const sorted: TriageFailures = {};
  for (const id of Object.keys(failures).sort(compareStrings)) sorted[id] = failures[id]!;
  writeFileAtomic(file, `${JSON.stringify(sorted, null, 2)}\n`);
}
