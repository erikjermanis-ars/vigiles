/** Pure presentation helpers for the finding pages (safe to import from server and client components). */

/**
 * Link into the snapshot source viewer; the fragment scrolls the target line into view without JS.
 * Evidence links pass their triage run so the viewer opens the commit that run read (a run stays the
 * finding's verdict across later scans); import-site links omit it and get the latest scanned commit.
 */
export function sourceHref(findingId: number, file: string, line?: number | null, runId?: number | null): string {
  const qs = new URLSearchParams({ file });
  if (line && line > 0) qs.set('line', String(line));
  if (runId && runId > 0) qs.set('run', String(runId));
  return `/findings/${findingId}/source?${qs.toString()}${line && line > 0 ? `#L${line}` : ''}`;
}

/**
 * Spec §9.1: malicious packages (MAL-*) are never triaged; the remediation is always the same.
 * Shown wherever a fix version would be (Finding and Review pages).
 */
export { MALICIOUS_REMEDIATION } from '@/lib/types';

/** 'showing 20 of 57' when the stored list is capped; '' when every site is listed. */
export function importSitesShownNote(shown: number, total: number): string {
  return total > shown ? `showing ${shown} of ${total}` : '';
}

/**
 * Triage evidence also cites non-files, e.g. "(dependency facts)" or "(project profile)". Those are
 * shown as text; only path-like citations link to the source viewer (which would just say "not found").
 */
export function isFileCitation(file: string): boolean {
  const f = file.trim();
  if (!f) return false;
  // "." (the whole repo) and globs ("**/*") cite a repo-wide search, not a file the viewer could open.
  if (/^[./\\]+$/.test(f) || /[*?]/.test(f)) return false;
  const wrapped = /^\(.*\)$|^\[.*\]$|^<.*>$/s.test(f);
  return !(wrapped && !f.includes('/'));
}

export function truncate(text: string | null | undefined, max: number): string {
  if (!text) return '';
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1).trimEnd()}…`;
}

/** 'build_or_tooling_only' → 'build or tooling only' */
export function humanize(value: string | null | undefined): string {
  return value ? value.replace(/_/g, ' ') : '—';
}

/** A dependency path rendered as a chain: 'shadcn › express › proxy-addr'. */
export function formatChain(path: readonly string[]): string {
  return path.join(' › ');
}

export function formatEpss(epss: number | null | undefined, percentile?: number | null): string {
  if (epss === null || epss === undefined) return '—';
  const base = `${(epss * 100).toFixed(epss < 0.001 ? 3 : 1)}%`;
  return percentile === null || percentile === undefined ? base : `${base} (p${Math.round(percentile * 100)})`;
}

export function formatCvss(score: number | null | undefined): string {
  return score === null || score === undefined ? '—' : score.toFixed(1);
}

/** Only http(s) URLs become links; advisory references are untrusted. */
export function isHttpUrl(url: string): boolean {
  return /^https?:\/\//i.test(url);
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

/** One-line summary of an event's data JSON, e.g. 'from: P2 · to: P1'. */
export function summarizeEventData(data: Record<string, unknown> | null | undefined, max = 200): string {
  if (!data) return '';
  const parts = Object.entries(data).map(([k, v]) => `${k}: ${truncate(formatValue(v), 80)}`);
  return truncate(parts.join(' · '), max);
}
