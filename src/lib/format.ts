/**
 * Small formatting helpers shared by pages.
 *
 * Timestamps are stored as UTC ISO strings. The dashboard runs on the user's own machine (server ==
 * browser), so dates and times are shown in the machine's local time zone, and times carry an explicit
 * zone label ('2026-11-10 22:41 CET') so they are never mistaken for UTC. Every function takes an
 * optional IANA `timeZone` (default: the process's zone) so tests are deterministic.
 */

export function relativeTime(iso: string | null | undefined, now = new Date()): string {
  if (!iso) return 'never';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((now.getTime() - t) / 1000);
  const abs = Math.abs(s);
  const fmt = (n: number, u: string) => `${n} ${u}${n === 1 ? '' : 's'}`;
  let out: string;
  if (abs < 60) out = fmt(abs, 'second');
  else if (abs < 3600) out = fmt(Math.round(abs / 60), 'minute');
  else if (abs < 86400) out = fmt(Math.round(abs / 3600), 'hour');
  else out = fmt(Math.round(abs / 86400), 'day');
  return s >= 0 ? `${out} ago` : `in ${out}`;
}

/** A bare calendar date ('2026-01-02', e.g. KEV dateAdded) has no time zone and is shown as is. */
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

type Parts = Partial<Record<Intl.DateTimeFormatPartTypes, string>>;

/**
 * Intl.DateTimeFormat construction is slow (~40µs); a 500-row Findings list formats ~1000 dates, so
 * formatters are cached per (kind, locale, zone). `undefined` (the process zone) is its own key: the
 * dashboard's zone does not change while it runs.
 */
const formatters = new Map<string, Intl.DateTimeFormat>();
function formatter(key: string, timeZone: string | undefined, make: () => Intl.DateTimeFormat): Intl.DateTimeFormat {
  const k = `${key}|${timeZone ?? ''}`;
  let f = formatters.get(k);
  if (!f) {
    f = make();
    formatters.set(k, f);
  }
  return f;
}

function localParts(date: Date, timeZone: string | undefined, withTime: boolean): Parts {
  const fmt = formatter(
    withTime ? 'datetime' : 'date',
    timeZone,
    () =>
      new Intl.DateTimeFormat('en-US', {
        timeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        ...(withTime ? { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' as const } : {}),
      }),
  );
  return Object.fromEntries(fmt.formatToParts(date).map((p) => [p.type, p.value])) as Parts;
}

function zoneName(date: Date, locale: string, timeZone: string | undefined): string {
  const fmt = formatter(`zone-${locale}`, timeZone, () => new Intl.DateTimeFormat(locale, { timeZone, timeZoneName: 'short' }));
  return fmt.formatToParts(date).find((p) => p.type === 'timeZoneName')?.value ?? '';
}

/** 'GMT+9', 'GMT-3:30', 'UTC+1' (also with U+2212 MINUS SIGN): an offset, not an abbreviation. */
const OFFSET_ZONE = /^(?:GMT|UTC)[+\-−]/;

/**
 * Short zone label for `date` in `timeZone`: an abbreviation where one exists ('CET', 'CEST', 'EST',
 * 'UTC'), else the GMT offset ('GMT+9'). en-US knows the American abbreviations, en-GB the European ones.
 */
export function timeZoneLabel(date: Date = new Date(), timeZone?: string): string {
  const candidates = ['en-US', 'en-GB'].map((locale) => zoneName(date, locale, timeZone));
  return candidates.find((z) => z && !OFFSET_ZONE.test(z)) ?? candidates[0] ?? '';
}

/** Local calendar date, 'YYYY-MM-DD'. */
export function shortDate(iso: string | null | undefined, timeZone?: string): string {
  if (!iso) return '—';
  if (DATE_ONLY.test(iso)) return iso;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  const p = localParts(d, timeZone, false);
  return `${p.year}-${p.month}-${p.day}`;
}

/** Local date and time with the zone, '2026-11-10 22:41 CET'. */
export function formatDateTime(iso: string | null | undefined, timeZone?: string): string {
  if (!iso) return '—';
  if (DATE_ONLY.test(iso)) return iso;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = localParts(d, timeZone, true);
  const zone = timeZoneLabel(d, timeZone);
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}${zone ? ` ${zone}` : ''}`;
}

export function formatUsd(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  return n < 0.01 ? `$${n.toFixed(4)}` : `$${n.toFixed(2)}`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 90) return `${s.toFixed(1)} s`;
  return `${(s / 60).toFixed(1)} min`;
}

export function pct(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return `${(n * 100).toFixed(digits)}%`;
}

/** Primary display id for an advisory: first CVE alias, else the OSV id. */
export function displayVulnId(osvId: string, cves: string[] | null | undefined): string {
  return cves && cves.length ? cves[0]! : osvId;
}

export function osvUrl(osvId: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(osvId)}`;
}
