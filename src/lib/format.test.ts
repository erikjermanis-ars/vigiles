import { describe, expect, it } from 'vitest';
import { formatDateTime, relativeTime, shortDate, timeZoneLabel } from './format';

describe('local date and time formatting', () => {
  it('labels times with the zone abbreviation, including daylight saving time', () => {
    expect(formatDateTime('2026-11-10T21:41:30.123Z', 'Europe/Zagreb')).toBe('2026-11-10 22:41 CET');
    expect(formatDateTime('2026-07-10T21:41:00Z', 'Europe/Zagreb')).toBe('2026-07-10 23:41 CEST');
    expect(formatDateTime('2026-11-10T21:41:00Z', 'America/New_York')).toBe('2026-11-10 16:41 EST');
    expect(formatDateTime('2026-11-10T21:41:00Z', 'UTC')).toBe('2026-11-10 21:41 UTC');
    // No common abbreviation: falls back to the GMT offset rather than nothing.
    expect(formatDateTime('2026-11-10T21:41:00Z', 'Asia/Tokyo')).toBe('2026-11-11 06:41 GMT+9');
    expect(formatDateTime('2026-11-10T23:05:00Z', 'Europe/Zagreb')).toBe('2026-11-11 00:05 CET'); // h23, not 24:05
  });

  it('formats dates in the local zone (a UTC evening can be the next local day)', () => {
    expect(shortDate('2026-11-10T23:30:00Z', 'Europe/Zagreb')).toBe('2026-11-11');
    expect(shortDate('2026-11-10T23:30:00Z', 'UTC')).toBe('2026-11-10');
    expect(shortDate('2026-11-10T02:00:00Z', 'America/New_York')).toBe('2026-11-09');
    // Offsets in the input are honoured (git %cI dates).
    expect(shortDate('2026-11-10T00:30:00+02:00', 'UTC')).toBe('2026-11-09');
  });

  it('keeps bare calendar dates and unparseable values as they are', () => {
    expect(shortDate('2026-01-02', 'America/New_York')).toBe('2026-01-02');
    expect(formatDateTime('2026-01-02', 'Asia/Tokyo')).toBe('2026-01-02');
    expect(shortDate('garbage-value')).toBe('garbage-va');
    expect(formatDateTime('garbage')).toBe('garbage');
    expect(shortDate(null)).toBe('—');
    expect(formatDateTime(undefined)).toBe('—');
  });

  it('prefers an abbreviation over an offset from either locale, and keeps GMT itself', () => {
    expect(timeZoneLabel(new Date('2026-11-10T12:00:00Z'), 'Europe/London')).toBe('GMT');
    expect(timeZoneLabel(new Date('2026-07-10T12:00:00Z'), 'Europe/London')).toBe('BST');
    expect(timeZoneLabel(new Date('2026-11-10T12:00:00Z'), 'America/Los_Angeles')).toBe('PST');
    // Offsets with minutes and negative offsets are still offsets (no abbreviation in either locale).
    expect(timeZoneLabel(new Date('2026-11-10T12:00:00Z'), 'Asia/Kolkata')).toMatch(/^(IST|GMT\+5:30)$/);
    expect(timeZoneLabel(new Date('2026-11-10T12:00:00Z'), 'America/Sao_Paulo')).toBe('GMT-3');
  });

  it('formats many dates quickly (formatters are cached) and gives the same result each time', () => {
    const iso = '2026-11-10T21:41:00Z';
    const first = formatDateTime(iso, 'Europe/Zagreb');
    const t = performance.now();
    for (let i = 0; i < 2000; i++) {
      expect(formatDateTime(iso, 'Europe/Zagreb')).toBe(first);
      shortDate(iso, 'Europe/Zagreb');
    }
    expect(performance.now() - t).toBeLessThan(1000);
    // A cached formatter of one zone never answers for another.
    expect(formatDateTime(iso, 'America/New_York')).toBe('2026-11-10 16:41 EST');
    expect(formatDateTime(iso, 'Europe/Zagreb')).toBe('2026-11-10 22:41 CET');
  });

  it('uses the process time zone by default', () => {
    const iso = '2026-11-10T21:41:00Z';
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    expect(formatDateTime(iso)).toBe(formatDateTime(iso, zone));
    expect(shortDate(iso)).toBe(shortDate(iso, zone));
    expect(timeZoneLabel(new Date(iso))).toBe(timeZoneLabel(new Date(iso), zone));
  });

  it('keeps relative times unchanged', () => {
    const now = new Date('2026-11-10T12:00:00Z');
    expect(relativeTime('2026-11-10T11:59:00Z', now)).toBe('1 minute ago');
    expect(relativeTime('2026-11-12T12:00:00Z', now)).toBe('in 2 days');
    expect(relativeTime(null, now)).toBe('never');
  });
});
