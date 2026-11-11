import { describe, expect, it } from 'vitest';
import { computeBasePriority, formatAgainst, priorityRank, type BasePriorityInput } from './priority';
import { THRESHOLDS } from './test-support';

const base: BasePriorityInput = {
  osvId: 'GHSA-aaaa-bbbb-cccc',
  malicious: false,
  inKev: false,
  kevDateAdded: null,
  epss: null,
  cvss: null,
  exposure: 'internal',
  criticality: 'low',
};

const prio = (over: Partial<BasePriorityInput>, t = THRESHOLDS) => computeBasePriority({ ...base, ...over }, t);

describe('computeBasePriority', () => {
  it.each<[string, Partial<BasePriorityInput>, string, string[]]>([
    // P0: malicious, in any context
    ['malicious on an internal low asset', { osvId: 'MAL-2025-1234', malicious: true }, 'P0', ['malicious package (MAL-2025-1234)']],
    [
      'malicious and in KEV lists both',
      { osvId: 'MAL-2025-1234', malicious: true, inKev: true, kevDateAdded: '2026-01-02' },
      'P0',
      ['malicious package (MAL-2025-1234)', 'in CISA KEV since 2026-01-02'],
    ],
    // P0: KEV and (internet-facing or criticality high)
    [
      'KEV on internet-facing asset',
      { inKev: true, kevDateAdded: '2026-01-02', exposure: 'internet-facing' },
      'P0',
      ['in CISA KEV since 2026-01-02', 'asset internet-facing'],
    ],
    ['KEV on high-criticality internal asset', { inKev: true, kevDateAdded: '2026-01-02', criticality: 'high' }, 'P0', ['in CISA KEV since 2026-01-02', 'criticality high']],
    [
      'KEV on internet-facing high-criticality asset',
      { inKev: true, kevDateAdded: '2026-01-02', exposure: 'internet-facing', criticality: 'high' },
      'P0',
      ['in CISA KEV since 2026-01-02', 'asset internet-facing', 'criticality high'],
    ],
    // P1
    ['KEV on vpn/medium asset', { inKev: true, kevDateAdded: '2026-01-02', exposure: 'vpn', criticality: 'medium' }, 'P1', ['in CISA KEV since 2026-01-02']],
    ['KEV without a date', { inKev: true }, 'P1', ['in CISA KEV']],
    ['KEV date with a time part is shortened', { inKev: true, kevDateAdded: '2026-01-02T00:00:00Z' }, 'P1', ['in CISA KEV since 2026-01-02']],
    ['EPSS exactly at epss_high', { epss: 0.5 }, 'P1', ['EPSS 0.5 ≥ 0.5']],
    ['EPSS above epss_high', { epss: 0.62345 }, 'P1', ['EPSS 0.62 ≥ 0.5']],
    ['CVSS exactly at cvss_critical, internet-facing', { cvss: 9.0, exposure: 'internet-facing' }, 'P1', ['CVSS 9 ≥ 9 on internet-facing asset']],
    [
      'every P1 signal is listed',
      { inKev: true, kevDateAdded: '2026-01-02', epss: 0.7, cvss: 9.8, exposure: 'vpn' },
      'P1',
      ['in CISA KEV since 2026-01-02', 'EPSS 0.7 ≥ 0.5'],
    ],
    [
      'EPSS and CVSS on internet-facing asset',
      { epss: 0.62, cvss: 9.8, exposure: 'internet-facing' },
      'P1',
      ['EPSS 0.62 ≥ 0.5', 'CVSS 9.8 ≥ 9 on internet-facing asset'],
    ],
    // P2
    // Rendered against both EPSS thresholds, so it never reads as 0.5 (which would have been P1).
    ['EPSS just below epss_high', { epss: 0.4999 }, 'P2', ['EPSS 0.4999 ≥ 0.1']],
    ['CVSS just below cvss_critical on a vpn asset', { cvss: 8.97, exposure: 'vpn' }, 'P2', ['CVSS 8.97 ≥ 7']],
    ['CVSS critical but not internet-facing', { cvss: 9.8, exposure: 'vpn' }, 'P2', ['CVSS 9.8 ≥ 7']],
    ['CVSS critical on a high-criticality internal asset', { cvss: 9.8, criticality: 'high' }, 'P2', ['CVSS 9.8 ≥ 7']],
    ['CVSS just below cvss_critical, internet-facing', { cvss: 8.9, exposure: 'internet-facing' }, 'P2', ['CVSS 8.9 ≥ 7']],
    ['CVSS exactly at cvss_high', { cvss: 7.0 }, 'P2', ['CVSS 7 ≥ 7']],
    ['EPSS exactly at epss_medium', { epss: 0.1 }, 'P2', ['EPSS 0.1 ≥ 0.1']],
    ['CVSS and EPSS both P2', { cvss: 7.5, epss: 0.2 }, 'P2', ['CVSS 7.5 ≥ 7', 'EPSS 0.2 ≥ 0.1']],
    // P3
    ['no signal at all', {}, 'P3', ['no CVSS/EPSS signal']],
    ['no signal, even on an internet-facing high-criticality asset', { exposure: 'internet-facing', criticality: 'high' }, 'P3', ['no CVSS/EPSS signal']],
    ['CVSS just below cvss_high, no EPSS', { cvss: 6.9 }, 'P3', ['CVSS 6.9 < 7', 'no EPSS score']],
    ['EPSS just below epss_medium, no CVSS', { epss: 0.0999 }, 'P3', ['no CVSS score', 'EPSS 0.0999 < 0.1']],
    ['both below thresholds', { cvss: 5.3, epss: 0.0123 }, 'P3', ['CVSS 5.3 < 7', 'EPSS 0.012 < 0.1']],
    ['zero scores are signals, not missing', { cvss: 0, epss: 0 }, 'P3', ['CVSS 0 < 7', 'EPSS 0 < 0.1']],
  ])('%s', (_name, over, priority, reasons) => {
    expect(prio(over)).toEqual({ priority, reasons });
  });

  it('first match wins: malicious beats everything', () => {
    expect(prio({ malicious: true, osvId: 'MAL-1', cvss: 1, epss: 0 }).priority).toBe('P0');
  });

  it('uses the thresholds it is given', () => {
    const strict = { epss_high: 0.9, epss_medium: 0.3, cvss_critical: 9.5, cvss_high: 8.0 };
    expect(prio({ cvss: 9.4, exposure: 'internet-facing' }, strict)).toEqual({ priority: 'P2', reasons: ['CVSS 9.4 ≥ 8'] });
    expect(prio({ epss: 0.6 }, strict)).toEqual({ priority: 'P2', reasons: ['EPSS 0.6 ≥ 0.3'] });
    expect(prio({ cvss: 7.5, epss: 0.2 }, strict)).toEqual({ priority: 'P3', reasons: ['CVSS 7.5 < 8', 'EPSS 0.2 < 0.3'] });
  });
});

describe('formatAgainst', () => {
  it.each([
    [0.62345, 0.5, '0.62'],
    [0.4999, 0.5, '0.4999'],
    [0.09996, 0.1, '0.09996'],
    [8.95, 9, '8.9'], // 8.95 is 8.9499… in binary; still reads as below 9
    [8.96, 9, '8.96'],
    [10, 9, '10'],
    [9.8, 9, '9.8'],
    [0.99999, 0.5, '0.99999'],
    [0.9949, 0.5, '0.99'],
    [0, 0.1, '0'],
  ])('%d vs %d → %s', (value, threshold, expected) => {
    expect(formatAgainst(value, threshold)).toBe(expected);
  });

  it.each<[number, number[], string]>([
    [0.4999, [0.5, 0.1], '0.4999'], // against 0.1 alone it would print 0.5
    [0.0999, [0.5, 0.1], '0.0999'],
    [0.62345, [0.5, 0.1], '0.62'],
    [0.30001, [0.5, 0.1], '0.3'],
    [8.97, [9, 7], '8.97'],
    [6.99, [9, 7], '6.99'],
  ])('%d against every mark in %j → %s', (value, marks, expected) => {
    expect(formatAgainst(value, marks)).toBe(expected);
  });

  it('shows why a single threshold is not enough', () => {
    expect(formatAgainst(0.4999, 0.1)).toBe('0.5');
  });
});

describe('priorityRank', () => {
  it('orders P0 as most urgent', () => {
    expect(['P3', 'P0', 'P2', 'P1'].map((p) => priorityRank(p as 'P0'))).toEqual([3, 0, 2, 1]);
  });
});
