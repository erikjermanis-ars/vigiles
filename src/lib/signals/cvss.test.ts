import { describe, expect, it } from 'vitest';
import { resolveCvssScore, severityLabelScore } from './cvss';

describe('severityLabelScore', () => {
  it.each([
    ['CRITICAL', 9.0],
    ['HIGH', 7.0],
    ['MODERATE', 4.0],
    ['MEDIUM', 4.0],
    ['LOW', 2.0],
    ['high', 7.0],
    [' Moderate ', 4.0],
  ])('%s → %d', (label, score) => {
    expect(severityLabelScore(label)).toBe(score);
  });

  it.each([null, undefined, '', 'UNKNOWN', 'NONE'])('%s → null', (label) => {
    expect(severityLabelScore(label)).toBeNull();
  });
});

describe('resolveCvssScore', () => {
  it('prefers the advisory score', () => {
    expect(resolveCvssScore({ cvssScore: 9.8, severityLabel: 'LOW' })).toBe(9.8);
  });
  it('keeps a real 0.0 score instead of falling back', () => {
    expect(resolveCvssScore({ cvssScore: 0, severityLabel: 'HIGH' })).toBe(0);
  });
  it('falls back to the label', () => {
    expect(resolveCvssScore({ cvssScore: null, severityLabel: 'CRITICAL' })).toBe(9.0);
  });
  it('is null without score or known label, or without an advisory', () => {
    expect(resolveCvssScore({ cvssScore: null, severityLabel: null })).toBeNull();
    expect(resolveCvssScore({ cvssScore: null, severityLabel: 'WEIRD' })).toBeNull();
    expect(resolveCvssScore(null)).toBeNull();
  });
});
