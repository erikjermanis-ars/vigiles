import { describe, expect, it } from 'vitest';
import type { DecideStats } from '../lib/policy/decide';
import { decideParams, decideSummary } from './decide';

describe('decide job params', () => {
  it('defaults to the current policy and the active config', () => {
    expect(decideParams({})).toEqual({ policyHash: undefined, configName: undefined });
    expect(decideParams({ policy: '', config: null })).toEqual({ policyHash: undefined, configName: undefined });
  });

  it('passes names through', () => {
    expect(decideParams({ policy: 'ac951b246a18', config: 'v1-sonnet-high-code' })).toEqual({
      policyHash: 'ac951b246a18',
      configName: 'v1-sonnet-high-code',
    });
  });

  it('restores the leading zeros the CLI drops from an all-digit policy hash', () => {
    // `--policy 012345678901` arrives as the number 12345678901.
    expect(decideParams({ policy: 12345678901 }).policyHash).toBe('012345678901');
    expect(decideParams({ policy: 123456789012 }).policyHash).toBe('123456789012');
  });

  it('rejects a bare flag or a non-name value', () => {
    expect(() => decideParams({ policy: true })).toThrow(/--policy needs a name/);
    expect(() => decideParams({ config: 1.5 })).toThrow(/--config needs a name/);
  });
});

describe('decide job log', () => {
  const stats: DecideStats = {
    policyHash: 'abc123def456',
    config: 'cfg',
    current: true,
    evaluated: 10,
    ping: 2,
    digest: 3,
    log: 5,
    changed: 1,
    firstDecisions: 4,
    unenriched: 0,
    disabledSkipped: 0,
    reprioritized: 0,
    rules: {},
  };

  it('summarizes the run', () => {
    expect(decideSummary(stats)).toEqual([
      'policy abc123def456 × cfg (current): 10 evaluated, 2 ping, 3 digest, 5 log, 1 changed, 4 first decision(s)',
    ]);
  });

  it('warns about findings left undecided because enrich has not scored them, and notes disabled projects', () => {
    const lines = decideSummary({ ...stats, unenriched: 3, disabledSkipped: 2 });
    expect(lines).toHaveLength(3);
    expect(lines[1]).toMatch(
      /^warning: 3 open finding\(s\) have no signals yet .* left undecided; run enrich \(or Refresh all\), then decide$/,
    );
    expect(lines[2]).toBe('2 open finding(s) of disabled projects were not evaluated (no current decision)');
  });
});
