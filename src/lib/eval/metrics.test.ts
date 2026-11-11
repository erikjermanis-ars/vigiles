import { describe, expect, it } from 'vitest';
import type { Action } from '../types';
import {
  basePriorityAction,
  confusionMatrix,
  consistency,
  deciderMetrics,
  exactAccuracy,
  floorPct,
  labelerAgreement,
  messageVolume,
  pingPrecision,
  pingRecall,
  quantile,
  ratio,
  triageRunStats,
  verdictAccuracy,
  verdictMatchesTruth,
} from './metrics';
import { compareVersions, highestVersion, isReleaseVersion, upgradeTarget } from './version';

const pair = (label: Action, decided: Action) => ({ label, decided });

describe('ratio', () => {
  it('keeps a zero denominator visible as null', () => {
    expect(ratio(0, 0)).toEqual({ num: 0, den: 0, value: null });
    expect(ratio(1, 4).value).toBe(0.25);
  });
});

describe('floorPct', () => {
  it('rounds down so a ratio below a target never reads as meeting it', () => {
    expect(floorPct(199 / 200)).toBe('99%');
    expect(floorPct(0.7999)).toBe('79%');
    expect(floorPct(1)).toBe('100%');
    expect(floorPct(0.8)).toBe('80%');
    expect(floorPct(0.29)).toBe('29%'); // 0.29 * 100 is 28.999… in floating point
    expect(floorPct(2 / 3, 1)).toBe('66.6%');
    expect(floorPct(0)).toBe('0%');
  });
});

describe('basePriorityAction', () => {
  it('maps priorities to actions', () => {
    expect(basePriorityAction('P0')).toBe('ping');
    expect(basePriorityAction('P1')).toBe('ping');
    expect(basePriorityAction('P2')).toBe('digest');
    expect(basePriorityAction('P3')).toBe('log');
    expect(basePriorityAction(null)).toBe('log');
  });
});

describe('ping recall and precision', () => {
  it('returns null values for empty input and when nothing was labeled or decided ping', () => {
    expect(pingRecall([]).value).toBeNull();
    expect(pingPrecision([]).value).toBeNull();
    const noPing = [pair('digest', 'log'), pair('log', 'log')];
    expect(pingRecall(noPing)).toEqual({ num: 0, den: 0, value: null });
    expect(pingPrecision(noPing)).toEqual({ num: 0, den: 0, value: null });
  });

  it('computes recall over labeled pings and precision over decided pings', () => {
    const pairs = [pair('ping', 'ping'), pair('ping', 'digest'), pair('log', 'ping'), pair('digest', 'ping'), pair('log', 'log')];
    expect(pingRecall(pairs)).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(pingPrecision(pairs)).toEqual({ num: 1, den: 3, value: 1 / 3 });
    expect(exactAccuracy(pairs)).toEqual({ num: 2, den: 5, value: 0.4 });
  });
});

describe('confusionMatrix', () => {
  it('counts rows by label and columns by decision', () => {
    const m = confusionMatrix([pair('ping', 'ping'), pair('ping', 'log'), pair('ping', 'log'), pair('digest', 'ping')]);
    expect(m.ping).toEqual({ ping: 1, digest: 0, log: 2 });
    expect(m.digest).toEqual({ ping: 1, digest: 0, log: 0 });
    expect(m.log).toEqual({ ping: 0, digest: 0, log: 0 });
  });

  it('is part of deciderMetrics', () => {
    const d = deciderMetrics([pair('log', 'log')]);
    expect(d.n).toBe(1);
    expect(d.matrix.log.log).toBe(1);
    expect(d.accuracy.value).toBe(1);
  });
});

describe('verdict accuracy', () => {
  it('maps verdicts onto affected truth', () => {
    expect(verdictMatchesTruth('affected', 'yes')).toBe(true);
    expect(verdictMatchesTruth('likely_affected', 'yes')).toBe(true);
    expect(verdictMatchesTruth('likely_not_affected', 'yes')).toBe(false);
    expect(verdictMatchesTruth('not_affected', 'no')).toBe(true);
    expect(verdictMatchesTruth('likely_not_affected', 'no')).toBe(true);
    expect(verdictMatchesTruth('affected', 'no')).toBe(false);
    expect(verdictMatchesTruth('affected', 'unsure')).toBeNull();
    expect(verdictMatchesTruth(null, 'yes')).toBeNull();
  });

  it('excludes unsure, missing truth and missing verdicts', () => {
    const r = verdictAccuracy([
      { truth: 'yes', verdict: 'affected' },
      { truth: 'no', verdict: 'affected' },
      { truth: 'unsure', verdict: 'affected' },
      { truth: null, verdict: 'not_affected' },
      { truth: 'yes', verdict: null },
    ]);
    expect(r).toMatchObject({ num: 1, den: 2, value: 0.5, excludedNoTruth: 2, excludedNoVerdict: 1 });
    expect(verdictAccuracy([]).value).toBeNull();
  });
});

describe('consistency', () => {
  it('ignores single runs and checks every run in a group', () => {
    const c = consistency([
      [{ verdict: 'affected', action: 'ping' }],
      [
        { verdict: 'affected', action: 'ping' },
        { verdict: 'affected', action: 'ping' },
      ],
      [
        { verdict: 'affected', action: 'ping' },
        { verdict: 'affected', action: 'ping' },
        { verdict: 'likely_affected', action: 'ping' },
      ],
      [
        { verdict: 'not_affected', action: 'log' },
        { verdict: 'not_affected', action: 'digest' },
      ],
    ]);
    expect(c.groups).toBe(3);
    expect(c.runs).toBe(7);
    expect(c.identicalVerdict).toEqual({ num: 2, den: 3, value: 2 / 3 });
    expect(c.identicalAction).toEqual({ num: 2, den: 3, value: 2 / 3 });
    // No policy actions given: nothing to score.
    expect(c.identicalPolicyAction).toEqual({ num: 0, den: 0, value: null });
  });

  it('scores identical policy actions only on groups where every run has one', () => {
    const c = consistency([
      // different verdict and suggested action, same policy action
      [
        { verdict: 'affected', action: 'ping', policyAction: 'ping' },
        { verdict: 'likely_affected', action: 'digest', policyAction: 'ping' },
      ],
      // same suggested action, different policy action
      [
        { verdict: 'affected', action: 'ping', policyAction: 'ping' },
        { verdict: 'not_affected', action: 'ping', policyAction: 'digest' },
      ],
      // a run without a policy action: not scored for the policy metric
      [
        { verdict: 'affected', action: 'ping', policyAction: 'ping' },
        { verdict: 'affected', action: 'ping', policyAction: null },
      ],
    ]);
    expect(c.groups).toBe(3);
    expect(c.identicalPolicyAction).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(c.identicalVerdict).toEqual({ num: 1, den: 3, value: 1 / 3 });
    expect(c.identicalAction).toEqual({ num: 2, den: 3, value: 2 / 3 });
  });

  it('is null with no repeated runs', () => {
    expect(consistency([]).identicalVerdict.value).toBeNull();
  });
});

describe('quantile and run stats', () => {
  it('interpolates linearly', () => {
    expect(quantile([], 0.5)).toBeNull();
    expect(quantile([5], 0.9)).toBe(5);
    expect(quantile([3, 1, 2], 0.5)).toBe(2);
    expect(quantile([1, 2, 3, 4], 0.5)).toBe(2.5);
    expect(quantile([0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 0.9)).toBe(90);
  });

  it('summarizes triage runs, skipping missing values', () => {
    const s = triageRunStats([
      { status: 'ok', durationMs: 1000, costUsd: 0.5, numTurns: 4 },
      { status: 'ok', durationMs: 3000, costUsd: 1.5, numTurns: 6 },
      { status: 'failed', durationMs: 2000, costUsd: null, numTurns: null },
    ]);
    expect(s.runs).toBe(3);
    expect(s.okRate).toEqual({ num: 2, den: 3, value: 2 / 3 });
    expect(s.durationMs.median).toBe(2000);
    expect(s.costUsd.total).toBe(2);
    expect(s.costUsd.median).toBe(1);
    expect(s.medianTurns).toBe(5);
    expect(triageRunStats([]).okRate.value).toBeNull();
  });

  it('keeps cancelled runs out of the ok rate and the time quantiles, but in runs and total cost', () => {
    const s = triageRunStats([
      { status: 'ok', durationMs: 10_000, costUsd: 1, numTurns: 4 },
      { status: 'timeout', durationMs: 600_000, costUsd: 2, numTurns: 9 },
      { status: 'cancelled', durationMs: 50, costUsd: 0.25, numTurns: 1 },
      { status: 'cancelled', durationMs: null, costUsd: null, numTurns: null },
    ]);
    expect(s.runs).toBe(4);
    expect(s.cancelled).toBe(2);
    expect(s.okRate).toEqual({ num: 1, den: 2, value: 0.5 });
    expect(s.durationMs.median).toBe(305_000);
    expect(s.costUsd.median).toBe(1.5);
    expect(s.costUsd.total).toBe(3.25);
    expect(s.medianTurns).toBe(6.5);
    expect(triageRunStats([{ status: 'cancelled', durationMs: 5, costUsd: null, numTurns: null }]).okRate.value).toBeNull();
  });
});

describe('labelerAgreement', () => {
  it('computes raw agreement and kappa', () => {
    const a = labelerAgreement([
      { a: 'ping', b: 'ping' },
      { a: 'log', b: 'log' },
      { a: 'digest', b: 'log' },
      { a: 'log', b: 'log' },
    ]);
    expect(a.n).toBe(4);
    expect(a.agree.value).toBe(0.75);
    // po = .75; pe = (1/4*1/4) + (1/4*0) + (2/4*3/4) = .4375; kappa = .3125/.5625
    expect(a.kappa).toBeCloseTo(0.5556, 3);
  });

  it('is undefined when empty or when both always pick the same class', () => {
    expect(labelerAgreement([]).kappa).toBeNull();
    expect(labelerAgreement([{ a: 'log', b: 'log' }]).kappa).toBeNull();
  });
});

describe('messageVolume', () => {
  it('counts one message per package and action', () => {
    const v = messageVolume([
      { projectId: 'web', packageName: 'next', action: 'ping' },
      { projectId: 'web', packageName: 'next', action: 'ping' },
      { projectId: 'web', packageName: 'zod', action: 'ping' },
      { projectId: 'web', packageName: 'next', action: 'digest' },
      { projectId: 'web', packageName: 'sharp', action: 'log' },
      { projectId: 'api', packageName: 'express', action: null },
    ]);
    expect(v).toEqual([
      { projectId: 'api', pingMessages: 0, pingFindings: 0, digestMessages: 0, digestFindings: 0, logFindings: 0 },
      { projectId: 'web', pingMessages: 2, pingFindings: 3, digestMessages: 1, digestFindings: 1, logFindings: 1 },
    ]);
  });
});

describe('version compare', () => {
  it('compares dot segments numerically', () => {
    expect(compareVersions('1.10.0', '1.9.9')).toBe(1);
    expect(compareVersions('16.2.13', '16.2.9')).toBe(1);
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('v2.0.0', '1.99.99')).toBe(1);
    expect(compareVersions('1.0.0', '1.0.1')).toBe(-1);
  });

  it('orders pre-releases below the release', () => {
    expect(compareVersions('2.0.0-rc.1', '2.0.0')).toBe(-1);
    expect(compareVersions('2.0.0-rc.2', '2.0.0-rc.10')).toBe(-1);
    expect(compareVersions('2.0.0-alpha', '2.0.0-alpha.1')).toBe(-1);
    expect(compareVersions('1.0.0+build.5', '1.0.0')).toBe(0);
  });

  it('finds the highest fixed version for "upgrade to"', () => {
    expect(highestVersion(['15.3.3', '14.2.30', '15.10.0', '15.4.0'])).toBe('15.10.0');
    expect(highestVersion(['4.17.21'])).toBe('4.17.21');
    expect(highestVersion([])).toBeNull();
    expect(highestVersion([''])).toBeNull();
  });

  it('picks the fix on the installed release line, not the highest one OSV lists', () => {
    // Real storybook advisory: one fix per line, plus an alpha of the next major.
    const storybook = ['8.6.19', '9.1.21', '10.6.2', '11.0.0-alpha.6'];
    expect(upgradeTarget(['10.5.5'], storybook)).toBe('10.6.2');
    expect(upgradeTarget(['9.0.0'], storybook)).toBe('9.1.21');
    expect(upgradeTarget(['11.0.0-alpha.3'], storybook)).toBe('11.0.0-alpha.6'); // only a pre-release is ahead
    expect(upgradeTarget(['15.2.0'], ['15.5.28', '16.4.1'])).toBe('15.5.28'); // no major bump for next 15.x
    // several installed versions: the target must be above all of them
    expect(upgradeTarget(['3.10.1', '4.17.20'], ['3.10.2', '4.17.21'])).toBe('4.17.21');
    // nothing above the installed version (odd data): fall back to the highest fix
    expect(upgradeTarget(['5.0.0'], ['4.1.0', '4.2.0'])).toBe('4.2.0');
    expect(upgradeTarget([], ['1.0.1', '2.0.1'])).toBe('2.0.1');
    expect(upgradeTarget(['1.0.0'], [])).toBeNull();
    expect(upgradeTarget(['1.0.0'], ['abcdef0123456789abcdef0123456789abcdef01'])).toBeNull();
  });

  it('ignores commit SHAs from GIT ranges, which are no upgrade target', () => {
    expect(isReleaseVersion('16.2.13')).toBe(true);
    expect(isReleaseVersion('v2.0.0-rc.1')).toBe(true);
    expect(isReleaseVersion('2.0.0a1')).toBe(true);
    expect(isReleaseVersion('7')).toBe(true);
    expect(isReleaseVersion('1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b')).toBe(false);
    expect(isReleaseVersion('deadbeef')).toBe(false);
    expect(highestVersion(['1.2.3', 'f00dbabe1234567890abcdef1234567890abcdef', '1.10.0'])).toBe('1.10.0');
    expect(highestVersion(['0123456789abcdef0123456789abcdef01234567'])).toBeNull();
  });
});
