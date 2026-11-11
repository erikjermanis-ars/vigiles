import { describe, expect, it } from 'vitest';
import { detectEscalation, type SignalSnapshot } from './escalation';
import { THRESHOLDS } from './test-support';

const snap = (over: Partial<SignalSnapshot> = {}): SignalSnapshot => ({ priority: 'P3', inKev: false, epss: null, ...over });
const detect = (from: Partial<SignalSnapshot>, to: Partial<SignalSnapshot>) => detectEscalation(snap(from), snap(to), THRESHOLDS);

describe('detectEscalation', () => {
  it('reports a priority that rose', () => {
    expect(detect({ priority: 'P3' }, { priority: 'P2' })).toEqual(['priority P3 → P2']);
    expect(detect({ priority: 'P1' }, { priority: 'P0' })).toEqual(['priority P1 → P0']);
  });

  it('ignores unchanged or lowered priority', () => {
    expect(detect({ priority: 'P2' }, { priority: 'P2' })).toEqual([]);
    expect(detect({ priority: 'P1' }, { priority: 'P3' })).toEqual([]);
  });

  it('ignores a missing previous priority', () => {
    expect(detect({ priority: null }, { priority: 'P0' })).toEqual([]);
  });

  it('reports KEV false → true only', () => {
    expect(detect({ inKev: false }, { inKev: true })).toEqual(['added to CISA KEV']);
    expect(detect({ inKev: true }, { inKev: true })).toEqual([]);
    expect(detect({ inKev: true }, { inKev: false })).toEqual([]);
  });

  it('reports EPSS crossing epss_medium, including landing exactly on it', () => {
    expect(detect({ epss: 0.05 }, { epss: 0.1 })).toEqual(['EPSS crossed 0.1 (0.05 → 0.1)']);
    expect(detect({ epss: 0.0999 }, { epss: 0.2 })).toEqual(['EPSS crossed 0.1 (0.0999 → 0.2)']);
  });

  it('never renders a value as if it sat on the other side of epss_high', () => {
    expect(detect({ epss: 0.05 }, { epss: 0.4999 })).toEqual(['EPSS crossed 0.1 (0.05 → 0.4999)']);
  });

  it('reports EPSS crossing epss_high once, even when it also crossed epss_medium', () => {
    expect(detect({ epss: 0.05 }, { epss: 0.7 })).toEqual(['EPSS crossed 0.5 (0.05 → 0.7)']);
    expect(detect({ epss: 0.4999 }, { epss: 0.5 })).toEqual(['EPSS crossed 0.5 (0.4999 → 0.5)']);
  });

  it('treats a previously unknown EPSS as below every threshold', () => {
    expect(detect({ epss: null }, { epss: 0.2 })).toEqual(['EPSS crossed 0.1 (none → 0.2)']);
    expect(detect({ epss: null }, { epss: 0.05 })).toEqual([]);
  });

  it('ignores EPSS moves that cross nothing upward', () => {
    expect(detect({ epss: 0.2 }, { epss: 0.3 })).toEqual([]);
    expect(detect({ epss: 0.5 }, { epss: 0.9 })).toEqual([]);
    expect(detect({ epss: 0.6 }, { epss: 0.4 })).toEqual([]);
    expect(detect({ epss: 0.2 }, { epss: null })).toEqual([]);
  });

  it('lists every trigger together', () => {
    expect(detect({ priority: 'P2', inKev: false, epss: 0.05 }, { priority: 'P0', inKev: true, epss: 0.6 })).toEqual([
      'priority P2 → P0',
      'added to CISA KEV',
      'EPSS crossed 0.5 (0.05 → 0.6)',
    ]);
  });
});
