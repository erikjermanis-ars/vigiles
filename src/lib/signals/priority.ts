/**
 * Base priority (spec §8). Computed before any LLM step and never changed by it.
 * Pure: thresholds come from config/policy.yaml, exposure/criticality from the project profile.
 *
 *   P0  malicious package, or in KEV and (internet-facing or criticality high)
 *   P1  in KEV, or EPSS ≥ epss_high, or CVSS ≥ cvss_critical on an internet-facing asset
 *   P2  CVSS ≥ cvss_high, or EPSS ≥ epss_medium
 *   P3  everything else
 */
import type { Policy } from '../config/schema';
import { PRIORITIES, type Criticality, type Exposure, type Priority } from '../types';

export type PriorityThresholds = Policy['thresholds'];

export interface BasePriorityInput {
  osvId: string;
  malicious: boolean;
  inKev: boolean;
  kevDateAdded: string | null;
  epss: number | null;
  cvss: number | null;
  exposure: Exposure;
  criticality: Criticality;
}

export interface BasePriority {
  priority: Priority;
  /** Every signal that put the finding in this tier, e.g. ['in CISA KEV since 2026-01-02', 'EPSS 0.62 ≥ 0.5'] */
  reasons: string[];
}

/** 0 for P0 … 3 for P3: lower is more urgent. */
export function priorityRank(p: Priority): number {
  return PRIORITIES.indexOf(p);
}

const atLeast = (value: number | null, threshold: number): value is number => value !== null && value >= threshold;

/**
 * Shortest rendering of `value` that stays on the same side of every threshold in `marks` and never
 * rounds across an integer. Checking all of a metric's thresholds matters: 0.4999 must not read
 * "EPSS 0.5 ≥ 0.1" (it would look like it should have been P1), nor 0.99999 read "EPSS 1".
 */
export function formatAgainst(value: number, marks: number | readonly number[]): string {
  const thresholds = typeof marks === 'number' ? [marks] : marks;
  for (let digits = 2; digits <= 6; digits++) {
    const rounded = Number(value.toPrecision(digits));
    const sameSide = thresholds.every((m) => rounded >= m === value >= m);
    if (sameSide && Math.trunc(rounded) === Math.trunc(value)) return String(rounded);
  }
  return String(value);
}

/** Both EPSS thresholds, so a rendered score never appears to sit on the other side of either. */
export const epssMarks = (t: PriorityThresholds) => [t.epss_high, t.epss_medium];
const cvssMarks = (t: PriorityThresholds) => [t.cvss_critical, t.cvss_high];

const kevReason = (dateAdded: string | null) => (dateAdded ? `in CISA KEV since ${dateAdded.slice(0, 10)}` : 'in CISA KEV');
const geReason = (label: string, value: number, threshold: number, marks: number[]) => `${label} ${formatAgainst(value, marks)} ≥ ${threshold}`;
const ltReason = (label: string, value: number, threshold: number, marks: number[]) => `${label} ${formatAgainst(value, marks)} < ${threshold}`;

export function computeBasePriority(input: BasePriorityInput, t: PriorityThresholds): BasePriority {
  const { epss, cvss } = input;
  const internetFacing = input.exposure === 'internet-facing';
  const highCriticality = input.criticality === 'high';
  const em = epssMarks(t);
  const cm = cvssMarks(t);

  if (input.malicious) {
    const reasons = [`malicious package (${input.osvId})`];
    if (input.inKev) reasons.push(kevReason(input.kevDateAdded));
    return { priority: 'P0', reasons };
  }

  if (input.inKev && (internetFacing || highCriticality)) {
    const reasons = [kevReason(input.kevDateAdded)];
    if (internetFacing) reasons.push('asset internet-facing');
    if (highCriticality) reasons.push('criticality high');
    return { priority: 'P0', reasons };
  }

  const p1: string[] = [];
  if (input.inKev) p1.push(kevReason(input.kevDateAdded));
  if (atLeast(epss, t.epss_high)) p1.push(geReason('EPSS', epss, t.epss_high, em));
  if (internetFacing && atLeast(cvss, t.cvss_critical)) p1.push(`${geReason('CVSS', cvss, t.cvss_critical, cm)} on internet-facing asset`);
  if (p1.length) return { priority: 'P1', reasons: p1 };

  const p2: string[] = [];
  if (atLeast(cvss, t.cvss_high)) p2.push(geReason('CVSS', cvss, t.cvss_high, cm));
  if (atLeast(epss, t.epss_medium)) p2.push(geReason('EPSS', epss, t.epss_medium, em));
  if (p2.length) return { priority: 'P2', reasons: p2 };

  return { priority: 'P3', reasons: p3Reasons(cvss, epss, t) };
}

function p3Reasons(cvss: number | null, epss: number | null, t: PriorityThresholds): string[] {
  if (cvss === null && epss === null) return ['no CVSS/EPSS signal'];
  return [
    cvss === null ? 'no CVSS score' : ltReason('CVSS', cvss, t.cvss_high, cvssMarks(t)),
    epss === null ? 'no EPSS score' : ltReason('EPSS', epss, t.epss_medium, epssMarks(t)),
  ];
}
