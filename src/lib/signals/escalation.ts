/**
 * Upward moves between two enrichments (spec §4.3: change detection comes from comparing
 * stored KEV/EPSS values with fresh ones). Downward moves are never events.
 */
import type { Priority } from '../types';
import { epssMarks, formatAgainst, priorityRank, type PriorityThresholds } from './priority';

export interface SignalSnapshot {
  priority: Priority | null;
  inKev: boolean;
  epss: number | null;
}

/** Threshold crossed upward: was below (or unknown), is now at or above. */
function crossedUp(before: number | null, after: number | null, threshold: number): after is number {
  return after !== null && after >= threshold && (before === null || before < threshold);
}

/** Human triggers for an escalation; empty when nothing moved up. */
export function detectEscalation(from: SignalSnapshot, to: SignalSnapshot, t: PriorityThresholds): string[] {
  const triggers: string[] = [];
  if (from.priority && to.priority && priorityRank(to.priority) < priorityRank(from.priority)) {
    triggers.push(`priority ${from.priority} → ${to.priority}`);
  }
  if (!from.inKev && to.inKev) triggers.push('added to CISA KEV');

  // Report only the highest threshold crossed, so one jump from 0.05 to 0.7 reads as one trigger.
  const crossed = [t.epss_high, t.epss_medium].find((threshold) => crossedUp(from.epss, to.epss, threshold));
  if (crossed !== undefined && to.epss !== null) {
    const marks = epssMarks(t);
    const before = from.epss === null ? 'none' : formatAgainst(from.epss, marks);
    triggers.push(`EPSS crossed ${crossed} (${before} → ${formatAgainst(to.epss, marks)})`);
  }
  return triggers;
}
