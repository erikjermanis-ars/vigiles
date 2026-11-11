/** Badges for finding facts. Server-component safe. */
import type { ComponentProps } from 'react';
import { Badge } from '@/components/ui';
import type { Agreement } from '@/lib/queries/review';
import type {
  Confidence,
  FindingOrigin,
  FindingStatus,
  RuntimeUsage,
  Tristate,
  TriageRunStatus,
  TriageStatus,
  Verdict,
} from '@/lib/types';
import { humanize } from './helpers';

type Tone = ComponentProps<typeof Badge>['tone'];

const verdictTone: Record<Verdict, Tone> = {
  affected: 'ping',
  likely_affected: 'digest',
  likely_not_affected: 'neutral',
  not_affected: 'ok',
};

export function VerdictBadge({ verdict, confidence }: { verdict: Verdict | null | undefined; confidence?: Confidence | null }) {
  if (!verdict) return <Badge>no verdict</Badge>;
  return (
    <Badge tone={verdictTone[verdict]} title={confidence ? `confidence: ${confidence}` : undefined}>
      {humanize(verdict)}
      {confidence ? <span className="ml-1 font-normal opacity-75">· {confidence}</span> : null}
    </Badge>
  );
}

/** For the three yes/no/unknown sub-answers, where "yes" always means more risk. */
export function TristateBadge({ value }: { value: Tristate | null | undefined }) {
  if (!value) return <Badge>—</Badge>;
  return <Badge tone={value === 'yes' ? 'ping' : value === 'no' ? 'ok' : 'neutral'}>{value}</Badge>;
}

export function RuntimeUsageBadge({ value }: { value: RuntimeUsage | null | undefined }) {
  if (!value) return <Badge>—</Badge>;
  const tone: Tone = value === 'unknown' ? 'neutral' : value === 'build_or_tooling_only' || value === 'not_used' ? 'ok' : 'digest';
  return <Badge tone={tone}>{humanize(value)}</Badge>;
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  return <Badge tone={status === 'open' ? 'accent' : status === 'fixed' ? 'ok' : 'neutral'}>{humanize(status)}</Badge>;
}

export function OriginBadge({ origin }: { origin: FindingOrigin }) {
  return <Badge tone={origin === 'baseline' ? 'neutral' : 'accent'}>{humanize(origin)}</Badge>;
}

export function RunStatusBadge({ status }: { status: TriageRunStatus }) {
  return <Badge tone={status === 'ok' ? 'ok' : status === 'cancelled' ? 'neutral' : 'ping'}>{status}</Badge>;
}

export function TriageStateBadge({ status }: { status: TriageStatus }) {
  const tone: Tone = status === 'ok' ? 'ok' : status === 'failed' ? 'ping' : status === 'pending' ? 'digest' : 'neutral';
  return <Badge tone={tone}>{status}</Badge>;
}

export function AgreementBadge({ value }: { value: Agreement }) {
  if (value === 'n/a') return <Badge>n/a</Badge>;
  return <Badge tone={value === 'agree' ? 'ok' : 'ping'}>{value === 'agree' ? 'agrees' : 'disagrees'}</Badge>;
}

/** direct/transitive, dev-only, KEV and malicious markers for a finding row. */
export function DependencyBadges({
  direct,
  devOnly,
  inKev,
  malicious,
}: {
  direct: boolean | null;
  devOnly: boolean;
  inKev: boolean;
  malicious?: boolean;
}) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {malicious ? <Badge tone="ping">malicious</Badge> : null}
      {inKev ? (
        <Badge tone="ping" title="In the CISA Known Exploited Vulnerabilities catalog">
          KEV
        </Badge>
      ) : null}
      <Badge title={direct === null ? 'Not known for this ecosystem' : undefined}>
        {direct === null ? 'direct?' : direct ? 'direct' : 'transitive'}
      </Badge>
      {devOnly ? <Badge tone="log">dev</Badge> : null}
    </span>
  );
}

/** The finding's project has `enabled: false`: scans and triage skip it, so its facts are from the last scan. */
export function ProjectDisabledBadge() {
  return <Badge title="enabled: false in its projects/*.yaml: scan and triage skip it, and Review leaves it out">project disabled</Badge>;
}
