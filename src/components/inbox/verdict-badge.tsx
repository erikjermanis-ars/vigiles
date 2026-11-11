import { Badge } from '@/components/ui';
import type { Confidence, Verdict } from '@/lib/types';

const verdictTone = {
  affected: 'ping',
  likely_affected: 'digest',
  likely_not_affected: 'ok',
  not_affected: 'ok',
} as const satisfies Record<Verdict, 'ping' | 'digest' | 'ok'>;

/** "likely_affected · medium", or "no verdict" when the finding has no usable triage output. */
export function VerdictBadge({ verdict, confidence }: { verdict: Verdict | null; confidence?: Confidence | null }) {
  if (!verdict) return <Badge>no verdict</Badge>;
  return (
    <Badge tone={verdictTone[verdict]} title="LLM verdict · confidence">
      {verdict.replaceAll('_', ' ')}
      {confidence ? ` · ${confidence}` : ''}
    </Badge>
  );
}
