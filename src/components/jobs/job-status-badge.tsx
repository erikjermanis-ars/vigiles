import { Badge } from '@/components/ui';
import type { JobStatus } from '@/lib/types';

const tone = {
  queued: 'neutral',
  running: 'accent',
  succeeded: 'ok',
  failed: 'ping',
  cancelled: 'log',
} as const satisfies Record<JobStatus, 'neutral' | 'accent' | 'ok' | 'ping' | 'log'>;

export function JobStatusBadge({ status, cancelRequested }: { status: JobStatus; cancelRequested?: boolean }) {
  return <Badge tone={tone[status]}>{status === 'running' && cancelRequested ? 'cancelling' : status}</Badge>;
}
