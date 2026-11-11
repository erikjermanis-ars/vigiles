import type { ReactNode } from 'react';
import { cx } from '@/components/ui';
import { floorPct, type Ratio } from '@/lib/eval/metrics';

/** "75% (6/8)", green when it meets `target`, red when it misses it, muted when undefined (0/0). */
export function RatioValue({ ratio, target, digits = 0 }: { ratio: Ratio; target?: number; digits?: number }) {
  if (ratio.value === null) {
    return (
      <span className="text-muted" title="no data (0/0)">
        — <span className="text-xs">(0/0)</span>
      </span>
    );
  }
  const tone = target === undefined ? undefined : ratio.value >= target ? 'text-ok' : 'text-ping';
  return (
    <span className={cx('tabular-nums', tone)}>
      {floorPct(ratio.value, digits)}{' '}
      <span className="text-xs text-muted">
        ({ratio.num}/{ratio.den})
      </span>
    </span>
  );
}

export function Target({ children }: { children: ReactNode }) {
  return <span className="ml-1 text-xs font-normal text-muted normal-case">target {children}</span>;
}
