/** 3×3 confusion matrix: rows are your label, columns the decider's action. Non-empty cells link to their findings. */
import Link from 'next/link';
import { ActionBadge, cx } from '@/components/ui';
import type { ConfusionMatrix as Matrix } from '@/lib/eval/metrics';
import { ACTIONS, type Action } from '@/lib/types';

function cellClass(label: Action, decided: Action, n: number): string {
  if (n === 0) return 'text-muted';
  if (label === decided) return 'bg-ok-bg text-ok';
  // A missed ping is the costly error (recall target 100%); a false ping costs precision.
  if (label === 'ping' || decided === 'ping') return 'bg-ping-bg text-ping';
  return 'bg-digest-bg text-digest';
}

export function ConfusionMatrix({
  title,
  matrix,
  cellHref,
  selected,
}: {
  title: string;
  matrix: Matrix;
  cellHref: (label: Action, decided: Action) => string;
  selected?: { label: Action; decided: Action } | null;
}) {
  return (
    <div>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr>
            <th className="px-2 py-1 text-left text-xs font-normal text-muted">label ↓ · decided →</th>
            {ACTIONS.map((a) => (
              <th key={a} className="px-2 py-1 text-center">
                <ActionBadge action={a} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ACTIONS.map((label) => (
            <tr key={label}>
              <th className="px-2 py-1 text-left">
                <ActionBadge action={label} />
              </th>
              {ACTIONS.map((decided) => {
                const n = matrix[label][decided];
                const isSelected = selected?.label === label && selected.decided === decided;
                return (
                  <td
                    key={decided}
                    className={cx(
                      'border border-border px-2 py-1.5 text-center tabular-nums',
                      cellClass(label, decided, n),
                      isSelected && 'outline-2 outline-accent',
                    )}
                  >
                    {n > 0 ? (
                      <Link href={cellHref(label, decided)} className="block font-medium text-inherit no-underline hover:underline">
                        {n}
                      </Link>
                    ) : (
                      '0'
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
