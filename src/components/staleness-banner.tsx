/**
 * Banner on every page when the OSV data or the last Refresh all is stale (spec §4.4).
 * Rendered by the root layout, so it must never throw: config or DB errors become a small error banner.
 */
import Link from 'next/link';
import type { ReactNode } from 'react';
import { loadVigilesConfig } from '@/lib/config/load';
import { getDb } from '@/lib/db/client';
import { getStalenessWarnings } from '@/lib/queries/jobs';

function Banner({ tone, children }: { tone: 'warn' | 'error'; children: ReactNode }) {
  const toneClass = tone === 'warn' ? 'bg-digest-bg text-digest' : 'bg-ping-bg text-ping';
  return (
    <div role="status" className={`border-b border-border ${toneClass}`}>
      <div className="mx-auto max-w-7xl px-4 py-2 text-sm">{children}</div>
    </div>
  );
}

export function StalenessBanner() {
  let warnings: string[];
  try {
    warnings = getStalenessWarnings(getDb(), loadVigilesConfig());
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const [first, ...rest] = message.split('\n');
    return (
      <Banner tone="error">
        <span className="font-medium">Could not check data freshness:</span> {first}
        {rest.length ? (
          <details className="mt-1">
            <summary className="cursor-pointer text-xs">details</summary>
            <pre className="mt-1 text-xs whitespace-pre-wrap">{rest.join('\n')}</pre>
          </details>
        ) : null}
      </Banner>
    );
  }
  if (!warnings.length) return null;
  return (
    <Banner tone="warn">
      <span className="font-medium">Data may be stale.</span> {warnings.join(' ')}{' '}
      <Link href="/jobs" className="font-medium text-inherit underline">
        Go to Jobs → Refresh all
      </Link>
    </Banner>
  );
}
