/**
 * "Your call" in the top nav, with a small badge counting the open owner cases. The layout renders it on
 * every page, so it never throws: when the count cannot be read the badge is simply left out.
 */
import Link from 'next/link';
import { getDb } from '@/lib/db/client';
import { countOpenOwnerCases } from '@/lib/queries/owner-cases';

const asCount = (n: unknown): number => (typeof n === 'number' && Number.isInteger(n) && n > 0 ? n : 0);

/** Open owner cases, or 0 when the database cannot be read. */
export function openCaseCount(load: () => number = () => countOpenOwnerCases(getDb())): number {
  try {
    return asCount(load());
  } catch (err) {
    console.error('DecideNavLink: could not count open owner cases:', err);
    return 0;
  }
}

export function DecideNavLink({ count }: { count?: number }) {
  const open = count === undefined ? openCaseCount() : asCount(count);
  return (
    <Link
      href="/decide"
      aria-label={open ? `Your call (${open} open)` : undefined}
      className="group inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm whitespace-nowrap no-underline hover:bg-panel-2"
    >
      {/* The colour sits on a span: globals.css colours <a> outside Tailwind's layers, which beats utilities on the <a>. */}
      <span className="text-muted group-hover:text-text">Your call</span>
      {open ? (
        <span className="inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-accent px-1.5 text-[11px] leading-none font-semibold text-bg tabular-nums">
          {open > 99 ? '99+' : open}
        </span>
      ) : null}
    </Link>
  );
}
