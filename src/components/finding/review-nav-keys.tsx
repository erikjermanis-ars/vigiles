'use client';

/** Keyboard navigation for the Review page after a label is saved: j / Enter = next, k = previous. */
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { keyInputFromEvent, reviewKeyCommand } from './review-keys';

export function ReviewNavKeys({ nextHref, prevHref }: { nextHref: string; prevHref: string | null }) {
  const router = useRouter();
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const cmd = reviewKeyCommand(keyInputFromEvent(e));
      if (cmd?.kind === 'next' || cmd?.kind === 'save') {
        e.preventDefault();
        router.push(nextHref);
      } else if (cmd?.kind === 'prev' && prevHref) {
        e.preventDefault();
        router.push(prevHref);
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [nextHref, prevHref, router]);
  return null;
}
