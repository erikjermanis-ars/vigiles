'use client';

/**
 * Behaviour of the reveal shown after answering: brings it into view (it sits at the top of the page, and the
 * owner answered further down) and makes Enter or n go to the next case. Mount it with a `key` that changes
 * with the answer so a changed answer scrolls up again.
 */
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { keyInputFromEvent } from '@/components/finding/review-keys';
import { decideKeyCommand } from './decide-keys';

export function RevealKeys({ nextHref }: { nextHref: string }) {
  const router = useRouter();

  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, []);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (decideKeyCommand(keyInputFromEvent(e), 'reveal')?.kind !== 'next') return;
      e.preventDefault();
      router.push(nextHref);
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [nextHref, router]);

  return null;
}
