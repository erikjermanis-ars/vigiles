'use client';

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

/** Calls router.refresh() every `intervalMs` while `active` (e.g. while a job is running). */
export function AutoRefresh({ active, intervalMs = 2000 }: { active: boolean; intervalMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => router.refresh(), intervalMs);
    return () => clearInterval(t);
  }, [active, intervalMs, router]);
  return null;
}
