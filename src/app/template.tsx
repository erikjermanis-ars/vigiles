import type { ReactNode } from 'react';
import { StalenessBanner } from '@/components/staleness-banner';

/** Re-rendered on every navigation (unlike layout.tsx), so the staleness banner stays current. */
export default function Template({ children }: { children: ReactNode }) {
  return (
    <>
      <StalenessBanner />
      <main className="mx-auto max-w-7xl px-4 py-6">{children}</main>
    </>
  );
}
