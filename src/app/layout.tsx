import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactNode } from 'react';
import './globals.css';

// Every page reads live SQLite data; never prerender.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Vigiles',
  description: 'Vulnerability triage POC',
};

const NAV = [
  { href: '/', label: 'Inbox' },
  { href: '/findings', label: 'Findings' },
  { href: '/review', label: 'Review' },
  { href: '/eval', label: 'Eval' },
  { href: '/projects', label: 'Projects' },
  { href: '/jobs', label: 'Jobs' },
];

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="sticky top-0 z-10 border-b border-border bg-panel/95 backdrop-blur">
          <nav className="mx-auto flex max-w-7xl items-center gap-1 overflow-x-auto px-4 py-2">
            <Link href="/" className="mr-4 font-semibold tracking-tight text-text no-underline">
              Vigiles
            </Link>
            {NAV.map((n) => (
              <Link key={n.href} href={n.href} className="rounded-md px-2.5 py-1.5 text-sm text-muted no-underline hover:bg-panel-2 hover:text-text">
                {n.label}
              </Link>
            ))}
          </nav>
        </header>
        {/* template.tsx renders the staleness banner + <main>; templates re-render on navigation */}
        {children}
      </body>
    </html>
  );
}
