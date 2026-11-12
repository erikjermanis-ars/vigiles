import type { Metadata } from 'next';
import Link from 'next/link';
import { unstable_rethrow } from 'next/navigation';
import { Suspense, type ReactNode } from 'react';
import { cookieProjectScope } from '@/app/projects/scope';
import { DecideNavLink } from '@/components/decide/nav-link';
import { ProjectSwitcher, ProjectSwitcherFallback, type SwitcherProject } from '@/components/project-switcher';
import { colorFor, projectColors, type ScopeProject } from '@/lib/project-scope';
import './globals.css';

// Every page reads live SQLite data; never prerender.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Vigiles',
  description: 'Vulnerability triage POC',
};

type NavItem = { href: string; label: string };
// "Your call" (the owner-case page) sits between Review and Eval.
const NAV_BEFORE_DECIDE: NavItem[] = [
  { href: '/', label: 'Inbox' },
  { href: '/findings', label: 'Findings' },
  { href: '/review', label: 'Review' },
];
const NAV_AFTER_DECIDE: NavItem[] = [
  { href: '/eval', label: 'Eval' },
  { href: '/projects', label: 'Projects' },
  { href: '/jobs', label: 'Jobs' },
];

function NavLinks({ items }: { items: NavItem[] }) {
  // The colour sits on a span, as in <DecideNavLink />: globals.css colours <a> outside Tailwind's layers, which
  // beats a text-* utility on the <a> itself (the links would all be accent blue, unlike "Your call").
  return items.map((n) => (
    <Link key={n.href} href={n.href} className="group rounded-md px-2.5 py-1.5 text-sm whitespace-nowrap no-underline hover:bg-panel-2">
      <span className="text-muted group-hover:text-text">{n.label}</span>
    </Link>
  ));
}

/** The header's scope; when the database cannot be read the switcher is left out, so the nav still renders. */
async function headerScope(): Promise<{ projects: ScopeProject[]; ids: string[] | null }> {
  try {
    return await cookieProjectScope();
  } catch (err) {
    unstable_rethrow(err); // Next's own control-flow errors (e.g. from cookies()) are not ours to swallow
    console.error('RootLayout: could not read the project scope:', err);
    return { projects: [], ids: null };
  }
}

export default async function RootLayout({ children }: { children: ReactNode }) {
  const scope = await headerScope();
  const colors = projectColors(scope.projects.map((p) => p.id));
  const switcherProjects: SwitcherProject[] = scope.projects.map((p) => ({ ...p, color: colorFor(colors, p.id) }));
  return (
    <html lang="en">
      <body>
        <header className="sticky top-0 z-10 border-b border-border bg-panel/95 backdrop-blur">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-1.5 px-4 py-2">
            <nav className="flex min-w-0 items-center gap-1 overflow-x-auto">
              <Link href="/" className="mr-4 font-semibold tracking-tight no-underline">
                <span className="text-text">Vigiles</span>
              </Link>
              <NavLinks items={NAV_BEFORE_DECIDE} />
              <DecideNavLink />
              <NavLinks items={NAV_AFTER_DECIDE} />
            </nav>
            {switcherProjects.length ? (
              <div className="ml-auto max-w-full min-w-0">
                <Suspense fallback={<ProjectSwitcherFallback projects={switcherProjects} cookieIds={scope.ids} />}>
                  <ProjectSwitcher projects={switcherProjects} cookieIds={scope.ids} />
                </Suspense>
              </div>
            ) : null}
          </div>
        </header>
        {/* template.tsx renders the staleness banner + <main>; templates re-render on navigation */}
        {children}
      </body>
    </html>
  );
}
