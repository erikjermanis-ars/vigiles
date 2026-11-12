'use client';

/**
 * The header's project switcher: "All projects" plus one button per project (disabled projects greyed). The
 * highlighted button is what the page shows: a `?project=` override in the URL when there is one, else the
 * cookie the server read. Clicking one stores it in the `vigiles_project` cookie (a server action) and reloads
 * the same page in the new scope. Works without JavaScript too: it is a plain form of submit buttons. On pages
 * the scope does not filter (Projects, Jobs, a finding's page) it is dimmed and labelled "Filter for lists".
 */
import { usePathname, useSearchParams } from 'next/navigation';
import type { ReactNode } from 'react';
import { useFormStatus } from 'react-dom';
import { setProjectScopeAction } from '@/app/projects/actions';
import { cx } from '@/components/ui';
import { ALL_PROJECTS, isScopedPath, resolveProjectScope, type ProjectColor } from '@/lib/project-scope';

export interface SwitcherProject {
  id: string;
  name: string;
  enabled: boolean;
  color: ProjectColor;
}

interface SwitcherProps {
  projects: SwitcherProject[];
  /** The scope from the cookie (null = every project), as the server resolved it */
  cookieIds: string[] | null;
}

function Option({
  value,
  active,
  title,
  className,
  children,
}: {
  value: string;
  active: boolean;
  title?: string;
  className?: string;
  children: ReactNode;
}) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      name="project"
      value={value}
      aria-pressed={active}
      title={title}
      disabled={pending}
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium whitespace-nowrap transition-colors disabled:cursor-wait',
        className,
      )}
    >
      {children}
    </button>
  );
}

const NOT_HERE = 'This page always shows every project. The filter applies to Inbox, Findings, Review and Eval.';

function SwitcherView({
  projects,
  activeIds,
  returnTo,
  applies,
}: {
  projects: SwitcherProject[];
  activeIds: string[] | null;
  returnTo: string;
  /** False on pages that ignore the scope (Projects, Jobs, a finding): the switcher is dimmed and says so */
  applies: boolean;
}) {
  const isActive = (id: string) => activeIds !== null && activeIds.includes(id);
  return (
    <form
      action={setProjectScopeAction}
      className={cx('flex max-w-full min-w-0 items-center gap-2', !applies && 'opacity-60 transition-opacity hover:opacity-100')}
      aria-label="Project scope"
      title={applies ? undefined : NOT_HERE}
    >
      <input type="hidden" name="returnTo" value={returnTo} />
      <span className="hidden text-xs text-muted sm:inline">{applies ? 'Showing' : 'Filter for lists'}</span>
      {/* One row that scrolls sideways on a narrow screen, so the pill shape never breaks. */}
      <div role="group" className="flex max-w-full min-w-0 items-center gap-0.5 overflow-x-auto rounded-full border border-border bg-panel-2 p-0.5">
        <Option
          value={ALL_PROJECTS}
          active={activeIds === null}
          className={activeIds === null ? 'bg-text text-panel' : 'text-muted hover:bg-panel hover:text-text'}
        >
          All projects
        </Option>
        {projects.map((p) => {
          const active = isActive(p.id);
          return (
            <Option
              key={p.id}
              value={p.id}
              active={active}
              title={p.enabled ? `Show only ${p.name}` : `${p.name} is disabled in projects/${p.id}.yaml: not scanned or triaged`}
              className={cx(active ? p.color.solid : 'text-muted hover:bg-panel hover:text-text', !p.enabled && !active && 'opacity-50')}
            >
              <span aria-hidden className={cx('inline-block size-2 shrink-0 rounded-full', active ? 'bg-white/80' : p.color.dot)} />
              {p.name}
              {p.enabled ? null : <span className="font-normal">(off)</span>}
            </Option>
          );
        })}
      </div>
    </form>
  );
}

/** Reads `?project=` from the URL; wrap it in <Suspense> with <ProjectSwitcherFallback> as the fallback. */
export function ProjectSwitcher({ projects, cookieIds }: SwitcherProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const knownIds = projects.map((p) => p.id);
  const scope = resolveProjectScope({
    query: searchParams.has('project') ? searchParams.getAll('project') : undefined,
    cookie: cookieIds?.join(','),
    knownIds,
  });
  const qs = searchParams.toString();
  return (
    <SwitcherView
      projects={projects}
      activeIds={scope.ids}
      returnTo={`${pathname}${qs ? `?${qs}` : ''}`}
      applies={isScopedPath(pathname)}
    />
  );
}

/** The switcher before the URL is known (prerendering): the cookie's scope, returning to the Inbox. */
export function ProjectSwitcherFallback({ projects, cookieIds }: SwitcherProps) {
  return <SwitcherView projects={projects} activeIds={cookieIds} returnTo="/" applies />;
}
