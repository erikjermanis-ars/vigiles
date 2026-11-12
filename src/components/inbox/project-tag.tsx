/**
 * A project's colour dot and name tag, and the "Showing: …" scope pill. Server-component safe; colours come from
 * projectColors() in src/lib/project-scope.ts so a project looks the same on every page.
 */
import { cx } from '@/components/ui';
import { colorFor, projectColors, scopeLabel, scopedProjects, type ProjectColor, type ScopeContext } from '@/lib/project-scope';

export function ProjectDot({ color, className }: { color: ProjectColor; className?: string }) {
  return <span aria-hidden className={cx('inline-block size-2 shrink-0 rounded-full', color.dot, className)} />;
}

/** "● Held API" as a tinted pill; greyed when the project is disabled. */
export function ProjectTag({
  name,
  color,
  enabled = true,
  solid = false,
  className,
}: {
  name: string;
  color: ProjectColor;
  enabled?: boolean;
  /** The strong variant, for the active scope */
  solid?: boolean;
  className?: string;
}) {
  return (
    <span
      title={enabled ? undefined : 'Disabled in its projects/*.yaml: not scanned or triaged'}
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap',
        solid ? color.solid : color.soft,
        !enabled && 'opacity-60',
        className,
      )}
    >
      {solid ? <span aria-hidden className="inline-block size-2 shrink-0 rounded-full bg-white/80" /> : <ProjectDot color={color} />}
      {name}
      {enabled ? null : <span className="font-normal">(disabled)</span>}
    </span>
  );
}

/** What the page is showing: "All projects" or the scoped projects' tags. */
export function ScopePill({ scope, className }: { scope: ScopeContext; className?: string }) {
  const colors = projectColors(scope.projects.map((p) => p.id));
  if (scope.ids === null) {
    return (
      <span
        className={cx('inline-flex items-center rounded-full bg-text px-2 py-0.5 text-xs font-medium whitespace-nowrap text-panel', className)}
        title="Every project. Pick one in the header to narrow the view."
      >
        {scopeLabel(scope)}
      </span>
    );
  }
  const shown = scopedProjects(scope);
  return (
    <span className={cx('inline-flex flex-wrap items-center gap-1', className)}>
      {shown.map((p) => (
        <ProjectTag key={p.id} name={p.name} color={colorFor(colors, p.id)} enabled={p.enabled} solid />
      ))}
    </span>
  );
}
