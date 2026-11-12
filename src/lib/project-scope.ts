/**
 * The dashboard's global project scope: which project(s) the Inbox, Findings, Review queue and Eval show.
 *
 * - The header switcher stores one project id in the `vigiles_project` cookie; no cookie means all projects.
 * - Any page can override it with `?project=<id>` (several: `?project=a,b`; every project: `?project=all`).
 * - Values are validated against the project ids in the database; an unknown id is ignored, so a stale
 *   cookie or a mistyped link falls back to the next source (query → cookie → all projects).
 *
 * Pure module (no Next or DB imports) so the client switcher, server pages and tests share it.
 */

export const PROJECT_COOKIE = 'vigiles_project';
/** `?project=all` selects every project. Project ids are kebab-case slugs; 'all' is reserved. */
export const ALL_PROJECTS = 'all';

/** Cookie attributes: server-only, sent on same-site navigations, kept for a year. */
export const PROJECT_COOKIE_OPTIONS = { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 24 * 365 } as const;

export interface ScopeProject {
  id: string;
  name: string;
  enabled: boolean;
}

/** Where the scope came from: `?project=` in the URL, the switcher's cookie, or the default (all projects). */
export type ScopeSource = 'query' | 'cookie' | 'default';

export interface ProjectScope {
  /** Project ids in scope, in the order given; null = every project */
  ids: string[] | null;
  source: ScopeSource;
}

/** A scope plus every known project (names, enabled flags, colours). What pages and the header render from. */
export interface ScopeContext extends ProjectScope {
  projects: ScopeProject[];
  /**
   * The cookie's scope alone (null = every project): what a link without `?project=` gets on the next request.
   * Links that must mean a specific scope compare against it.
   */
  cookieIds: string[] | null;
}

function valueParts(raw: unknown): string[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  const list = Array.isArray(raw) ? raw : [raw];
  if (!list.every((v) => typeof v === 'string')) return undefined;
  return (list as string[])
    .flatMap((v) => v.split(','))
    .map((v) => v.trim())
    .filter(Boolean);
}

/**
 * Reads one scope value (a cookie or `?project=`). Returns null for "all projects" (`all`, or an empty value
 * such as the Findings filter's "all projects" option), the known project ids it names (deduplicated), or
 * undefined when it is absent or names no known project, so the caller falls back to the next source.
 */
export function parseScopeValue(raw: unknown, knownIds: readonly string[]): string[] | null | undefined {
  const parts = valueParts(raw);
  if (parts === undefined) return undefined;
  if (parts.length === 0 || parts.includes(ALL_PROJECTS)) return null;
  const known = new Set(knownIds);
  const ids = [...new Set(parts.filter((p) => known.has(p)))];
  return ids.length ? ids : undefined;
}

/** The scope a request asks for: `?project=` wins over the cookie, which wins over the default (all projects). */
export function resolveProjectScope(input: { query?: unknown; cookie?: unknown; knownIds: readonly string[] }): ProjectScope {
  const fromQuery = parseScopeValue(input.query, input.knownIds);
  if (fromQuery !== undefined) return { ids: fromQuery, source: 'query' };
  const fromCookie = parseScopeValue(input.cookie, input.knownIds);
  if (fromCookie) return { ids: fromCookie, source: 'cookie' };
  return { ids: null, source: 'default' };
}

/** The pages the scope applies to; every other page (Projects, Jobs, a finding, Your call) shows every project. */
export const SCOPED_PATHS = ['/', '/findings', '/review', '/eval'] as const;

/** True when the page at `pathname` follows the scope (exact paths: a finding's own page is not a list). */
export function isScopedPath(pathname: string | null | undefined): boolean {
  if (!pathname) return true;
  const p = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  return (SCOPED_PATHS as readonly string[]).includes(p);
}

export function scopeIncludes(scope: Pick<ProjectScope, 'ids'>, projectId: string): boolean {
  return scope.ids === null || scope.ids.includes(projectId);
}

/** The projects a scope shows, in the context's order; for "all", every project (enabled or not). */
export function scopedProjects(ctx: ScopeContext): ScopeProject[] {
  return ctx.ids === null ? ctx.projects : ctx.projects.filter((p) => ctx.ids!.includes(p.id));
}

/** "All projects", "Held API", or "Held API and Held iOS": the scope in words. */
export function scopeLabel(ctx: ScopeContext): string {
  if (ctx.ids === null) return 'All projects';
  const names = ctx.ids.map((id) => ctx.projects.find((p) => p.id === id)?.name ?? id);
  return names.length <= 1 ? (names[0] ?? 'All projects') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}

/**
 * The `project` query value that keeps this scope on in-page links, or null when links need none: a
 * cookie or default scope applies by itself, but an override from the URL must be carried along.
 */
export function scopeParam(scope: ProjectScope): string | null {
  if (scope.source !== 'query') return null;
  return scope.ids === null ? ALL_PROJECTS : scope.ids.join(',');
}

/** `href` with the scope's `project` parameter added when the scope came from the URL (see scopeParam). */
export function withScope(href: string, scope: ProjectScope): string {
  const p = scopeParam(scope);
  if (p === null) return href;
  const [pathAndQuery, hash = ''] = href.split('#', 2) as [string, string?];
  const sep = pathAndQuery.includes('?') ? '&' : '?';
  return `${pathAndQuery}${sep}project=${encodeURIComponent(p).replaceAll('%2C', ',')}${hash ? `#${hash}` : ''}`;
}

/**
 * Where the switcher returns to after changing the scope: the same page, minus its `project` override (so the
 * new cookie applies) and, on the Review page, minus the finding id (so the queue of the new scope starts over).
 * Only same-origin paths are accepted; anything else returns to the Inbox.
 */
export function scopeReturnPath(raw: unknown): string {
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return '/';
  let url: URL;
  try {
    url = new URL(raw, 'http://vigiles.invalid');
  } catch {
    return '/';
  }
  if (url.origin !== 'http://vigiles.invalid') return '/';
  url.searchParams.delete('project');
  if (url.pathname === '/review') url.searchParams.delete('id');
  const qs = url.searchParams.toString();
  return `${url.pathname}${qs ? `?${qs}` : ''}`;
}

// ---------- per-project colours ----------

/** Tailwind classes for one project's colour (literal strings so Tailwind's scanner sees them). */
export interface ProjectColor {
  /** Small solid dot */
  dot: string;
  /** Soft pill: tinted background, dark text */
  soft: string;
  /** Solid pill: strong background, white text (the active scope) */
  solid: string;
  /** Left border accent for cards */
  border: string;
}

/** Hues that do not collide with the ping (red), digest (amber), ok (green) and accent (blue) tones. */
export const PROJECT_PALETTE: readonly ProjectColor[] = [
  {
    dot: 'bg-violet-500',
    soft: 'bg-violet-100 text-violet-900 dark:bg-violet-500/20 dark:text-violet-200',
    solid: 'bg-violet-600 text-white',
    border: 'border-l-violet-500',
  },
  {
    dot: 'bg-teal-500',
    soft: 'bg-teal-100 text-teal-900 dark:bg-teal-500/20 dark:text-teal-200',
    solid: 'bg-teal-600 text-white',
    border: 'border-l-teal-500',
  },
  {
    dot: 'bg-fuchsia-500',
    soft: 'bg-fuchsia-100 text-fuchsia-900 dark:bg-fuchsia-500/20 dark:text-fuchsia-200',
    solid: 'bg-fuchsia-600 text-white',
    border: 'border-l-fuchsia-500',
  },
  {
    dot: 'bg-cyan-500',
    soft: 'bg-cyan-100 text-cyan-900 dark:bg-cyan-500/20 dark:text-cyan-200',
    solid: 'bg-cyan-700 text-white',
    border: 'border-l-cyan-500',
  },
  {
    dot: 'bg-indigo-500',
    soft: 'bg-indigo-100 text-indigo-900 dark:bg-indigo-500/20 dark:text-indigo-200',
    solid: 'bg-indigo-600 text-white',
    border: 'border-l-indigo-500',
  },
  {
    dot: 'bg-lime-600',
    soft: 'bg-lime-100 text-lime-900 dark:bg-lime-500/20 dark:text-lime-200',
    solid: 'bg-lime-700 text-white',
    border: 'border-l-lime-600',
  },
];

/** For a project id that is not in the database (its profile was removed). */
export const UNKNOWN_PROJECT_COLOR: ProjectColor = {
  dot: 'bg-neutral-400',
  soft: 'bg-neutral-200 text-neutral-800 dark:bg-neutral-500/20 dark:text-neutral-200',
  solid: 'bg-neutral-600 text-white',
  border: 'border-l-neutral-400',
};

function hashId(id: string): number {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * A colour per project, the same on every page. Each id prefers the slot its hash picks (so adding a project
 * rarely recolours the others); collisions move to the next free slot, in id order, so up to
 * PROJECT_PALETTE.length projects never share a colour.
 */
export function projectColors(ids: readonly string[]): Map<string, ProjectColor> {
  const out = new Map<string, ProjectColor>();
  const taken = new Set<number>();
  const n = PROJECT_PALETTE.length;
  for (const id of [...new Set(ids)].sort()) {
    let slot = hashId(id) % n;
    if (taken.size < n) {
      while (taken.has(slot)) slot = (slot + 1) % n;
    }
    taken.add(slot);
    out.set(id, PROJECT_PALETTE[slot]!);
  }
  return out;
}

export function colorFor(colors: ReadonlyMap<string, ProjectColor>, id: string): ProjectColor {
  return colors.get(id) ?? UNKNOWN_PROJECT_COLOR;
}
